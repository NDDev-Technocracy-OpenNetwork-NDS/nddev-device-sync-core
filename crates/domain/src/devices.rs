//! Enrollment and device control policy, separate from module declarations.
use crate::{
    DeviceId,
    identity::{AuthenticatedSession, Owner},
};
use std::collections::BTreeSet;

pub const ENROLLMENT_LIFETIME_MS: u64 = 300_000;
pub const ENROLLMENT_ATTEMPTS: u8 = 5;
pub const MAX_PENDING_ENROLLMENTS: usize = 8;
pub const MAX_ACTIVE_DEVICES: usize = 32;
/// Authenticated onboarding has its own per-owner budget, independent of the
/// unauthenticated sign-in source limit. Admit a full fleet without a quota reset.
pub const ENROLLMENT_RATE: crate::identity::RatePolicy = crate::identity::RatePolicy {
    limit: 32,
    window_ms: 3_600_000,
};
// Revoked identities are retained, never silently forgotten or reassigned.
pub const MAX_DEVICE_IDENTITIES: usize = 128;
pub const MAX_DEVICE_PAGE: usize = 100;
// Even maximal Unicode names fit a 64 KiB response with this finite page cap.
pub const DEVICE_RESPONSE_ITEMS: usize = 32;
pub const ENROLLMENT_DOMAIN: &[u8] = b"NDS-ENROLLMENT-V2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePlatform {
    Macos,
    Linux,
    Windows,
    Ios,
    Android,
    Web,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeviceError {
    #[error("invalid_device_input")]
    InvalidInput,
    #[error("device_authorization_denied")]
    Denied,
    #[error("invalid_enrollment_proof")]
    InvalidProof,
    #[error("enrollment_challenge_expired")]
    Expired,
    #[error("device_rate_limited")]
    RateLimited,
    #[error("device_capacity_reached")]
    Capacity,
    #[error("device_dependency_unavailable")]
    Unavailable,
    /// The caller's expected policy revision is no longer current.
    #[error("device_policy_conflict")]
    Conflict,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceName(String);
impl DeviceName {
    pub fn new(value: String) -> Result<Self, DeviceError> {
        if value.trim() != value
            || value.is_empty()
            || value.chars().count() > 128
            || value.chars().any(char::is_control)
        {
            return Err(DeviceError::InvalidInput);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicDeviceKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone)]
pub struct Device {
    pub id: DeviceId,
    pub owner: Owner,
    pub platform: DevicePlatform,
    pub name: DeviceName,
    pub public_key: PublicDeviceKey,
    pub status: DeviceStatus,
    pub created_at_ms: u64,
}

/// Intended workload of an enrolled device (architecture "Devices and workload
/// placement"). A profile describes intent; it never grants authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DevicePurpose {
    ServerHosting,
    ServerDevDesktop,
    ServerDesktop,
    BuildDevDesktop,
    DevDesktop,
    Desktop,
}
impl DevicePurpose {
    pub const ALL: [Self; 6] = [
        Self::ServerHosting,
        Self::ServerDevDesktop,
        Self::ServerDesktop,
        Self::BuildDevDesktop,
        Self::DevDesktop,
        Self::Desktop,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServerHosting => "server-hosting",
            Self::ServerDevDesktop => "server-dev-desktop",
            Self::ServerDesktop => "server-desktop",
            Self::BuildDevDesktop => "build-dev-desktop",
            Self::DevDesktop => "dev-desktop",
            Self::Desktop => "desktop",
        }
    }
    pub fn parse(value: &str) -> Result<Self, DeviceError> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.as_str() == value)
            .ok_or(DeviceError::InvalidInput)
    }
}

/// Authenticated action-admission mode of one device (ADR 0018). It is stored
/// with the device's owning space, never accepted as a per-command flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMode {
    /// The trusted actor controls its own space without an NDS checklist.
    Fullauto,
    /// The owner's explicit module configuration narrows admission.
    Manual,
}
impl ControlMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fullauto => "fullauto",
            Self::Manual => "manual",
        }
    }
    pub fn parse(value: &str) -> Result<Self, DeviceError> {
        match value {
            "fullauto" => Ok(Self::Fullauto),
            "manual" => Ok(Self::Manual),
            _ => Err(DeviceError::InvalidInput),
        }
    }
}

/// Largest revision every supported JSON consumer represents exactly.
pub const MAX_POLICY_REVISION: u64 = 9_007_199_254_740_991;

/// Current purpose profiles and control mode of one device. Replacing it never
/// changes the device ID, owner, public key or proof; only its revision moves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePolicy {
    mode: ControlMode,
    purposes: BTreeSet<DevicePurpose>,
    revision: u64,
}
impl DevicePolicy {
    pub fn new(
        mode: ControlMode,
        purposes: BTreeSet<DevicePurpose>,
        revision: u64,
    ) -> Result<Self, DeviceError> {
        if purposes.is_empty() || !(1..=MAX_POLICY_REVISION).contains(&revision) {
            return Err(DeviceError::InvalidInput);
        }
        Ok(Self {
            mode,
            purposes,
            revision,
        })
    }
    /// A device enrolled under ADR 0018 starts as a trusted general computer.
    pub fn enrolled() -> Self {
        Self {
            mode: ControlMode::Fullauto,
            purposes: BTreeSet::from([DevicePurpose::Desktop]),
            revision: 1,
        }
    }
    /// A device enrolled before control profiles keeps its explicit module
    /// checklist; migration never widens its authority.
    pub fn retained() -> Self {
        Self {
            mode: ControlMode::Manual,
            purposes: BTreeSet::from([DevicePurpose::Desktop]),
            revision: 1,
        }
    }
    pub fn mode(&self) -> ControlMode {
        self.mode
    }
    pub fn purposes(&self) -> &BTreeSet<DevicePurpose> {
        &self.purposes
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Compare-and-set replacement by the device's own authenticated owner.
    /// Widening manual into fullauto is a sensitive change and requires a recent
    /// sign-in proof; narrowing or reclassifying needs only an active session.
    /// The owning store applies this under the device row lock.
    pub fn replace(
        &self,
        authorization: &AuthenticatedSession,
        device: &Device,
        expected_revision: u64,
        mode: ControlMode,
        purposes: BTreeSet<DevicePurpose>,
        now: u64,
    ) -> Result<Self, DeviceError> {
        if !authorization.session.active(now)
            || device.owner != authorization.session.owner
            || device.status != DeviceStatus::Active
        {
            return Err(DeviceError::Denied);
        }
        if expected_revision != self.revision {
            return Err(DeviceError::Conflict);
        }
        if self.mode == ControlMode::Manual
            && mode == ControlMode::Fullauto
            && !authorization.session.recently_authenticated(now)
        {
            return Err(DeviceError::Denied);
        }
        let revision = self
            .revision
            .checked_add(1)
            .filter(|value| *value <= MAX_POLICY_REVISION)
            .ok_or(DeviceError::Capacity)?;
        Self::new(mode, purposes, revision)
    }
}

#[derive(Clone)]
pub struct EnrollmentChallenge {
    pub id: String,
    pub device: Device,
    pub session: crate::identity::ProtectedDigest,
    pub challenge: [u8; 32],
    pub expires_at_ms: u64,
    pub attempts_remaining: u8,
    pub consumed: bool,
}
impl EnrollmentChallenge {
    pub fn new(
        id: String,
        device: Device,
        session: &AuthenticatedSession,
        challenge: [u8; 32],
        now: u64,
    ) -> Result<Self, DeviceError> {
        if !crate::valid_identifier(&id) {
            return Err(DeviceError::InvalidInput);
        }
        if !session.session.active(now)
            || device.owner != session.session.owner
            || device.status != DeviceStatus::Active
        {
            return Err(DeviceError::Denied);
        }
        let expires = now
            .checked_add(ENROLLMENT_LIFETIME_MS)
            .ok_or(DeviceError::InvalidInput)?;
        Ok(Self {
            id,
            device,
            session: session.binding,
            challenge,
            expires_at_ms: expires.min(session.session.expires_at_ms),
            attempts_remaining: ENROLLMENT_ATTEMPTS,
            consumed: false,
        })
    }
    pub fn signing_bytes(&self) -> [u8; ENROLLMENT_DOMAIN.len() + 32] {
        let mut bytes = [0; ENROLLMENT_DOMAIN.len() + 32];
        bytes[..ENROLLMENT_DOMAIN.len()].copy_from_slice(ENROLLMENT_DOMAIN);
        bytes[ENROLLMENT_DOMAIN.len()..].copy_from_slice(&self.challenge);
        bytes
    }
    /// The owning store checks the same current session, then verifies Ed25519
    /// and persists this transition under its row lock, including failed proofs.
    pub fn consume(&mut self, signature_valid: bool, now: u64) -> Result<(), DeviceError> {
        if self.consumed || self.attempts_remaining == 0 {
            return Err(DeviceError::InvalidProof);
        }
        if now >= self.expires_at_ms {
            self.consumed = true;
            return Err(DeviceError::Expired);
        }
        self.attempts_remaining -= 1;
        if !signature_valid {
            return Err(DeviceError::InvalidProof);
        }
        self.consumed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TenantId, UserId,
        identity::{AuthMethod, ProtectedDigest, Session},
    };
    #[test]
    fn a_full_fleet_fits_one_owner_window_without_removing_its_bound() {
        let mut window = crate::identity::RateWindow::default();
        // Four onboarding batches of eight, without modifying time or the window.
        for batch in 0..4 {
            for _ in 0..8 {
                assert!(window.admit(1000 + batch, ENROLLMENT_RATE).is_ok());
            }
        }
        assert_eq!(
            window.admit(1004, ENROLLMENT_RATE),
            Err(crate::identity::IdentityError::RateLimited)
        );
        assert_eq!(
            window.admit(1000 + ENROLLMENT_RATE.window_ms - 1, ENROLLMENT_RATE),
            Err(crate::identity::IdentityError::RateLimited)
        );
        assert!(
            window
                .admit(1000 + ENROLLMENT_RATE.window_ms, ENROLLMENT_RATE)
                .is_ok()
        );
    }
    fn challenge(now: u64) -> EnrollmentChallenge {
        let owner = Owner {
            user_id: UserId::new("owner").unwrap(),
            tenant_id: TenantId::new("tenant").unwrap(),
        };
        let session = AuthenticatedSession {
            session: Session::new(owner.clone(), AuthMethod::EmailOtp, now).unwrap(),
            binding: ProtectedDigest([7; 32]),
        };
        let device = Device {
            id: DeviceId::new("device").unwrap(),
            owner,
            platform: DevicePlatform::Android,
            name: DeviceName::new("Test device".into()).unwrap(),
            public_key: PublicDeviceKey([9; 32]),
            status: DeviceStatus::Active,
            created_at_ms: now,
        };
        EnrollmentChallenge::new("challenge".into(), device, &session, [3; 32], now).unwrap()
    }
    #[test]
    fn proof_attempts_and_success_are_terminal() {
        let mut invalid = challenge(0);
        for _ in 0..ENROLLMENT_ATTEMPTS {
            assert_eq!(invalid.consume(false, 1), Err(DeviceError::InvalidProof));
        }
        assert_eq!(invalid.consume(true, 1), Err(DeviceError::InvalidProof));
        let mut valid = challenge(0);
        assert_eq!(valid.consume(true, 1), Ok(()));
        assert_eq!(valid.consume(true, 1), Err(DeviceError::InvalidProof));
    }
    #[test]
    fn observed_expiry_cannot_revive_with_clock_rollback() {
        let mut value = challenge(100);
        assert_eq!(
            value.consume(true, value.expires_at_ms),
            Err(DeviceError::Expired)
        );
        assert_eq!(value.consume(true, 101), Err(DeviceError::InvalidProof));
    }
    #[test]
    fn enrollment_cannot_outlive_or_cross_the_initiating_session() {
        let value = challenge(100);
        let mut session = AuthenticatedSession {
            session: Session::new(value.device.owner.clone(), AuthMethod::Github, 100).unwrap(),
            binding: ProtectedDigest([8; 32]),
        };
        session.session.expires_at_ms = 200;
        let short = EnrollmentChallenge::new(
            value.id.clone(),
            value.device.clone(),
            &session,
            value.challenge,
            100,
        )
        .unwrap();
        assert_eq!(short.expires_at_ms, 200);
        assert!(
            EnrollmentChallenge::new(
                value.id.clone(),
                value.device.clone(),
                &session,
                value.challenge,
                200
            )
            .is_err()
        );
        session.session.owner.user_id = UserId::new("other").unwrap();
        assert!(
            EnrollmentChallenge::new(value.id, value.device, &session, value.challenge, 100)
                .is_err()
        );
    }
    #[test]
    fn purpose_and_mode_vocabularies_are_closed() {
        for purpose in DevicePurpose::ALL {
            assert_eq!(DevicePurpose::parse(purpose.as_str()), Ok(purpose));
        }
        for invalid in ["", "Desktop", "server_hosting", "desktop ", "admin"] {
            assert_eq!(
                DevicePurpose::parse(invalid),
                Err(DeviceError::InvalidInput)
            );
        }
        for mode in [ControlMode::Fullauto, ControlMode::Manual] {
            assert_eq!(ControlMode::parse(mode.as_str()), Ok(mode));
        }
        assert_eq!(ControlMode::parse("auto"), Err(DeviceError::InvalidInput));
        assert!(DevicePolicy::new(ControlMode::Manual, BTreeSet::new(), 1).is_err());
        assert!(
            DevicePolicy::new(
                ControlMode::Manual,
                BTreeSet::from([DevicePurpose::Desktop]),
                0
            )
            .is_err()
        );
        assert!(
            DevicePolicy::new(
                ControlMode::Manual,
                BTreeSet::from([DevicePurpose::Desktop]),
                MAX_POLICY_REVISION + 1
            )
            .is_err()
        );
        assert_eq!(DevicePolicy::enrolled().mode(), ControlMode::Fullauto);
        assert_eq!(DevicePolicy::retained().mode(), ControlMode::Manual);
    }
    #[test]
    fn policy_replacement_is_owner_scoped_compare_and_set_and_widening_needs_recent_proof() {
        let value = challenge(100);
        let device = value.device.clone();
        let mut auth = AuthenticatedSession {
            session: Session::new(device.owner.clone(), AuthMethod::Passkey, 100).unwrap(),
            binding: ProtectedDigest([1; 32]),
        };
        let retained = DevicePolicy::retained();
        let servers = BTreeSet::from([DevicePurpose::ServerDevDesktop, DevicePurpose::Desktop]);
        // Reclassification keeps manual and only advances the revision.
        let reclassified = retained
            .replace(&auth, &device, 1, ControlMode::Manual, servers.clone(), 101)
            .unwrap();
        assert_eq!(reclassified.revision(), 2);
        assert_eq!(reclassified.purposes(), &servers);
        assert_eq!(
            retained.replace(&auth, &device, 2, ControlMode::Manual, servers.clone(), 101),
            Err(DeviceError::Conflict)
        );
        let later = 100 + crate::identity::RECENT_AUTHENTICATION_MS + 1;
        assert_eq!(
            reclassified.replace(
                &auth,
                &device,
                2,
                ControlMode::Fullauto,
                servers.clone(),
                later
            ),
            Err(DeviceError::Denied)
        );
        let widened = reclassified
            .replace(
                &auth,
                &device,
                2,
                ControlMode::Fullauto,
                servers.clone(),
                102,
            )
            .unwrap();
        assert_eq!(widened.mode(), ControlMode::Fullauto);
        // Narrowing remains available without a fresh proof.
        let narrowed = widened
            .replace(
                &auth,
                &device,
                3,
                ControlMode::Manual,
                servers.clone(),
                later,
            )
            .unwrap();
        assert_eq!(
            (narrowed.mode(), narrowed.revision()),
            (ControlMode::Manual, 4)
        );
        let mut revoked = device.clone();
        revoked.status = DeviceStatus::Revoked;
        assert_eq!(
            narrowed.replace(
                &auth,
                &revoked,
                4,
                ControlMode::Manual,
                servers.clone(),
                103
            ),
            Err(DeviceError::Denied)
        );
        auth.session.owner.user_id = UserId::new("other").unwrap();
        assert_eq!(
            narrowed.replace(&auth, &device, 4, ControlMode::Manual, servers, 103),
            Err(DeviceError::Denied)
        );
        let last = DevicePolicy::new(
            ControlMode::Manual,
            BTreeSet::from([DevicePurpose::Desktop]),
            MAX_POLICY_REVISION,
        )
        .unwrap();
        auth.session.owner = device.owner.clone();
        assert_eq!(
            last.replace(
                &auth,
                &device,
                MAX_POLICY_REVISION,
                ControlMode::Manual,
                BTreeSet::from([DevicePurpose::Desktop]),
                103
            ),
            Err(DeviceError::Capacity)
        );
    }
    #[test]
    fn signing_domain_and_unicode_name_bounds_are_explicit() {
        let value = challenge(0);
        assert_eq!(
            &value.signing_bytes()[..ENROLLMENT_DOMAIN.len()],
            b"NDS-ENROLLMENT-V2\0"
        );
        assert_eq!(&value.signing_bytes()[ENROLLMENT_DOMAIN.len()..], &[3; 32]);
        assert!(DeviceName::new("я".repeat(128)).is_ok());
        for invalid in [
            "я".repeat(129),
            "bad\nname".into(),
            " leading".into(),
            String::new(),
        ] {
            assert!(DeviceName::new(invalid).is_err());
        }
    }
}
