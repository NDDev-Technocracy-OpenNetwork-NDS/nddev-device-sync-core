//! Original personal-space context, distinct from the retained storage namespace.
//!
//! This is an authenticated-session snapshot, not a new grant. Owning stores
//! still revalidate the exact session at their transaction/effect boundary.
use crate::{
    UserId,
    identity::{AuthenticatedSession, IdentityError, Owner},
};

/// Personal space identity is the stable user ID. The original user/tenant
/// storage binding remains unchanged, including keys, ciphertext and cursors.
/// No serialization or credential material crosses the presentation boundary.
#[derive(Clone)]
pub struct PersonalContext {
    authorization: AuthenticatedSession,
}

impl PersonalContext {
    pub fn new(authorization: &AuthenticatedSession, now: u64) -> Result<Self, IdentityError> {
        if !authorization.session.active(now) {
            return Err(IdentityError::Denied);
        }
        Ok(Self {
            authorization: authorization.clone(),
        })
    }

    pub fn principal_id(&self) -> &UserId {
        &self.authorization.session.owner.user_id
    }

    /// The personal namespace is typed by this context, not inferred from an
    /// untrusted query parameter or an organization ID with the same text.
    pub fn space_id(&self) -> &UserId {
        self.principal_id()
    }

    pub fn storage_owner(&self) -> &Owner {
        &self.authorization.session.owner
    }

    pub fn authorization(&self) -> &AuthenticatedSession {
        &self.authorization
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TenantId, identity::AuthMethod, identity::ProtectedDigest, identity::Session};

    fn authorization() -> AuthenticatedSession {
        AuthenticatedSession {
            session: Session::new(
                Owner {
                    user_id: UserId::new("principal").unwrap(),
                    tenant_id: TenantId::new("retained-tenant").unwrap(),
                },
                AuthMethod::Passkey,
                100,
            )
            .unwrap(),
            binding: ProtectedDigest([7; 32]),
        }
    }

    #[test]
    fn personal_identity_keeps_the_exact_original_storage_and_session_binding() {
        let mut original = authorization();
        let context = PersonalContext::new(&original, 100).unwrap();
        original.session.owner.tenant_id = TenantId::new("replacement").unwrap();
        original.binding = ProtectedDigest([8; 32]);
        assert_eq!(context.principal_id().as_str(), "principal");
        assert_eq!(context.space_id(), context.principal_id());
        assert_eq!(
            context.storage_owner().tenant_id.as_str(),
            "retained-tenant"
        );
        assert_eq!(context.authorization().binding.0, [7; 32]);
    }

    #[test]
    fn expired_or_future_authority_cannot_create_a_personal_context() {
        let auth = authorization();
        for now in [99, auth.session.expires_at_ms, u64::MAX] {
            assert!(matches!(
                PersonalContext::new(&auth, now),
                Err(IdentityError::Denied)
            ));
        }
    }
}
