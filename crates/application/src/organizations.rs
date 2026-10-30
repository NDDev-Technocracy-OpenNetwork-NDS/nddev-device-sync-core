//! Company control use cases and ports. Adapters supply current membership under
//! the same transaction as session/device verification, receipt and state writes.
use crate::{
    identity::{EmailAddress, IdentityCrypto, Locale, ProtectedDigest, SecretText},
    sync::{SignedRequest, StoredResult, active},
};
use nddev_device_sync_domain::{
    InvitationId, UserId,
    organizations::{
        Company, CompanyRole, Membership, MembershipChange, OrganizationError,
        commands::{CommandId, DeliveryState},
        invitations::InvitationMetadata,
    },
    scope::PersonalContext,
    sync::MAX_REVISION,
};
use std::future::Future;

pub struct Context {
    pub personal: PersonalContext,
    pub company_id: Option<nddev_device_sync_domain::TenantId>,
    pub expected_membership_revision: Option<u64>,
    pub signed: SignedRequest,
    pub now_ms: u64,
}
impl Context {
    pub fn company(&self) -> Result<&nddev_device_sync_domain::TenantId, OrganizationError> {
        self.company_id
            .as_ref()
            .ok_or(OrganizationError::InvalidInput)
    }
}
pub fn authorize_personal(
    context: &Context,
    command: Option<&CommandId>,
    now: u64,
) -> Result<(), OrganizationError> {
    active(context.personal.authorization(), &context.signed, now)
        .map_err(OrganizationError::Authorization)?;
    if let Some(command) = command {
        command.validate(now)?;
    }
    Ok(())
}
pub fn authorize(
    context: &Context,
    member: &Member,
    command: Option<&CommandId>,
    now: u64,
    administrative: bool,
) -> Result<(), OrganizationError> {
    authorize_personal(context, command, now)?;
    if !(1..=MAX_REVISION).contains(&member.revision) {
        return Err(OrganizationError::InvalidState);
    }
    // A command cannot borrow a grant created by a later role change or rejoin.
    // Discovery may observe the current revision; admitted scoped work captures it.
    if context
        .expected_membership_revision
        .is_some_and(|revision| revision != member.revision)
        || command.is_some() && context.expected_membership_revision.is_none()
    {
        return Err(OrganizationError::Denied);
    }
    let owner = context.personal.storage_owner();
    if administrative {
        member
            .membership
            .authorize_administration(owner, context.company()?)?;
    } else {
        member
            .membership
            .authorize_membership(owner, context.company()?)?;
    }
    Ok(())
}

pub struct Member {
    pub membership: Membership,
    pub revision: u64,
    pub email: Option<EmailAddress>,
}
impl Member {
    pub fn change(
        &self,
        administrator: &Membership,
        actor: &nddev_device_sync_domain::identity::Owner,
        expected: u64,
        change: MembershipChange,
        active_administrators: usize,
    ) -> Result<(Membership, u64), OrganizationError> {
        if !(1..=MAX_REVISION).contains(&self.revision) {
            return Err(OrganizationError::InvalidState);
        }
        administrator.authorize_administration(actor, &self.membership.company_id)?;
        if expected != self.revision {
            return Err(OrganizationError::Conflict);
        }
        let next = self
            .membership
            .change(administrator, actor, change, active_administrators)?;
        let revision = if next == self.membership {
            self.revision
        } else {
            self.revision
                .checked_add(1)
                .filter(|value| *value <= MAX_REVISION)
                .ok_or(OrganizationError::RevisionExhausted)?
        };
        Ok((next, revision))
    }
}
pub struct Overview {
    pub company: Company,
    pub member: Member,
}
pub struct InvitationRecord {
    pub metadata: InvitationMetadata,
    pub email: EmailAddress,
    pub delivery: DeliveryState,
}
pub struct Page<T> {
    pub entries: Vec<T>,
    pub next_cursor: Option<String>,
}

pub struct InvitationRequest {
    pub email: EmailAddress,
    pub role: CompanyRole,
    pub locale: Locale,
}
pub struct PreparedInvitation {
    pub id: InvitationId,
    pub request: InvitationRequest,
    pub recipient_binding: ProtectedDigest,
    pub recipient_subject: ProtectedDigest,
    pub verifier: ProtectedDigest,
    pub token: SecretText,
}
pub struct InvitationMessage {
    pub id: InvitationId,
    pub recipient: EmailAddress,
    pub token: SecretText,
    pub expires_at_ms: u64,
    pub delivery_deadline_ms: u64,
    pub locale: Locale,
}
pub struct CreatedInvitation {
    pub result: StoredResult,
    /// Present only after a new committed creation. Receipt replay never resends.
    pub delivery: Option<InvitationMessage>,
}
pub trait InvitationDelivery: Send + Sync {
    fn available(&self) -> bool;
    fn queue(&self, message: InvitationMessage) -> Result<(), OrganizationError>;
}
pub trait OrganizationStore: Send + Sync {
    fn organizations(
        &self,
        context: &Context,
    ) -> impl Future<Output = Result<Vec<Overview>, OrganizationError>> + Send;
    fn create_company(
        &self,
        context: &Context,
        command: &CommandId,
        name: nddev_device_sync_domain::organizations::CompanyName,
    ) -> impl Future<Output = Result<StoredResult, OrganizationError>> + Send;
    fn overview(
        &self,
        context: &Context,
    ) -> impl Future<Output = Result<Overview, OrganizationError>> + Send;
    fn members(
        &self,
        context: &Context,
        after: Option<UserId>,
    ) -> impl Future<Output = Result<Page<Member>, OrganizationError>> + Send;
    fn invitations(
        &self,
        context: &Context,
        after: Option<InvitationId>,
    ) -> impl Future<Output = Result<Page<InvitationRecord>, OrganizationError>> + Send;
    fn create(
        &self,
        context: &Context,
        command: &CommandId,
        invitation: PreparedInvitation,
    ) -> impl Future<Output = Result<CreatedInvitation, OrganizationError>> + Send;
    fn revoke(
        &self,
        context: &Context,
        command: &CommandId,
        invitation: &InvitationId,
    ) -> impl Future<Output = Result<StoredResult, OrganizationError>> + Send;
    fn change(
        &self,
        context: &Context,
        command: &CommandId,
        target: &UserId,
        expected: u64,
        change: MembershipChange,
    ) -> impl Future<Output = Result<StoredResult, OrganizationError>> + Send;
    fn delivery(
        &self,
        id: &InvitationId,
        state: DeliveryState,
    ) -> impl Future<Output = Result<(), OrganizationError>> + Send;
}

pub async fn create_invitation<S: OrganizationStore, C: IdentityCrypto, D: InvitationDelivery>(
    store: &S,
    crypto: &C,
    delivery: &D,
    context: &Context,
    command: &CommandId,
    request: InvitationRequest,
) -> Result<StoredResult, OrganizationError> {
    command.validate(context.now_ms)?;
    let id = InvitationId::new(
        crypto
            .token()
            .map_err(|_| OrganizationError::Unavailable)?
            .into_inner(),
    )
    .map_err(|_| OrganizationError::Unavailable)?;
    let token = crypto.token().map_err(|_| OrganizationError::Unavailable)?;
    let prepared = PreparedInvitation {
        verifier: crypto.protect(
            "company_invitation",
            &[id.as_str().as_bytes(), token.expose().as_bytes()],
        ),
        recipient_binding: crypto.protect("owner_binding", &[request.email.as_str().as_bytes()]),
        recipient_subject: crypto.protect("email_subject", &[request.email.as_str().as_bytes()]),
        id,
        token,
        request,
    };
    // Availability is observed after storage so an existing receipt remains
    // replayable during SMTP downtime. A new resource has an explicit failure
    // state if its bounded queue cannot accept the one-use delivery material.
    let created = store.create(context, command, prepared).await?;
    if let Some(message) = created.delivery {
        let id = message.id.clone();
        if !delivery.available() || delivery.queue(message).is_err() {
            store.delivery(&id, DeliveryState::Failed).await?;
        }
    }
    Ok(created.result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::{TenantId, identity::Owner};
    #[test]
    fn organization_admission_uses_original_personal_context_and_current_selected_membership() {
        use nddev_device_sync_domain::{
            DeviceId,
            identity::{AuthMethod, AuthenticatedSession, ProtectedDigest, Session},
        };
        let owner = Owner {
            user_id: UserId::new("principal").unwrap(),
            tenant_id: TenantId::new("original-storage").unwrap(),
        };
        let auth = AuthenticatedSession {
            session: Session::new(owner.clone(), AuthMethod::EmailOtp, 1000).unwrap(),
            binding: ProtectedDigest([1; 32]),
        };
        let mut context = Context {
            personal: PersonalContext::new(&auth, 1000).unwrap(),
            company_id: Some(TenantId::new("first").unwrap()),
            expected_membership_revision: Some(4),
            signed: SignedRequest {
                device: DeviceId::new("device").unwrap(),
                nonce: "organization_nonce_1".into(),
                expires_at_ms: 2000,
                fingerprint: [2; 32],
            },
            now_ms: 1000,
        };
        let first = Membership {
            owner: owner.clone(),
            company_id: context.company().unwrap().clone(),
            role: CompanyRole::Admin,
            active: true,
        };
        let second = Membership {
            company_id: TenantId::new("second").unwrap(),
            role: CompanyRole::User,
            ..first.clone()
        };
        let current = |membership| Member {
            membership,
            revision: 4,
            email: None,
        };
        assert!(authorize(&context, &current(first.clone()), None, 1000, true).is_ok());
        context.company_id = Some(second.company_id.clone());
        assert_eq!(
            authorize(&context, &current(first.clone()), None, 1000, true),
            Err(OrganizationError::Denied)
        );
        assert!(authorize(&context, &current(second.clone()), None, 1000, false).is_ok());
        assert_eq!(
            authorize(&context, &current(second.clone()), None, 1000, true),
            Err(OrganizationError::Denied)
        );
        let removed = Membership {
            active: false,
            ..second
        };
        assert_eq!(
            authorize(&context, &current(removed.clone()), None, 1000, false),
            Err(OrganizationError::Denied)
        );
        let rejoined = Member {
            membership: Membership {
                active: true,
                role: CompanyRole::Admin,
                ..removed
            },
            revision: 5,
            email: None,
        };
        assert_eq!(
            authorize(&context, &rejoined, None, 1000, true),
            Err(OrganizationError::Denied)
        );
        let command = CommandId::new("00000000-03e8-7000-8000-000000000001".into()).unwrap();
        context.expected_membership_revision = Some(5);
        assert!(authorize(&context, &rejoined, Some(&command), 1000, true).is_ok());
        context.expected_membership_revision = None;
        assert_eq!(
            authorize(&context, &rejoined, Some(&command), 1000, true),
            Err(OrganizationError::Denied)
        );
        let invalid = Member {
            revision: 0,
            ..rejoined
        };
        assert_eq!(
            authorize(&context, &invalid, None, 1000, false),
            Err(OrganizationError::InvalidState)
        );
        context.expected_membership_revision = Some(4);
        // The same principal and a new, even broader role cannot revive the
        // old captured membership revision.
        assert!(authorize_personal(&context, None, 1000).is_ok());
        assert_eq!(context.personal.storage_owner(), &owner);
        assert_eq!(context.personal.principal_id().as_str(), "principal");
        context.company_id = None;
        assert_eq!(
            authorize(&context, &current(first.clone()), None, 1000, false),
            Err(OrganizationError::InvalidInput)
        );
        assert!(authorize_personal(&context, None, 2000).is_err());
    }
    #[test]
    fn member_revision_fences_changes_and_preserves_last_admin_policy() {
        let owner = Owner {
            user_id: UserId::new("admin").unwrap(),
            tenant_id: TenantId::new("company").unwrap(),
        };
        let member = Member {
            membership: Membership {
                owner: owner.clone(),
                company_id: owner.tenant_id.clone(),
                role: CompanyRole::Admin,
                active: true,
            },
            revision: 4,
            email: None,
        };
        assert_eq!(
            member.change(&member.membership, &owner, 3, MembershipChange::Remove, 2),
            Err(OrganizationError::Conflict)
        );
        assert_eq!(
            member.change(&member.membership, &owner, 4, MembershipChange::Remove, 1),
            Err(OrganizationError::LastAdministrator)
        );
        assert_eq!(
            member
                .change(
                    &member.membership,
                    &owner,
                    4,
                    MembershipChange::SetRole(CompanyRole::Admin),
                    1
                )
                .unwrap()
                .1,
            4
        );
        let (next, revision) = member
            .change(&member.membership, &owner, 4, MembershipChange::Remove, 2)
            .unwrap();
        assert!(!next.active);
        assert_eq!(next.owner, owner);
        assert_eq!(revision, 5);
        let exhausted = Member {
            revision: MAX_REVISION,
            ..member
        };
        assert_eq!(
            exhausted.change(
                &exhausted.membership,
                &owner,
                MAX_REVISION,
                MembershipChange::Remove,
                2
            ),
            Err(OrganizationError::RevisionExhausted)
        );
    }
}
