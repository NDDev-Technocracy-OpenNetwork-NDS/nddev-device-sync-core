//! Pure application/port ordering tests; real storage is qualified by Server.
use nddev_device_sync_application::devices::*;
use nddev_device_sync_domain::{
    TenantId, UserId,
    identity::{AuthMethod, Owner, ProtectedDigest, Session},
};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

struct State {
    held: AtomicBool,
    calls: AtomicUsize,
    response: Mutex<Vec<Device>>,
    seen: Mutex<Option<(Owner, [u8; 32], usize)>>,
    wake: Mutex<Option<Waker>>,
}
struct Store(Arc<State>);

impl DeviceStore for Store {
    async fn issue(&self, _: EnrollmentIssue, _: u64) -> Result<EnrollmentChallenge, DeviceError> {
        panic!("inventory must not issue an enrollment")
    }
    async fn complete(
        &self,
        _: &AuthenticatedSession,
        _: &str,
        _: [u8; 64],
        _: u64,
    ) -> Result<Device, DeviceError> {
        panic!("inventory must not complete an enrollment")
    }
    async fn revoke(
        &self,
        _: &AuthenticatedSession,
        _: &DeviceId,
        _: u64,
    ) -> Result<(), DeviceError> {
        panic!("inventory must not revoke a device")
    }
    async fn list(
        &self,
        auth: &AuthenticatedSession,
        _: u16,
        limit: usize,
        _: u64,
    ) -> Result<DevicePage, DeviceError> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        *self.0.seen.lock().unwrap() = Some((auth.session.owner.clone(), auth.binding.0, limit));
        poll_fn(|cx| {
            if self.0.held.load(Ordering::SeqCst) {
                *self.0.wake.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(DevicePage {
                    devices: self.0.response.lock().unwrap().clone(),
                    next_after: None,
                }))
            }
        })
        .await
    }
}

fn auth() -> AuthenticatedSession {
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
fn device(owner: Owner) -> Device {
    Device {
        id: DeviceId::new("device").unwrap(),
        owner,
        platform: DevicePlatform::Linux,
        name: DeviceName::new("Synthetic device".into()).unwrap(),
        public_key: PublicDeviceKey([1; 32]),
        status: DeviceStatus::Active,
        created_at_ms: 100,
    }
}
fn service(rows: Vec<Device>, held: bool) -> (DeviceService<Store, ()>, Arc<State>) {
    let state = Arc::new(State {
        held: AtomicBool::new(held),
        calls: AtomicUsize::new(0),
        response: Mutex::new(rows),
        seen: Mutex::new(None),
        wake: Mutex::new(None),
    });
    (DeviceService::new(Store(state.clone()), ()), state)
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture response must be ready"),
    }
}

#[test]
fn inventory_retains_the_original_personal_and_storage_context() {
    let auth = auth();
    let (service, state) = service(vec![device(auth.session.owner.clone())], false);
    let result = ready(service.list_personal(&auth, 0, 100, 100)).unwrap();
    assert_eq!(result.context.principal_id(), &auth.session.owner.user_id);
    assert_eq!(result.context.space_id(), &auth.session.owner.user_id);
    assert_eq!(result.context.storage_owner(), &auth.session.owner);
    assert_eq!(result.page.devices[0].id.as_str(), "device");
    assert_eq!(
        state.seen.lock().unwrap().as_ref(),
        Some(&(auth.session.owner, [7; 32], DEVICE_RESPONSE_ITEMS))
    );
}

#[test]
fn a_provider_cannot_rebind_a_held_page_even_when_device_or_principal_ids_collide() {
    for foreign in [
        Owner {
            user_id: UserId::new("principal").unwrap(),
            tenant_id: TenantId::new("other-tenant").unwrap(),
        },
        Owner {
            user_id: UserId::new("other-principal").unwrap(),
            tenant_id: TenantId::new("retained-tenant").unwrap(),
        },
    ] {
        let auth = auth();
        let (service, state) = service(vec![device(auth.session.owner.clone())], true);
        let mut future = pin!(service.list_personal(&auth, 0, 32, 100));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        *state.response.lock().unwrap() = vec![device(foreign)];
        state.held.store(false, Ordering::SeqCst);
        state.wake.lock().unwrap().take().unwrap().wake();
        assert!(matches!(
            future.as_mut().poll(&mut cx),
            Poll::Ready(Err(DeviceError::Unavailable))
        ));
    }
}

#[test]
fn legacy_inventory_uses_the_same_scope_check_and_refuses_oversized_provider_pages() {
    let auth = auth();
    let (service, _) = service(vec![device(auth.session.owner.clone()); 33], false);
    assert!(matches!(
        ready(service.list(&auth, 0, 100, 100)),
        Err(DeviceError::Unavailable)
    ));
}

#[test]
fn expired_authority_and_invalid_pagination_never_poll_the_store() {
    let auth = auth();
    let (service, state) = service(vec![], false);
    for (after, limit, now) in [
        (0, 32, auth.session.expires_at_ms),
        (0, 0, 100),
        (129, 32, 100),
    ] {
        assert!(ready(service.list_personal(&auth, after, limit, now)).is_err());
    }
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
}
