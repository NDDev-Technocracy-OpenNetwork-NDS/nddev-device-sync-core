//! Named caller: Vault's elected replica task. The GDS adapter owns provider
//! I/O and the retained page; collection never creates another replica owner.
use std::{any::Any, future::Future, pin::Pin, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
pub type Collection = Pin<Box<dyn Future<Output = bool> + Send>>;
#[cfg(target_arch = "wasm32")]
pub type Collection = Pin<Box<dyn Future<Output = bool>>>;

/// One process-local catalog resource retained by the existing native owner.
/// `true` reports durable local changes, including partial publication before a
/// provider refusal. The replica then reads its actual local progress again;
/// a catalog failure must never turn successful Vault replication into failure.
pub trait CatalogCollector: Any + Send + Sync {
    fn collect(self: Arc<Self>) -> Collection;
    fn cancel(&self);
}
