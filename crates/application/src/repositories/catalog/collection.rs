//! Named caller: Vault's elected replica task. The GDS adapter owns provider
//! I/O and the retained page; collection never creates another replica owner.
use std::{any::Any, future::Future, pin::Pin, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
pub type Collection = Pin<Box<dyn Future<Output = CollectionProgress> + Send>>;
#[cfg(target_arch = "wasm32")]
pub type Collection = Pin<Box<dyn Future<Output = CollectionProgress>>>;

#[derive(Clone, Copy, Default)]
pub struct CollectionProgress {
    pub local_changes: bool,
    pub continue_traversal: bool,
}

/// One process-local catalog resource retained by the existing native owner.
/// Progress reports durable local changes, including partial publication before
/// a provider refusal, separately from an unfinished bounded traversal. The
/// replica then reads its actual local progress again;
/// a catalog failure must never turn successful Vault replication into failure.
pub trait CatalogCollector: Any + Send + Sync {
    fn collect(self: Arc<Self>) -> Collection;
    fn cancel(&self);
}
