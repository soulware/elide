// Adapter: implement `elide_fetch::RangeFetcher` on top of `object_store`.
//
// The coordinator already owns an `Arc<dyn ObjectStore>` for upload, list and
// delete; demand-fetch (called from `spawn_blocking` worker threads) needs a
// sync interface. This wrapper bridges the two by capturing the current tokio
// runtime handle at construction time and using `Handle::block_on` to drive
// the async `get_range` call.
//
// Must be constructed inside a tokio runtime (so `Handle::current()` resolves);
// `get_range` itself must be called from a blocking context — i.e. a thread
// outside the reactor's worker pool, such as one spawned by `spawn_blocking`.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use ulid::Ulid;

use elide_fetch::RangeFetcher;

use crate::stores::ScopedStores;

pub struct ObjectStoreRangeFetcher {
    store: Arc<dyn ObjectStore>,
    handle: tokio::runtime::Handle,
}

impl ObjectStoreRangeFetcher {
    /// Construct an adapter capturing the current tokio runtime handle.
    /// Panics if called outside a tokio runtime.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self::with_handle(store, tokio::runtime::Handle::current())
    }

    /// Construct an adapter with an explicit runtime handle — for callers
    /// that build the adapter lazily from a blocking context (where
    /// `Handle::current()` would panic) having captured the handle
    /// earlier on the reactor.
    pub fn with_handle(store: Arc<dyn ObjectStore>, handle: tokio::runtime::Handle) -> Self {
        Self { store, handle }
    }
}

impl RangeFetcher for ObjectStoreRangeFetcher {
    fn get_range(&self, key: &str, start: u64, end_exclusive: u64) -> io::Result<Vec<u8>> {
        let path = StorePath::from(key);
        let range = (start as usize)..(end_exclusive as usize);
        let store = self.store.clone();
        let result = self
            .handle
            .block_on(async move { store.get_range(&path, range).await });
        match result {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(object_store::Error::NotFound { .. }) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{key} not found"),
            )),
            Err(e) => Err(io::Error::other(format!(
                "object_store get_range {key}: {e}"
            ))),
        }
    }
}

/// `RangeFetcher` that routes each key to a per-owner read store.
///
/// Every fetch key is `by_id/<owner>/…`, so the owner volume is read
/// straight from the key and used to select (or lazily build) a
/// single-prefix `volume-ro` store ([`ScopedStores::read_volume`]). Used
/// by filemap generation, whose range fetcher reads segment bodies that
/// may live under the leaf's prefix or any ancestor's — each owner gets
/// its own credential, none spanning the chain.
pub struct PerOwnerObjectStoreFetcher {
    stores: Arc<dyn ScopedStores>,
    handle: tokio::runtime::Handle,
    cache: Mutex<HashMap<Ulid, Arc<ObjectStoreRangeFetcher>>>,
}

impl PerOwnerObjectStoreFetcher {
    /// Capture the current runtime handle (call on the reactor) so the
    /// per-owner adapters can be built lazily inside `get_range`, which
    /// runs in a blocking worker.
    pub fn new(stores: Arc<dyn ScopedStores>) -> Self {
        Self {
            stores,
            handle: tokio::runtime::Handle::current(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn fetcher_for(&self, owner: Ulid) -> Arc<ObjectStoreRangeFetcher> {
        let mut cache = self.cache.lock().expect("per-owner fetcher cache lock");
        if let Some(f) = cache.get(&owner) {
            return Arc::clone(f);
        }
        let f = Arc::new(ObjectStoreRangeFetcher::with_handle(
            self.stores.read_volume(&owner),
            self.handle.clone(),
        ));
        cache.insert(owner, Arc::clone(&f));
        f
    }
}

impl RangeFetcher for PerOwnerObjectStoreFetcher {
    fn get_range(&self, key: &str, start: u64, end_exclusive: u64) -> io::Result<Vec<u8>> {
        let owner = owner_from_key(key)?;
        self.fetcher_for(owner).get_range(key, start, end_exclusive)
    }
}

/// Parse the owning volume ULID from a `by_id/<owner>/…` object key.
fn owner_from_key(key: &str) -> io::Result<Ulid> {
    let owner = key
        .strip_prefix("by_id/")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| io::Error::other(format!("fetch key is not under by_id/: {key}")))?;
    Ulid::from_string(owner)
        .map_err(|e| io::Error::other(format!("fetch key owner '{owner}' is not a ULID: {e}")))
}
