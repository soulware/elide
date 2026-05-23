//! Scoped store provider for coordinator-side S3 access.
//!
//! Every coordinator S3 op routes through a [`ScopedStores`] handle.
//! The trait carves the bucket into the three mint credential roles
//! the coordinator wields (`docs/design-mint.md` § *Coordinator store
//! architecture*). A call site picks the role matching the purpose of
//! its code path. A mutation path uses [`ScopedStores::writer`] for
//! its whole `names/`+`events/`+own-`coordinators/` interaction; the
//! `coord-writer` policy holds `GetObject` on those prefixes, so the
//! reads inside a name-claim CAS run on the same credential as the
//! conditional write.
//!
//! * [`ScopedStores::base_ro`] — `coord-ro`. The read-only
//!   control-plane baseline, and the credential the LAN/internet-
//!   exposed peer-fetch verifier holds. Returns a narrow [`ReadStore`]
//!   so a holder can read and `head` only.
//!
//! * [`ScopedStores::writer`] — `coord-writer`. Coordinator-wide
//!   write: `names/`, `events/` (get + append), own
//!   `coordinators/<sub>/`, and `ListBucket`.
//!
//! * [`ScopedStores::volume_rw`] — `volume-rw`. Per-volume
//!   read+write under `by_id/<vol_ulid>/`.
//!
//! `volume-ro` is vended to the volume process
//! (`crate::mint_client`); the coordinator holds the three roles
//! above.
//!
//! [`PassthroughStores`] is the impl for the local-store / no-`[mint]`
//! case: one underlying store for every role. The mint-backed impl
//! ([`crate::mint_stores`]) is selected when `[mint]` is configured.

use std::sync::Arc;

use async_trait::async_trait;
use object_store::path::Path;
use object_store::{GetResult, ObjectMeta, ObjectStore};
use ulid::Ulid;

use crate::event_journal::{
    BucketEventJournal, EventJournal, EventJournalReader, ReadOnlyEventJournal,
};
use crate::name_claims::{BucketNameClaims, NameClaims, NameClaimsReader, ReadOnlyNameClaims};
use crate::volume_data::VolumeData;

/// Read-only S3 surface — `coord-ro`. Exposes `get` and `head`. A
/// holder can read individual objects; the containment boundary the
/// exposed peer-fetch verifier relies on is carried by this type.
#[async_trait]
pub trait ReadStore: Send + Sync {
    async fn get(&self, location: &Path) -> object_store::Result<GetResult>;
    async fn head(&self, location: &Path) -> object_store::Result<ObjectMeta>;
}

/// Adapts any [`ObjectStore`] down to the read-only [`ReadStore`]
/// surface. The passthrough / local-store impl returns this over its
/// single inner store; the mint-backed impl returns it over the
/// `coord-ro`-keyed store.
pub struct ReadOnlyAdapter {
    inner: Arc<dyn ObjectStore>,
}

impl ReadOnlyAdapter {
    pub fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ReadStore for ReadOnlyAdapter {
    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        self.inner.as_ref().get(location).await
    }
    async fn head(&self, location: &Path) -> object_store::Result<ObjectMeta> {
        self.inner.as_ref().head(location).await
    }
}

/// A full [`ObjectStore`] handle also satisfies [`ReadStore`]. This is
/// what lets a pure-read helper take `&dyn ReadStore` while both a
/// read-only path (passing [`ScopedStores::base_ro`]) and a mutation
/// path (passing its already-held [`ScopedStores::writer`]) call it
/// unchanged — the credential is decided by what the call site
/// acquired for its purpose, not by the helper. A read-only path
/// still cannot write, because it only ever holds the narrow
/// `base_ro()` handle.
#[async_trait]
impl ReadStore for Arc<dyn ObjectStore> {
    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        (**self).get(location).await
    }
    async fn head(&self, location: &Path) -> object_store::Result<ObjectMeta> {
        (**self).head(location).await
    }
}

/// Picks the right credential-scoped handle for a given coordinator
/// S3 op. With [`PassthroughStores`] every handle wraps the same inner
/// store; with the mint-backed impl they are distinct mint-vended
/// keypairs.
pub trait ScopedStores: Send + Sync {
    /// `coord-ro`: read-only `names/* coordinators/* events/*`.
    /// Read-only paths and the exposed verifier.
    fn base_ro(&self) -> Arc<dyn ReadStore>;

    /// `coord-writer`: coordinator-wide write authority. Mutation
    /// paths use this end-to-end (the reads in a CAS included).
    fn writer(&self) -> Arc<dyn ObjectStore>;

    /// `volume-rw`: read+write under `by_id/<vol_ulid>/`. The write
    /// credential for one volume's data — segment drain, GC, snapshot
    /// publish — and the credential for mixed read+write paths (a
    /// recovery flow that reads HEAD then publishes a synthesised
    /// manifest). Pure-read sites use [`Self::read_volume`] instead.
    fn volume_rw(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore>;

    /// `volume-ro` scoped to one volume's prefix only. Read-only
    /// under `by_id/<vol_ulid>/*`. Used by single-volume read sites:
    /// pulling an ancestor's skeleton, fetching a parent's handoff
    /// manifest, walking an extent-source ancestor. The returned
    /// store is `GetObject`-only — wrong-prefix writes fail at IAM,
    /// not at the call site.
    fn read_volume(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore>;

    /// `volume-ro` scoped to a head fork plus its full ancestor chain.
    /// Read-only under `by_id/<vol_ulid>/*` plus one
    /// `by_id/<ancestor>/*` per entry in `ancestors`
    /// (`docs/design-mint.md` § `volume-ro`). Used by the
    /// head-prefetch fan-out (`prefetch::prefetch_indexes` pass 2),
    /// which dispatches per-fork reads against a single shared
    /// credential. `ancestors` is the chain derived from the head's
    /// own provenance; for a given vol_ulid it is deterministic.
    fn read_head_with_ancestors(&self, vol_ulid: &Ulid, ancestors: &[Ulid])
    -> Arc<dyn ObjectStore>;

    /// The `coord-ro` store as a plain [`ObjectStore`]. Reads the
    /// coordinator-wide control-plane prefixes plus `meta/*` (every
    /// volume's `volume.provenance` / `volume.pub`); the read-only
    /// guarantee rests on `coord-ro`'s IAM policy. Used for the
    /// ancestor-skeleton pulls (`meta/` is bucket-wide, so chain
    /// discovery needs no per-volume credential) and by the peer-fetch
    /// verifier (`elide_peer_fetch::auth::AuthState`), which lives in a
    /// lower crate that cannot depend on [`ReadStore`].
    fn base_object_store(&self) -> Arc<dyn ObjectStore>;

    /// Full read+write handle for the per-name event log
    /// (`events/<name>/…`). Backed by both `coord-writer` (for
    /// emit's CAS, which runs wholly on one credential) and
    /// `coord-ro` (for the inherited reads, which need
    /// cross-coordinator pubkey lookups in `list_and_verify`).
    /// First slice of the domain-typed store layer
    /// (`docs/design-domain-store.md`); the trait deliberately has
    /// no `delete`, so a caller holding only an [`EventJournal`]
    /// cannot violate the append-only invariant.
    fn event_journal(&self) -> Arc<dyn EventJournal> {
        Arc::new(BucketEventJournal::new(
            self.writer(),
            self.base_object_store(),
        ))
    }

    /// Read-only handle for the per-name event log — `coord-ro`
    /// scope. A holder cannot call `emit`, so pure-read call sites
    /// (`volume events` IPC, peer-discovery) carry no over-privilege
    /// at the type level either. Mirrors the
    /// [`ReadStore`] vs `ObjectStore` split.
    fn event_journal_ro(&self) -> Arc<dyn EventJournalReader> {
        Arc::new(ReadOnlyEventJournal::new(self.base_object_store()))
    }

    /// Full read+write handle for the `names/<name>` claim records.
    /// Backed by both `coord-writer` (for the `mark_*` CAS verbs,
    /// which run wholly on one credential per mutation) and
    /// `coord-ro` (for the inherited reads). The trait exposes no
    /// untyped `update` / `overwrite` — every state change is a typed
    /// `mark_*` verb.
    fn name_claims(&self) -> Arc<dyn NameClaims> {
        Arc::new(BucketNameClaims::new(
            self.writer(),
            self.base_object_store(),
        ))
    }

    /// Read-only handle for the `names/<name>` claim records —
    /// `coord-ro` scope. A holder cannot invoke any `mark_*` verb
    /// at the type level. Used by `Request::ResolveName`,
    /// `bucket_position::fetch_position`, and the few pure-display
    /// readers.
    fn name_claims_ro(&self) -> Arc<dyn NameClaimsReader> {
        Arc::new(ReadOnlyNameClaims::new(self.base_object_store()))
    }

    /// Per-volume domain handle for `by_id/<vol>/…` objects. Vends
    /// non-`async` sub-accessors (`head()`, `metadata()`) that group
    /// the operations a caller may name. Backed by the same
    /// `volume-rw` credential as [`Self::volume_rw`]; the two
    /// co-exist while the remaining object-class views
    /// (segments / snapshots / retention) migrate in later steps of
    /// `docs/design-domain-store.md`.
    fn volume_data(&self, vol_ulid: &Ulid) -> VolumeData {
        VolumeData::new(self.volume_rw(vol_ulid), *vol_ulid)
    }
}

/// Returns the same underlying `Arc<dyn ObjectStore>` for every role
/// (wrapped in [`ReadOnlyAdapter`] for `base_ro`). The minimum-viable
/// impl — equivalent to the pre-mint behaviour where every op used one
/// full-bucket key. Used for the local-store / no-`[mint]` case.
pub struct PassthroughStores {
    inner: Arc<dyn ObjectStore>,
}

impl PassthroughStores {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { inner: store }
    }
}

impl ScopedStores for PassthroughStores {
    fn base_ro(&self) -> Arc<dyn ReadStore> {
        Arc::new(ReadOnlyAdapter::new(Arc::clone(&self.inner)))
    }

    fn writer(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.inner)
    }

    fn volume_rw(&self, _vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.inner)
    }

    fn read_volume(&self, _vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.inner)
    }

    fn read_head_with_ancestors(
        &self,
        _vol_ulid: &Ulid,
        _ancestors: &[Ulid],
    ) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.inner)
    }

    fn base_object_store(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.inner)
    }
}

/// Which `ScopedStores` method a caller selected, captured by
/// [`RecordingStores`] in the order the calls happened. Tests assert
/// against this sequence to pin down credential-routing decisions
/// per IPC verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleCall {
    BaseRo,
    Writer,
    VolumeRw(Ulid),
    ReadVolume(Ulid),
    ReadHeadWithAncestors(Ulid, Vec<Ulid>),
    BaseObjectStore,
}

/// `ScopedStores` decorator that records every method call and
/// delegates behaviour to an inner impl (typically
/// [`PassthroughStores`] over an `InMemory` store). Lets tests assert
/// "verb X selected role Y for vol Z" without spinning up the mint.
///
/// Cheap: `Arc<Mutex<Vec<RoleCall>>>` for the log, no synchronous I/O
/// beyond the delegate.
pub struct RecordingStores {
    inner: Arc<dyn ScopedStores>,
    calls: std::sync::Mutex<Vec<RoleCall>>,
}

impl RecordingStores {
    pub fn wrap(inner: Arc<dyn ScopedStores>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Snapshot the recorded call sequence.
    pub fn calls(&self) -> Vec<RoleCall> {
        self.calls
            .lock()
            .expect("recording stores poisoned")
            .clone()
    }

    /// Drop the recorded calls. Useful when a test wants to ignore
    /// setup-phase calls and only inspect the verb under test.
    pub fn clear(&self) {
        self.calls
            .lock()
            .expect("recording stores poisoned")
            .clear();
    }

    fn record(&self, call: RoleCall) {
        self.calls
            .lock()
            .expect("recording stores poisoned")
            .push(call);
    }
}

impl ScopedStores for RecordingStores {
    fn base_ro(&self) -> Arc<dyn ReadStore> {
        self.record(RoleCall::BaseRo);
        self.inner.base_ro()
    }
    fn writer(&self) -> Arc<dyn ObjectStore> {
        self.record(RoleCall::Writer);
        self.inner.writer()
    }
    fn volume_rw(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        self.record(RoleCall::VolumeRw(*vol_ulid));
        self.inner.volume_rw(vol_ulid)
    }
    fn read_volume(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        self.record(RoleCall::ReadVolume(*vol_ulid));
        self.inner.read_volume(vol_ulid)
    }
    fn read_head_with_ancestors(
        &self,
        vol_ulid: &Ulid,
        ancestors: &[Ulid],
    ) -> Arc<dyn ObjectStore> {
        self.record(RoleCall::ReadHeadWithAncestors(
            *vol_ulid,
            ancestors.to_vec(),
        ));
        self.inner.read_head_with_ancestors(vol_ulid, ancestors)
    }
    fn base_object_store(&self) -> Arc<dyn ObjectStore> {
        self.record(RoleCall::BaseObjectStore);
        self.inner.base_object_store()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    #[tokio::test]
    async fn passthrough_shares_one_store_and_readstore_can_read() {
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores = PassthroughStores::new(Arc::clone(&inner));

        let w = stores.writer();
        let d = stores.volume_rw(&Ulid::new());
        assert!(Arc::ptr_eq(&w, &inner));
        assert!(Arc::ptr_eq(&d, &inner));

        // The narrow ReadStore reads through to the same bytes.
        let key = Path::from("names/demo");
        w.put(&key, b"v".to_vec().into()).await.expect("put");
        let got = stores.base_ro().get(&key).await.expect("get");
        assert_eq!(got.bytes().await.expect("bytes").as_ref(), b"v");
    }
}
