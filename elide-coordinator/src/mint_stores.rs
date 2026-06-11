//! Mint-backed [`ScopedStores`] (`docs/design-mint.md` § *Coordinator
//! store architecture*).
//!
//! Each coordinator role (`coord-ro`, `coord-rw`, and one
//! `volume-rw` per volume) is a [`RoleStore`] facade over a Tigris
//! keypair that mint vends via `assume-role`. The facade implements
//! [`ObjectStore`] and acquires its keypair lazily on first use,
//! caching the built `AmazonS3` client and re-assuming once the cached
//! credential passes its refresh point (half of the remaining TTL —
//! the *TTL principle*: refresh well inside the revocation window). A
//! brief refresh stall is absorbed by the WAL for writes and is off
//! the hot path for reads.
//!
//! `ScopedStores`'s methods are sync, so the facade is returned
//! immediately and the `assume-role` round-trip happens inside the
//! facade's own async ops.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use object_store::path::Path;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMultipartOpts,
    PutOptions, PutPayload, PutResult, Result as OsResult,
};
use tokio::sync::Mutex;
use tracing::info;
use ulid::Ulid;

use elide_coordinator::config::{MintConfig, StoreSection};
use elide_coordinator::identity::CoordinatorIdentity;
use elide_coordinator::stores::{ReadOnlyAdapter, ReadStore, ScopedStores};

use crate::mint_client::{
    MintEndpoint, ROLE_COORD_RO, ROLE_COORD_RW, ROLE_VOLUME_RO, ROLE_VOLUME_RW, VOLUME_RO_TTL_SECS,
};

/// Documented coord-* TTLs (`docs/design-mint.md` § *Elide as
/// customer*): coordinator-wide control plane 1h, per-volume data 24h.
const COORD_CONTROL_TTL_SECS: u64 = 60 * 60;
const VOLUME_RW_TTL_SECS: u64 = 24 * 60 * 60;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Cached {
    store: Arc<dyn ObjectStore>,
    /// Unix seconds at which `ensure` re-assumes — half the original
    /// TTL window before the credential's hard expiry.
    refresh_at: u64,
}

/// One mint credential role as an [`ObjectStore`]. Holds the cached
/// `AmazonS3` built from the last vended keypair and re-assumes when
/// it passes `refresh_at`.
pub struct RoleStore {
    endpoint: MintEndpoint,
    store_cfg: StoreSection,
    role: &'static str,
    ttl_secs: u64,
    /// `volume-rw` and `volume-ro` are per-volume; the `elide:Volume`
    /// narrowing caveat + audit value. `None` for the coordinator-wide
    /// roles.
    vol_ulid: Option<Ulid>,
    cached: Mutex<Option<Cached>>,
}

impl fmt::Debug for RoleStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoleStore({}", self.role)?;
        if let Some(v) = &self.vol_ulid {
            write!(f, " vol={v}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for RoleStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mint:{}", self.role)
    }
}

impl RoleStore {
    fn new(
        endpoint: MintEndpoint,
        store_cfg: StoreSection,
        role: &'static str,
        ttl_secs: u64,
        vol_ulid: Option<Ulid>,
    ) -> Self {
        Self {
            endpoint,
            store_cfg,
            role,
            ttl_secs,
            vol_ulid,
            cached: Mutex::new(None),
        }
    }

    /// Return a live `AmazonS3` for this role, re-assuming via mint if
    /// there is no cached keypair or the cached one has passed its
    /// refresh point.
    async fn ensure(&self) -> OsResult<Arc<dyn ObjectStore>> {
        let mut guard = self.cached.lock().await;
        if let Some(c) = guard.as_ref()
            && now_unix() < c.refresh_at
        {
            return Ok(Arc::clone(&c.store));
        }

        // Time the assume-role round-trip and S3-client construction
        // together — both are on the critical path of a credential
        // miss and we want to know how much one cache miss costs.
        let mint_started = Instant::now();
        let issued = self
            .assume()
            .await
            .map_err(|e| object_store::Error::Generic {
                store: "mint",
                source: Box::new(e),
            })?;
        let assume_elapsed = mint_started.elapsed();
        let store = self
            .store_cfg
            .build_with_creds(&issued.access_key_id, &issued.secret_access_key)
            .map_err(|e| object_store::Error::Generic {
                store: "mint",
                source: e.into(),
            })?;
        let total_elapsed = mint_started.elapsed();
        info!(
            "[mint] assume role={} vol={} assume={:.2?} total={:.2?} ttl={}s",
            self.role,
            self.vol_ulid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            assume_elapsed,
            total_elapsed,
            self.ttl_secs,
        );

        let now = now_unix();
        let expiry = issued.expiry_unix.unwrap_or(now + self.ttl_secs);
        // Refresh at the midpoint of the remaining window so a stalled
        // refresh still leaves a valid credential in hand.
        let refresh_at = now + expiry.saturating_sub(now) / 2;
        *guard = Some(Cached {
            store: Arc::clone(&store),
            refresh_at,
        });
        Ok(store)
    }

    async fn assume(&self) -> std::io::Result<crate::credential::IssuedCredentials> {
        // The per-volume target (`volume-ro` / `volume-rw`) rides the
        // assume-role body as `req.volume`; coord-wide roles pass `None`.
        self.endpoint
            .assume_role(self.role, self.ttl_secs, self.vol_ulid)
            .await
    }
}

#[async_trait]
impl ObjectStore for RoleStore {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> OsResult<PutResult> {
        self.ensure().await?.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOpts,
    ) -> OsResult<Box<dyn MultipartUpload>> {
        self.ensure()
            .await?
            .put_multipart_opts(location, opts)
            .await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> OsResult<GetResult> {
        self.ensure().await?.get_opts(location, options).await
    }

    async fn get_range(&self, location: &Path, range: Range<usize>) -> OsResult<Bytes> {
        self.ensure().await?.get_range(location, range).await
    }

    async fn head(&self, location: &Path) -> OsResult<ObjectMeta> {
        self.ensure().await?.as_ref().head(location).await
    }

    async fn delete(&self, location: &Path) -> OsResult<()> {
        self.ensure().await?.delete(location).await
    }

    fn list(&self, _prefix: Option<&Path>) -> BoxStream<'_, OsResult<ObjectMeta>> {
        // No coordinator credential carries `s3:ListBucket`
        // (`docs/list-elimination-plan.md` P5). Refuse locally
        // rather than forward; a forward would 403 on Tigris with
        // a generic S3 error. The `ObjectStore` trait requires
        // this method on `RoleStore` as long as `MintScopedStores`
        // returns `Arc<dyn ObjectStore>` —
        // `project_objectstore_trait_overreach` tracks the
        // higher-level surface narrowing that would let this fn
        // not exist at all.
        Box::pin(futures::stream::once(async {
            Err(object_store::Error::NotSupported {
                source: "coord-role credentials carry no s3:ListBucket; \
                         see docs/list-elimination-plan.md"
                    .into(),
            })
        }))
    }

    async fn list_with_delimiter(&self, _prefix: Option<&Path>) -> OsResult<ListResult> {
        Err(object_store::Error::NotSupported {
            source: "coord-role credentials carry no s3:ListBucket; \
                     see docs/list-elimination-plan.md"
                .into(),
        })
    }

    async fn copy(&self, from: &Path, to: &Path) -> OsResult<()> {
        self.ensure().await?.copy(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> OsResult<()> {
        self.ensure().await?.copy_if_not_exists(from, to).await
    }
}

/// [`ScopedStores`] backed by the external mint service. Selected when
/// `[mint]` is configured; otherwise the coordinator uses
/// `PassthroughStores`.
pub struct MintScopedStores {
    base: Arc<RoleStore>,
    writer: Arc<RoleStore>,
    endpoint: MintEndpoint,
    store_cfg: StoreSection,
    data: Mutex<HashMap<Ulid, Arc<RoleStore>>>,
    /// `volume-ro` facades for single-volume reads, keyed by
    /// `(owned, target)`. Each entry's mint policy grants
    /// `by_id/<target>/*` only; the `owned` half of the key is the
    /// anchor whose key signs the `ro-ancestor` possession proof at
    /// assume time, so facades with different anchors never share a
    /// credential cache.
    read_volume: Mutex<HashMap<(Ulid, Ulid), Arc<RoleStore>>>,
}

impl MintScopedStores {
    pub fn new(
        cfg: &MintConfig,
        store_cfg: StoreSection,
        data_dir: std::path::PathBuf,
        identity: Arc<CoordinatorIdentity>,
    ) -> Self {
        let endpoint = MintEndpoint::new(cfg, data_dir, identity);
        let base = Arc::new(RoleStore::new(
            endpoint.clone(),
            store_cfg.clone(),
            ROLE_COORD_RO,
            COORD_CONTROL_TTL_SECS,
            None,
        ));
        let writer = Arc::new(RoleStore::new(
            endpoint.clone(),
            store_cfg.clone(),
            ROLE_COORD_RW,
            COORD_CONTROL_TTL_SECS,
            None,
        ));
        Self {
            base,
            writer,
            endpoint,
            store_cfg,
            data: Mutex::new(HashMap::new()),
            read_volume: Mutex::new(HashMap::new()),
        }
    }

    /// Block until the mint endpoint accepts a `coord-ro`
    /// `assume-role`, then eagerly warm the `coord-ro` credential.
    ///
    /// Used at startup so the coordinator survives mint coming up after
    /// it (systemd ordering, fresh box, etc.) instead of failing on the
    /// first S3 op. `coord-ro` is the always-held control-plane
    /// credential, so the first op that touches it — a claim, a
    /// peer-fetch verification — should not be the one to pay its
    /// ~0.5s `assume-role`: assume it now and seed the cache. The probe
    /// proves mint is reachable; the warm-up populates `base`'s cache.
    /// Warm-up failure is non-fatal — the lazy path still mints on
    /// first use, so a transient blip just defers the cost.
    pub async fn wait_for_ready(&self) -> std::io::Result<()> {
        self.endpoint
            .wait_for_ready(ROLE_COORD_RO, COORD_CONTROL_TTL_SECS)
            .await?;
        if let Err(e) = self.base.ensure().await {
            tracing::warn!(
                "[coordinator] coord-ro warm-up failed ({e}); \
                 first control-plane op will assume it lazily"
            );
        }
        Ok(())
    }
}

impl ScopedStores for MintScopedStores {
    fn base_ro(&self) -> Arc<dyn ReadStore> {
        Arc::new(ReadOnlyAdapter::new(
            Arc::clone(&self.base) as Arc<dyn ObjectStore>
        ))
    }

    fn writer(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.writer) as Arc<dyn ObjectStore>
    }

    fn base_object_store(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.base) as Arc<dyn ObjectStore>
    }

    fn volume_rw(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        // Reuse a volume's facade so its keypair cache is shared
        // across ops. `try_lock` keeps this sync method non-blocking;
        // a momentary contention just builds a fresh facade (its first
        // op assumes lazily either way — no correctness impact).
        if let Ok(map) = self.data.try_lock()
            && let Some(rs) = map.get(vol_ulid)
        {
            return Arc::clone(rs) as Arc<dyn ObjectStore>;
        }
        let rs = Arc::new(RoleStore::new(
            self.endpoint.clone(),
            self.store_cfg.clone(),
            ROLE_VOLUME_RW,
            VOLUME_RW_TTL_SECS,
            Some(*vol_ulid),
        ));
        if let Ok(mut map) = self.data.try_lock() {
            map.insert(*vol_ulid, Arc::clone(&rs));
        }
        rs as Arc<dyn ObjectStore>
    }

    fn read_volume(&self, owned: &Ulid, target: &Ulid) -> Arc<dyn ObjectStore> {
        // Cached by (owned, target) so successive reads of the same
        // parent inside one claim/start collapse onto one mint
        // round-trip — the role's 1h TTL covers a whole orchestrator
        // pass. `try_lock` keeps the method sync; momentary contention
        // falls back to constructing a fresh facade (its first op
        // assumes lazily either way — no correctness impact).
        let key = (*owned, *target);
        if let Ok(map) = self.read_volume.try_lock()
            && let Some(rs) = map.get(&key)
        {
            return Arc::clone(rs) as Arc<dyn ObjectStore>;
        }
        let rs = Arc::new(RoleStore::new(
            self.endpoint.clone(),
            self.store_cfg.clone(),
            ROLE_VOLUME_RO,
            VOLUME_RO_TTL_SECS,
            Some(*target),
        ));
        if let Ok(mut map) = self.read_volume.try_lock() {
            map.insert(key, Arc::clone(&rs));
        }
        rs as Arc<dyn ObjectStore>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_ttls_match_doc() {
        assert_eq!(COORD_CONTROL_TTL_SECS, 3600);
        assert_eq!(VOLUME_RW_TTL_SECS, 86400);
    }

    #[test]
    fn refresh_at_is_window_midpoint() {
        // expiry 1000s out → refresh at +500s.
        let now: u64 = 10_000;
        let expiry: u64 = now + 1000;
        let refresh_at = now + expiry.saturating_sub(now) / 2;
        assert_eq!(refresh_at, now + 500);
    }

    fn test_scoped_stores() -> MintScopedStores {
        use elide_coordinator::config::StoreSection;
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let identity = Arc::new(
            CoordinatorIdentity::load_or_generate(tmp.path()).expect("identity load_or_generate"),
        );
        // A unix:<path> URL satisfies validation; no `assume_role` is
        // ever invoked in these tests — the facades are inspected for
        // cache identity only.
        let cfg = MintConfig {
            url: "unix:/tmp/elide-mint-test.sock".to_owned(),
            connect_timeout: std::time::Duration::from_secs(5),
            request_timeout: std::time::Duration::from_secs(30),
            attestation_location: None,
        };
        MintScopedStores::new(
            &cfg,
            StoreSection::default(),
            tmp.path().to_path_buf(),
            identity,
        )
    }

    #[test]
    fn read_volume_cache_reuses_facade_for_same_owned_target_pair() {
        let stores = test_scoped_stores();
        let owned = Ulid::new();
        let target = Ulid::new();
        let s1 = stores.read_volume(&owned, &target);
        let s2 = stores.read_volume(&owned, &target);
        assert!(
            Arc::ptr_eq(&s1, &s2),
            "second read_volume call for the same (owned, target) must hit the cache"
        );
    }

    #[test]
    fn read_volume_cache_separates_distinct_targets() {
        let stores = test_scoped_stores();
        let owned = Ulid::new();
        let s_parent = stores.read_volume(&owned, &Ulid::new());
        let s_other = stores.read_volume(&owned, &Ulid::new());
        assert!(
            !Arc::ptr_eq(&s_parent, &s_other),
            "different targets must not share a facade"
        );
    }

    #[test]
    fn read_volume_cache_separates_distinct_owned_anchors() {
        let stores = test_scoped_stores();
        let target = Ulid::new();
        let s_a = stores.read_volume(&Ulid::new(), &target);
        let s_b = stores.read_volume(&Ulid::new(), &target);
        assert!(
            !Arc::ptr_eq(&s_a, &s_b),
            "same target under different anchors must not share a facade \
             (each anchor signs its own possession proof)"
        );
    }
}
