//! Mint-backed [`ScopedStores`] (`docs/design-mint.md` § *Coordinator
//! store architecture*).
//!
//! Each coordinator role (`coord-base`, `coord-writer`, and one
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
    MintEndpoint, ROLE_COORD_BASE, ROLE_COORD_WRITER, ROLE_VOLUME_RO, ROLE_VOLUME_RW,
    VOLUME_RO_TTL_SECS,
};

const CAVEAT_VOLUME: &str = "elide:Volume";

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
    /// `volume-ro`-only: the PoP-signed ancestor list the role template
    /// expands into per-ancestor read ARNs. Empty for every other role.
    ancestors: Vec<Ulid>,
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

/// Per-role `extra_body` fields surfaced through `assume-role`'s
/// PoP-signed body. `volume-ro` is the one role whose policy template
/// references `request.ancestors`; the key must be present even when
/// the list is empty, because handlebars strict mode treats a missing
/// path as a render failure (whereas an empty `{{#each}}` block simply
/// emits nothing — mint-side test
/// `empty_request_ancestors_renders_self_only`).
fn extra_body_for(role: &str, ancestors: &[Ulid]) -> Vec<(&'static str, serde_json::Value)> {
    if role == ROLE_VOLUME_RO {
        let ancestor_strs: Vec<String> = ancestors.iter().map(Ulid::to_string).collect();
        vec![("ancestors", serde_json::json!(ancestor_strs))]
    } else {
        Vec::new()
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
        Self::with_ancestors(endpoint, store_cfg, role, ttl_secs, vol_ulid, Vec::new())
    }

    fn with_ancestors(
        endpoint: MintEndpoint,
        store_cfg: StoreSection,
        role: &'static str,
        ttl_secs: u64,
        vol_ulid: Option<Ulid>,
        ancestors: Vec<Ulid>,
    ) -> Self {
        Self {
            endpoint,
            store_cfg,
            role,
            ttl_secs,
            vol_ulid,
            ancestors,
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
        let vol = self.vol_ulid.map(|v| v.to_string());
        let narrowing: Vec<(&str, &str)> = match &vol {
            Some(v) => vec![(CAVEAT_VOLUME, v.as_str())],
            None => Vec::new(),
        };
        let extra_owned = extra_body_for(self.role, &self.ancestors);
        self.endpoint
            .assume_role(self.role, self.ttl_secs, &narrowing, &extra_owned)
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
    /// `volume-ro` facades for single-volume reads, keyed by `vol_ulid`.
    /// Populated by `read_volume`; each entry's mint policy grants
    /// `by_id/<vol_ulid>/*` only.
    read_volume: Mutex<HashMap<Ulid, Arc<RoleStore>>>,
    /// `volume-ro` facades for head-prefetch reads, keyed by the head
    /// `vol_ulid`. The ancestor chain is deterministic from the head's
    /// provenance, so the first call's chain wins; subsequent calls for
    /// the same head reuse the facade. Kept separate from `read_volume`
    /// so a previously-cached narrow facade can't satisfy a later wide
    /// request (and vice versa, the wide facade is more permissive than
    /// any future narrow request needs).
    read_head: Mutex<HashMap<Ulid, Arc<RoleStore>>>,
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
            ROLE_COORD_BASE,
            COORD_CONTROL_TTL_SECS,
            None,
        ));
        let writer = Arc::new(RoleStore::new(
            endpoint.clone(),
            store_cfg.clone(),
            ROLE_COORD_WRITER,
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
            read_head: Mutex::new(HashMap::new()),
        }
    }

    /// Block until the mint endpoint accepts a `coord-base`
    /// `assume-role`. Used at startup so the coordinator survives mint
    /// coming up after it (systemd ordering, fresh box, etc.) instead
    /// of failing on the first S3 op.
    pub async fn wait_for_ready(&self) -> std::io::Result<()> {
        self.endpoint
            .wait_for_ready(ROLE_COORD_BASE, COORD_CONTROL_TTL_SECS)
            .await
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

    fn peer_verifier_store(&self) -> Arc<dyn ObjectStore> {
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

    fn read_volume(&self, vol_ulid: &Ulid) -> Arc<dyn ObjectStore> {
        // Cached by vol_ulid so successive reads of the same parent
        // inside one claim/start collapse onto one mint round-trip —
        // the role's 1h TTL covers a whole orchestrator pass.
        // `try_lock` keeps the method sync; momentary contention falls
        // back to constructing a fresh facade (its first op assumes
        // lazily either way — no correctness impact).
        if let Ok(map) = self.read_volume.try_lock()
            && let Some(rs) = map.get(vol_ulid)
        {
            return Arc::clone(rs) as Arc<dyn ObjectStore>;
        }
        let rs = Arc::new(RoleStore::new(
            self.endpoint.clone(),
            self.store_cfg.clone(),
            ROLE_VOLUME_RO,
            VOLUME_RO_TTL_SECS,
            Some(*vol_ulid),
        ));
        if let Ok(mut map) = self.read_volume.try_lock() {
            map.insert(*vol_ulid, Arc::clone(&rs));
        }
        rs as Arc<dyn ObjectStore>
    }

    fn read_head_with_ancestors(
        &self,
        vol_ulid: &Ulid,
        ancestors: &[Ulid],
    ) -> Arc<dyn ObjectStore> {
        // Cached by vol_ulid. The ancestor chain is deterministic from
        // the head's own provenance, so a second call for the same head
        // hits the cache regardless of the literal ancestor argument.
        if let Ok(map) = self.read_head.try_lock()
            && let Some(rs) = map.get(vol_ulid)
        {
            return Arc::clone(rs) as Arc<dyn ObjectStore>;
        }
        let rs = Arc::new(RoleStore::with_ancestors(
            self.endpoint.clone(),
            self.store_cfg.clone(),
            ROLE_VOLUME_RO,
            VOLUME_RO_TTL_SECS,
            Some(*vol_ulid),
            ancestors.to_vec(),
        ));
        if let Ok(mut map) = self.read_head.try_lock() {
            map.insert(*vol_ulid, Arc::clone(&rs));
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

    #[test]
    fn volume_ro_always_emits_ancestors_key_even_when_empty() {
        // Regression: the volume-ro policy template references
        // `request.ancestors`; handlebars strict mode rejects a missing
        // path. The chain-walk skeleton path mints with `&[]`, so the
        // empty case must still emit the key.
        let body = extra_body_for(ROLE_VOLUME_RO, &[]);
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].0, "ancestors");
        assert_eq!(body[0].1, serde_json::json!([] as [&str; 0]));
    }

    #[test]
    fn volume_ro_serialises_ancestor_chain_as_string_array() {
        let a = Ulid::new();
        let b = Ulid::new();
        let body = extra_body_for(ROLE_VOLUME_RO, &[a, b]);
        assert_eq!(body[0].1, serde_json::json!([a.to_string(), b.to_string()]));
    }

    #[test]
    fn non_volume_ro_roles_emit_no_extra_body() {
        for role in [ROLE_COORD_BASE, ROLE_COORD_WRITER, ROLE_VOLUME_RW] {
            assert!(extra_body_for(role, &[Ulid::new()]).is_empty());
        }
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
        };
        MintScopedStores::new(
            &cfg,
            StoreSection::default(),
            tmp.path().to_path_buf(),
            identity,
        )
    }

    #[test]
    fn read_volume_cache_reuses_facade_for_same_vol_ulid() {
        let stores = test_scoped_stores();
        let v = Ulid::new();
        let s1 = stores.read_volume(&v);
        let s2 = stores.read_volume(&v);
        assert!(
            Arc::ptr_eq(&s1, &s2),
            "second read_volume call for the same vol_ulid must hit the cache"
        );
    }

    #[test]
    fn read_volume_cache_separates_distinct_vol_ulids() {
        let stores = test_scoped_stores();
        let s_parent = stores.read_volume(&Ulid::new());
        let s_other = stores.read_volume(&Ulid::new());
        assert!(
            !Arc::ptr_eq(&s_parent, &s_other),
            "different vol_ulids must not share a facade"
        );
    }

    #[test]
    fn read_head_cache_reuses_facade_for_same_head() {
        let stores = test_scoped_stores();
        let v = Ulid::new();
        let a = Ulid::new();
        let s1 = stores.read_head_with_ancestors(&v, &[a]);
        let s2 = stores.read_head_with_ancestors(&v, &[a]);
        assert!(
            Arc::ptr_eq(&s1, &s2),
            "second head-prefetch call for the same head must hit the cache"
        );
    }

    #[test]
    fn read_volume_and_read_head_use_independent_caches() {
        // The same vol_ulid called via the two methods must produce
        // distinct facades — the narrow one (read_volume) and the wide
        // one (read_head_with_ancestors) carry different mint policies,
        // and the wide-then-narrow / narrow-then-wide ordering must
        // not contaminate either cache.
        let stores = test_scoped_stores();
        let v = Ulid::new();
        let a = Ulid::new();
        let narrow = stores.read_volume(&v);
        let wide = stores.read_head_with_ancestors(&v, &[a]);
        assert!(
            !Arc::ptr_eq(&narrow, &wide),
            "single-volume and head-with-ancestors facades must be independent"
        );
    }
}
