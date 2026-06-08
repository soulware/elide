// Lazy-credential `RangeFetcher` wrapper.
//
// Holds a credentialed inner `RangeFetcher` built from a current set of
// S3 credentials alongside the inputs needed to re-acquire them via the
// coordinator's macaroon-authenticated `Credentials` IPC. A background
// timer thread drops the cached fetcher (and the credentials baked into
// it) after the volume goes idle for `ttl`. The next `get_range` call
// rebuilds the fetcher under a write lock — concurrent waiters
// single-flight on the rebuild and share the result.
//
// Idle is not the only invalidation: credentials carry a policy expiry
// that can elapse while the volume is still busy, ahead of the idle
// timer. A `get_range` rejected with `PermissionDenied` reissues once
// and retries, so a continuously-active volume recovers without a fatal
// fetch failure.
//
// Trigger model is uniform: warm-stage activity keeps `last_use`
// fresh, so creds stay alive for the duration of warm; once warm
// exits, idle elapses TTL and creds are dropped; subsequent demand
// fetches re-acquire transparently.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use elide_fetch::{RangeFetcher, S3Credentials, S3RangeFetcher};

use crate::coordinator_client;

/// Default idle window after which cached credentials are dropped.
pub const DEFAULT_CREDS_IDLE_TTL: Duration = Duration::from_secs(60);

/// Interval at which the timer thread checks idleness. Half the TTL
/// so a drop fires within at most `1.5 * ttl` of the last access.
fn check_interval(ttl: Duration) -> Duration {
    (ttl / 2).max(Duration::from_secs(1))
}

/// Backend that produces a fresh `S3Credentials` value on demand.
/// Production impl talks to the coordinator over the macaroon IPC;
/// tests provide a stub.
pub trait CredsIssuer: Send + Sync {
    fn reissue(&self) -> io::Result<S3Credentials>;
}

/// `CredsIssuer` backed by the coordinator's `Credentials` IPC, scoped
/// to one owner volume's `by_id/<owner>/*` read prefix. Holds the
/// macaroon obtained at registration time and re-authenticates on every
/// call; `owner` is the `target` the coordinator authorizes and grants.
pub struct CoordinatorIssuer {
    socket: PathBuf,
    macaroon: String,
    owner: ulid::Ulid,
}

impl CoordinatorIssuer {
    pub fn new(socket: PathBuf, macaroon: String, owner: ulid::Ulid) -> Self {
        Self {
            socket,
            macaroon,
            owner,
        }
    }
}

impl CredsIssuer for CoordinatorIssuer {
    fn reissue(&self) -> io::Result<S3Credentials> {
        let client = coordinator_client::Client::new(&self.socket);
        let reply = client.macaroon_credentials(&self.macaroon, self.owner)?;
        Ok(S3Credentials {
            access_key_id: reply.access_key_id,
            secret_access_key: reply.secret_access_key,
            session_token: reply.session_token,
        })
    }
}

/// Builds a live `RangeFetcher` from a freshly-issued credential set.
/// In production this is an `S3RangeFetcher` bound to the bucket; the
/// seam lets tests inject a fetcher that simulates credential rejection
/// without touching S3.
type FetcherBuilder = Box<dyn Fn(S3Credentials) -> io::Result<Arc<dyn RangeFetcher>> + Send + Sync>;

/// `RangeFetcher` that caches a credentialed inner fetcher and drops it
/// after `ttl` of idleness, re-acquiring on the next request. A request
/// rejected with `PermissionDenied` (creds expired mid-use, before the
/// idle timer dropped them) forces a single reissue-and-retry.
pub struct LazyCredsFetcher {
    issuer: Arc<dyn CredsIssuer>,
    build: FetcherBuilder,
    inner: RwLock<Option<Arc<dyn RangeFetcher>>>,
    last_use_unix: AtomicU64,
    ttl: Duration,
}

impl LazyCredsFetcher {
    /// Build a wrapper that holds no credentials. The first
    /// `get_range` call invokes `issuer` to acquire creds and build
    /// an `S3RangeFetcher` — volumes whose warm plan is empty and
    /// whose reads are all cached never trigger an issuance.
    pub fn new(
        bucket: String,
        endpoint: Option<String>,
        region: Option<String>,
        issuer: Arc<dyn CredsIssuer>,
        ttl: Duration,
    ) -> Arc<Self> {
        let build: FetcherBuilder = Box::new(move |creds| {
            let f = S3RangeFetcher::new(&bucket, endpoint.as_deref(), region.as_deref(), creds)?;
            Ok(Arc::new(f) as Arc<dyn RangeFetcher>)
        });
        Self::with_builder(issuer, ttl, build)
    }

    fn with_builder(
        issuer: Arc<dyn CredsIssuer>,
        ttl: Duration,
        build: FetcherBuilder,
    ) -> Arc<Self> {
        let me = Arc::new(Self {
            issuer,
            build,
            inner: RwLock::new(None),
            last_use_unix: AtomicU64::new(now_unix()),
            ttl,
        });
        spawn_idle_timer(Arc::downgrade(&me));
        me
    }

    fn touch(&self) {
        self.last_use_unix.store(now_unix(), Ordering::Relaxed);
    }

    fn idle_secs(&self) -> u64 {
        let last = self.last_use_unix.load(Ordering::Relaxed);
        now_unix().saturating_sub(last)
    }

    /// Reissue credentials and build a fresh inner fetcher from them.
    fn build_fresh(&self) -> io::Result<Arc<dyn RangeFetcher>> {
        let creds = self.issuer.reissue()?;
        (self.build)(creds)
    }

    /// Acquire (or reuse) a live fetcher. Single-flight under the write
    /// lock — concurrent waiters during a rebuild see the freshly-built
    /// fetcher when they take the lock.
    fn acquire(&self) -> io::Result<Arc<dyn RangeFetcher>> {
        if let Some(f) = self.inner.read().expect("creds-fetcher read lock").as_ref() {
            return Ok(Arc::clone(f));
        }
        let mut guard = self.inner.write().expect("creds-fetcher write lock");
        if let Some(f) = guard.as_ref() {
            return Ok(Arc::clone(f));
        }
        let new = self.build_fresh()?;
        *guard = Some(Arc::clone(&new));
        info!("[creds] re-acquired S3 credentials after idle drop");
        Ok(new)
    }

    /// Reissue after `failed`'s credentials were rejected by S3.
    /// Single-flight against `failed`: if another thread already swapped
    /// in a fresh fetcher, reuse theirs rather than reissuing again —
    /// concurrent denials hit the coordinator at most once.
    fn reissue_after_denial(
        &self,
        failed: &Arc<dyn RangeFetcher>,
    ) -> io::Result<Arc<dyn RangeFetcher>> {
        let mut guard = self.inner.write().expect("creds-fetcher write lock");
        if let Some(f) = guard.as_ref()
            && !Arc::ptr_eq(f, failed)
        {
            return Ok(Arc::clone(f));
        }
        let new = self.build_fresh()?;
        *guard = Some(Arc::clone(&new));
        info!("[creds] reissued S3 credentials after access denial");
        Ok(new)
    }
}

impl RangeFetcher for LazyCredsFetcher {
    fn get_range(&self, key: &str, start: u64, end_exclusive: u64) -> io::Result<Vec<u8>> {
        self.touch();
        let f = self.acquire()?;
        match f.get_range(key, start, end_exclusive) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Cached creds were rejected — expired mid-use ahead of the
                // idle timer. Reissue once and retry; a second denial is a
                // genuine authz failure and propagates as fatal.
                warn!("[creds] S3 denied cached creds for {key}, reissuing: {e}");
                let fresh = self.reissue_after_denial(&f)?;
                fresh.get_range(key, start, end_exclusive)
            }
            other => other,
        }
    }
}

/// `RangeFetcher` that routes each key to a per-owner [`LazyCredsFetcher`].
///
/// Every fetch key is `by_id/<owner>/…`, so the owner volume is read
/// straight from the key and used to select (or lazily build) a
/// credential scoped to exactly that volume's prefix. Each owner gets
/// its own coordinator-vended credential (requested with `target = owner`,
/// which the coordinator authorizes against the requester's lineage) and
/// its own idle-drop timer — so a volume holds read credentials only for
/// the ancestors it actually pages in, one prefix each.
pub struct PerOwnerCredsFetcher {
    bucket: String,
    endpoint: Option<String>,
    region: Option<String>,
    socket: PathBuf,
    macaroon: String,
    ttl: Duration,
    owners: RwLock<HashMap<ulid::Ulid, Arc<LazyCredsFetcher>>>,
}

impl PerOwnerCredsFetcher {
    pub fn new(
        bucket: String,
        endpoint: Option<String>,
        region: Option<String>,
        socket: PathBuf,
        macaroon: String,
        ttl: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            bucket,
            endpoint,
            region,
            socket,
            macaroon,
            ttl,
            owners: RwLock::new(HashMap::new()),
        })
    }

    /// Get (or lazily build) the credential fetcher for `owner`.
    fn fetcher_for(&self, owner: ulid::Ulid) -> Arc<LazyCredsFetcher> {
        if let Some(f) = self.owners.read().expect("per-owner read lock").get(&owner) {
            return Arc::clone(f);
        }
        let mut guard = self.owners.write().expect("per-owner write lock");
        if let Some(f) = guard.get(&owner) {
            return Arc::clone(f);
        }
        let issuer = Arc::new(CoordinatorIssuer::new(
            self.socket.clone(),
            self.macaroon.clone(),
            owner,
        ));
        let lazy = LazyCredsFetcher::new(
            self.bucket.clone(),
            self.endpoint.clone(),
            self.region.clone(),
            issuer,
            self.ttl,
        );
        guard.insert(owner, Arc::clone(&lazy));
        lazy
    }
}

impl RangeFetcher for PerOwnerCredsFetcher {
    fn get_range(&self, key: &str, start: u64, end_exclusive: u64) -> io::Result<Vec<u8>> {
        let owner = owner_from_key(key)?;
        self.fetcher_for(owner).get_range(key, start, end_exclusive)
    }
}

/// Parse the owning volume ULID from a `by_id/<owner>/…` object key.
fn owner_from_key(key: &str) -> io::Result<ulid::Ulid> {
    let owner = key
        .strip_prefix("by_id/")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| io::Error::other(format!("fetch key is not under by_id/: {key}")))?;
    ulid::Ulid::from_string(owner)
        .map_err(|e| io::Error::other(format!("fetch key owner '{owner}' is not a ULID: {e}")))
}

/// Spawn a background thread that drops the cached fetcher when the
/// wrapper has been idle for at least `ttl`. The thread holds a
/// `Weak` so it self-terminates when the wrapper is dropped.
fn spawn_idle_timer(weak: Weak<LazyCredsFetcher>) {
    let interval = match weak.upgrade() {
        Some(s) => check_interval(s.ttl),
        None => return,
    };
    let _ = thread::Builder::new()
        .name("creds-idle".into())
        .spawn(move || {
            loop {
                thread::sleep(interval);
                let Some(strong) = weak.upgrade() else {
                    return;
                };
                let idle = strong.idle_secs();
                if idle < strong.ttl.as_secs() {
                    continue;
                }
                let mut guard = match strong.inner.write() {
                    Ok(g) => g,
                    Err(e) => {
                        warn!("[creds] idle timer write lock poisoned: {e}");
                        return;
                    }
                };
                if guard.is_some() {
                    *guard = None;
                    info!("[creds] dropped cached creds after {idle}s idle");
                }
            }
        });
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lazy, cached source of the coordinator-signed `PeerFetchToken`
/// claimer credential presented on `.body` peer-fetch requests.
///
/// Modeled on the S3-creds path: one IPC at first use, then cached and
/// refreshed at ≈ half the token freshness window (the cadence the
/// body-token bearer already uses), never per cache miss. A refresh
/// failure falls back to the last good token until it would itself be
/// stale on the peer, then returns `None` — the request proceeds with
/// no claimer header and the peer's claimer gate fails it closed (S3
/// fallback), same as any other peer miss.
pub struct LazyClaimerToken {
    socket: PathBuf,
    macaroon: String,
    cached: std::sync::Mutex<Option<CachedClaimer>>,
}

struct CachedClaimer {
    token: String,
    /// unix seconds after which we refresh proactively
    refresh_at: u64,
    /// unix seconds after which the token is no longer presentable
    expires_at: u64,
}

impl LazyClaimerToken {
    pub fn new(socket: PathBuf, macaroon: String) -> Self {
        Self {
            socket,
            macaroon,
            cached: std::sync::Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for LazyClaimerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyClaimerToken").finish_non_exhaustive()
    }
}

impl elide_peer_fetch::ClaimerTokenProvider for LazyClaimerToken {
    fn claimer_bearer(&self) -> Option<String> {
        let now = now_unix();
        let mut guard = self.cached.lock().ok()?;
        if let Some(c) = guard.as_ref()
            && now < c.refresh_at
        {
            return Some(c.token.clone());
        }
        let client = coordinator_client::Client::new(&self.socket);
        match client.peer_claimer_token(&self.macaroon) {
            Ok(reply) => {
                let window = elide_peer_fetch::DEFAULT_FRESHNESS_WINDOW_SECS;
                let token = reply.token.clone();
                *guard = Some(CachedClaimer {
                    token: reply.token,
                    refresh_at: reply.issued_at + window / 2,
                    expires_at: reply.issued_at + window,
                });
                Some(token)
            }
            Err(e) => match guard.as_ref() {
                Some(c) if now < c.expires_at => {
                    warn!("[claimer] refresh failed, using cached token: {e}");
                    Some(c.token.clone())
                }
                _ => {
                    warn!("[claimer] no claimer token available: {e}");
                    None
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Stub issuer that counts calls and returns a fixed (invalid)
    /// credential triple. Used to verify drop / reacquire control flow
    /// without touching S3 or the coordinator.
    struct StubIssuer {
        calls: AtomicUsize,
    }

    impl StubIssuer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
            })
        }
        fn count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl CredsIssuer for StubIssuer {
        fn reissue(&self) -> io::Result<S3Credentials> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(S3Credentials {
                access_key_id: "stub-key".into(),
                secret_access_key: "stub-secret".into(),
                session_token: None,
            })
        }
    }

    fn build_fetcher(issuer: Arc<StubIssuer>, ttl: Duration) -> Arc<LazyCredsFetcher> {
        LazyCredsFetcher::new(
            "test-bucket".into(),
            Some("http://127.0.0.1:1".into()),
            Some("us-east-1".into()),
            Arc::clone(&issuer) as Arc<dyn CredsIssuer>,
            ttl,
        )
    }

    /// Drives the wrapper directly via [`LazyCredsFetcher::acquire`] /
    /// idle bookkeeping rather than [`RangeFetcher::get_range`], because
    /// the latter would issue a real S3 request against an unreachable
    /// bucket. The two paths share the same caching primitives, so this
    /// covers them both.
    #[test]
    fn owner_from_key_parses_by_id_prefix() {
        // The owner is the second path segment of a `by_id/<owner>/…`
        // fetch key — this is the routing key for per-owner credentials.
        let owner = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let key = format!("by_id/{owner}/segments/20260101/01JQBBBBBBBBBBBBBBBBBBBBBB");
        assert_eq!(
            super::owner_from_key(&key).unwrap(),
            ulid::Ulid::from_string(owner).unwrap()
        );
        // Not under by_id/, or a non-ULID owner → hard error (never a
        // silent mis-route to the wrong credential).
        assert!(super::owner_from_key("snapshots/foo").is_err());
        assert!(super::owner_from_key("by_id/not-a-ulid/segments/x").is_err());
    }

    #[test]
    fn cold_start_then_acquire_then_idle_drop() {
        let issuer = StubIssuer::new();
        let ttl = Duration::from_secs(2);
        let fetcher = build_fetcher(Arc::clone(&issuer), ttl);

        // Cold start — no inner fetcher, no issuer calls.
        assert!(fetcher.inner.read().unwrap().is_none());
        assert_eq!(issuer.count(), 0);

        // First acquire issues creds and builds the inner fetcher.
        let _ = fetcher.acquire().expect("acquire");
        assert!(fetcher.inner.read().unwrap().is_some());
        assert_eq!(issuer.count(), 1);

        // Wait past TTL + check interval. With ttl=2s, check
        // interval is 1s, so within 4s the timer should drop.
        thread::sleep(Duration::from_secs(4));
        assert!(fetcher.inner.read().unwrap().is_none());
        assert_eq!(issuer.count(), 1);

        // Next acquire re-issues.
        let _ = fetcher.acquire().expect("re-acquire");
        assert!(fetcher.inner.read().unwrap().is_some());
        assert_eq!(issuer.count(), 2);
    }

    #[test]
    fn touch_resets_idle_clock() {
        let issuer = StubIssuer::new();
        let ttl = Duration::from_secs(3);
        let fetcher = build_fetcher(Arc::clone(&issuer), ttl);

        // Populate the inner so the timer has something to drop.
        let _ = fetcher.acquire().expect("acquire");
        assert_eq!(issuer.count(), 1);

        for _ in 0..6 {
            thread::sleep(Duration::from_millis(800));
            fetcher.touch();
        }
        // Total elapsed ~4.8s; with ttl=3s the timer would have
        // fired had touch() not reset the clock. Inner must still
        // be present and no re-issue.
        assert!(fetcher.inner.read().unwrap().is_some());
        assert_eq!(issuer.count(), 1);
    }

    #[test]
    fn timer_thread_self_terminates_on_drop() {
        // Just confirms drop doesn't deadlock or panic. Timer holds
        // a Weak; releasing the last strong reference must let the
        // thread observe `upgrade() == None` and exit cleanly.
        let issuer = StubIssuer::new();
        let fetcher = build_fetcher(issuer, Duration::from_secs(2));
        drop(fetcher);
        thread::sleep(Duration::from_secs(2));
    }

    #[test]
    fn cold_volume_never_issues_creds() {
        // The whole point of cold-start: a volume that never calls
        // get_range / acquire must never trigger an issuance.
        let issuer = StubIssuer::new();
        let _fetcher = build_fetcher(Arc::clone(&issuer), Duration::from_secs(2));
        thread::sleep(Duration::from_secs(3));
        assert_eq!(issuer.count(), 0);
    }

    /// Inner fetcher stub: returns `PermissionDenied` while `fail` is
    /// set, otherwise a fixed body. Counts the get_range calls so a test
    /// can see both the failed attempt and the successful retry.
    struct DenyingFetcher {
        fail: bool,
        calls: Arc<AtomicUsize>,
    }

    impl RangeFetcher for DenyingFetcher {
        fn get_range(&self, _key: &str, _start: u64, _end: u64) -> io::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "stale creds",
                ))
            } else {
                Ok(vec![1, 2, 3, 4])
            }
        }
    }

    #[test]
    fn permission_denied_reissues_and_retries() {
        // First-built inner rejects (creds expired mid-use); the reissued
        // inner succeeds. One get_range call retried transparently.
        let issuer = StubIssuer::new();
        let builds = Arc::new(AtomicUsize::new(0));
        let get_calls = Arc::new(AtomicUsize::new(0));
        let build: FetcherBuilder = {
            let builds = Arc::clone(&builds);
            let get_calls = Arc::clone(&get_calls);
            Box::new(move |_creds| {
                let n = builds.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::new(DenyingFetcher {
                    fail: n == 0,
                    calls: Arc::clone(&get_calls),
                }) as Arc<dyn RangeFetcher>)
            })
        };
        let fetcher = LazyCredsFetcher::with_builder(
            Arc::clone(&issuer) as Arc<dyn CredsIssuer>,
            Duration::from_secs(60),
            build,
        );

        let out = fetcher
            .get_range("by_id/x/seg", 0, 4)
            .expect("retry succeeds with reissued creds");
        assert_eq!(out, vec![1, 2, 3, 4]);
        // Acquired once, reissued once after the denial.
        assert_eq!(issuer.count(), 2);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        // Failed attempt + successful retry.
        assert_eq!(get_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn persistent_denial_fails_after_single_retry() {
        // Every inner rejects: the retry must not loop — exactly one
        // reissue, then the PermissionDenied propagates as fatal.
        let issuer = StubIssuer::new();
        let get_calls = Arc::new(AtomicUsize::new(0));
        let build: FetcherBuilder = {
            let get_calls = Arc::clone(&get_calls);
            Box::new(move |_creds| {
                Ok(Arc::new(DenyingFetcher {
                    fail: true,
                    calls: Arc::clone(&get_calls),
                }) as Arc<dyn RangeFetcher>)
            })
        };
        let fetcher = LazyCredsFetcher::with_builder(
            Arc::clone(&issuer) as Arc<dyn CredsIssuer>,
            Duration::from_secs(60),
            build,
        );

        let err = fetcher.get_range("by_id/x/seg", 0, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // Initial acquire + exactly one reissue (no unbounded retry loop).
        assert_eq!(issuer.count(), 2);
        assert_eq!(get_calls.load(Ordering::Relaxed), 2);
    }
}
