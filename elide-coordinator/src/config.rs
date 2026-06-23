// Coordinator configuration, loaded from coordinator.toml.
//
// Example coordinator.toml:
//
//   data_dir = "elide_data"   # directory containing volumes; default: ./elide_data
//
//   # [store] section is optional; defaults to a local directory at ./elide_store
//   # To use a specific local path:
//   # [store]
//   # local_path = "/var/lib/elide/store"
//   #
//   # To use S3:
//   # [store]
//   # bucket   = "my-elide-bucket"
//   # endpoint = "https://s3.amazonaws.com"  # optional; omit for AWS default
//   # region   = "us-east-1"                 # optional; falls back to AWS_DEFAULT_REGION
//   #
//   # To use Tigris (single global endpoint, region "auto"):
//   # [store]
//   # bucket   = "my-elide-bucket"
//   # endpoint = "https://t3.storage.dev"
//   # region   = "auto"
//   #
//   # Multipart upload tuning for segment bodies (all optional):
//   # multipart_part_size_mb = 5      # part size in MiB (min 5, S3 rule)
//   # request_timeout       = "5m"    # per-HTTP-request timeout (humantime)
//   # connect_timeout       = "5s"    # TCP+TLS connect timeout (humantime)
//   #
//   # Access keys are NOT configured here — they are read from the usual
//   # AWS env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) by both
//   # the coordinator and the spawned volume subprocesses. The coordinator
//   # exports `ELIDE_S3_BUCKET`, `AWS_ENDPOINT_URL`, and `AWS_DEFAULT_REGION`
//   # into each volume subprocess so only coordinator.toml needs to be set
//   # — no per-volume `fetch.toml` required for a uniform store.
//
//   [supervisor]
//   drain_interval  = "5s"   # how often each fork is checked for pending segments
//   scan_interval   = "30s"  # how often root directories are re-scanned for new forks
//
//   [gc]
//   density_threshold    = 0.70   # compact when live_bytes/file_bytes < threshold
//   interval             = "10s"  # how often GC runs per fork
//   retention_window     = "10m"  # how long GC inputs are retained in S3
//   max_buckets_per_tick = 4      # max independent output buckets per GC tick
//
// All duration fields use humantime ("5s", "30m", "24h").

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use humantime_serde::re::humantime;
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use object_store::local::LocalFileSystem;
use object_store::{ClientOptions, ObjectStore};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CoordinatorConfig {
    /// Directory containing volumes. Default: `./elide_data`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Path to the coordinator inbound socket.
    /// Defaults to `<data_dir>/control.sock`.
    pub socket_path: Option<PathBuf>,

    /// Object store configuration. Defaults to a local directory at `./elide_store`.
    #[serde(default)]
    pub store: StoreSection,

    /// Supervisor loop timings (drain cadence, root scan cadence).
    #[serde(default)]
    pub supervisor: SupervisorConfig,

    /// Path to the `elide` volume binary.
    /// Defaults to `"elide"` (resolved via PATH).
    #[serde(default = "default_elide_bin")]
    pub elide_bin: PathBuf,

    /// Path to the `elide-import` binary.
    /// Defaults to `"elide-import"` (resolved via PATH).
    #[serde(default = "default_elide_import_bin")]
    pub elide_import_bin: PathBuf,

    /// GC configuration.
    #[serde(default)]
    pub gc: GcConfig,

    /// Peer-fetch configuration. Optional; absence keeps peer fetch
    /// fully disabled (no HTTP server bound, no `peer-endpoint.toml`
    /// published, prefetch path skips the peer tier). v1 ships
    /// off-by-default.
    #[serde(default)]
    pub peer_fetch: PeerFetchConfig,

    /// External `mint` credential service. Optional; absence keeps the
    /// shared-key downgrade (every volume gets the coordinator's own
    /// key). Presence routes per-volume RO issuance through mint's
    /// `assume-role` over the configured endpoint
    /// (`docs/design-mint.md` § "Coordinator configuration").
    #[serde(default)]
    pub mint: Option<MintConfig>,

    /// Volume-attestation discharge authority (coord B). Optional; absence
    /// means this coordinator is not mint's discharge authority. When
    /// present with a `listen` address, serves `POST /v1/discharge` on its
    /// own listener — independent of `[peer_fetch]`, so a pure verifier
    /// enables only this (and may keep it off the network on a UDS).
    #[serde(default)]
    pub attestation: Option<AttestationConfig>,

    /// Operator-auth source for `elide coord enroll`. Absent → enrollment
    /// has no discharge source and fails with a pointer to configure one.
    /// `[auth.demo]` selects the shared-key demo where the coordinator
    /// holds the same `K_M-A` as mint and self-issues operator discharges
    /// locally (`docs/design-auth-service.md` § *Proposed: distributed
    /// demo — shared K_M-A*).
    #[serde(default)]
    pub auth: Option<AuthSection>,
}

impl CoordinatorConfig {
    /// Resolve the socket path: explicit config value, or `<data_dir>/control.sock`.
    pub fn resolved_socket_path(&self) -> PathBuf {
        self.socket_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("control.sock"))
    }

    /// The shared-key demo `K_M-A`, decoded from `[auth.demo].k_m_a`
    /// (standard base64 of 32 bytes — the identical value mint sources from
    /// its own `[auth.demo].k_m_a`). `Ok(None)` when no `[auth.demo]` is set.
    pub fn demo_k_m_a(&self) -> Result<Option<[u8; 32]>> {
        use base64::Engine as _;
        let Some(raw) = self.auth.as_ref().and_then(|a| a.demo.as_ref()) else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.k_m_a.trim())
            .context("[auth.demo].k_m_a is not valid standard base64")?;
        let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("[auth.demo].k_m_a decoded {} bytes, need 32", v.len())
        })?;
        Ok(Some(key))
    }
}

/// `[auth]` — the operator-auth source for enrollment.
#[derive(Deserialize)]
pub struct AuthSection {
    /// `[auth.demo]` — the shared-key demo (`docs/design-auth-service.md`
    /// § *Proposed: distributed demo — shared K_M-A*).
    #[serde(default)]
    pub demo: Option<RawDemoAuth>,
}

/// `[auth.demo]` — shared-key demo auth: the coordinator holds the same
/// `K_M-A` as mint and self-issues the operator discharges enrollment
/// needs, without a cross-host auth call.
#[derive(Deserialize)]
pub struct RawDemoAuth {
    /// `K_M-A` as standard base64 of 32 bytes — the identical value mint is
    /// deployed with (`openssl rand -base64 32`).
    pub k_m_a: String,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("elide_data")
}

fn default_elide_bin() -> PathBuf {
    sibling_bin("elide")
}

fn default_elide_import_bin() -> PathBuf {
    sibling_bin("elide-import")
}

/// Return a path to `name` in the same directory as the running coordinator
/// binary. Falls back to just `name` (PATH lookup) if the current exe path
/// cannot be determined.
fn sibling_bin(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

#[derive(Clone, Deserialize)]
pub struct StoreSection {
    /// Use a local directory as the object store (for testing).
    /// Mutually exclusive with `bucket`.
    #[serde(default)]
    pub local_path: Option<PathBuf>,

    /// S3 bucket name.
    #[serde(default)]
    pub bucket: Option<String>,

    /// S3-compatible endpoint URL (optional; omit for AWS default).
    #[serde(default)]
    pub endpoint: Option<String>,

    /// AWS region (optional; falls back to AWS_DEFAULT_REGION env var).
    #[serde(default)]
    pub region: Option<String>,

    /// Multipart upload part size in MiB for segment bodies. Must be at
    /// least 5 (S3 minimum part size, except the final part). Larger parts
    /// amortise request overhead; smaller parts retry faster on failure.
    /// Default: 5.
    #[serde(default = "default_multipart_part_size_mb")]
    pub multipart_part_size_mb: u64,

    /// Per-request timeout. Covers the full HTTP request lifetime (DNS +
    /// connect + TLS + body transfer + response). Must be long enough for
    /// a single multipart part to upload on the slowest link the
    /// coordinator is expected to run on. Default: 5m.
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// TCP+TLS connection-establishment timeout. Default: 5s.
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
}

fn default_multipart_part_size_mb() -> u64 {
    5
}
fn default_request_timeout() -> Duration {
    Duration::from_secs(300)
}
fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            local_path: None,
            bucket: None,
            endpoint: None,
            region: None,
            multipart_part_size_mb: default_multipart_part_size_mb(),
            request_timeout: default_request_timeout(),
            connect_timeout: default_connect_timeout(),
        }
    }
}

impl StoreSection {
    /// Non-secret store-locator env vars to export into spawned volume
    /// subprocesses so the volume's fetcher picks up the same store
    /// config as the coordinator without requiring the operator to also
    /// set env vars on the parent shell or drop a `fetch.toml` into
    /// every volume directory.
    ///
    /// Secrets are not in this list — and the coordinator scrubs
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
    /// `AWS_SESSION_TOKEN` from the inherited env at spawn
    /// (`supervisor::spawn_volume`). Volumes obtain credentials over
    /// the macaroon-authenticated IPC handshake. Local store mode
    /// returns an empty list; the volume's fallback to `./elide_store`
    /// handles that case.
    pub fn child_env(&self) -> Vec<(&'static str, String)> {
        let mut env = Vec::new();
        if let Some(bucket) = &self.bucket {
            env.push(("ELIDE_S3_BUCKET", bucket.clone()));
            if let Some(ep) = &self.endpoint {
                env.push(("AWS_ENDPOINT_URL", ep.clone()));
            }
            if let Some(region) = &self.region {
                env.push(("AWS_DEFAULT_REGION", region.clone()));
            }
        }
        env
    }

    /// Multipart part size in bytes, clamped to the S3 minimum of 5 MiB.
    pub fn multipart_part_size_bytes(&self) -> usize {
        (self.multipart_part_size_mb.max(5) * 1024 * 1024) as usize
    }

    /// `reqwest` client options (timeouts) derived from config.
    fn client_options(&self) -> ClientOptions {
        ClientOptions::default()
            .with_timeout(self.request_timeout)
            .with_connect_timeout(self.connect_timeout)
    }

    /// One-line human-readable summary of the configured object store, for
    /// startup logs. Does not include secrets.
    pub fn describe(&self) -> String {
        if let Some(path) = &self.local_path {
            format!("local {}", path.display())
        } else if let Some(bucket) = &self.bucket {
            let mut s = format!("s3 bucket={bucket}");
            if let Some(ep) = &self.endpoint {
                s.push_str(&format!(" endpoint={ep}"));
            }
            if let Some(region) = &self.region {
                s.push_str(&format!(" region={region}"));
            }
            s.push_str(&format!(
                " part={}MiB req_timeout={} connect_timeout={}",
                self.multipart_part_size_mb.max(5),
                humantime::format_duration(self.request_timeout),
                humantime::format_duration(self.connect_timeout),
            ));
            s
        } else {
            "local elide_store (default)".to_owned()
        }
    }

    /// Validate startup-time inputs that must be present before any
    /// object-store I/O. For S3 stores, bails immediately if
    /// `AWS_ACCESS_KEY_ID` is unset — without that, the object_store
    /// client falls back to the EC2 IMDS credential provider and spends
    /// ~11s per call on retries.
    ///
    /// Reachability + auth are proven by the subsequent
    /// `portable::probe_capabilities` call (PUT + conditional PUT +
    /// DELETE on a per-coordinator probe key); no separate read probe
    /// is needed.
    pub fn precheck_env(&self) -> Result<()> {
        if self.bucket.is_some() && std::env::var_os("AWS_ACCESS_KEY_ID").is_none() {
            bail!(
                "object store configured for S3 (bucket={}) but AWS_ACCESS_KEY_ID \
                 is not set in the environment; set AWS_ACCESS_KEY_ID and \
                 AWS_SECRET_ACCESS_KEY before starting the coordinator",
                self.bucket.as_deref().unwrap_or("?"),
            );
        }
        Ok(())
    }

    /// Build the S3 store with an explicitly-supplied access key pair,
    /// bypassing the `AWS_*` env vars `AmazonS3Builder::from_env`
    /// reads. Used by the `[mint]` path, which signs S3 ops with a
    /// keypair mint vended for the role, not with env credentials.
    ///
    /// Behaviour matches `build` for the local-store and default
    /// fallback branches; only the S3 branch differs (explicit
    /// `with_access_key_id` / `with_secret_access_key` instead of
    /// `from_env`).
    pub fn build_with_creds(
        &self,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Arc<dyn ObjectStore>> {
        if let Some(path) = &self.local_path {
            std::fs::create_dir_all(path)
                .with_context(|| format!("creating local store dir: {}", path.display()))?;
            let local = LocalFileSystem::new_with_prefix(path).context("building local store")?;
            return Ok(Arc::new(
                crate::local_cond_store::ConditionalLocalStore::new(local),
            ));
        }
        let Some(bucket) = &self.bucket else {
            bail!(
                "[mint] requires an S3 [store] section (bucket set); a local-only store \
                 has no role keypair to vend"
            );
        };
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_access_key_id(access_key_id)
            .with_secret_access_key(secret_access_key)
            .with_client_options(self.client_options())
            .with_conditional_put(S3ConditionalPut::ETagMatch);
        if let Some(ep) = &self.endpoint {
            builder = builder
                .with_endpoint(ep)
                .with_virtual_hosted_style_request(false);
        }
        if let Some(region) = &self.region {
            builder = builder.with_region(region);
        }
        Ok(Arc::new(builder.build().context("building S3 client")?))
    }

    pub fn build(&self) -> Result<Arc<dyn ObjectStore>> {
        if let Some(path) = &self.local_path {
            std::fs::create_dir_all(path)
                .with_context(|| format!("creating local store dir: {}", path.display()))?;
            // Wrap LocalFileSystem so PutMode::Update is honoured — the
            // upstream impl returns NotImplemented for it, which would
            // break the lifecycle verbs' If-Match read-modify-write.
            let local = LocalFileSystem::new_with_prefix(path).context("building local store")?;
            Ok(Arc::new(
                crate::local_cond_store::ConditionalLocalStore::new(local),
            ))
        } else if let Some(bucket) = &self.bucket {
            // Enable conditional PUT (`If-Match` ETag) so the lifecycle
            // verbs in `crate::lifecycle` can do read-modify-write on
            // `names/<name>` records atomically. Tigris and current AWS
            // S3 both support this; without it the S3 backend returns
            // `Error::NotImplemented` for `PutMode::Update`.
            let mut builder = AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .with_client_options(self.client_options())
                .with_conditional_put(S3ConditionalPut::ETagMatch);
            if let Some(ep) = &self.endpoint {
                builder = builder
                    .with_endpoint(ep)
                    .with_virtual_hosted_style_request(false);
            }
            if let Some(region) = &self.region {
                builder = builder.with_region(region);
            }
            Ok(Arc::new(builder.build().context("building S3 client")?))
        } else {
            // Default to a local directory store.
            let path = PathBuf::from("elide_store");
            std::fs::create_dir_all(&path)
                .with_context(|| format!("creating local store dir: {}", path.display()))?;
            Ok(Arc::new(
                LocalFileSystem::new_with_prefix(&path).context("building local store")?,
            ))
        }
    }
}

/// Process-global daemon `[store]` configuration. Set once by
/// `daemon::run` from the parsed `CoordinatorConfig`; read by the IPC
/// handler that vends store config to volume subprocesses
/// (`render_store_config` for `Request::GetStoreConfig`). Stored as
/// `&'static StoreSection` via `Box::leak` so the value can be plumbed
/// nowhere — IPC handlers read it directly — and so reads cost nothing
/// (no `Arc` clones, no `OnceLock` lookup falling back to a default).
static STORE_CONFIG: OnceLock<&'static StoreSection> = OnceLock::new();

/// Install the daemon-wide `[store]` config. Called once by
/// `daemon::run` before the IPC socket is bound; later calls are
/// silently ignored.
pub fn set_store_config(store: StoreSection) {
    let _ = STORE_CONFIG.set(Box::leak(Box::new(store)));
}

/// Read the daemon-wide `[store]` config.
///
/// Panics if `set_store_config` has not been called. The only caller
/// is `render_store_config` in `inbound::dispatch_json`, reachable
/// only via the IPC server bound after `daemon::run` installs the
/// value — so the unset case is an impossible-to-violate invariant
/// in production, and no test path reaches this getter.
pub fn store_config() -> &'static StoreSection {
    STORE_CONFIG
        .get()
        .copied()
        .expect("store_config not set before IPC dispatch")
}

/// Process-global coordinator IPC socket path. Set once by
/// `daemon::run` so coordinator-spawned subprocesses (currently the
/// `elide fetch-volume` worker) can be handed the right
/// `ELIDE_COORDINATOR_SOCKET` value at spawn time. Mirrors the
/// `STORE_CONFIG` pattern: `Box::leak`'d for cheap reads and so
/// callers don't need to thread the path through.
static COORDINATOR_SOCKET_PATH: OnceLock<&'static std::path::Path> = OnceLock::new();

/// Install the coordinator IPC socket path. Called once by
/// `daemon::run` before any subprocess is spawned.
pub fn set_coordinator_socket_path(path: std::path::PathBuf) {
    let _ = COORDINATOR_SOCKET_PATH.set(Box::leak(path.into_boxed_path()));
}

/// Read the coordinator IPC socket path. Returns `None` when
/// `set_coordinator_socket_path` has not been called (e.g. unit
/// tests that exercise IPC handlers without a full `daemon::run`).
pub fn coordinator_socket_path() -> Option<&'static std::path::Path> {
    COORDINATOR_SOCKET_PATH.get().copied()
}

#[derive(Deserialize)]
pub struct SupervisorConfig {
    /// How often each fork is checked for pending segments to upload.
    #[serde(default = "default_drain_interval", with = "humantime_serde")]
    pub drain_interval: Duration,

    /// How often root directories are re-scanned for newly-created forks.
    #[serde(default = "default_scan_interval", with = "humantime_serde")]
    pub scan_interval: Duration,
}

fn default_drain_interval() -> Duration {
    Duration::from_secs(5)
}
fn default_scan_interval() -> Duration {
    Duration::from_secs(30)
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            drain_interval: default_drain_interval(),
            scan_interval: default_scan_interval(),
        }
    }
}

/// Configuration for coordinator-driven segment GC.
#[derive(Deserialize, Clone)]
pub struct GcConfig {
    /// Compact a segment when live_bytes / file_bytes falls below this ratio.
    /// Default: 0.70.
    #[serde(default = "default_gc_density")]
    pub density_threshold: f64,

    /// How often to run a GC pass per fork. Default: 10s.
    #[serde(default = "default_gc_interval", with = "humantime_serde")]
    pub interval: Duration,

    /// Retention window for GC input segments. After a successful GC
    /// handoff, inputs are not deleted from S3 immediately; the
    /// handoff records them as `superseded` entries in
    /// `by_id/<vol>/HEAD` and the tick loop's reap step deletes them
    /// once this window has elapsed. Accepts humantime-style
    /// strings like `"24h"`, `"30s"`, `"5m"`. Default: `10m`.
    #[serde(default = "default_retention_window", with = "humantime_serde")]
    pub retention_window: Duration,

    /// Maximum number of output buckets emitted per GC tick. Each bucket
    /// produces one `gc/<ulid>.plan` and ultimately one S3 object, so
    /// raising this multiplies per-tick rewrite throughput and the
    /// retention-window peak by the same factor. Selection is filtered
    /// to fully cache-resident segments, so a tick never issues S3 GETs
    /// purely to enable a rewrite. Default: `4`.
    #[serde(default = "default_max_buckets_per_tick")]
    pub max_buckets_per_tick: usize,
}

fn default_gc_density() -> f64 {
    0.70
}
fn default_gc_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_retention_window() -> Duration {
    Duration::from_secs(10 * 60)
}
fn default_max_buckets_per_tick() -> usize {
    4
}

impl GcConfig {
    /// Cadence at which the reaper ticks: `max(retention / 10, 1s)`. The 1s
    /// floor exists for tests with very short retention; production T is
    /// hours, so the floor never binds in real deployments.
    pub fn reaper_cadence(&self) -> Duration {
        let derived = self.retention_window / 10;
        derived.max(Duration::from_secs(1))
    }
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            density_threshold: default_gc_density(),
            interval: default_gc_interval(),
            retention_window: default_retention_window(),
            max_buckets_per_tick: default_max_buckets_per_tick(),
        }
    }
}

/// Default `coordinator.toml` template emitted by `elide-coordinator init`.
/// All fields are commented out so the file documents itself: every value
/// shown is the default the daemon would use if the file were absent.
pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# Elide coordinator configuration.
# Every field below is optional; the values shown are the defaults.

# data_dir = "elide_data"
# socket_path = "elide_data/control.sock"  # defaults to <data_dir>/control.sock
# elide_bin = "elide"                      # resolved via PATH
# elide_import_bin = "elide-import"        # resolved via PATH

[store]
# Local directory store (default if neither local_path nor bucket is set):
# local_path = "elide_store"
#
# S3-compatible store:
# bucket   = "my-elide-bucket"
# endpoint = "https://s3.amazonaws.com"   # optional; omit for AWS default
# region   = "us-east-1"                  # falls back to AWS_DEFAULT_REGION
#
# Tigris (https://www.tigrisdata.com) — single global endpoint, region "auto":
# bucket   = "my-elide-bucket"
# endpoint = "https://t3.storage.dev"
# region   = "auto"
#
# Access keys come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the
# coordinator's environment and are inherited by spawned volume subprocesses.
#
# multipart_part_size_mb = 5      # min 5 (S3 rule)
# request_timeout        = "5m"   # per-HTTP-request timeout (humantime)
# connect_timeout        = "5s"   # TCP+TLS connect timeout (humantime)

[supervisor]
# drain_interval = "5s"   # how often each fork is checked for pending segments
# scan_interval  = "30s"  # how often roots are re-scanned for new forks

[gc]
# density_threshold    = 0.70    # compact when live_bytes / file_bytes < threshold
# interval             = "10s"   # how often GC runs per fork
# retention_window     = "10m"   # how long GC inputs stay in S3 before reaping
# max_buckets_per_tick = 4       # max independent output buckets per GC tick

# [mint] — opt-in; uncomment the header and `url` to enable. Routes
# per-volume RO credential issuance through the external `mint`
# service's `assume-role` (docs/design-mint.md § "Coordinator
# configuration"). Absence keeps the shared-key downgrade where every
# volume gets the coordinator's own AWS_* key. The coordinator's
# mint identity is its existing `coordinator.key`; the per-role
# capability macaroons live under <data_dir>/credentials/<role>
# (provisioned by enrollment, not here). `url` is required and is
# scheme-discriminated exactly as mint's reference client:
# `unix:<path>` selects the UDS transport (bundled single-host shape),
# `http(s)://host:port` the TCP transport (network shapes).
#
# [mint]
# url             = "unix:mint/mint_data/mint.sock"
# connect_timeout = "5s"
# request_timeout = "30s"

# [auth] — operator-auth source for `elide coord enroll`. `[auth.demo]`
# selects the shared-key demo: the coordinator holds the same K_M-A as the
# mint it enrolls against and self-issues the operator discharges locally,
# with no cross-host auth call (docs/design-auth-service.md § "Proposed:
# distributed demo — shared K_M-A"). `k_m_a` is standard base64 of 32 bytes
# — the identical value set in mint's own [auth.demo].k_m_a.
#
# [auth.demo]
# k_m_a = "..."   # openssl rand -base64 32, shared with mint

[peer_fetch]
# Setting `port` enables peer fetch: the coordinator binds an HTTP server on
# this port and advertises it at `coordinators/<id>/peer-endpoint.toml` for
# other coordinators on the LAN. Leaving `port` unset keeps peer fetch fully
# disabled — no server, no advertisement, no peer tier in the prefetch path.
# v1 ships off-by-default.
#
# port = 8443                  # absent → peer fetch disabled
# bind = "0.0.0.0"             # interface to bind on; default 0.0.0.0
# host = "host.example.com"    # advertised hostname for peers; default gethostname()
"#;

/// Load and parse a `coordinator.toml` file.
///
/// A missing file is an error, not a silent fall-through to defaults: a
/// coordinator with no `[store]`/`[mint]` config cannot serve, and a default
/// config quietly routes serve into the shared-key passthrough branch where it
/// fails far from the cause (an opaque conditional-PUT bail on the default local
/// store). Surfacing the missing path here is immediately actionable.
pub fn load(path: &Path) -> Result<CoordinatorConfig> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading config file: {} (pass --config, set ELIDE_COORD_CONFIG, \
             or run `elide-coordinator init` to create one)",
            path.display()
        )
    })?;
    toml::from_str(&text).with_context(|| format!("parsing config file: {}", path.display()))
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            socket_path: None,
            store: StoreSection::default(),
            supervisor: SupervisorConfig::default(),
            elide_bin: default_elide_bin(),
            elide_import_bin: default_elide_import_bin(),
            gc: GcConfig::default(),
            peer_fetch: PeerFetchConfig::default(),
            mint: None,
            attestation: None,
            auth: None,
        }
    }
}

/// External `mint` credential service (`docs/design-mint.md`). The
/// coordinator holds a per-role capability macaroon under
/// `<data_dir>/credentials/<role>` (provisioned by enrollment, not
/// config) and exercises it via mint's `assume-role`. Identity is the
/// existing `coordinator.key`; `aud=mint` is fixed inside the
/// macaroon. The only configurable surface is the endpoint and its
/// timeouts — see the doc's "deliberately thin" note.
#[derive(Deserialize, Clone, Debug)]
pub struct MintConfig {
    /// mint endpoint, scheme-discriminated exactly as mint's reference
    /// client `--url` (`docs/design-mint.md` § "Transport"):
    /// `unix:<path>` selects the UDS leg (the bundled single-host
    /// shape), `http://`/`https://` the TCP leg (the network shapes).
    pub url: String,

    /// Connection-establishment timeout. Default: 5s.
    #[serde(default = "default_mint_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Per-request timeout for an `assume-role` call. Credential
    /// vending is a small request; the default is generous. Default:
    /// 30s.
    #[serde(default = "default_mint_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Discharge location of the attestation coordinator (coord B) that
    /// vouches volume ownership (`docs/design-mint-volume-attestation.md`).
    /// When set, a primary credential carrying a third-party caveat at
    /// this exact location is discharged before `assume-role`: the
    /// coordinator proves possession of the volume's `volume.key` and
    /// attaches the returned discharge to the bundle. Absent → no
    /// discharge is fetched (the enrolled credentials carry no attestation
    /// caveat). Must equal the `attestation_location` mint sealed into the
    /// caveat — the authority's *identity*, a URL whose path is the
    /// discharge route. The connection comes from
    /// [`attestation_transport`](Self::attestation_transport) when set,
    /// else the location is dialled directly.
    #[serde(default)]
    pub attestation_location: Option<String>,

    /// How to dial coord B when its location is not the connection:
    /// `unix:<path>` (the co-located, off-network shape) or
    /// `http(s)://host:port`. The request path still comes from
    /// `attestation_location`. Absent → the location itself is dialled,
    /// so it must then be a reachable `http(s)` URL.
    #[serde(default)]
    pub attestation_transport: Option<String>,
}

fn default_mint_connect_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_mint_request_timeout() -> Duration {
    Duration::from_secs(30)
}

/// The request path of a discharge-authority location URL (e.g.
/// `https://coord-b.example/v1/discharge` → `/v1/discharge`). The host
/// part is an identity, not necessarily dialable — a separate transport
/// may supply the connection — so only the path is taken. `None` when
/// the location carries no route.
pub fn location_path(location: &str) -> Option<&str> {
    let rest = location
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(location);
    let path = &rest[rest.find('/')?..];
    (path != "/").then_some(path)
}

/// `unix:<path>` or `http(s)://…` — the scheme set every dial target in
/// this config speaks (`docs/design-mint.md` § "Transport").
fn valid_dial_scheme(s: &str) -> bool {
    s.starts_with("unix:") || s.starts_with("http://") || s.starts_with("https://")
}

impl MintConfig {
    /// Reject a dial target whose scheme is neither `unix:` nor
    /// `http(s)://`, an attestation location with no discharge route,
    /// and a transport with nothing to route. Validated at issuer-build
    /// time so a typo fails at startup rather than on the first
    /// `assume-role`.
    pub fn validate(&self) -> Result<()> {
        if !valid_dial_scheme(self.url.trim()) {
            bail!(
                "[mint] url must be `unix:<path>` or `http(s)://host:port` (got {:?})",
                self.url
            );
        }
        if let Some(loc) = &self.attestation_location
            && location_path(loc.trim()).is_none()
        {
            bail!(
                "[mint] attestation_location must carry the discharge route as its \
                 URL path (e.g. `https://coord-b/v1/discharge`), got {loc:?}"
            );
        }
        match &self.attestation_transport {
            Some(_) if self.attestation_location.is_none() => {
                bail!("[mint] attestation_transport is set without attestation_location");
            }
            Some(t) if !valid_dial_scheme(t.trim()) => {
                bail!(
                    "[mint] attestation_transport must be `unix:<path>` or \
                     `http(s)://host:port` (got {t:?})"
                );
            }
            _ => Ok(()),
        }
    }
}

/// A server listen address: a TCP socket or a Unix-domain socket,
/// discriminated by an optional `unix:` scheme prefix — the same
/// convention as `[mint] url`. `unix:<path>` selects a UDS; anything else
/// parses as a `<host>:<port>` TCP socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenAddr {
    Tcp(std::net::SocketAddr),
    Uds(PathBuf),
}

/// Parse a scheme-discriminated listen string into a [`ListenAddr`].
pub fn parse_listen(s: &str) -> Result<ListenAddr> {
    let s = s.trim();
    if let Some(path) = s.strip_prefix("unix:") {
        return Ok(ListenAddr::Uds(PathBuf::from(path)));
    }
    let addr = s
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("listen {s:?} must be `<host>:<port>` or `unix:<path>`"))?;
    Ok(ListenAddr::Tcp(addr))
}

/// Peer-fetch configuration. v1 is opt-in: setting `listen` enables the
/// HTTP server and the `coordinators/<id>/peer-endpoint.toml`
/// advertisement. Leaving it unset keeps peer fetch fully disabled.
#[derive(Deserialize, Default, Clone)]
pub struct PeerFetchConfig {
    /// TCP listen address `<host>:<port>` for the peer-fetch HTTP server.
    /// Absent → peer fetch disabled (no server bound, no advertised
    /// endpoint, prefetch path skips the peer tier). Must be a TCP
    /// address: the endpoint is advertised to remote coordinators, so a
    /// `unix:` value is rejected.
    #[serde(default)]
    pub listen: Option<String>,

    /// Hostname or IP advertised in `peer-endpoint.toml` for other
    /// coordinators to dial. Default: the result of `gethostname()`,
    /// which is correct on LANs with mDNS or DNS resolution. Set
    /// explicitly when the host's name is not routable from peer
    /// coordinators (e.g. when running behind a NAT or a load
    /// balancer). Only relevant when `listen` is set.
    #[serde(default)]
    pub host: Option<String>,
}

impl PeerFetchConfig {
    /// Parse `listen` into its TCP socket address, or `None` when peer
    /// fetch is disabled. Errors if set but not a `<host>:<port>` TCP
    /// address — peer fetch must be TCP because it is advertised.
    pub fn tcp_listen(&self) -> Result<Option<std::net::SocketAddr>> {
        match &self.listen {
            None => Ok(None),
            Some(s) => match parse_listen(s)? {
                ListenAddr::Tcp(addr) => Ok(Some(addr)),
                ListenAddr::Uds(_) => bail!(
                    "[peer_fetch] listen must be `<host>:<port>`: the peer-fetch endpoint is \
                     advertised to remote coordinators and cannot be a unix socket"
                ),
            },
        }
    }

    /// Advertised host. Falls back to the cached coordinator hostname if
    /// `host` is unset; if `gethostname()` also failed, falls back to the
    /// bind IP (which works for `127.0.0.1` localhost-only setups but
    /// won't be routable across hosts — operators should set `host`
    /// explicitly in that case).
    pub fn advertised_host(&self, fallback_hostname: Option<&str>, bind_ip: &str) -> String {
        self.host
            .clone()
            .or_else(|| fallback_hostname.map(str::to_owned))
            .unwrap_or_else(|| bind_ip.to_owned())
    }
}

/// Volume-attestation discharge-authority configuration (coord B).
#[derive(Clone, Deserialize)]
pub struct AttestationConfig {
    /// Path to the `attestation-shared.key` file (64 hex chars = 32 bytes):
    /// the symmetric `K_M-B` mint shares with this authority. In the
    /// co-located demo this is the same file mint generates.
    pub discharge_key_file: PathBuf,

    /// Listen address for `POST /v1/discharge`: `<host>:<port>` (TCP) or
    /// `unix:<path>` (UDS — keeps the discharge endpoint off the network,
    /// reachable only by a co-located coord A). Absent → the authority is
    /// configured but not served. Independent of `[peer_fetch]`: a pure
    /// verifier sets only this.
    #[serde(default)]
    pub listen: Option<String>,
}

impl AttestationConfig {
    /// Parse `listen` into a [`ListenAddr`], or `None` when the authority
    /// is configured but not to be served.
    pub fn listen_addr(&self) -> Result<Option<ListenAddr>> {
        self.listen.as_deref().map(parse_listen).transpose()
    }

    /// Load and parse the shared `K_M-B` discharge key.
    pub fn load_discharge_key(&self) -> Result<[u8; 32]> {
        let text = std::fs::read_to_string(&self.discharge_key_file)
            .with_context(|| format!("read discharge key {:?}", self.discharge_key_file))?;
        let bytes = elide_core::signing::decode_hex(text.trim())
            .with_context(|| format!("decode discharge key {:?}", self.discharge_key_file))?;
        bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "discharge key {:?} must be 32 bytes (64 hex chars)",
                self.discharge_key_file
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_env_empty_for_local_store() {
        let store = StoreSection {
            local_path: Some(PathBuf::from("/tmp/whatever")),
            ..StoreSection::default()
        };
        assert!(store.child_env().is_empty());
    }

    #[test]
    fn child_env_empty_when_unset() {
        let store = StoreSection::default();
        assert!(store.child_env().is_empty());
    }

    #[test]
    fn child_env_exports_bucket_endpoint_region() {
        let store = StoreSection {
            bucket: Some("elide-test".into()),
            endpoint: Some("https://t3.storage.dev".into()),
            region: Some("auto".into()),
            local_path: None,
            ..StoreSection::default()
        };
        let env = store.child_env();
        assert_eq!(
            env,
            vec![
                ("ELIDE_S3_BUCKET", "elide-test".to_owned()),
                ("AWS_ENDPOINT_URL", "https://t3.storage.dev".to_owned()),
                ("AWS_DEFAULT_REGION", "auto".to_owned()),
            ]
        );
    }

    #[test]
    fn child_env_bucket_only_omits_optional_fields() {
        let store = StoreSection {
            bucket: Some("elide-test".into()),
            endpoint: None,
            region: None,
            local_path: None,
            ..StoreSection::default()
        };
        let env = store.child_env();
        assert_eq!(env, vec![("ELIDE_S3_BUCKET", "elide-test".to_owned())]);
    }

    #[test]
    fn parses_toml_with_store_section() {
        let toml_str = r#"
            data_dir = "elide_data"

            [store]
            bucket = "elide-test"
            endpoint = "https://t3.storage.dev"
            region = "auto"
        "#;
        let cfg: CoordinatorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.store.bucket.as_deref(), Some("elide-test"));
        assert_eq!(
            cfg.store.endpoint.as_deref(),
            Some("https://t3.storage.dev")
        );
        assert_eq!(cfg.store.region.as_deref(), Some("auto"));
    }

    #[test]
    fn shipped_coordinator_demo_config_parses() {
        // The committed shared-key demo config (deploy/coord/) — nothing else
        // loads it, so this is its guard: it must parse and its
        // [auth.demo].k_m_a must decode to 32 bytes, matching mint-fly.toml.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/coord/coord.toml");
        let text = std::fs::read_to_string(path).expect("read coord.toml");
        let cfg: CoordinatorConfig =
            toml::from_str(&text).expect("coordinator.toml must parse as a CoordinatorConfig");
        assert_eq!(
            cfg.demo_k_m_a().expect("k_m_a decodes").map(|k| k.len()),
            Some(32)
        );
        assert!(cfg.mint.is_some(), "[mint] present");
    }

    #[test]
    fn load_errors_on_missing_file() {
        // A missing config path must fail loudly, not silently fall through to
        // a default config — a default routes serve into the shared-key
        // passthrough branch and bails on conditional PUT far from the cause.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope.toml");
        let Err(err) = load(&missing) else {
            panic!("missing config must error, not fall through to defaults");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("nope.toml"), "error names the path: {msg}");
    }

    #[test]
    fn default_config_template_parses_to_defaults() {
        let cfg: CoordinatorConfig = toml::from_str(DEFAULT_CONFIG_TEMPLATE)
            .expect("DEFAULT_CONFIG_TEMPLATE must parse as a CoordinatorConfig");
        let defaults = CoordinatorConfig::default();
        assert_eq!(cfg.data_dir, defaults.data_dir);
        assert_eq!(
            cfg.supervisor.drain_interval,
            defaults.supervisor.drain_interval
        );
        assert_eq!(
            cfg.supervisor.scan_interval,
            defaults.supervisor.scan_interval
        );
        assert_eq!(cfg.gc.interval, defaults.gc.interval);
        assert_eq!(cfg.gc.retention_window, defaults.gc.retention_window);
        assert_eq!(cfg.store.request_timeout, defaults.store.request_timeout);
        assert_eq!(cfg.store.connect_timeout, defaults.store.connect_timeout);
    }

    #[test]
    fn peer_fetch_defaults_off() {
        let cfg = CoordinatorConfig::default();
        assert!(cfg.peer_fetch.listen.is_none());
        assert!(cfg.peer_fetch.host.is_none());
        assert!(cfg.peer_fetch.tcp_listen().unwrap().is_none());
    }

    #[test]
    fn peer_fetch_section_parses() {
        let toml_str = r#"
            [peer_fetch]
            listen = "127.0.0.1:8443"
            host = "host.example.com"
        "#;
        let cfg: CoordinatorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.peer_fetch.tcp_listen().unwrap().unwrap(),
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(cfg.peer_fetch.host.as_deref(), Some("host.example.com"));
    }

    #[test]
    fn peer_fetch_listen_rejects_unix_socket() {
        let cfg = PeerFetchConfig {
            listen: Some("unix:/run/elide/peer.sock".to_owned()),
            ..PeerFetchConfig::default()
        };
        assert!(cfg.tcp_listen().is_err());
    }

    #[test]
    fn attestation_listen_parses_tcp_and_uds() {
        assert_eq!(
            parse_listen("0.0.0.0:8086").unwrap(),
            ListenAddr::Tcp("0.0.0.0:8086".parse().unwrap())
        );
        assert_eq!(
            parse_listen("unix:/run/elide/discharge.sock").unwrap(),
            ListenAddr::Uds(PathBuf::from("/run/elide/discharge.sock"))
        );
        assert!(parse_listen("not-an-address").is_err());
    }

    #[test]
    fn location_path_takes_only_the_path() {
        assert_eq!(
            location_path("https://coord-b.example/v1/discharge"),
            Some("/v1/discharge")
        );
        assert_eq!(
            location_path("http://127.0.0.1:8086/v1/discharge"),
            Some("/v1/discharge")
        );
        assert_eq!(location_path("https://coord-b.example"), None);
        assert_eq!(location_path("https://coord-b.example/"), None);
    }

    #[test]
    fn mint_validate_checks_the_attestation_pair() {
        let base = MintConfig {
            url: "unix:/run/elide/mint.sock".into(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            attestation_location: None,
            attestation_transport: None,
        };
        assert!(base.validate().is_ok());

        // A location must carry the discharge route.
        let pathless = MintConfig {
            attestation_location: Some("https://coord-b.example".into()),
            ..base.clone()
        };
        assert!(pathless.validate().is_err());

        // A transport needs a location to take the route from.
        let dangling = MintConfig {
            attestation_transport: Some("unix:/run/elide/coord-b.sock".into()),
            ..base.clone()
        };
        assert!(dangling.validate().is_err());

        // The co-located shape: logical location, UDS connection.
        let uds = MintConfig {
            attestation_location: Some("https://coord-b.example/v1/discharge".into()),
            attestation_transport: Some("unix:/run/elide/coord-b.sock".into()),
            ..base.clone()
        };
        assert!(uds.validate().is_ok());

        let bad_scheme = MintConfig {
            attestation_location: Some("https://coord-b.example/v1/discharge".into()),
            attestation_transport: Some("coord-b.example:8086".into()),
            ..base
        };
        assert!(bad_scheme.validate().is_err());
    }

    #[test]
    fn peer_fetch_advertised_host_prefers_explicit_then_hostname_then_bind() {
        let with_explicit = PeerFetchConfig {
            host: Some("explicit.example".to_owned()),
            ..PeerFetchConfig::default()
        };
        assert_eq!(
            with_explicit.advertised_host(Some("ignored.example"), "0.0.0.0"),
            "explicit.example"
        );

        let no_explicit = PeerFetchConfig::default();
        assert_eq!(
            no_explicit.advertised_host(Some("host.from.gethostname"), "0.0.0.0"),
            "host.from.gethostname"
        );

        let no_explicit_no_hostname = PeerFetchConfig::default();
        assert_eq!(
            no_explicit_no_hostname.advertised_host(None, "0.0.0.0"),
            "0.0.0.0"
        );
    }

    #[test]
    fn parses_humantime_durations() {
        let toml_str = r#"
            [supervisor]
            drain_interval = "2s"
            scan_interval  = "1m"

            [store]
            request_timeout = "10m"
            connect_timeout = "500ms"

            [gc]
            interval         = "15s"
            retention_window = "1h"
        "#;
        let cfg: CoordinatorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.supervisor.drain_interval, Duration::from_secs(2));
        assert_eq!(cfg.supervisor.scan_interval, Duration::from_secs(60));
        assert_eq!(cfg.store.request_timeout, Duration::from_secs(600));
        assert_eq!(cfg.store.connect_timeout, Duration::from_millis(500));
        assert_eq!(cfg.gc.interval, Duration::from_secs(15));
        assert_eq!(cfg.gc.retention_window, Duration::from_secs(3600));
    }
}
