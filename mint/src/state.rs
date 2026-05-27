//! Mint enrollment state: the current invite nonce, the transient
//! pending-enrollment table, and the long-lived approved-coordinator
//! registry (`docs/design-mint.md` § *Enrollment* / *Mint state in the
//! tenant bucket*).
//!
//! State lives behind an [`object_store::ObjectStore`]: in production
//! the bucket-backed implementation under the `_mint/` prefix of the
//! tenant bucket (accessed via a self-vended `mint-rw` keypair, not the
//! admin credential); in dev / tests a `LocalFileSystem` or `InMemory`
//! backend. The same key layout applies either way:
//!
//! ```text
//! _mint/invite                 current random nonce (one object)
//! _mint/pending/<sub>.json     transient (sub, pub, invite, first_seen, peer_ip);
//!                              GC'd at ticket-exp, deleted at approve()
//! _mint/approved/<sub>         long-lived {pub, approved_at, fingerprint_shown,
//!                              kid, mac}; powers the re-enrollment fast path
//! ```
//!
//! **Every approved-registry entry carries a MAC over its body keyed by
//! the keyring generation that issued it.** A holder of a `mint-rw`
//! bucket credential can `PutObject` to `_mint/approved/<sub>`, so the
//! object body cannot be trusted on its own — only mint instances
//! holding the corresponding [`Keyring`] key can produce a valid MAC.
//! [`Store::get_approved`] re-derives and constant-time-compares; a
//! mismatch is treated as if the record were absent (logged loudly
//! server-side; opaque to the client).
//!
//! The macaroon keyring does **not** live in object storage — it is
//! the master mint secret and stays on local disk
//! (`<data_dir>/root_keys/`, mode 0600 per file). For multi-instance
//! deployments operators replicate it out-of-band (e.g. systemd
//! `LoadCredential=`), since instances sharing a `_mint/` prefix must
//! agree on every `(kid, key)` or they mint and approve in a way the
//! sibling cannot verify.
//!
//! Concurrency: `record_pending` uses `PutMode::Create`
//! (`If-None-Match: *`) so multi-instance writes are serialised
//! bucket-side; the conditional primitive is the only ordering
//! mint relies on — no in-process mutex.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path as OPath;
use object_store::{
    Error as OsError, GetOptions, ObjectStore, PutMode, PutOptions, PutPayload,
    local::LocalFileSystem, memory::InMemory,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::keyring::{Keyring, Kid};

/// Top-level prefix for mint state inside whatever bucket / directory
/// the backing [`ObjectStore`] is rooted at — see *Mint state in the
/// tenant bucket*.
pub const STATE_PREFIX: &str = "_mint";

/// Filename for the on-disk K_M-A under `<data_dir>/`. 64-hex-byte
/// file, mode 0600 — same custody discipline as the keyring's
/// `root_keys/`. See `docs/design-auth-service.md` § *Keys*.
pub const K_M_A_FILE: &str = "k_m_a";

/// One pending-enrollment record (`_mint/pending/<sub>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The self-asserted `cnf` value (`ed25519:<b64 pub>`).
    pub pubkey: String,
    /// The invite nonce this enrollment was opened under; rotation
    /// drops records whose nonce is no longer current.
    pub invite: String,
    /// First-seen unix seconds (kept stable across idempotent retries).
    pub first_seen: u64,
    /// Peer IP at first sight, for the operator's out-of-band check.
    pub peer_ip: String,
}

/// One approved-coordinator registry entry (`_mint/approved/<sub>`).
/// Long-lived; written at `approve()`, consulted by every subsequent
/// `/v1/enroll` (fast path) and `/v1/enroll-exchange`.
///
/// The record carries its own MAC under the keyring generation that
/// issued it. A bucket-level forgery (anyone with `mint-rw` PUT access
/// to `_mint/*`) cannot produce a valid MAC, because the keyring stays
/// on local disk. [`Store::get_approved`] verifies and returns the
/// record only if the MAC matches; a mismatch is treated as if the
/// record were absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approved {
    /// The pinned `cnf` value the operator confirmed. A later
    /// re-enrollment with the same `(sub, pubkey)` skips operator
    /// approval; a different `pubkey` for the same `sub` is treated as
    /// a key-rotation request and requires fresh approval.
    pub pubkey: String,
    /// RFC 3339 timestamp the operator approved the pairing.
    pub approved_at: String,
    /// The fingerprint shown to the operator at approval, recorded so
    /// audits can re-derive what was on screen at the moment of consent.
    pub fingerprint_shown: String,
    /// Keyring generation that MAC'd this record. Retired kids fail
    /// verification — that is the rotation invalidation step.
    pub kid: Kid,
    /// The coord's per-coord discharge-key epoch. `r = HKDF(K_M,
    /// "r-coord-" || coord_ulid || r_epoch)`; bumping `r_epoch`
    /// invalidates every existing TPC/CID for this coord without
    /// touching the keyring. Operator-driven; defaults to 0 at
    /// approval time. Bumps land via a separate admin verb (out of
    /// scope here) and are covered by the body MAC like every other
    /// field.
    #[serde(default)]
    pub r_epoch: u32,
    /// BLAKE3-keyed MAC over the body, hex-encoded. See
    /// [`approval_mac`] for the exact input domain-separation.
    pub mac: String,
}

/// What `record_pending` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Recorded {
    /// New pending record written; awaits operator approval.
    Created,
    /// Identical `(sub, pub)` already pending — idempotent retry.
    Idempotent,
    /// `(sub, pub)` already in the approved registry; no pending was
    /// written, and `/v1/enroll-exchange` will succeed immediately
    /// against the existing approval (fast path).
    AlreadyApproved,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("object store: {0}")]
    Store(String),
    #[error("malformed sub")]
    BadSub,
    /// A different `pub` is already pending for this `sub` — never
    /// overwritten, never auto-resolved (operator must intervene).
    #[error("sub already pending with a different key")]
    Conflict,
    #[error("corrupt enrollment record")]
    Corrupt,
    /// An approved-registry entry's MAC did not validate under any kid
    /// in the keyring — either a bucket-level forgery, a record left
    /// over from a retired kid, or storage corruption. The HTTP layer
    /// treats this as "not approved" (returns 403 awaiting_approval)
    /// and logs loudly server-side; the client gets no signal that
    /// distinguishes it from a missing record.
    #[error("approval MAC verification failed")]
    Forged,
}

impl From<OsError> for StateError {
    fn from(e: OsError) -> Self {
        StateError::Store(e.to_string())
    }
}

/// Outcome counts from a [`Store::sweep_approvals_to_current_kid`] run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Records re-MAC'd from an older kid to the current kid.
    pub rekeyed: usize,
    /// Records already on the current kid; left untouched.
    pub already_current: usize,
    /// Records skipped because their MAC did not validate under any
    /// kid in the ring, or because the body was corrupt. Each skip is
    /// logged with the sub and the kid the record claimed.
    pub skipped: usize,
}

/// Lifecycle bucket of an enrollment row for `mint enroll list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Pending,
    Approved,
}

/// One row of `mint enroll list` — the unified pending+approved view.
#[derive(Debug, Clone)]
pub struct EnrollmentView {
    pub sub: String,
    pub state: EnrollmentState,
    pub pubkey: String,
    /// Short, stable fingerprint of the bound key for the operator's
    /// side-channel comparison (the client prints the same).
    pub fingerprint: String,
    /// Peer IP at first sight (pending only — registry entries do not
    /// keep one because re-enrollment moves the IP around).
    pub peer_ip: Option<String>,
    /// Age in seconds since `first_seen` (pending) / `approved_at`
    /// (approved).
    pub age_seconds: u64,
    /// This `pub` is also pending under a *different* `sub` — anomalous
    /// (a new key is a new principal); surfaced, not auto-rejected.
    /// Only set for `Pending` rows.
    pub anomalous_pub: bool,
}

/// `sub` becomes a path segment, so it must be a safe, inspectable
/// token. Opaque but constrained: ULIDs and the like pass; anything
/// with a separator or control char is rejected at the boundary.
fn safe_sub(sub: &str) -> bool {
    !sub.is_empty()
        && sub.len() <= 256
        && sub
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && sub != "."
        && sub != ".."
}

/// Stable short fingerprint of a `cnf` pubkey value, for the operator's
/// out-of-band comparison. BLAKE3 of the raw value, first 8 bytes hex —
/// the client computes the identical string from its own key.
pub fn fingerprint(pubkey_value: &str) -> String {
    let h = blake3::hash(pubkey_value.as_bytes());
    h.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Domain separator for approval-record MACs. Distinct from the
/// macaroon DOMAIN so the same key cannot be tricked into producing an
/// approval MAC that doubles as a credential MAC or vice versa.
const APPROVAL_DOMAIN: &[u8] = b"mint-approved-v1";

/// MAC over an approval record body. `sub` is included even though it
/// is encoded in the object key, so a record cannot be copied to a
/// different `<sub>` and still verify (cross-record substitution).
/// Every variable-length field is length-prefixed to prevent
/// canonicalization ambiguity.
fn approval_mac(
    key: &[u8; 32],
    sub: &str,
    pubkey: &str,
    approved_at: &str,
    fingerprint_shown: &str,
    r_epoch: u32,
) -> [u8; 32] {
    let mut msg = Vec::new();
    msg.extend_from_slice(APPROVAL_DOMAIN);
    append_len_prefixed(&mut msg, sub.as_bytes());
    append_len_prefixed(&mut msg, pubkey.as_bytes());
    append_len_prefixed(&mut msg, approved_at.as_bytes());
    append_len_prefixed(&mut msg, fingerprint_shown.as_bytes());
    msg.extend_from_slice(&r_epoch.to_be_bytes());
    *blake3::keyed_hash(key, &msg).as_bytes()
}

fn append_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Write `contents` to `path` mode 0600 via an atomic rename — same
/// custody discipline as the keyring's per-kid files.
fn write_key_file(path: &Path, contents: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Object-store-backed mint state. Cross-process safety comes from the
/// conditional-put primitives (`PutMode::Create` → S3 `If-None-Match: *`
/// or local `O_EXCL`); within one process tokio's async scheduling is
/// enough — no internal mutex.
///
/// The invite nonce is cached locally with an ETag stamp; the
/// background task spawned by [`Store::spawn_invite_refresh`] polls
/// with `If-None-Match` so steady-state reads cost a cheap 304 instead
/// of a full body fetch (`docs/design-mint.md` § *Mint state in the
/// tenant bucket*).
pub struct Store {
    /// The macaroon keyring — generations loaded from
    /// `<data_dir>/root_keys/`. Symmetric: mint both mints and verifies
    /// with the keys here. Wrapped in `RwLock` so rotation admin paths
    /// can swap it; the steady-state minting and verification paths
    /// snapshot via [`Store::keyring`] and read without holding the
    /// lock across awaits.
    keyring: Arc<RwLock<Arc<Keyring>>>,
    /// The auth-service wrapping key. `None` for a mint configured
    /// without `[auth]` — issuance for any role with
    /// `issues_with_tpc = true` is then refused (validated at config
    /// load). In demo mode mint generates K_M-A itself at first
    /// start; in prod the auth-service binary provisions it via
    /// `/v1/mint/enroll` (separate PR). Immutable for the lifetime
    /// of the process — rotation lands on a new Store via restart.
    k_m_a: Option<Arc<[u8; 32]>>,
    /// The org this mint serves. Paired with `k_m_a`: both come from
    /// auth-service enrollment in production, both are generated
    /// locally in demo mode (where mint assigns `OrgId = "demo"`).
    /// `None` when `k_m_a` is `None`.
    org_id: Option<String>,
    objects: Arc<dyn ObjectStore>,
    invite_cache: Arc<RwLock<InviteSnapshot>>,
}

#[derive(Debug, Clone)]
struct InviteSnapshot {
    value: String,
    etag: Option<String>,
}

/// Default cadence at which the background task polls
/// `_mint/invite` for rotation. 30 s keeps the staleness window short
/// enough that rotation-cancels-in-flight stays meaningful while
/// reducing per-request load on the object store to zero in steady
/// state.
pub const INVITE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

impl Store {
    /// Local-filesystem backend rooted at `dir` — the dev / co-resident
    /// shape. `dir/root_keys/` holds the keyring (migrated from
    /// `dir/root_key` if the legacy singleton is present); everything
    /// else lives under `dir/_mint/`, matching the bucket-side layout
    /// key for key so an operator can `ls` either and see the same
    /// structure.
    pub async fn open_local(dir: impl Into<PathBuf>) -> io::Result<Store> {
        Self::open_local_with_initial_key(dir, None).await
    }

    /// Like [`Self::open_local`] but accepts an operator-supplied
    /// initial key for the first-start case (the multi-host shape:
    /// every instance is launched with the same seed so all instances
    /// converge on the same `kid=0`).
    pub async fn open_local_with_initial_key(
        dir: impl Into<PathBuf>,
        initial_key: Option<[u8; 32]>,
    ) -> io::Result<Store> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let keyring = Keyring::open(
            &dir.join("root_keys"),
            Some(&dir.join("root_key")),
            initial_key,
        )
        .map_err(io::Error::other)?;
        // LocalFileSystem rejects paths that don't exist; create the
        // _mint subtree so the first PUT lands. (PUTs auto-create
        // intermediate directories, but the prefix root must exist.)
        std::fs::create_dir_all(dir.join(STATE_PREFIX))?;
        let lfs = LocalFileSystem::new_with_prefix(&dir).map_err(io::Error::other)?;
        let store = Store::with_object_store(keyring, Arc::new(lfs));
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    /// Bucket-backed store. `objects` is a [`ObjectStore`] whose root
    /// is the tenant bucket; the `_mint/` prefix is applied to every
    /// key. `keyring_dir` is the local directory the macaroon keyring
    /// is loaded from / written to. `legacy_singleton` migrates an
    /// older `<data_dir>/root_key` if present. `initial_key` seeds the
    /// first-start case for multi-host deployments.
    pub async fn open_remote(
        objects: Arc<dyn ObjectStore>,
        keyring_dir: &Path,
        legacy_singleton: Option<&Path>,
        initial_key: Option<[u8; 32]>,
    ) -> io::Result<Store> {
        let keyring =
            Keyring::open(keyring_dir, legacy_singleton, initial_key).map_err(io::Error::other)?;
        let store = Store::with_object_store(keyring, objects);
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    /// In-memory backend with a one-key keyring supplied directly.
    /// For tests.
    pub async fn open_in_memory(root_key: [u8; 32]) -> io::Result<Store> {
        let store = Store::with_object_store(Keyring::single(root_key), Arc::new(InMemory::new()));
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    fn with_object_store(keyring: Keyring, objects: Arc<dyn ObjectStore>) -> Store {
        Store {
            keyring: Arc::new(RwLock::new(Arc::new(keyring))),
            k_m_a: None,
            org_id: None,
            objects,
            invite_cache: Arc::new(RwLock::new(InviteSnapshot {
                value: String::new(),
                etag: None,
            })),
        }
    }

    /// Load or — when `demo_enabled` is true and the file is absent —
    /// generate the K_M-A wrapping key under `<dir>/k_m_a`. Mutates
    /// `self.k_m_a`. Called from the bootstrap path once the Store
    /// has been opened and the auth-mode is known from config.
    ///
    /// On disk: 64 ASCII hex characters (the canonical 32-byte
    /// representation, matching the keyring's per-generation files),
    /// no newline, mode 0600. Same custody discipline as the
    /// keyring — anyone with filesystem read on `data_dir` already
    /// has the keys mint depends on.
    pub fn init_k_m_a(&mut self, dir: &Path, demo_enabled: bool) -> io::Result<()> {
        let path = dir.join(K_M_A_FILE);
        let bytes = match std::fs::read_to_string(&path) {
            Ok(s) => unhex32(s.trim())
                .ok_or_else(|| io::Error::other(format!("{path:?}: not 64 hex bytes")))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !demo_enabled {
                    return Err(io::Error::other(format!(
                        "K_M-A absent at {path:?}; mint requires auth-service \
                         enrollment or [auth] demo_enabled = true"
                    )));
                }
                let mut fresh = [0u8; 32];
                rand_core::OsRng.fill_bytes(&mut fresh);
                write_key_file(&path, &hex32(&fresh))?;
                fresh
            }
            Err(e) => return Err(e),
        };
        self.k_m_a = Some(Arc::new(bytes));
        // Demo mode assigns the conventional OrgId; production
        // deployments will receive OrgId from auth-service enrollment
        // alongside K_M-A and persist it separately.
        if self.org_id.is_none() {
            self.org_id = Some("demo".to_string());
        }
        Ok(())
    }

    /// `Some` when [`init_k_m_a`] has loaded or generated the key;
    /// `None` for a Store opened in no-auth mode (tests, mint
    /// configurations without `[auth]`).
    pub fn k_m_a(&self) -> Option<&[u8; 32]> {
        self.k_m_a.as_deref()
    }

    /// The org this mint serves (`Some("demo")` in demo mode; set by
    /// auth-service enrollment in production). Paired with
    /// [`k_m_a`](Self::k_m_a) — both `Some` or both `None`.
    pub fn org_id(&self) -> Option<&str> {
        self.org_id.as_deref()
    }

    /// Snapshot the current keyring as an `Arc`. Steady-state minting
    /// and verification go through this — the lock is held only for
    /// the `Arc::clone`, not across the actual MAC work.
    pub async fn keyring(&self) -> Arc<Keyring> {
        self.keyring.read().await.clone()
    }

    /// Replace the in-memory keyring. The on-disk store is the
    /// canonical source; callers that have mutated disk via
    /// [`Keyring::add_and_promote`] / [`Keyring::retire`] should swap
    /// the in-memory copy here so subsequent handlers see the new
    /// generations.
    pub async fn set_keyring(&self, keyring: Keyring) {
        *self.keyring.write().await = Arc::new(keyring);
    }

    /// Direct access to the underlying object store. For diagnostics
    /// only — production callers should go through the typed methods.
    pub fn objects(&self) -> &Arc<dyn ObjectStore> {
        &self.objects
    }

    fn invite_key() -> OPath {
        OPath::from(format!("{STATE_PREFIX}/invite"))
    }
    fn pending_key(sub: &str) -> OPath {
        OPath::from(format!("{STATE_PREFIX}/pending/{sub}.json"))
    }
    fn approved_key(sub: &str) -> OPath {
        OPath::from(format!("{STATE_PREFIX}/approved/{sub}"))
    }
    fn pending_prefix() -> OPath {
        OPath::from(format!("{STATE_PREFIX}/pending"))
    }
    fn approved_prefix() -> OPath {
        OPath::from(format!("{STATE_PREFIX}/approved"))
    }
    fn template_seal_key() -> OPath {
        OPath::from(format!("{STATE_PREFIX}/templates/seal.json"))
    }

    /// Initialise the invite nonce on first start (idempotent), then
    /// populate the local cache from the canonical object.
    /// `PutMode::Create` keeps concurrent inits race-safe.
    async fn ensure_invite(&self) -> Result<(), StateError> {
        match self
            .objects
            .put_opts(
                &Self::invite_key(),
                PutPayload::from(Bytes::from(fresh_nonce().into_bytes())),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(_) | Err(OsError::AlreadyExists { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        let (value, etag) = self.fetch_invite().await?;
        *self.invite_cache.write().await = InviteSnapshot { value, etag };
        Ok(())
    }

    /// Single unconditional GET of `_mint/invite`, returning the body
    /// and its ETag. Used at construction and by the refresh task on a
    /// 200 response.
    async fn fetch_invite(&self) -> Result<(String, Option<String>), StateError> {
        let g = self.objects.get(&Self::invite_key()).await?;
        let etag = g.meta.e_tag.clone();
        let bytes = g.bytes().await?;
        let value = String::from_utf8_lossy(&bytes).trim().to_string();
        Ok((value, etag))
    }

    /// The current invite nonce — the value a presented invite
    /// macaroon's `invite` caveat must equal. Reads the cached value;
    /// `spawn_invite_refresh` keeps the cache fresh in the background.
    pub async fn current_invite(&self) -> Result<String, StateError> {
        let snap = self.invite_cache.read().await;
        if snap.value.is_empty() {
            return Err(StateError::Corrupt);
        }
        Ok(snap.value.clone())
    }

    /// Spawn the background task that keeps `current_invite()` fresh
    /// by polling `_mint/invite` with `If-None-Match: <etag>` every
    /// [`INVITE_REFRESH_INTERVAL`]. On `304 Not Modified` (the common
    /// case) the cache is left alone; a `200` swaps in the new
    /// `(value, etag)`. Returns the handle so callers can cancel; the
    /// task exits cleanly when its [`Store`] strong references are
    /// dropped because the inner `Arc<RwLock>` is the only thing it
    /// retains across `.await` boundaries.
    pub fn spawn_invite_refresh(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately by default; skip it so the
            // background work doesn't double up with the construction
            // path's eager fetch.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(store) = weak.upgrade() else {
                    return;
                };
                let last_etag = store.invite_cache.read().await.etag.clone();
                let opts = GetOptions {
                    if_none_match: last_etag.clone(),
                    ..Default::default()
                };
                match store.objects.get_opts(&Self::invite_key(), opts).await {
                    Ok(g) => {
                        let etag = g.meta.e_tag.clone();
                        match g.bytes().await {
                            Ok(bytes) => {
                                let value = String::from_utf8_lossy(&bytes).trim().to_string();
                                *store.invite_cache.write().await = InviteSnapshot { value, etag };
                            }
                            Err(e) => tracing::warn!(
                                target: "mint::state",
                                error = %e,
                                "invite refresh: body read failed"
                            ),
                        }
                    }
                    // `Error::NotModified` is the steady-state hit: the
                    // object hasn't changed since `last_etag`. Quiet success.
                    Err(OsError::NotModified { .. }) => {}
                    // `Error::Precondition` is what some backends return for
                    // `If-None-Match` matches when they don't model 304
                    // separately. Treat it the same — no rotation.
                    Err(OsError::Precondition { .. }) => {}
                    Err(e) => tracing::warn!(
                        target: "mint::state",
                        error = %e,
                        "invite refresh: get failed"
                    ),
                }
            }
        })
    }

    /// Draw and persist a new invite nonce, then drop every pending
    /// record opened under an older nonce. The approved registry is
    /// **not** touched: outstanding credentials and the re-enrollment
    /// fast path survive rotation. Returns the new nonce.
    pub async fn rotate_invite(&self) -> Result<String, StateError> {
        let nonce = fresh_nonce();
        self.objects
            .put_opts(
                &Self::invite_key(),
                PutPayload::from(Bytes::from(nonce.clone().into_bytes())),
                PutOptions::default(),
            )
            .await?;
        // Re-read so the cache picks up the canonical ETag the backend
        // assigned, not a synthesised one — keeps `If-None-Match`
        // poll-paths consistent across processes.
        let (value, etag) = self.fetch_invite().await?;
        *self.invite_cache.write().await = InviteSnapshot { value, etag };
        for sub in self.pending_subs().await? {
            if let Ok(Some(p)) = self.get_pending(&sub).await
                && p.invite != nonce
            {
                let _ = self.objects.delete(&Self::pending_key(&sub)).await;
            }
        }
        Ok(nonce)
    }

    /// Record (or idempotently re-confirm) a pending enrollment.
    ///
    /// Fast path: if `_mint/approved/<sub>` already exists with the
    /// same `pub`, no pending record is written and `Recorded::AlreadyApproved`
    /// is returned — `/v1/enroll-exchange` will succeed against the
    /// existing registry entry without operator intervention.
    ///
    /// A different `pub` for an existing approved `sub` falls through
    /// to the normal pending path, surfacing as a key-rotation request
    /// the operator must re-approve.
    pub async fn record_pending(
        &self,
        sub: &str,
        pubkey: &str,
        invite: &str,
        peer_ip: &str,
        now_unix: u64,
    ) -> Result<Recorded, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        // Fast-path check: only `Ok(Some(_))` is load-bearing here.
        // A forged or corrupt approved record (e.g. left over from a
        // retired-kid generation, or a pre-#454 unsigned body that
        // can't be deserialised) is operationally equivalent to "no
        // approved record" — we want the slow path to proceed so the
        // operator can re-approve cleanly. Propagating Forged/Corrupt
        // through here would block re-enrollment behind an opaque
        // 401 with no way for the operator to recover without
        // manually deleting the bucket object.
        let approved = match self.get_approved(sub).await {
            Ok(a) => a,
            Err(StateError::Forged | StateError::Corrupt) => None,
            Err(e) => return Err(e),
        };
        if let Some(approved) = approved
            && approved.pubkey == pubkey
        {
            return Ok(Recorded::AlreadyApproved);
        }
        let rec = Pending {
            pubkey: pubkey.to_string(),
            invite: invite.to_string(),
            first_seen: now_unix,
            peer_ip: peer_ip.to_string(),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|_| StateError::Corrupt)?;
        match self
            .objects
            .put_opts(
                &Self::pending_key(sub),
                PutPayload::from(Bytes::from(bytes)),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(_) => Ok(Recorded::Created),
            Err(OsError::AlreadyExists { .. }) => {
                let existing = self.get_pending(sub).await?.ok_or(StateError::Corrupt)?;
                if existing.pubkey == pubkey {
                    Ok(Recorded::Idempotent)
                } else {
                    Err(StateError::Conflict)
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Operator approval — writes the long-lived `_mint/approved/<sub>`
    /// registry entry with the operator-confirmed `(sub, pubkey)`, then
    /// deletes the now-redundant pending record. Always overwrites an
    /// existing approval (a different `pubkey` is a key-rotation
    /// acknowledgment). The pending delete is best-effort.
    ///
    /// The record is MAC'd under the current keyring generation, so a
    /// later [`Self::get_approved`] rejects any record whose body has
    /// been tampered with at the bucket level or that was minted under
    /// a now-retired kid.
    pub async fn approve(
        &self,
        sub: &str,
        pubkey: &str,
        now_iso8601: &str,
    ) -> Result<(), StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        let fingerprint_shown = fingerprint(pubkey);
        let kr = self.keyring().await;
        let kid = kr.current_kid();
        // Fresh approval starts at r_epoch = 0; admin verbs bump it
        // independently (out of scope here).
        let r_epoch: u32 = 0;
        let mac = approval_mac(
            kr.current_key(),
            sub,
            pubkey,
            now_iso8601,
            &fingerprint_shown,
            r_epoch,
        );
        let rec = Approved {
            pubkey: pubkey.to_string(),
            approved_at: now_iso8601.to_string(),
            fingerprint_shown,
            kid,
            r_epoch,
            mac: hex32(&mac),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|_| StateError::Corrupt)?;
        self.objects
            .put_opts(
                &Self::approved_key(sub),
                PutPayload::from(Bytes::from(bytes)),
                PutOptions::default(),
            )
            .await?;
        // Best-effort: a missing pending record (already GC'd, or this
        // is a no-op re-approval) is not an error.
        match self.objects.delete(&Self::pending_key(sub)).await {
            Ok(()) | Err(OsError::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Remove an approved-registry entry. After this call, the next
    /// `/v1/enroll` for `<sub>` falls back to the slow path
    /// (operator-gated approval). Returns `true` if a record existed.
    pub async fn revoke(&self, sub: &str) -> Result<bool, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        match self.objects.delete(&Self::approved_key(sub)).await {
            Ok(()) => Ok(true),
            Err(OsError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// The pending record for `sub`, if any.
    pub async fn get_pending(&self, sub: &str) -> Result<Option<Pending>, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        match self.objects.get(&Self::pending_key(sub)).await {
            Ok(g) => {
                let bytes = g.bytes().await?;
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|_| StateError::Corrupt)
            }
            Err(OsError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The approved-registry entry for `sub`, if any. Used at
    /// `/v1/enroll-exchange` to verify the operator's binding, and at
    /// `/v1/enroll` to take the fast path on a matching `pubkey`.
    ///
    /// The record's MAC is verified under the keyring before it is
    /// returned: a record under a retired kid, a bucket-level forgery,
    /// or a partial overwrite all surface as [`StateError::Forged`].
    /// Callers that want to treat a forgery the same as an absent
    /// record (the HTTP layer's policy — don't leak forensic signal to
    /// the client) should map both to "not approved" themselves.
    pub async fn get_approved(&self, sub: &str) -> Result<Option<Approved>, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        let bytes = match self.objects.get(&Self::approved_key(sub)).await {
            Ok(g) => g.bytes().await?,
            Err(OsError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let rec: Approved = serde_json::from_slice(&bytes).map_err(|_| StateError::Corrupt)?;
        let kr = self.keyring().await;
        let Some(key) = kr.get(rec.kid) else {
            tracing::warn!(
                target: "mint::state",
                sub,
                kid = rec.kid,
                "approved record claims a kid not in the keyring; treating as forged"
            );
            return Err(StateError::Forged);
        };
        let expected = approval_mac(
            key,
            sub,
            &rec.pubkey,
            &rec.approved_at,
            &rec.fingerprint_shown,
            rec.r_epoch,
        );
        let actual = unhex32(&rec.mac).ok_or(StateError::Corrupt)?;
        if !bool::from(expected.ct_eq(&actual)) {
            tracing::warn!(
                target: "mint::state",
                sub,
                kid = rec.kid,
                "approved record MAC mismatch; treating as forged"
            );
            return Err(StateError::Forged);
        }
        Ok(Some(rec))
    }

    async fn pending_subs(&self) -> Result<Vec<String>, StateError> {
        let mut out = Vec::new();
        let mut stream = self.objects.list(Some(&Self::pending_prefix()));
        while let Some(item) = stream.next().await {
            let meta = item?;
            if let Some(sub) = sub_from_pending_key(meta.location.as_ref()) {
                out.push(sub);
            }
        }
        Ok(out)
    }

    async fn approved_subs(&self) -> Result<Vec<String>, StateError> {
        let mut out = Vec::new();
        let mut stream = self.objects.list(Some(&Self::approved_prefix()));
        while let Some(item) = stream.next().await {
            let meta = item?;
            if let Some(sub) = sub_from_approved_key(meta.location.as_ref()) {
                out.push(sub);
            }
        }
        Ok(out)
    }

    /// Lazy migration: if `_mint/approved/<sub>` is on an older kid,
    /// re-MAC it under `current_kid` and PUT back with `If-Match` on
    /// the etag we just read. Called opportunistically by the enroll
    /// fast path so each coordinator's record drifts forward to the
    /// current kid on its next restart, without any global sweep.
    ///
    /// Best-effort by design: a missing record, a kid mismatch already
    /// at current, a 412 (concurrent rotation / revoke racing us), or
    /// a body that no longer verifies are all silent no-ops returning
    /// `Ok(false)`. `Ok(true)` means a migration write actually
    /// happened. The caller never branches on the return value beyond
    /// logging — verification-time correctness is provided by the MAC
    /// check in `get_approved`, not by this method completing.
    pub async fn migrate_approval_to_current_kid(&self, sub: &str) -> Result<bool, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        let key = Self::approved_key(sub);
        let g = match self.objects.get(&key).await {
            Ok(g) => g,
            Err(OsError::NotFound { .. }) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let etag = g.meta.e_tag.clone();
        let version = g.meta.version.clone();
        let bytes = g.bytes().await?;
        let rec: Approved = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };
        let kr = self.keyring().await;
        if rec.kid == kr.current_kid() {
            return Ok(false);
        }
        // Verify under the old kid before migrating; we never re-MAC a
        // record we couldn't validate as authentic in the first place.
        let Some(old_key) = kr.get(rec.kid) else {
            return Ok(false);
        };
        let expected_old = approval_mac(
            old_key,
            sub,
            &rec.pubkey,
            &rec.approved_at,
            &rec.fingerprint_shown,
            rec.r_epoch,
        );
        let actual = match unhex32(&rec.mac) {
            Some(a) => a,
            None => return Ok(false),
        };
        if !bool::from(expected_old.ct_eq(&actual)) {
            return Ok(false);
        }
        let new_mac = approval_mac(
            kr.current_key(),
            sub,
            &rec.pubkey,
            &rec.approved_at,
            &rec.fingerprint_shown,
            rec.r_epoch,
        );
        let next = Approved {
            pubkey: rec.pubkey,
            approved_at: rec.approved_at,
            fingerprint_shown: rec.fingerprint_shown,
            kid: kr.current_kid(),
            r_epoch: rec.r_epoch,
            mac: hex32(&new_mac),
        };
        let body = serde_json::to_vec(&next).map_err(|_| StateError::Corrupt)?;
        let opts = PutOptions::from(PutMode::Update(object_store::UpdateVersion {
            e_tag: etag,
            version,
        }));
        match self
            .objects
            .put_opts(&key, PutPayload::from(Bytes::from(body)), opts)
            .await
        {
            Ok(_) => Ok(true),
            // 412 (Precondition) means the record changed under us —
            // most commonly a peer mint just migrated it (idempotent
            // race), or the operator revoked. Either way: don't retry,
            // don't error.
            Err(OsError::Precondition { .. }) => Ok(false),
            // `LocalFileSystem` returns `NotImplemented` for
            // `PutMode::Update` — dev backend, single-process, no
            // multi-writer concerns. Treat as a quiet no-op so the
            // dev shape doesn't error out on rotation; the record
            // stays valid under its old kid and the next attempt
            // (against an S3 backend in production) will migrate it.
            Err(OsError::NotImplemented) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Re-MAC every approval record under the keyring's current
    /// generation (rotation step 2 — `docs/design-mint.md` §
    /// *Root-key rotation*). Verifies each record under any kid still
    /// in the ring before re-emitting it, so a forged or tampered
    /// record is skipped (logged + reported in the return value),
    /// never propagated under a new MAC. Returns the count of records
    /// re-MAC'd and the count skipped.
    ///
    /// Safe to run repeatedly — a record already at `current_kid`
    /// re-serialises to identical bytes. Intended to be invoked once
    /// per rotation by an admin command; the steady-state HTTP path
    /// does not call it.
    pub async fn sweep_approvals_to_current_kid(&self) -> Result<SweepReport, StateError> {
        let mut report = SweepReport::default();
        let kr = self.keyring().await;
        let new_kid = kr.current_kid();
        let new_key = kr.current_key();
        for sub in self.approved_subs().await? {
            // Read raw so we can decide what to do with a forged record
            // (skip + count) instead of inheriting `get_approved`'s
            // policy of erroring.
            let bytes = match self.objects.get(&Self::approved_key(&sub)).await {
                Ok(g) => g.bytes().await?,
                Err(OsError::NotFound { .. }) => continue,
                Err(e) => return Err(e.into()),
            };
            let rec: Approved = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(_) => {
                    report.skipped += 1;
                    tracing::warn!(target: "mint::state", sub, "sweep: corrupt body");
                    continue;
                }
            };
            // Verify under whatever kid the record claims; any kid
            // still in the ring is acceptable input to the sweep.
            let Some(old_key) = kr.get(rec.kid) else {
                report.skipped += 1;
                tracing::warn!(
                    target: "mint::state",
                    sub,
                    kid = rec.kid,
                    "sweep: record under unknown kid"
                );
                continue;
            };
            let expected = approval_mac(
                old_key,
                &sub,
                &rec.pubkey,
                &rec.approved_at,
                &rec.fingerprint_shown,
                rec.r_epoch,
            );
            let actual = match unhex32(&rec.mac) {
                Some(a) => a,
                None => {
                    report.skipped += 1;
                    continue;
                }
            };
            if !bool::from(expected.ct_eq(&actual)) {
                report.skipped += 1;
                tracing::warn!(
                    target: "mint::state",
                    sub,
                    kid = rec.kid,
                    "sweep: MAC mismatch; skipping"
                );
                continue;
            }
            if rec.kid == new_kid {
                report.already_current += 1;
                continue;
            }
            let new_mac = approval_mac(
                new_key,
                &sub,
                &rec.pubkey,
                &rec.approved_at,
                &rec.fingerprint_shown,
                rec.r_epoch,
            );
            let next = Approved {
                pubkey: rec.pubkey,
                approved_at: rec.approved_at,
                fingerprint_shown: rec.fingerprint_shown,
                kid: new_kid,
                r_epoch: rec.r_epoch,
                mac: hex32(&new_mac),
            };
            let bytes = serde_json::to_vec(&next).map_err(|_| StateError::Corrupt)?;
            self.objects
                .put_opts(
                    &Self::approved_key(&sub),
                    PutPayload::from(Bytes::from(bytes)),
                    PutOptions::default(),
                )
                .await?;
            report.rekeyed += 1;
        }
        Ok(report)
    }

    /// Drop pending records older than `max_age_seconds`. The bound is
    /// ≥ the credential ticket `exp`; once it passes, an unexchanged
    /// pending is dead weight. The approved registry is **not** GC'd.
    pub async fn gc(&self, now_unix: u64, max_age_seconds: u64) -> Result<usize, StateError> {
        let mut dropped = 0;
        for sub in self.pending_subs().await? {
            if let Ok(Some(p)) = self.get_pending(&sub).await
                && now_unix.saturating_sub(p.first_seen) > max_age_seconds
            {
                let _ = self.objects.delete(&Self::pending_key(&sub)).await;
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    /// Read the bucket-canonical template seal, if any. Returns
    /// `Ok(None)` for an empty bucket (the operator hasn't run
    /// `mint seal` yet); otherwise the deserialised seal body
    /// **without** any MAC verification — callers verify against
    /// their local keyring themselves so the caller's keyring
    /// snapshot is consistent with whatever else they're checking.
    pub async fn get_template_seal(&self) -> Result<Option<crate::seal::Seal>, StateError> {
        match self.objects.get(&Self::template_seal_key()).await {
            Ok(g) => {
                let bytes = g.bytes().await?;
                let seal: crate::seal::Seal =
                    serde_json::from_slice(&bytes).map_err(|_| StateError::Corrupt)?;
                Ok(Some(seal))
            }
            Err(OsError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the bucket-canonical template seal (overwrite). The
    /// operator is the authority for seal content; this is the one
    /// PUT path. Caller is responsible for having built and MAC'd the
    /// seal under a kid that is current at publish time — typically
    /// `mint serve`'s startup, picking up a pending file from disk.
    pub async fn put_template_seal(&self, seal: &crate::seal::Seal) -> Result<(), StateError> {
        let bytes = serde_json::to_vec(seal).map_err(|_| StateError::Corrupt)?;
        self.objects
            .put_opts(
                &Self::template_seal_key(),
                PutPayload::from(Bytes::from(bytes)),
                PutOptions::default(),
            )
            .await?;
        Ok(())
    }

    /// All enrollment rows — pending and approved — for
    /// `mint enroll list`. State is a column, not a filter.
    pub async fn list(&self, now_unix: u64) -> Result<Vec<EnrollmentView>, StateError> {
        let pending_subs = self.pending_subs().await?;
        let mut pendings: Vec<(String, Pending)> = Vec::new();
        for sub in pending_subs {
            if let Some(p) = self.get_pending(&sub).await? {
                pendings.push((sub, p));
            }
        }
        let approved_subs = self.approved_subs().await?;
        let mut approveds: Vec<(String, Approved)> = Vec::new();
        for sub in approved_subs {
            match self.get_approved(&sub).await {
                Ok(Some(a)) => approveds.push((sub, a)),
                Ok(None) => {}
                // A forged or retired-kid entry must not poison the
                // whole `mint enroll list` view — it has already been
                // logged inside `get_approved`. Skipping it here is
                // consistent with the HTTP layer's "treat as absent"
                // policy and matches what the operator would otherwise
                // see if they retried after the bad record was cleared.
                Err(StateError::Forged) => {}
                Err(e) => return Err(e),
            }
        }

        let mut out = Vec::with_capacity(pendings.len() + approveds.len());
        for (sub, p) in &pendings {
            let anomalous_pub = pendings
                .iter()
                .any(|(s, q)| s != sub && q.pubkey == p.pubkey);
            out.push(EnrollmentView {
                sub: sub.clone(),
                state: EnrollmentState::Pending,
                pubkey: p.pubkey.clone(),
                fingerprint: fingerprint(&p.pubkey),
                peer_ip: Some(p.peer_ip.clone()),
                age_seconds: now_unix.saturating_sub(p.first_seen),
                anomalous_pub,
            });
        }
        for (sub, a) in &approveds {
            // approved_at is RFC 3339; converting to age requires
            // parsing. Best-effort: leave 0 on parse failure rather
            // than failing the whole list.
            let age = chrono::DateTime::parse_from_rfc3339(&a.approved_at)
                .ok()
                .map(|t| now_unix.saturating_sub(t.timestamp().max(0) as u64))
                .unwrap_or(0);
            out.push(EnrollmentView {
                sub: sub.clone(),
                state: EnrollmentState::Approved,
                pubkey: a.pubkey.clone(),
                fingerprint: a.fingerprint_shown.clone(),
                peer_ip: None,
                age_seconds: age,
                anomalous_pub: false,
            });
        }
        out.sort_by(|a, b| a.sub.cmp(&b.sub).then(a.state.cmp(&b.state)));
        Ok(out)
    }
}

impl Ord for EnrollmentState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use EnrollmentState::*;
        match (self, other) {
            (Pending, Pending) | (Approved, Approved) => std::cmp::Ordering::Equal,
            (Pending, Approved) => std::cmp::Ordering::Less,
            (Approved, Pending) => std::cmp::Ordering::Greater,
        }
    }
}
impl PartialOrd for EnrollmentState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn sub_from_pending_key(key: &str) -> Option<String> {
    let prefix = format!("{STATE_PREFIX}/pending/");
    key.strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(".json"))
        .filter(|s| safe_sub(s))
        .map(str::to_owned)
}

fn sub_from_approved_key(key: &str) -> Option<String> {
    let prefix = format!("{STATE_PREFIX}/approved/");
    key.strip_prefix(&prefix)
        .filter(|s| safe_sub(s))
        .map(str::to_owned)
}

fn fresh_nonce() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    BASE64.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().expect("tempdir");
        let s = Store::open_local(d.path()).await.expect("open");
        (d, s)
    }

    const PUBA: &str = "ed25519:AAAA";
    const PUBB: &str = "ed25519:BBBB";
    const APPROVED_AT: &str = "2026-05-23T12:00:00Z";

    #[tokio::test]
    async fn k_m_a_generated_on_first_start_with_demo_enabled() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open_local(d.path()).await.unwrap();
        s.init_k_m_a(d.path(), true).expect("init");
        let first = *s.k_m_a().expect("present");
        // File exists and is mode 0600.
        let meta = std::fs::metadata(d.path().join(K_M_A_FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // Restart loads the same bytes.
        let mut s2 = Store::open_local(d.path()).await.unwrap();
        s2.init_k_m_a(d.path(), true).expect("init");
        assert_eq!(first, *s2.k_m_a().expect("present"));
    }

    #[tokio::test]
    async fn k_m_a_absent_without_demo_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open_local(d.path()).await.unwrap();
        let err = s.init_k_m_a(d.path(), false).expect_err("must refuse");
        assert!(format!("{err}").contains("K_M-A"));
    }

    #[tokio::test]
    async fn k_m_a_loads_existing_file_even_without_demo() {
        // Once an operator has provisioned K_M-A (via auth-service
        // enrollment in production, or via demo-mode first-start),
        // subsequent starts don't need demo_enabled to load it.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(K_M_A_FILE), hex32(&[7u8; 32])).unwrap();
        let mut s = Store::open_local(d.path()).await.unwrap();
        s.init_k_m_a(d.path(), false).expect("loads");
        assert_eq!(*s.k_m_a().unwrap(), [7u8; 32]);
    }

    #[tokio::test]
    async fn invite_persists_and_is_stable_across_open() {
        let d = tempfile::tempdir().unwrap();
        let n1 = Store::open_local(d.path())
            .await
            .unwrap()
            .current_invite()
            .await
            .unwrap();
        let n2 = Store::open_local(d.path())
            .await
            .unwrap()
            .current_invite()
            .await
            .unwrap();
        assert_eq!(n1, n2, "restart preserves the nonce");
        assert!(!n1.is_empty());
    }

    #[tokio::test]
    async fn keyring_generated_once_and_stable_across_open() {
        let d = tempfile::tempdir().unwrap();
        let r1 = *Store::open_local(d.path())
            .await
            .unwrap()
            .keyring()
            .await
            .current_key();
        let r2 = *Store::open_local(d.path())
            .await
            .unwrap()
            .keyring()
            .await
            .current_key();
        assert_eq!(r1, r2, "restart preserves the key");
        assert_ne!(r1, [0u8; 32], "key is random, not zero");
        let f = d.path().join("root_keys").join("0000");
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = std::fs::read_to_string(&f).unwrap();
        assert_eq!(text.trim().len(), 64, "stored as 64 hex chars");
    }

    #[tokio::test]
    async fn legacy_root_key_file_migrated_into_keyring() {
        let d = tempfile::tempdir().unwrap();
        let hex: String = [7u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(d.path().join("root_key"), hex).unwrap();
        let store = Store::open_local(d.path()).await.unwrap();
        let kr = store.keyring().await;
        assert_eq!(kr.current_kid(), 0);
        assert_eq!(kr.current_key(), &[7u8; 32]);
        assert!(
            d.path().join("root_keys").join("0000").exists(),
            "migrated into the new layout"
        );
        assert!(
            !d.path().join("root_key").exists(),
            "legacy singleton removed"
        );
    }

    #[tokio::test]
    async fn first_start_with_supplied_initial_key() {
        // Multi-host shape: operator launches every instance with the
        // same key so they all converge on the same kid=0.
        let d = tempfile::tempdir().unwrap();
        let store = Store::open_local_with_initial_key(d.path(), Some([7u8; 32]))
            .await
            .unwrap();
        assert_eq!(store.keyring().await.current_key(), &[7u8; 32]);
    }

    #[tokio::test]
    async fn keyring_malformed_root_key_file_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("root_key"), b"not hex").unwrap();
        assert!(Store::open_local(d.path()).await.is_err());
    }

    #[tokio::test]
    async fn rotate_changes_nonce_and_drops_noncurrent_pending() {
        let (_d, s) = store().await;
        let old = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &old, "1.2.3.4", 100)
            .await
            .unwrap();
        let new = s.rotate_invite().await.unwrap();
        assert_ne!(old, new);
        assert!(
            s.get_pending("01ARZ").await.unwrap().is_none(),
            "stale pending dropped"
        );
    }

    #[tokio::test]
    async fn rotate_does_not_touch_approved_registry() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        s.rotate_invite().await.unwrap();
        assert!(
            s.get_approved("01ARZ").await.unwrap().is_some(),
            "approved registry survives rotation"
        );
    }

    #[tokio::test]
    async fn record_is_idempotent_for_same_pub_and_conflicts_on_different() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        assert_eq!(
            s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap(),
            Recorded::Created
        );
        assert_eq!(
            s.record_pending("01ARZ", PUBA, &b, "ip2", 9).await.unwrap(),
            Recorded::Idempotent
        );
        assert_eq!(s.get_pending("01ARZ").await.unwrap().unwrap().first_seen, 1);
        assert!(matches!(
            s.record_pending("01ARZ", PUBB, &b, "ip", 1).await,
            Err(StateError::Conflict)
        ));
    }

    #[tokio::test]
    async fn fast_path_skips_pending_when_approved_pub_matches() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        // Re-enroll with the same pub — the fast path kicks in.
        assert_eq!(
            s.record_pending("01ARZ", PUBA, &b, "ip", 2).await.unwrap(),
            Recorded::AlreadyApproved
        );
        assert!(
            s.get_pending("01ARZ").await.unwrap().is_none(),
            "no pending written on fast path"
        );
    }

    #[tokio::test]
    async fn key_rotation_surfaces_as_fresh_pending() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        // Same sub, different pub — falls through to slow path.
        assert_eq!(
            s.record_pending("01ARZ", PUBB, &b, "ip", 2).await.unwrap(),
            Recorded::Created
        );
        let pending = s.get_pending("01ARZ").await.unwrap().unwrap();
        assert_eq!(pending.pubkey, PUBB);
        // The old approval is still there; exchange would still match
        // PUBA only — until the operator re-approves PUBB.
        let approved = s.get_approved("01ARZ").await.unwrap().unwrap();
        assert_eq!(approved.pubkey, PUBA);
    }

    #[tokio::test]
    async fn approve_writes_registry_and_deletes_pending() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        assert!(s.get_approved("01ARZ").await.unwrap().is_some());
        assert!(
            s.get_pending("01ARZ").await.unwrap().is_none(),
            "pending deleted at approval"
        );
        // Re-approval is idempotent at the registry level.
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        assert!(s.get_approved("01ARZ").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_removes_registry_entry() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("01ARZ", PUBA, &b, "ip", 1).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        assert!(s.revoke("01ARZ").await.unwrap());
        assert!(s.get_approved("01ARZ").await.unwrap().is_none());
        assert!(
            !s.revoke("01ARZ").await.unwrap(),
            "second revoke is a no-op"
        );
        // Next enroll falls back to the slow path.
        assert_eq!(
            s.record_pending("01ARZ", PUBA, &b, "ip", 3).await.unwrap(),
            Recorded::Created
        );
    }

    #[tokio::test]
    async fn gc_drops_old_pending_only_never_approved() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("old-pending", PUBA, &b, "ip", 0)
            .await
            .unwrap();
        s.record_pending("kept-approved", PUBB, &b, "ip", 0)
            .await
            .unwrap();
        s.approve("kept-approved", PUBB, APPROVED_AT).await.unwrap();
        s.record_pending("fresh", PUBA, &b, "ip", 950)
            .await
            .unwrap();
        let dropped = s.gc(1_000, 100).await.unwrap();
        assert_eq!(dropped, 1, "only the stale pending goes");
        assert!(s.get_pending("old-pending").await.unwrap().is_none());
        assert!(
            s.get_approved("kept-approved").await.unwrap().is_some(),
            "gc never touches the approved registry"
        );
        assert!(s.get_pending("fresh").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn malformed_sub_rejected() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        for bad in ["../etc", "a/b", "", "."] {
            assert!(matches!(
                s.record_pending(bad, PUBA, &b, "ip", 1).await,
                Err(StateError::BadSub)
            ));
        }
    }

    #[tokio::test]
    async fn list_unifies_pending_and_approved_with_state_column() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("subP", PUBA, &b, "ip", 1).await.unwrap();
        s.record_pending("subQ", PUBB, &b, "ip", 1).await.unwrap();
        s.approve("subQ", PUBB, APPROVED_AT).await.unwrap();
        let rows = s.list(10).await.unwrap();
        let by_sub: std::collections::HashMap<_, _> =
            rows.iter().map(|r| (r.sub.as_str(), r.state)).collect();
        assert_eq!(by_sub.get("subP"), Some(&EnrollmentState::Pending));
        assert_eq!(by_sub.get("subQ"), Some(&EnrollmentState::Approved));
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn list_flags_anomalous_shared_pub() {
        let (_d, s) = store().await;
        let b = s.current_invite().await.unwrap();
        s.record_pending("subX", PUBA, &b, "ip", 1).await.unwrap();
        s.record_pending("subY", PUBA, &b, "ip", 1).await.unwrap();
        let rows = s.list(10).await.unwrap();
        let pendings: Vec<_> = rows
            .iter()
            .filter(|r| r.state == EnrollmentState::Pending)
            .collect();
        assert_eq!(pendings.len(), 2);
        assert!(pendings.iter().all(|r| r.anomalous_pub));
    }

    #[tokio::test]
    async fn in_memory_backend_works_for_quick_tests() {
        let s = Store::open_in_memory([1u8; 32]).await.unwrap();
        let inv = s.current_invite().await.unwrap();
        assert!(!inv.is_empty());
        s.record_pending("01ARZ", PUBA, &inv, "ip", 1)
            .await
            .unwrap();
        assert!(s.get_pending("01ARZ").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn rotate_updates_local_cache_immediately() {
        // Without waiting for the background refresh tick, the rotating
        // process must see the new nonce on its very next read.
        let (_d, s) = store().await;
        let before = s.current_invite().await.unwrap();
        let after = s.rotate_invite().await.unwrap();
        assert_ne!(before, after);
        assert_eq!(s.current_invite().await.unwrap(), after);
    }

    // ---- Approval-MAC / keyring-rotation behaviour ----

    /// Write a raw JSON body directly to `_mint/approved/<sub>` via the
    /// backing object store. Simulates a bucket-level attacker that
    /// holds a `mint-rw` credential (PUT on `_mint/*`) but does not
    /// have the macaroon keyring on local disk — every test that asks
    /// "could this be forged?" exercises this path.
    async fn raw_put_approved(store: &Store, sub: &str, body: &serde_json::Value) {
        let key = Store::approved_key(sub);
        let bytes = serde_json::to_vec(body).unwrap();
        store
            .objects
            .put_opts(
                &key,
                PutPayload::from(Bytes::from(bytes)),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn approved_record_round_trips_with_mac() {
        let (_d, s) = store().await;
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        let got = s.get_approved("01ARZ").await.unwrap().expect("present");
        let kr = s.keyring().await;
        assert_eq!(got.kid, kr.current_kid());
        assert_eq!(got.mac.len(), 64, "32-byte mac as hex");
    }

    #[tokio::test]
    async fn forged_unsigned_put_rejected_as_forged() {
        let (_d, s) = store().await;
        // A bucket-level write of a record that omits the MAC entirely
        // (or, equivalently, supplies any random value) must not be
        // honoured by `get_approved`.
        let forged = serde_json::json!({
            "pubkey": PUBA,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBA),
            "kid": 0,
            "mac": "00".repeat(32),
        });
        raw_put_approved(&s, "01ARZ", &forged).await;
        assert!(matches!(
            s.get_approved("01ARZ").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn record_pending_falls_through_on_corrupt_approved() {
        // A pre-#454 unsigned body (or any record that won't
        // deserialise as the current `Approved` struct) is treated as
        // "no approved record" for the fast-path check — the slow
        // path proceeds and writes a fresh pending. Previously this
        // returned Err(Corrupt) and surfaced as an opaque 401 with
        // a misleading `denied:conflict` audit tag, blocking
        // re-enrollment behind a state the operator couldn't see
        // without inspecting the bucket directly.
        let (_d, s) = store().await;
        let legacy_unsigned = serde_json::json!({
            "pubkey": PUBA,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBA),
            // No kid, no mac — pre-#454 shape.
        });
        raw_put_approved(&s, "01ARZ", &legacy_unsigned).await;
        let invite = s.current_invite().await.unwrap();
        let recorded = s
            .record_pending("01ARZ", PUBA, &invite, "ip", 1)
            .await
            .expect("record_pending must NOT error on corrupt approved");
        assert_eq!(recorded, Recorded::Created);
        // And the pending record now exists so the next /v1/enroll
        // (with the same pubkey) is idempotent and the operator can
        // re-approve cleanly.
        assert!(s.get_pending("01ARZ").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn record_pending_falls_through_on_forged_approved() {
        // Same defence-in-depth as the Corrupt case: an approved
        // record under a retired/unknown kid (or with a forged MAC)
        // should not block re-enrollment.
        let (_d, s) = store().await;
        let forged = serde_json::json!({
            "pubkey": PUBA,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBA),
            "kid": 0,
            "mac": "00".repeat(32),
        });
        raw_put_approved(&s, "01ARZ", &forged).await;
        let invite = s.current_invite().await.unwrap();
        let recorded = s
            .record_pending("01ARZ", PUBA, &invite, "ip", 1)
            .await
            .expect("record_pending must NOT error on forged approved");
        assert_eq!(recorded, Recorded::Created);
        assert!(s.get_pending("01ARZ").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn record_copied_to_a_different_sub_fails_to_verify() {
        // The MAC binds `sub` into its input, so an attacker who copies
        // a valid record verbatim from `_mint/approved/subA` to
        // `_mint/approved/subB` cannot replay it under the new sub.
        let (_d, s) = store().await;
        s.approve("subA", PUBA, APPROVED_AT).await.unwrap();
        let real = s.get_approved("subA").await.unwrap().expect("present");
        let body = serde_json::to_value(&real).unwrap();
        raw_put_approved(&s, "subB", &body).await;
        assert!(matches!(
            s.get_approved("subB").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn record_under_retired_kid_is_forged() {
        // Even an authentic record dies when its kid leaves the ring.
        // This is the rotation invalidation step (`retire(kid)`) doing
        // its job — old approvals stop verifying the moment the kid is
        // removed from the keyring.
        let d = tempfile::tempdir().unwrap();
        let s = Store::open_local(d.path()).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        // Rotate the keyring on disk, then retire the original kid.
        let mut kr = (*s.keyring().await).clone();
        let rk = d.path().join("root_keys");
        kr.add_and_promote(&rk, None).unwrap();
        kr.retire(&rk, 0).unwrap();
        s.set_keyring(kr).await;
        assert!(matches!(
            s.get_approved("01ARZ").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn record_under_old_kid_still_verifies_until_retired() {
        // The retain-keychain shape: rotation is additive. An approval
        // minted under kid=0 keeps verifying after a new kid joins the
        // ring, because verification picks the key by kid.
        let d = tempfile::tempdir().unwrap();
        let s = Store::open_local(d.path()).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        let mut kr = (*s.keyring().await).clone();
        let rk = d.path().join("root_keys");
        kr.add_and_promote(&rk, None).unwrap();
        s.set_keyring(kr).await;
        // get_approved still returns the original record — the new kid
        // is current, but kid=0 is still in the ring for verification.
        let got = s.get_approved("01ARZ").await.unwrap().expect("present");
        assert_eq!(got.kid, 0, "record stays on its issuing kid");
    }

    /// Build a two-kid in-memory keyring `{0 → key_0, 1 → key_1}` with
    /// kid=1 as current. Used by the lazy-migration tests, which need
    /// a backend that implements `PutMode::Update` (`LocalFileSystem`
    /// returns `NotImplemented`; `InMemory` and the production S3
    /// backend both do).
    fn ring_two_keys(key_0: [u8; 32], key_1: [u8; 32]) -> Keyring {
        let mut map = std::collections::BTreeMap::new();
        map.insert(0, key_0);
        map.insert(1, key_1);
        Keyring::from_parts(map, 1).expect("from_parts")
    }

    #[tokio::test]
    async fn lazy_migration_drifts_record_to_current_kid() {
        // The runtime path: a coordinator restart triggers re-MAC of
        // its approval forward to the current kid. The record's body
        // is unchanged except for `kid` and `mac`; subsequent reads
        // verify under the new kid.
        let s = Store::open_in_memory([1u8; 32]).await.unwrap();
        s.approve("01ARZ", PUBA, APPROVED_AT).await.unwrap();
        s.set_keyring(ring_two_keys([1u8; 32], [2u8; 32])).await;
        let migrated = s.migrate_approval_to_current_kid("01ARZ").await.unwrap();
        assert!(migrated, "first call moves it forward");
        let after = s.get_approved("01ARZ").await.unwrap().expect("present");
        assert_eq!(after.kid, 1);
        assert_eq!(after.pubkey, PUBA, "body content unchanged");
        let again = s.migrate_approval_to_current_kid("01ARZ").await.unwrap();
        assert!(!again, "already at current kid → no-op");
    }

    #[tokio::test]
    async fn lazy_migration_refuses_forged_record() {
        // A forged record at the old kid must not be re-MAC'd forward
        // under the new kid — that would launder it into validity.
        let s = Store::open_in_memory([1u8; 32]).await.unwrap();
        let forged = serde_json::json!({
            "pubkey": PUBA,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBA),
            "kid": 0,
            "mac": "00".repeat(32),
        });
        raw_put_approved(&s, "01ARZ", &forged).await;
        s.set_keyring(ring_two_keys([1u8; 32], [2u8; 32])).await;
        let migrated = s.migrate_approval_to_current_kid("01ARZ").await.unwrap();
        assert!(!migrated, "forged record is not re-MAC'd forward");
        // And the record still fails to verify under the new kid: the
        // MAC didn't change, and the new kid's key wouldn't match it
        // either.
        assert!(matches!(
            s.get_approved("01ARZ").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn sweep_rekeys_old_records_skips_forged() {
        // The admin sweep is the explicit "consolidate before retire"
        // path. Mixes a real record at kid=0, a forged record at
        // kid=0, and a record already at current — the sweep moves the
        // first, skips the second, leaves the third alone.
        let d = tempfile::tempdir().unwrap();
        let s = Store::open_local(d.path()).await.unwrap();
        s.approve("real-old", PUBA, APPROVED_AT).await.unwrap();
        let forged = serde_json::json!({
            "pubkey": PUBB,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBB),
            "kid": 0,
            "mac": "00".repeat(32),
        });
        raw_put_approved(&s, "forged", &forged).await;
        let mut kr = (*s.keyring().await).clone();
        let rk = d.path().join("root_keys");
        kr.add_and_promote(&rk, None).unwrap();
        s.set_keyring(kr).await;
        // A record approved AFTER the rotation already sits on the new
        // kid — the sweep should report it as already_current.
        s.approve("on-current", PUBA, APPROVED_AT).await.unwrap();
        let report = s.sweep_approvals_to_current_kid().await.unwrap();
        assert_eq!(report.rekeyed, 1, "real-old moved forward");
        assert_eq!(report.skipped, 1, "forged not laundered");
        assert_eq!(report.already_current, 1, "on-current untouched");
        assert_eq!(s.get_approved("real-old").await.unwrap().unwrap().kid, 1);
        assert!(matches!(
            s.get_approved("forged").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn intermediate_kid_retire_does_not_affect_other_kids() {
        // Per-kid retire is independent: removing kid 1 from a ring of
        // {0, 1, 2} leaves records under 0 and 2 verifying as before.
        let d = tempfile::tempdir().unwrap();
        let s = Store::open_local(d.path()).await.unwrap();
        s.approve("under-0", PUBA, APPROVED_AT).await.unwrap();
        // Rotate to kid 1, approve a second record there.
        let mut kr = (*s.keyring().await).clone();
        let rk = d.path().join("root_keys");
        kr.add_and_promote(&rk, None).unwrap();
        s.set_keyring(kr).await;
        s.approve("under-1", PUBB, APPROVED_AT).await.unwrap();
        // Rotate again to kid 2, approve a third.
        let mut kr = (*s.keyring().await).clone();
        kr.add_and_promote(&rk, None).unwrap();
        s.set_keyring(kr).await;
        s.approve("under-2", PUBA, APPROVED_AT).await.unwrap();
        // Now retire only the intermediate kid 1. `under-0` and
        // `under-2` should still verify; `under-1` should not.
        let mut kr = (*s.keyring().await).clone();
        kr.retire(&rk, 1).unwrap();
        s.set_keyring(kr).await;
        assert!(s.get_approved("under-0").await.unwrap().is_some());
        assert!(s.get_approved("under-2").await.unwrap().is_some());
        assert!(matches!(
            s.get_approved("under-1").await,
            Err(StateError::Forged)
        ));
    }

    #[tokio::test]
    async fn list_skips_forged_records_without_failing() {
        // `mint enroll list` must not crash because one record was
        // forged or under a retired kid; that record is silently
        // dropped from the view (logged inside get_approved).
        let (_d, s) = store().await;
        s.approve("good", PUBA, APPROVED_AT).await.unwrap();
        let forged = serde_json::json!({
            "pubkey": PUBB,
            "approved_at": APPROVED_AT,
            "fingerprint_shown": fingerprint(PUBB),
            "kid": 0,
            "mac": "00".repeat(32),
        });
        raw_put_approved(&s, "bad", &forged).await;
        let rows = s.list(0).await.unwrap();
        let subs: Vec<&str> = rows.iter().map(|r| r.sub.as_str()).collect();
        assert!(subs.contains(&"good"));
        assert!(!subs.contains(&"bad"), "forged entry filtered from list");
    }

    #[tokio::test]
    async fn background_refresh_picks_up_external_rotation() {
        // Simulate a peer mint instance rotating the invite by writing
        // directly to the backend; the refresh task should swap our
        // cache the next time it polls.
        let s = Arc::new(Store::open_in_memory([1u8; 32]).await.unwrap());
        let initial = s.current_invite().await.unwrap();
        // Fast poll interval so the test doesn't waste real time.
        let handle = s.spawn_invite_refresh(std::time::Duration::from_millis(50));
        // External write under the canonical key.
        let new_nonce = "EXTERNALLY_ROTATED_NONCE";
        s.objects
            .put_opts(
                &Store::invite_key(),
                PutPayload::from(Bytes::from(new_nonce.as_bytes().to_vec())),
                PutOptions::default(),
            )
            .await
            .unwrap();
        // Wait a few intervals for the refresh task to catch up.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if s.current_invite().await.unwrap() == new_nonce {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("cache did not refresh from external write");
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert_ne!(initial, new_nonce);
        handle.abort();
    }
}
