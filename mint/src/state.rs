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
//! _mint/approved/<sub>         long-lived {pub, approved_at, fingerprint_shown};
//!                              powers the re-enrollment fast path
//! ```
//!
//! The macaroon `root_key` does **not** live in object storage — it is
//! the master mint secret and stays on local disk
//! (`<data_dir>/root_key`, 0600). For multi-instance deployments
//! operators replicate it out-of-band (e.g. systemd `LoadCredential=`),
//! since instances sharing a `_mint/` prefix must agree on the MAC key
//! or they mint mutually-unverifiable macaroons.
//!
//! Concurrency: `record_pending` uses `PutMode::Create`
//! (`If-None-Match: *`) so multi-instance writes are serialised
//! bucket-side; the conditional primitive is the only ordering
//! mint relies on — no in-process mutex.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
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
use tokio::sync::RwLock;

/// Top-level prefix for mint state inside whatever bucket / directory
/// the backing [`ObjectStore`] is rooted at — see *Mint state in the
/// tenant bucket*.
pub const STATE_PREFIX: &str = "_mint";

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
}

impl From<OsError> for StateError {
    fn from(e: OsError) -> Self {
        StateError::Store(e.to_string())
    }
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

fn write_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)
}

/// Load the macaroon root key from `path` (64 hex chars → 32 bytes),
/// generating a fresh CSPRNG one (hex, mode 0600) on first start. Hex
/// so the secret is a single ASCII line — backup/transport friendly
/// (an operator who loses it loses every outstanding macaroon).
fn load_or_generate_root_key(path: &Path) -> io::Result<[u8; 32]> {
    match fs::read_to_string(path) {
        Ok(text) => decode_root_key(text.trim())
            .ok_or_else(|| io::Error::other(format!("{}: not 64 hex chars", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            write_0600(path, encode_root_key(&key).as_bytes())?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

fn encode_root_key(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_root_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
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
    /// The macaroon root, loaded (or generated on first start) from
    /// `<data_dir>/root_key`. Symmetric: mint both mints and verifies
    /// with it. Copied out via [`Store::root_key`]; never logged.
    root_key: [u8; 32],
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
    /// shape. `dir/root_key` is loaded or generated; everything else
    /// lives under `dir/_mint/`, matching the bucket-side layout key for
    /// key so an operator can `ls` either and see the same structure.
    pub async fn open_local(dir: impl Into<PathBuf>) -> io::Result<Store> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let root_key = load_or_generate_root_key(&dir.join("root_key"))?;
        // LocalFileSystem rejects paths that don't exist; create the
        // _mint subtree so the first PUT lands. (PUTs auto-create
        // intermediate directories, but the prefix root must exist.)
        fs::create_dir_all(dir.join(STATE_PREFIX))?;
        let lfs = LocalFileSystem::new_with_prefix(&dir).map_err(io::Error::other)?;
        let store = Store::with_object_store(root_key, Arc::new(lfs));
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    /// Bucket-backed store. `objects` is a [`ObjectStore`] whose root
    /// is the tenant bucket; the `_mint/` prefix is applied to every
    /// key. `root_key_path` is the local file the macaroon root is
    /// loaded or generated from (see *`root_key` does not move*).
    pub async fn open_remote(
        objects: Arc<dyn ObjectStore>,
        root_key_path: &Path,
    ) -> io::Result<Store> {
        let root_key = load_or_generate_root_key(root_key_path)?;
        let store = Store::with_object_store(root_key, objects);
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    /// In-memory backend, root key supplied directly. For tests.
    pub async fn open_in_memory(root_key: [u8; 32]) -> io::Result<Store> {
        let store = Store::with_object_store(root_key, Arc::new(InMemory::new()));
        store.ensure_invite().await.map_err(io::Error::other)?;
        Ok(store)
    }

    fn with_object_store(root_key: [u8; 32], objects: Arc<dyn ObjectStore>) -> Store {
        Store {
            root_key,
            objects,
            invite_cache: Arc::new(RwLock::new(InviteSnapshot {
                value: String::new(),
                etag: None,
            })),
        }
    }

    /// The macaroon root key. Symmetric — used to both mint and verify.
    pub fn root_key(&self) -> [u8; 32] {
        self.root_key
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
        if let Some(approved) = self.get_approved(sub).await?
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
    pub async fn approve(
        &self,
        sub: &str,
        pubkey: &str,
        now_iso8601: &str,
    ) -> Result<(), StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        let rec = Approved {
            pubkey: pubkey.to_string(),
            approved_at: now_iso8601.to_string(),
            fingerprint_shown: fingerprint(pubkey),
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
    pub async fn get_approved(&self, sub: &str) -> Result<Option<Approved>, StateError> {
        if !safe_sub(sub) {
            return Err(StateError::BadSub);
        }
        match self.objects.get(&Self::approved_key(sub)).await {
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
            if let Some(a) = self.get_approved(&sub).await? {
                approveds.push((sub, a));
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

    async fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().expect("tempdir");
        let s = Store::open_local(d.path()).await.expect("open");
        (d, s)
    }

    const PUBA: &str = "ed25519:AAAA";
    const PUBB: &str = "ed25519:BBBB";
    const APPROVED_AT: &str = "2026-05-23T12:00:00Z";

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
    async fn root_key_generated_once_and_stable_across_open() {
        let d = tempfile::tempdir().unwrap();
        let r1 = Store::open_local(d.path()).await.unwrap().root_key();
        let r2 = Store::open_local(d.path()).await.unwrap().root_key();
        assert_eq!(r1, r2, "restart preserves the key");
        assert_ne!(r1, [0u8; 32], "key is random, not zero");
        let f = d.path().join("root_key");
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = std::fs::read_to_string(&f).unwrap();
        assert_eq!(text.trim().len(), 64, "stored as 64 hex chars");
    }

    #[tokio::test]
    async fn root_key_seeded_file_is_loaded() {
        let d = tempfile::tempdir().unwrap();
        let hex: String = [7u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(d.path().join("root_key"), hex).unwrap();
        assert_eq!(
            Store::open_local(d.path()).await.unwrap().root_key(),
            [7u8; 32]
        );
    }

    #[tokio::test]
    async fn root_key_bad_format_is_an_error() {
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
