//! Local-only volume lifecycle and mode classification.
//!
//! `VolumeMode` and `VolumeLifecycle` capture the on-disk state the
//! coordinator can determine by inspecting a volume directory. Both
//! the CLI (`elide volume list`) and the coordinator's
//! `volume_status` IPC verb derive their answers through this
//! module, so the operator vocabulary lives in exactly one place.
//!
//! This is distinct from `NameState` (in `elide-core::name_record`),
//! which describes the *bucket-level* lifecycle of a named volume. A
//! single volume may simultaneously be `NameState::Live` (S3 thinks
//! we own it) and `VolumeLifecycle::Stopped` (the daemon is down on
//! this host); the two views are intentionally orthogonal.

use std::path::{Path, PathBuf};

use elide_core::process::pid_is_alive;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Per-volume daemon pidfile. Written by the volume process on
/// startup; presence + liveness drives the `Running` classification.
/// Canonical home for the filename — other modules consume it from
/// here rather than redefining the literal.
pub const PID_FILE: &str = "volume.pid";

/// Manual-stop marker. Presence pins the volume to `StoppedManual`
/// regardless of any other state — the coordinator's supervisor
/// treats this as "do not relaunch".
pub const STOPPED_FILE: &str = "volume.stopped";

/// Released marker. Written by the release IPC handlers after a
/// successful `names/<name>` flip to `Released`, cleared by the
/// in-place reclaim path. Body is the handoff snapshot ULID.
///
/// Acts as a park marker: the supervisor refuses to spawn a daemon
/// while this is present (see [`crate::park`]). `lifecycle::reconcile_marker`
/// keeps the file in sync with the bucket's `names/<name>` record so
/// drift self-heals at the next scan. Authoritative claim state still
/// lives in S3.
pub const RELEASED_FILE: &str = "volume.released";

/// Importing marker. Written by `elide-import`'s supervision protocol
/// while a subprocess is running. Body is the import ULID. Naming is
/// aligned with the other `volume.<state>` lifecycle markers.
pub const IMPORTING_FILE: &str = "volume.importing";

/// Read/write mode for a volume. Readonly is set on imported OCI
/// volumes; everything else is read/write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VolumeMode {
    /// Read-only (typically an imported OCI image).
    Ro,
    /// Read/write.
    Rw,
}

impl VolumeMode {
    /// Lowercase 2-char label for table display.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ro => "ro",
            Self::Rw => "rw",
        }
    }
}

impl std::fmt::Display for VolumeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Local lifecycle of a volume, derived from on-disk markers.
///
/// Single source of truth for "what shape is this fork in on disk?"
/// — used by lifecycle verbs ([`Self::resolve`]) for dispatch and by
/// the CLI / `volume_status` IPC ([`Self::label`], [`Self::wire_body`])
/// for display.
///
/// Order of precedence in [`Self::from_dir`]:
///   1. `volume.released` → `Released { handoff_snapshot }`
///   2. `volume.readonly` → `ReadonlyImported`
///   3. `volume.stopped`  → `StoppedManual`
///   4. `volume.importing`→ `Importing { import_ulid }`
///   5. `volume.pid` names a live process → `Running { pid }`
///   6. otherwise → `Stopped`
///
/// `Absent` is produced only by [`Self::resolve`] — it represents
/// "the `by_name/<name>` symlink canonicalised to NotFound", which
/// `from_dir` (which takes an existing directory) cannot express.
///
/// `ReadonlyImported` is the readonly-flavoured variant; verbs that
/// need a signing key refuse on it via [`Self::is_readonly_local`]
/// (OCI base or readonly skeleton).
///
/// `Released` is a sticky terminal local marker. The bucket's
/// `names/<name>` record is authoritative for claim state; the local
/// marker drives table rendering so `volume list` can label a
/// released volume without an S3 round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VolumeLifecycle {
    /// `by_name/<name>` is absent (or canonicalize returned NotFound).
    /// Produced only by [`Self::resolve`]; verbs route to hydrate /
    /// claim. Distinct from "stopped but never started" — there is
    /// no fork directory at all.
    Absent,
    /// Daemon is running with the embedded pid.
    Running { pid: u32 },
    /// Import subprocess is active. The ULID is read from the lock file.
    Importing { import_ulid: String },
    /// `volume.released` marker is present; the bucket record is in
    /// `Released` state and a fresh claim is needed before this host
    /// can serve the volume again. The handoff snapshot ULID is read
    /// from the marker body (`None` when absent or unparsable).
    Released {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff_snapshot: Option<Ulid>,
    },
    /// `volume.readonly` is present — an imported OCI base, or a
    /// readonly skeleton pulled by ancestor chain-walk.
    ReadonlyImported,
    /// `volume.stopped` marker is present; supervisor will not relaunch.
    StoppedManual,
    /// Daemon is not running and no manual-stop marker is present.
    Stopped,
}

impl VolumeLifecycle {
    /// Derive lifecycle from the on-disk markers in `vol_dir`.
    ///
    /// Reads up to five small files; fast enough to call per-volume
    /// in the CLI's list path. An unparseable ULID body in
    /// `volume.released` causes the variant to fall through to the
    /// next-precedence classification rather than surfacing an error
    /// — the classifier never blocks a recovery verb.
    ///
    /// Never returns [`Self::Absent`] — that variant is the
    /// `resolve()`-only signal that no fork exists at all.
    pub fn from_dir(vol_dir: &Path) -> Self {
        let released = vol_dir.join(RELEASED_FILE);
        if released.exists() {
            let handoff_snapshot = std::fs::read_to_string(&released)
                .ok()
                .and_then(|s| Ulid::from_string(s.trim()).ok());
            return Self::Released { handoff_snapshot };
        }
        if vol_dir.join("volume.readonly").exists() {
            return Self::ReadonlyImported;
        }
        if vol_dir.join(STOPPED_FILE).exists() {
            return Self::StoppedManual;
        }
        let lock = vol_dir.join(IMPORTING_FILE);
        if lock.exists() {
            let import_ulid = std::fs::read_to_string(&lock)
                .unwrap_or_default()
                .trim()
                .to_owned();
            return Self::Importing { import_ulid };
        }
        if let Ok(text) = std::fs::read_to_string(vol_dir.join(PID_FILE))
            && let Ok(pid) = text.trim().parse::<u32>()
            && pid_is_alive(pid)
        {
            return Self::Running { pid };
        }
        Self::Stopped
    }

    /// Canonicalise `by_name_link` and classify the resulting
    /// directory. Returns the resolved `vol_dir` alongside the
    /// shape — `vol_dir` is `Some` exactly when the shape is not
    /// [`Self::Absent`].
    ///
    /// Use this at the top of every lifecycle verb so the marker
    /// probes happen once, in one place.
    pub fn resolve(by_name_link: &Path) -> std::io::Result<(Option<PathBuf>, Self)> {
        match std::fs::canonicalize(by_name_link) {
            Ok(vol_dir) => {
                let shape = Self::from_dir(&vol_dir);
                Ok((Some(vol_dir), shape))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((None, Self::Absent)),
            Err(e) => Err(e),
        }
    }

    /// Operator-facing label for table display. Drops the pid/ulid
    /// payload — see [`Self::wire_body`] for the IPC format.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Running { .. } => "running",
            Self::Importing { .. } => "importing",
            Self::Released { .. } => "released",
            Self::ReadonlyImported => "readonly",
            Self::StoppedManual => "stopped (manual)",
            Self::Stopped => "stopped",
        }
    }

    /// Body string for the `volume_status` IPC reply (without the
    /// leading `"ok "`). Identical to [`Self::label`] except
    /// `Importing` and `Released` append their associated ULIDs so
    /// clients can correlate with bucket state.
    pub fn wire_body(&self) -> String {
        match self {
            Self::Importing { import_ulid } if !import_ulid.is_empty() => {
                format!("importing {import_ulid}")
            }
            Self::Released {
                handoff_snapshot: Some(u),
            } => format!("released {u}"),
            other => other.label().to_owned(),
        }
    }

    /// Pid of the live volume daemon, when running.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Running { pid } => Some(*pid),
            _ => None,
        }
    }

    /// True when a daemon is provably alive for this fork.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// True when the local fork's on-disk markers say "no signing
    /// key available" — `volume.readonly`. Verbs that need to sign
    /// segments refuse on this.
    pub fn is_readonly_local(&self) -> bool {
        matches!(self, Self::ReadonlyImported)
    }

    /// True only for the `resolve()`-only `Absent` variant.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// Write `volume.released` with the handoff snapshot ULID as the body.
///
/// Called from the release IPC handlers after the bucket-side
/// `names/<name>` flip succeeds. Display-only — see [`RELEASED_FILE`].
pub fn write_released_marker(vol_dir: &Path, handoff: ulid::Ulid) -> std::io::Result<()> {
    std::fs::write(vol_dir.join(RELEASED_FILE), handoff.to_string())
}

/// Remove `volume.released` if present; missing-file is not an error.
///
/// Called from the in-place reclaim path after the bucket flip back
/// to a non-`Released` state succeeds.
pub fn clear_released_marker(vol_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(vol_dir.join(RELEASED_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The fork directory for `vol`: `data_dir/by_id/<vol>`.
pub fn fork_dir(data_dir: &Path, vol: Ulid) -> PathBuf {
    data_dir.join("by_id").join(vol.to_string())
}

/// Resolve `by_name/<name>` to the volume ULID it points at.
///
/// Canonicalises the symlink and parses the trailing path component
/// through the ULID parser, so callers get a typed ID rather than a
/// raw path. `NotFound` propagates with its kind intact so callers
/// can distinguish "no such volume" from other I/O failures; a
/// target that is not a `by_id/<ulid>` directory is `other`.
pub fn resolve_volume_ulid(data_dir: &Path, name: &str) -> std::io::Result<Ulid> {
    let link = data_dir.join("by_name").join(name);
    let canon = std::fs::canonicalize(&link)?;
    let stem = canon
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other(format!("by_name/{name} target is not utf-8")))?;
    Ulid::from_string(stem).map_err(|e| {
        std::io::Error::other(format!("by_name/{name} target {stem:?} is not a ULID: {e}"))
    })
}

/// Outcome categories for [`reconcile_owned_local_to_stopped`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Local fork was already in the canonical Stopped+writable shape;
    /// nothing was changed. Returned when `volume.key` was present,
    /// `volume.readonly` was not stamped, and `volume.stopped` already
    /// existed.
    AlreadyStopped,
    /// At least one of `volume.key`, the transient readonly marker, or
    /// `volume.stopped` had to be written/removed to reach the
    /// canonical shape.
    Reconciled,
}

/// Errors returned by [`reconcile_owned_local_to_stopped`].
#[derive(Debug)]
pub enum ReconcileError {
    /// `volume.key` is missing locally and no key shadow exists at
    /// `data_dir/keys/<vol_ulid>.key`. This fork can't be made
    /// writable in place — the caller should refuse and direct the
    /// operator to fork via `volume create --from`.
    NoKeyShadow,
    /// Filesystem I/O failed mid-reconcile (e.g. permission denied
    /// writing `volume.key` or `volume.stopped`). Local state may be
    /// partially reconciled; idempotent retry is the recovery path.
    Io(std::io::Error),
    /// The volume daemon is currently running for this fork (live pid
    /// in `volume.pid`). Reconciliation refuses rather than racing the
    /// daemon — operator should `volume stop` first.
    DaemonRunning,
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKeyShadow => write!(
                f,
                "no key shadow available; foreign readonly fork cannot be made \
                 writable in place"
            ),
            Self::Io(e) => write!(f, "i/o error during reconcile: {e}"),
            Self::DaemonRunning => {
                write!(f, "volume daemon is running; stop it before reconciling")
            }
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<std::io::Error> for ReconcileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Bring an owned-by-us local fork into the canonical Stopped+
/// writable shape. Idempotent — calling on an already-reconciled
/// fork returns [`ReconcileOutcome::AlreadyStopped`].
///
/// The shape we converge on:
///
///   - `volume.key` present (restored from `data_dir/keys/<vol_ulid>.key`
///     when absent).
///   - `volume.readonly` absent.
///   - `volume.stopped` present.
///   - No live daemon (no `volume.pid` with an alive pid).
///
/// Used by:
///   - `volume claim` against a `Live`/`Stopped` record owned by us
///     (idempotent "I already own this; just make sure local is
///     consistent").
///   - `volume claim` against a `Released` record where the local
///     fork is a readonly copy of our own lineage (the case fixed in
///     the original key-shadow rollout).
pub fn reconcile_owned_local_to_stopped(
    fork_dir: &Path,
    data_dir: &Path,
    vol_ulid: ulid::Ulid,
) -> Result<ReconcileOutcome, ReconcileError> {
    // `control.sock` alone is not a reliable liveness signal — it
    // survives a `process::exit` shutdown or a crash. Trust the
    // PID-anchored classifier instead so a stale socket file from a
    // dead daemon doesn't block reconcile.
    if VolumeLifecycle::from_dir(fork_dir).is_running() {
        return Err(ReconcileError::DaemonRunning);
    }

    let mut changed = false;

    // (1) Ensure volume.key is present.
    let key_path = fork_dir.join(elide_core::signing::VOLUME_KEY_FILE);
    if !key_path.exists() {
        let shadow = crate::key_shadow::read(data_dir, vol_ulid)?;
        let Some(key_bytes) = shadow else {
            return Err(ReconcileError::NoKeyShadow);
        };
        elide_core::segment::write_file_atomic(&key_path, &key_bytes)?;
        changed = true;
    }

    // (2) Strip the transient readonly marker.
    match std::fs::remove_file(fork_dir.join("volume.readonly")) {
        Ok(()) => changed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ReconcileError::Io(e)),
    }

    // (3) Ensure volume.stopped is present.
    let stopped = fork_dir.join(STOPPED_FILE);
    if !stopped.exists() {
        std::fs::write(&stopped, "")?;
        changed = true;
    }

    Ok(if changed {
        ReconcileOutcome::Reconciled
    } else {
        ReconcileOutcome::AlreadyStopped
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_dir_classifies_as_stopped() {
        let d = TempDir::new().unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Stopped
        );
    }

    #[test]
    fn released_marker_classifies_as_released() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(RELEASED_FILE), "01J0000000000000000000000V").unwrap();
        match VolumeLifecycle::from_dir(d.path()) {
            VolumeLifecycle::Released {
                handoff_snapshot: Some(u),
            } => {
                assert_eq!(u.to_string(), "01J0000000000000000000000V");
            }
            other => panic!("expected Released with handoff, got {other:?}"),
        }
    }

    #[test]
    fn released_marker_takes_precedence_over_stopped_pid_and_import_lock() {
        let d = TempDir::new().unwrap();
        let snap = ulid::Ulid::new();
        std::fs::write(d.path().join(RELEASED_FILE), snap.to_string()).unwrap();
        std::fs::write(d.path().join(STOPPED_FILE), "").unwrap();
        std::fs::write(d.path().join(IMPORTING_FILE), "01J7").unwrap();
        std::fs::write(d.path().join(PID_FILE), std::process::id().to_string()).unwrap();
        match VolumeLifecycle::from_dir(d.path()) {
            VolumeLifecycle::Released {
                handoff_snapshot: Some(u),
            } => {
                assert_eq!(u, snap);
            }
            other => panic!("expected Released, got {other:?}"),
        }
    }

    #[test]
    fn released_marker_with_empty_body_classifies_as_released_with_no_snapshot() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(RELEASED_FILE), "").unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Released {
                handoff_snapshot: None
            }
        );
    }

    #[test]
    fn readonly_marker_classifies_as_readonly_imported() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join("volume.readonly"), "").unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::ReadonlyImported
        );
    }

    #[test]
    fn readonly_marker_takes_precedence_over_stopped_and_pid() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join("volume.readonly"), "").unwrap();
        std::fs::write(d.path().join(STOPPED_FILE), "").unwrap();
        std::fs::write(d.path().join(PID_FILE), std::process::id().to_string()).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::ReadonlyImported
        );
    }

    #[test]
    fn write_and_clear_released_marker_round_trip() {
        let d = TempDir::new().unwrap();
        let snap = ulid::Ulid::new();
        write_released_marker(d.path(), snap).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Released {
                handoff_snapshot: Some(snap)
            }
        );
        clear_released_marker(d.path()).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Stopped
        );
        // Idempotent when already cleared.
        clear_released_marker(d.path()).unwrap();
    }

    #[test]
    fn stopped_marker_takes_precedence_over_pid_and_lock() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(STOPPED_FILE), "").unwrap();
        std::fs::write(d.path().join(IMPORTING_FILE), "01J0000000000000000000000V").unwrap();
        std::fs::write(d.path().join(PID_FILE), std::process::id().to_string()).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::StoppedManual
        );
    }

    #[test]
    fn import_lock_takes_precedence_over_pid() {
        let d = TempDir::new().unwrap();
        std::fs::write(
            d.path().join(IMPORTING_FILE),
            "01J0000000000000000000000V\n",
        )
        .unwrap();
        std::fs::write(d.path().join(PID_FILE), std::process::id().to_string()).unwrap();
        match VolumeLifecycle::from_dir(d.path()) {
            VolumeLifecycle::Importing { import_ulid } => {
                assert_eq!(import_ulid, "01J0000000000000000000000V");
            }
            other => panic!("expected Importing, got {other:?}"),
        }
    }

    #[test]
    fn import_lock_with_empty_body_classifies_as_importing_with_empty_ulid() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(IMPORTING_FILE), "").unwrap();
        match VolumeLifecycle::from_dir(d.path()) {
            VolumeLifecycle::Importing { import_ulid } => {
                assert_eq!(import_ulid, "");
            }
            other => panic!("expected Importing, got {other:?}"),
        }
    }

    #[test]
    fn live_pidfile_classifies_as_running() {
        let d = TempDir::new().unwrap();
        let me = std::process::id();
        std::fs::write(d.path().join(PID_FILE), me.to_string()).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Running { pid: me }
        );
    }

    #[test]
    fn dead_pidfile_classifies_as_stopped() {
        let d = TempDir::new().unwrap();
        // u32::MAX is far above any plausible system pid_max, so the
        // kernel returns ESRCH for `kill(pid, 0)` (matches the
        // `pid_is_alive` test in elide-core).
        std::fs::write(d.path().join(PID_FILE), u32::MAX.to_string()).unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Stopped
        );
    }

    #[test]
    fn malformed_pidfile_classifies_as_stopped() {
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join(PID_FILE), "not a number").unwrap();
        assert_eq!(
            VolumeLifecycle::from_dir(d.path()),
            VolumeLifecycle::Stopped
        );
    }

    #[test]
    fn label_drops_payload() {
        let snap = ulid::Ulid::new();
        assert_eq!(VolumeLifecycle::Absent.label(), "absent");
        assert_eq!(VolumeLifecycle::Running { pid: 42 }.label(), "running");
        assert_eq!(
            VolumeLifecycle::Importing {
                import_ulid: "01...".to_owned()
            }
            .label(),
            "importing"
        );
        assert_eq!(VolumeLifecycle::StoppedManual.label(), "stopped (manual)");
        assert_eq!(VolumeLifecycle::Stopped.label(), "stopped");
        assert_eq!(VolumeLifecycle::ReadonlyImported.label(), "readonly");
        assert_eq!(
            VolumeLifecycle::Released {
                handoff_snapshot: Some(snap)
            }
            .label(),
            "released"
        );
    }

    #[test]
    fn wire_body_appends_ulids() {
        let snap = ulid::Ulid::new();
        assert_eq!(VolumeLifecycle::Absent.wire_body(), "absent");
        assert_eq!(VolumeLifecycle::Running { pid: 42 }.wire_body(), "running");
        assert_eq!(
            VolumeLifecycle::Importing {
                import_ulid: "01J0".to_owned()
            }
            .wire_body(),
            "importing 01J0"
        );
        // Empty importing ulid degrades to the bare label.
        assert_eq!(
            VolumeLifecycle::Importing {
                import_ulid: String::new()
            }
            .wire_body(),
            "importing"
        );
        assert_eq!(
            VolumeLifecycle::StoppedManual.wire_body(),
            "stopped (manual)"
        );
        assert_eq!(VolumeLifecycle::Stopped.wire_body(), "stopped");
        assert_eq!(VolumeLifecycle::ReadonlyImported.wire_body(), "readonly");
        assert_eq!(
            VolumeLifecycle::Released {
                handoff_snapshot: Some(snap)
            }
            .wire_body(),
            format!("released {snap}")
        );
        assert_eq!(
            VolumeLifecycle::Released {
                handoff_snapshot: None
            }
            .wire_body(),
            "released"
        );
    }

    #[test]
    fn pid_only_set_for_running() {
        let snap = ulid::Ulid::new();
        assert_eq!(VolumeLifecycle::Absent.pid(), None);
        assert_eq!(VolumeLifecycle::Running { pid: 42 }.pid(), Some(42));
        assert_eq!(
            VolumeLifecycle::Importing {
                import_ulid: String::new()
            }
            .pid(),
            None
        );
        assert_eq!(VolumeLifecycle::StoppedManual.pid(), None);
        assert_eq!(VolumeLifecycle::Stopped.pid(), None);
        assert_eq!(VolumeLifecycle::ReadonlyImported.pid(), None);
        assert_eq!(
            VolumeLifecycle::Released {
                handoff_snapshot: Some(snap)
            }
            .pid(),
            None
        );
    }

    #[test]
    fn resolve_returns_absent_for_missing_link() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("by_name/nope");
        let (vol_dir, shape) = VolumeLifecycle::resolve(&missing).unwrap();
        assert!(vol_dir.is_none());
        assert_eq!(shape, VolumeLifecycle::Absent);
    }

    #[test]
    fn resolve_follows_symlink_and_classifies() {
        // by_name/<n> → ../by_id/<ulid>
        let tmp = TempDir::new().unwrap();
        let by_id = tmp.path().join("by_id/01J0000000000000000000000V");
        std::fs::create_dir_all(&by_id).unwrap();
        let by_name_dir = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_name_dir).unwrap();
        let link = by_name_dir.join("vol");
        std::os::unix::fs::symlink("../by_id/01J0000000000000000000000V", &link).unwrap();
        let (vol_dir, shape) = VolumeLifecycle::resolve(&link).unwrap();
        assert_eq!(vol_dir.unwrap(), std::fs::canonicalize(&by_id).unwrap());
        assert_eq!(shape, VolumeLifecycle::Stopped);
    }

    #[test]
    fn helpers_match_variants() {
        assert!(VolumeLifecycle::Running { pid: 1 }.is_running());
        assert!(!VolumeLifecycle::Stopped.is_running());
        assert!(VolumeLifecycle::ReadonlyImported.is_readonly_local());
        assert!(!VolumeLifecycle::Stopped.is_readonly_local());
        assert!(VolumeLifecycle::Absent.is_absent());
        assert!(!VolumeLifecycle::Stopped.is_absent());
    }

    #[test]
    fn volume_mode_label() {
        assert_eq!(VolumeMode::Ro.label(), "ro");
        assert_eq!(VolumeMode::Rw.label(), "rw");
        assert_eq!(format!("{}", VolumeMode::Ro), "ro");
    }

    // ── reconcile_owned_local_to_stopped ─────────────────────────────

    /// Set up a `(data_dir, vol_dir)` pair plus an optional key shadow
    /// under `data_dir/keys/<vol_ulid>.key`. Returns the temp guard
    /// alongside the paths so the caller can let it drop on exit.
    fn reconcile_scaffolding(
        with_shadow: bool,
    ) -> (TempDir, std::path::PathBuf, std::path::PathBuf, ulid::Ulid) {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let vol_ulid = ulid::Ulid::new();
        let vol_dir = data_dir.join("by_id").join(vol_ulid.to_string());
        std::fs::create_dir_all(&vol_dir).unwrap();
        if with_shadow {
            crate::key_shadow::write(&data_dir, vol_ulid, &[0u8; 32]).unwrap();
        }
        (tmp, data_dir, vol_dir, vol_ulid)
    }

    #[test]
    fn reconcile_no_op_when_already_stopped_writable() {
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(false);
        // Already-good shape: key present, stopped marker present, no
        // transient markers.
        std::fs::write(
            vol_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            [0u8; 32],
        )
        .unwrap();
        std::fs::write(vol_dir.join(STOPPED_FILE), "").unwrap();
        let out = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid).unwrap();
        assert_eq!(out, ReconcileOutcome::AlreadyStopped);
    }

    #[test]
    fn reconcile_restores_key_from_shadow_and_strips_markers() {
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(true);
        // Readonly shape: readonly marker, no key, no stopped.
        std::fs::write(vol_dir.join("volume.readonly"), "").unwrap();
        let out = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid).unwrap();
        assert_eq!(out, ReconcileOutcome::Reconciled);
        assert!(
            vol_dir.join(elide_core::signing::VOLUME_KEY_FILE).exists(),
            "key must be restored from shadow"
        );
        assert!(
            !vol_dir.join("volume.readonly").exists(),
            "readonly marker must be stripped"
        );
        assert!(
            vol_dir.join(STOPPED_FILE).exists(),
            "stopped marker must be written"
        );
    }

    #[test]
    fn reconcile_refuses_when_no_key_and_no_shadow() {
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(false);
        std::fs::write(vol_dir.join("volume.readonly"), "").unwrap();
        let err = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid)
            .expect_err("foreign readonly fork must refuse");
        assert!(matches!(err, ReconcileError::NoKeyShadow));
        // No destructive side-effects on refusal.
        assert!(vol_dir.join("volume.readonly").exists());
    }

    #[test]
    fn reconcile_writes_stopped_marker_when_only_missing_part() {
        // Volume.key is present (operator manually placed it, or this
        // is an in-flight reconcile); only the stopped marker is missing.
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(false);
        std::fs::write(
            vol_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            [0u8; 32],
        )
        .unwrap();
        let out = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid).unwrap();
        assert_eq!(out, ReconcileOutcome::Reconciled);
        assert!(vol_dir.join(STOPPED_FILE).exists());
    }

    #[test]
    fn reconcile_refuses_when_daemon_running() {
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(false);
        std::fs::write(
            vol_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            [0u8; 32],
        )
        .unwrap();
        // A live pid in volume.pid is the canonical "daemon is running"
        // signal — see `VolumeLifecycle::from_dir`.
        std::fs::write(vol_dir.join(PID_FILE), std::process::id().to_string()).unwrap();
        let err = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid)
            .expect_err("running daemon must refuse");
        assert!(matches!(err, ReconcileError::DaemonRunning));
    }

    #[test]
    fn reconcile_ignores_stale_control_sock() {
        // Regression for the second site in #432: a stale control.sock
        // left behind by a `process::exit` shutdown (or a crash) must
        // not be misread as "daemon running". Without a live pid the
        // fork is parked and reconcile must proceed.
        let (_tmp, data_dir, vol_dir, vol_ulid) = reconcile_scaffolding(false);
        std::fs::write(
            vol_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            [0u8; 32],
        )
        .unwrap();
        std::fs::write(vol_dir.join("control.sock"), "").unwrap();
        // Also plant volume.released — this is the exact shape hit by
        // `stop` → `release` → `claim` on the live VM.
        std::fs::write(vol_dir.join(RELEASED_FILE), ulid::Ulid::new().to_string()).unwrap();
        let out = reconcile_owned_local_to_stopped(&vol_dir, &data_dir, vol_ulid)
            .expect("stale socket alone must not block reconcile");
        assert_eq!(out, ReconcileOutcome::Reconciled);
    }
}
