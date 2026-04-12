use std::fmt;
use std::io;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "volume.toml";

/// Consolidated per-volume configuration stored in `volume.toml`.
///
/// Contains everything that was previously scattered across `volume.name`,
/// `volume.size`, `nbd.port`, `nbd.bind`, and `nbd.socket`.
///
/// Files that remain separate:
/// - `volume.key` / `volume.pub` / `volume.provenance` — signing key material
/// - `volume.lock` — advisory lock (flock on a standalone fd)
/// - `volume.readonly` — safety marker written early during import
/// - `control.sock` — runtime Unix socket
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VolumeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbd: Option<NbdConfig>,
}

/// NBD server configuration within `volume.toml`.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NbdConfig {
    /// IP address to bind on. Defaults to `127.0.0.1` if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// TCP port. Mutually exclusive with `socket`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Unix socket path. Mutually exclusive with `port`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
}

/// Resolved NBD endpoint for conflict detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NbdEndpoint {
    Tcp { bind: String, port: u16 },
    Socket(PathBuf),
}

impl fmt::Display for NbdEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { bind, port } => write!(f, "{bind}:{port}"),
            Self::Socket(path) => write!(f, "{}", path.display()),
        }
    }
}

impl NbdEndpoint {
    /// Probe whether something is already listening on this endpoint.
    ///
    /// For sockets: attempts a non-blocking `connect(2)`.
    /// For TCP: attempts a blocking connect to `bind:port`.
    ///
    /// Returns `true` if a connection succeeds (endpoint is in use).
    pub fn is_in_use(&self) -> bool {
        match self {
            Self::Socket(path) => UnixStream::connect(path).is_ok(),
            Self::Tcp { bind, port } => TcpStream::connect((bind.as_str(), *port)).is_ok(),
        }
    }
}

impl NbdConfig {
    /// Resolve this config to an endpoint, using the volume directory to
    /// absolutify relative socket paths.
    pub fn endpoint(&self, vol_dir: &Path) -> Option<NbdEndpoint> {
        if let Some(ref socket) = self.socket {
            let resolved = if socket.is_absolute() {
                socket.clone()
            } else {
                vol_dir.join(socket)
            };
            Some(NbdEndpoint::Socket(resolved))
        } else {
            let port = self.port?;
            let bind = self.bind.clone().unwrap_or_else(|| "127.0.0.1".to_owned());
            Some(NbdEndpoint::Tcp { bind, port })
        }
    }
}

impl VolumeConfig {
    /// Read `volume.toml` from `dir`. Returns an empty config if the file does
    /// not exist (e.g. volume predates the consolidated config).
    pub fn read(dir: &Path) -> io::Result<Self> {
        let path = dir.join(CONFIG_FILE);
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s)
                .map_err(|e| io::Error::other(format!("invalid {CONFIG_FILE}: {e}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write `volume.toml` to `dir` atomically (via temp-file rename).
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        let s = toml::to_string(self)
            .map_err(|e| io::Error::other(format!("serializing {CONFIG_FILE}: {e}")))?;
        crate::segment::write_file_atomic(&dir.join(CONFIG_FILE), s.as_bytes())
    }
}

/// Details of an NBD endpoint conflict.
pub struct NbdConflict {
    pub endpoint: NbdEndpoint,
    /// Human-readable name of the conflicting volume (falls back to ULID).
    pub name: String,
    /// Directory of the conflicting volume, if the conflict was found via
    /// config scan. `None` when detected by endpoint probe only.
    pub dir: Option<PathBuf>,
}

/// Check whether `vol_dir`'s NBD endpoint conflicts with another volume or
/// is already in use by something else.
///
/// Two checks are performed:
///   1. Config scan: walks `data_dir/by_id/` looking for another active
///      (non-stopped, non-readonly) volume with the same endpoint.
///   2. Probe: tries to connect to the endpoint to catch conflicts from
///      outside elide or stale state.
///
/// Returns `Ok(Some(conflict))` on conflict, `Ok(None)` if the endpoint is
/// free (or the volume has no NBD config).
pub fn find_nbd_conflict(vol_dir: &Path, data_dir: &Path) -> io::Result<Option<NbdConflict>> {
    let cfg = VolumeConfig::read(vol_dir)?;
    let endpoint = match cfg.nbd.as_ref().and_then(|nbd| nbd.endpoint(vol_dir)) {
        Some(ep) => ep,
        None => return Ok(None),
    };

    // Canonicalize vol_dir so we can skip it in the scan (vol_dir may be a
    // by_name/ symlink pointing into by_id/).
    let canonical = std::fs::canonicalize(vol_dir)?;

    // 1. Config scan: another elide volume claims the same endpoint.
    let by_id = data_dir.join("by_id");
    let entries = match std::fs::read_dir(&by_id) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    for entry in entries.flatten() {
        let other = entry.path();
        if !other.is_dir() {
            continue;
        }
        // Skip self.
        if let Ok(other_canon) = std::fs::canonicalize(&other)
            && other_canon == canonical
        {
            continue;
        }
        // Skip stopped / readonly volumes — they won't bind the endpoint.
        if other.join("volume.stopped").exists() || other.join("volume.readonly").exists() {
            continue;
        }
        let other_cfg = match VolumeConfig::read(&other) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(other_nbd) = other_cfg.nbd.as_ref()
            && let Some(other_ep) = other_nbd.endpoint(&other)
            && other_ep == endpoint
        {
            let name = other_cfg.name.unwrap_or_else(|| {
                other
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            return Ok(Some(NbdConflict {
                endpoint,
                name,
                dir: Some(other.clone()),
            }));
        }
    }

    // 2. Probe: something outside elide (or a volume whose config we missed)
    //    is already listening on the endpoint.
    if endpoint.is_in_use() {
        return Ok(Some(NbdConflict {
            endpoint,
            name: "unknown (endpoint already in use)".to_owned(),
            dir: None,
        }));
    }

    Ok(None)
}
