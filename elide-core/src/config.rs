use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub const CONFIG_FILE: &str = "volume.toml";

/// Consolidated per-volume configuration stored in `volume.toml`.
///
/// Files that remain separate:
/// - `volume.key` / `volume.pub` / `volume.provenance` — signing key material
/// - `volume.lock` — advisory lock (flock on a standalone fd)
/// - `volume.readonly` — safety marker written early during import
/// - `control.sock` — runtime Unix socket
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct VolumeConfig {
    /// The volume's ULID. Advisory self-description: the `by_id/<ulid>`
    /// directory name is authoritative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulid: Option<Ulid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ublk: Option<UblkConfig>,
    /// Opt out of background full-volume warming on writable start.
    /// `Some(true)` keeps the volume on demand-fetch only; default (None /
    /// false) eagerly warms every live extent from S3 in the background.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy: Option<bool>,
    /// The guest filesystem's journal window (`[journal]`). Absent =
    /// never derived: derivation is re-attempted at open and at every
    /// promote take, so a filesystem formatted mid-session gains
    /// awareness without a reopen. Present = an authoritative parse
    /// answered, including "no internal journal" (empty `ranges`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<JournalConfig>,
}

/// The derived journal window within `volume.toml` (`[journal]`).
///
/// Consulted by the extent index's canonical-ownership rule before the
/// filesystem is parseable.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct JournalConfig {
    /// LBA ranges of the journal (for ext4, inode 8's extents). Empty
    /// means the filesystem has no internal journal.
    pub ranges: crate::journal::JournalRanges,
    /// First segment ULID minted after a mid-session flip of the
    /// window. While present, journal classification applies the
    /// window only to segments at or above this ULID, so rebuilds
    /// during the flip session reproduce the live stamps. The next
    /// open reclassifies uniformly and clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ulid::Ulid>,
}

/// ublk server configuration within `volume.toml`.
///
/// The presence of the `[ublk]` section means "serve this volume over ublk".
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UblkConfig {
    /// Bound ublk device id (maps to `/dev/ublkb<id>`).
    ///
    /// Carries two related meanings:
    ///   * Before the first ADD: user-supplied pin. `None` means "kernel
    ///     auto-allocates on first start".
    ///   * After a successful ADD: the kernel-assigned id, written back so
    ///     the next serve recognises and recovers the QUIESCED device.
    ///
    /// Authoritative ownership lives in the kernel device's `target_data`
    /// stamp; this field is the local hint for which id to look at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_id: Option<i32>,
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

    /// The stored journal window as a [`crate::journal::JournalWindow`],
    /// including any live-flip activation marker. Never-derived reads
    /// as the empty window.
    pub fn journal_window(&self) -> crate::journal::JournalWindow {
        match &self.journal {
            Some(j) => crate::journal::JournalWindow {
                ranges: j.ranges.clone(),
                activation: j.activation,
            },
            None => crate::journal::JournalWindow::default(),
        }
    }

    /// Read the bound ublk device id, if any.
    ///
    /// `None` means either no ublk transport (no `[ublk]` section) or
    /// `[ublk]` exists but no id has been bound yet (auto-allocate on
    /// next ADD). Callers that need to distinguish the two cases must
    /// inspect `cfg.ublk` directly.
    pub fn bound_ublk_id(dir: &Path) -> io::Result<Option<i32>> {
        Ok(Self::read(dir)?.ublk.and_then(|u| u.dev_id))
    }

    /// Persist the kernel-assigned ublk device id into `volume.toml`.
    ///
    /// Called from the ublk daemon's `wait_hook` once the kernel commits
    /// to an id. Read-modify-write so unrelated config (size, name) is
    /// preserved. Idempotent: rewriting the same id is a no-op on disk
    /// if the file content is unchanged.
    pub fn set_bound_ublk_id(dir: &Path, id: i32) -> io::Result<()> {
        let mut cfg = Self::read(dir)?;
        let ublk = cfg.ublk.get_or_insert_with(Default::default);
        ublk.dev_id = Some(id);
        cfg.write(dir)
    }

    /// Clear the bound ublk device id while preserving the `[ublk]`
    /// section. Used by `elide ublk delete` and the coordinator's
    /// reconciliation sweep: the operator removed the binding but did
    /// not change transport policy, so the next serve auto-allocates.
    ///
    /// No-op (no write) if there is no `[ublk]` section or the id is
    /// already absent.
    pub fn clear_bound_ublk_id(dir: &Path) -> io::Result<()> {
        let mut cfg = Self::read(dir)?;
        let Some(ublk) = cfg.ublk.as_mut() else {
            return Ok(());
        };
        if ublk.dev_id.is_none() {
            return Ok(());
        }
        ublk.dev_id = None;
        cfg.write(dir)
    }

    /// Persist `name` into `volume.toml`, preserving unrelated config
    /// (size, ublk, lazy). Read-modify-write. Idempotent: rewriting the
    /// same name leaves the file content unchanged.
    pub fn set_name(dir: &Path, name: &str) -> io::Result<()> {
        let mut cfg = Self::read(dir)?;
        cfg.name = Some(name.to_owned());
        cfg.write(dir)
    }

    /// Remove the `[ublk]` transport section from `volume.toml`. After this
    /// the volume carries no configured transport.
    ///
    /// No-op (no write) when there is no `[ublk]` section.
    pub fn clear_ublk_transport(dir: &Path) -> io::Result<()> {
        let mut cfg = Self::read(dir)?;
        if cfg.ublk.is_none() {
            return Ok(());
        }
        cfg.ublk = None;
        cfg.write(dir)
    }
}

/// Details of a ublk dev-id conflict.
pub struct UblkConflict {
    pub dev_id: i32,
    /// Human-readable name of the conflicting volume.
    pub name: String,
    pub dir: PathBuf,
}

/// Check whether `vol_dir`'s ublk dev-id collides with another active volume.
///
/// Only volumes that pin an explicit `dev_id` participate — auto-allocated
/// devices (no `dev_id` in `[ublk]`) are resolved by the kernel at start time
/// and cannot conflict ahead of spawn.
///
/// Returns `Ok(Some(conflict))` on conflict, `Ok(None)` otherwise.
pub fn find_ublk_conflict(vol_dir: &Path, data_dir: &Path) -> io::Result<Option<UblkConflict>> {
    let cfg = VolumeConfig::read(vol_dir)?;
    let dev_id = match cfg.ublk.as_ref().and_then(|u| u.dev_id) {
        Some(id) => id,
        None => return Ok(None),
    };

    let canonical = std::fs::canonicalize(vol_dir)?;

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
        if let Ok(other_canon) = std::fs::canonicalize(&other)
            && other_canon == canonical
        {
            continue;
        }
        if other.join("volume.stopped").exists() || other.join("volume.readonly").exists() {
            continue;
        }
        let other_cfg = match VolumeConfig::read(&other) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(other_ublk) = other_cfg.ublk.as_ref()
            && other_ublk.dev_id == Some(dev_id)
        {
            let name = other_cfg.name.unwrap_or_else(|| {
                other
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            return Ok(Some(UblkConflict {
                dev_id,
                name,
                dir: other,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_config(dir: &Path, contents: &str) {
        std::fs::write(dir.join(CONFIG_FILE), contents).unwrap();
    }

    #[test]
    fn ublk_section_with_no_keys_parses_as_enabled() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "[ublk]\n");
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        let ublk = cfg.ublk.expect("ublk section should be present");
        assert_eq!(ublk.dev_id, None);
    }

    #[test]
    fn toml_without_journal_section_parses_never_derived() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "size = 1024\n");
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(cfg.journal, None);
    }

    #[test]
    fn journal_ranges_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = VolumeConfig::read(tmp.path()).unwrap();
        cfg.journal = Some(JournalConfig {
            ranges: crate::journal::JournalRanges::new(vec![(100, 16), (300, 4)]),
            activation: None,
        });
        cfg.write(tmp.path()).unwrap();
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(
            cfg.journal.unwrap().ranges.as_slice(),
            &[(100, 16), (300, 4)]
        );
    }

    #[test]
    fn journal_derived_empty_roundtrips_distinct_from_never_derived() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = VolumeConfig::read(tmp.path()).unwrap();
        cfg.journal = Some(JournalConfig::default());
        cfg.write(tmp.path()).unwrap();
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(cfg.journal, Some(JournalConfig::default()));
    }

    #[test]
    fn journal_activation_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = VolumeConfig::read(tmp.path()).unwrap();
        let activation = ulid::Ulid::from_parts(1234, 42);
        cfg.journal = Some(JournalConfig {
            ranges: crate::journal::JournalRanges::new(vec![(100, 16)]),
            activation: Some(activation),
        });
        cfg.write(tmp.path()).unwrap();
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(cfg.journal.unwrap().activation, Some(activation));
    }

    #[test]
    fn ublk_dev_id_roundtrips() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "[ublk]\ndev_id = 7\n");
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(cfg.ublk.unwrap().dev_id, Some(7));
    }

    #[test]
    fn bound_ublk_id_returns_none_when_no_section() {
        let tmp = TempDir::new().unwrap();
        // No volume.toml at all.
        assert_eq!(VolumeConfig::bound_ublk_id(tmp.path()).unwrap(), None);
        // Empty volume.toml.
        write_config(tmp.path(), "");
        assert_eq!(VolumeConfig::bound_ublk_id(tmp.path()).unwrap(), None);
        // [ublk] enabled but no id bound yet.
        write_config(tmp.path(), "[ublk]\n");
        assert_eq!(VolumeConfig::bound_ublk_id(tmp.path()).unwrap(), None);
    }

    #[test]
    fn ulid_roundtrips_as_canonical_string() {
        let tmp = TempDir::new().unwrap();
        let ulid = Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        VolumeConfig {
            ulid: Some(ulid),
            ..Default::default()
        }
        .write(tmp.path())
        .unwrap();

        let raw = std::fs::read_to_string(tmp.path().join(CONFIG_FILE)).unwrap();
        assert!(raw.contains("ulid = \"01JQAAAAAAAAAAAAAAAAAAAAAA\""));
        assert_eq!(VolumeConfig::read(tmp.path()).unwrap().ulid, Some(ulid));
    }

    #[test]
    fn set_bound_ublk_id_creates_section_and_preserves_other_fields() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "name = \"alpha\"\nsize = 1024\n");
        VolumeConfig::set_bound_ublk_id(tmp.path(), 5).unwrap();

        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert_eq!(cfg.name.as_deref(), Some("alpha"));
        assert_eq!(cfg.size, Some(1024));
        assert_eq!(cfg.ublk.unwrap().dev_id, Some(5));
    }

    #[test]
    fn set_bound_ublk_id_overwrites_existing_id() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "[ublk]\ndev_id = 3\n");
        VolumeConfig::set_bound_ublk_id(tmp.path(), 9).unwrap();
        assert_eq!(VolumeConfig::bound_ublk_id(tmp.path()).unwrap(), Some(9));
    }

    #[test]
    fn clear_bound_ublk_id_keeps_section_drops_id() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "[ublk]\ndev_id = 5\n");
        VolumeConfig::clear_bound_ublk_id(tmp.path()).unwrap();

        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        let ublk = cfg
            .ublk
            .expect("clearing the dev_id must not remove the [ublk] section");
        assert_eq!(ublk.dev_id, None);
    }

    #[test]
    fn clear_bound_ublk_id_is_noop_without_section() {
        let tmp = TempDir::new().unwrap();
        // Empty file: no [ublk] section means there's nothing to clear.
        write_config(tmp.path(), "name = \"alpha\"\n");
        VolumeConfig::clear_bound_ublk_id(tmp.path()).unwrap();
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert!(cfg.ublk.is_none());
        assert_eq!(cfg.name.as_deref(), Some("alpha"));
    }

    #[test]
    fn clear_ublk_transport_drops_section_preserving_other_fields() {
        let tmp = TempDir::new().unwrap();
        write_config(
            tmp.path(),
            "name = \"alpha\"\nsize = 1024\n[ublk]\ndev_id = 5\n",
        );
        VolumeConfig::clear_ublk_transport(tmp.path()).unwrap();

        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert!(cfg.ublk.is_none(), "the whole [ublk] section must be gone");
        assert_eq!(cfg.name.as_deref(), Some("alpha"));
        assert_eq!(cfg.size, Some(1024));
    }

    #[test]
    fn clear_ublk_transport_is_noop_without_section() {
        let tmp = TempDir::new().unwrap();
        write_config(tmp.path(), "name = \"alpha\"\n");
        VolumeConfig::clear_ublk_transport(tmp.path()).unwrap();
        let cfg = VolumeConfig::read(tmp.path()).unwrap();
        assert!(cfg.ublk.is_none());
        assert_eq!(cfg.name.as_deref(), Some("alpha"));
    }

    #[test]
    fn find_ublk_conflict_detects_dev_id_collision() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path();
        let by_id = data.join("by_id");
        std::fs::create_dir_all(&by_id).unwrap();

        let a = by_id.join("01J000000000000000000000A0");
        let b = by_id.join("01J000000000000000000000B0");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_config(&a, "name = \"alpha\"\n[ublk]\ndev_id = 3\n");
        write_config(&b, "name = \"beta\"\n[ublk]\ndev_id = 3\n");

        let conflict = find_ublk_conflict(&a, data).unwrap().expect("conflict");
        assert_eq!(conflict.dev_id, 3);
        assert_eq!(conflict.name, "beta");
    }

    #[test]
    fn find_ublk_conflict_ignores_auto_alloc() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path();
        let by_id = data.join("by_id");
        std::fs::create_dir_all(&by_id).unwrap();

        let a = by_id.join("01J000000000000000000000A0");
        let b = by_id.join("01J000000000000000000000B0");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_config(&a, "[ublk]\n");
        write_config(&b, "[ublk]\n");

        assert!(find_ublk_conflict(&a, data).unwrap().is_none());
    }

    #[test]
    fn find_ublk_conflict_skips_stopped_volume() {
        let tmp = TempDir::new().unwrap();
        let data = tmp.path();
        let by_id = data.join("by_id");
        std::fs::create_dir_all(&by_id).unwrap();

        let a = by_id.join("01J000000000000000000000A0");
        let b = by_id.join("01J000000000000000000000B0");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_config(&a, "[ublk]\ndev_id = 4\n");
        write_config(&b, "[ublk]\ndev_id = 4\n");
        std::fs::write(b.join("volume.stopped"), "").unwrap();

        assert!(find_ublk_conflict(&a, data).unwrap().is_none());
    }
}
