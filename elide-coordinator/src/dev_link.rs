//! `/dev/elide/<name>` device links.
//!
//! A served named volume is reachable at `/dev/elide/<name>`, a symlink to
//! its kernel block device `/dev/ublkb<N>`. The link is an invariant of
//! serving: the volume daemon publishes it before the device goes live and
//! fails the serve if it cannot, so tooling may rely on the path
//! unconditionally. See `docs/design/ublk-transport.md`.
//!
//! The name registry is the link itself plus the kernel `target_data`
//! ownership stamp on its target device: a link counts as *held* only while
//! its target device is live and the stamped volume still claims the link's
//! name in its `volume.toml`. Everything else — dangling target, our own
//! stamp, a renumbered device whose volume claims a different name — is
//! replaceable.
//!
//! All functions take the filesystem roots and the two attribution readers
//! as parameters, so the decision logic is testable without a kernel.

use std::io;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

/// Where the links and the kernel block-device nodes live. Production is
/// [`LinkPaths::system`]; tests point both roots at temp directories.
pub struct LinkPaths<'a> {
    pub base: &'a Path,
    pub dev_root: &'a Path,
}

impl LinkPaths<'static> {
    pub fn system() -> Self {
        Self {
            base: Path::new("/dev/elide"),
            dev_root: Path::new("/dev"),
        }
    }
}

impl LinkPaths<'_> {
    fn link(&self, name: &str) -> io::Result<PathBuf> {
        validate_link_name(name)?;
        Ok(self.base.join(name))
    }

    fn dev_node(&self, id: i32) -> PathBuf {
        self.dev_root.join(format!("ublkb{id}"))
    }

    /// The device id a link target refers to, if the target is a
    /// `ublkb<N>` node under `dev_root`.
    fn parse_id(&self, target: &Path) -> Option<i32> {
        if target.parent() != Some(self.dev_root) {
            return None;
        }
        target
            .file_name()?
            .to_str()?
            .strip_prefix("ublkb")?
            .parse()
            .ok()
    }
}

/// Volume names are validated at creation (`validate_volume_name`), but the
/// link path is where a hostile component would do damage, so re-check at
/// the boundary.
fn validate_link_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::other(format!(
            "volume name {name:?} is not usable as a /dev/elide link component"
        )));
    }
    Ok(())
}

/// What currently sits at `base/<name>`.
enum Existing {
    /// No link, a dangling link, our own device, or a renumbered device
    /// whose volume no longer claims this name — free to (re)create.
    Replaceable,
    /// A live device stamped by a different volume that still claims this
    /// name: a genuine per-host name collision.
    Held { holder: PathBuf },
    /// The path exists but is not an elide artefact (not a symlink, or a
    /// symlink outside `dev_root`) — refuse to touch it.
    Unrecognised { target: Option<PathBuf> },
}

fn classify(
    paths: &LinkPaths<'_>,
    name: &str,
    our_vol_dir: &Path,
    read_owner: impl Fn(i32) -> Option<PathBuf>,
    read_name: impl Fn(&Path) -> Option<String>,
) -> io::Result<Existing> {
    let link = paths.link(name)?;
    let target = match std::fs::read_link(&link) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Existing::Replaceable),
        // Exists but is not a symlink (EINVAL): not ours to replace.
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
            return Ok(Existing::Unrecognised { target: None });
        }
        Err(e) => return Err(e),
    };
    let Some(id) = paths.parse_id(&target) else {
        return Ok(Existing::Unrecognised {
            target: Some(target),
        });
    };
    if !target.exists() {
        return Ok(Existing::Replaceable);
    }
    let Some(holder) = read_owner(id) else {
        // Live device with no readable ownership stamp: nothing claims the
        // name through it.
        return Ok(Existing::Replaceable);
    };
    if holder == our_vol_dir {
        return Ok(Existing::Replaceable);
    }
    // The holder's claim to the name is its volume.toml, not the link: a
    // reboot can hand our old device id to another volume, leaving this
    // link pointing at a live foreign device that never asked for the name.
    if read_name(&holder).as_deref() == Some(name) {
        Ok(Existing::Held { holder })
    } else {
        Ok(Existing::Replaceable)
    }
}

fn refuse(name: &str, existing: Existing) -> io::Result<()> {
    match existing {
        Existing::Replaceable => Ok(()),
        Existing::Held { holder } => Err(io::Error::other(format!(
            "volume name {name:?} is already served on this host by the volume at {}",
            holder.display()
        ))),
        Existing::Unrecognised { target } => Err(io::Error::other(match target {
            Some(t) => format!(
                "/dev/elide link for {name:?} points outside the device root ({}); refusing to replace it",
                t.display()
            ),
            None => format!("/dev/elide path for {name:?} exists and is not a symlink"),
        })),
    }
}

/// Fail-fast check before `ADD_DEV`: the link directory is writable and the
/// name is not held by another volume. Failing here leaves no kernel device
/// behind.
pub fn preflight(
    paths: &LinkPaths<'_>,
    name: &str,
    our_vol_dir: &Path,
    read_owner: impl Fn(i32) -> Option<PathBuf>,
    read_name: impl Fn(&Path) -> Option<String>,
) -> io::Result<()> {
    std::fs::create_dir_all(paths.base)?;
    refuse(
        name,
        classify(paths, name, our_vol_dir, read_owner, read_name)?,
    )
}

/// Point `base/<name>` at `dev_root/ublkb<id>`, atomically (symlink at a
/// temp path, rename over). Refuses a held or unrecognised existing link.
pub fn publish(
    paths: &LinkPaths<'_>,
    name: &str,
    id: i32,
    our_vol_dir: &Path,
    read_owner: impl Fn(i32) -> Option<PathBuf>,
    read_name: impl Fn(&Path) -> Option<String>,
) -> io::Result<()> {
    std::fs::create_dir_all(paths.base)?;
    refuse(
        name,
        classify(paths, name, our_vol_dir, read_owner, read_name)?,
    )?;
    let link = paths.link(name)?;
    let tmp = paths
        .base
        .join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(paths.dev_node(id), &tmp)?;
    std::fs::rename(&tmp, &link).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// Remove `base/<name>` iff it points at `dev_root/ublkb<id>` — a link
/// since claimed by another device is left alone. Returns whether a link
/// was removed; a missing link is `Ok(false)`.
pub fn retract(paths: &LinkPaths<'_>, name: &str, id: i32) -> io::Result<bool> {
    let link = paths.link(name)?;
    match std::fs::read_link(&link) {
        Ok(target) if target == paths.dev_node(id) => {
            std::fs::remove_file(&link)?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(false),
        Err(e) => Err(e),
    }
}

/// [`retract`] keyed by the volume directory: reads the volume's name from
/// its `volume.toml`. Best-effort — device teardown must not fail on link
/// cleanup; the sweep collects anything missed.
pub fn retract_for_volume(paths: &LinkPaths<'_>, vol_dir: &Path, id: i32) {
    let Some(name) = read_config_name(vol_dir) else {
        return;
    };
    match retract(paths, &name, id) {
        Ok(true) => info!("[dev-link] removed {}/{name}", paths.base.display()),
        Ok(false) => {}
        Err(e) => warn!("[dev-link] removing {}/{name}: {e}", paths.base.display()),
    }
}

/// Drop links this coordinator can prove stale: dangling targets, and links
/// to devices stamped with a volume directory under `by_id_root` whose
/// `volume.toml` name no longer matches the link. Links attributable to
/// other coordinators (or to nothing) are left for their owners.
pub fn sweep(
    paths: &LinkPaths<'_>,
    by_id_root: &Path,
    read_owner: impl Fn(i32) -> Option<PathBuf>,
    read_name: impl Fn(&Path) -> Option<String>,
) {
    let entries = match std::fs::read_dir(paths.base) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!("[dev-link] reading {}: {e}", paths.base.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let link = entry.path();
        let Ok(target) = std::fs::read_link(&link) else {
            continue;
        };
        let stale = if !target.exists() {
            true
        } else {
            match paths.parse_id(&target).and_then(&read_owner) {
                Some(vol_dir) if vol_dir.parent() == Some(by_id_root) => {
                    read_name(&vol_dir).as_deref() != link.file_name().and_then(|n| n.to_str())
                }
                _ => false,
            }
        };
        if stale {
            match std::fs::remove_file(&link) {
                Ok(()) => info!("[dev-link] swept stale link {}", link.display()),
                Err(e) => warn!("[dev-link] sweeping {}: {e}", link.display()),
            }
        }
    }
}

/// The name a volume directory claims, per its `volume.toml`.
pub fn read_config_name(vol_dir: &Path) -> Option<String> {
    elide_core::config::VolumeConfig::read(vol_dir)
        .ok()
        .and_then(|c| c.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fixture {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        dev_root: PathBuf,
        by_id: PathBuf,
        owners: HashMap<i32, PathBuf>,
        names: HashMap<PathBuf, String>,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let base = tmp.path().join("elide");
            let dev_root = tmp.path().join("dev");
            let by_id = tmp.path().join("by_id");
            std::fs::create_dir_all(&dev_root).expect("dev root");
            std::fs::create_dir_all(&by_id).expect("by_id root");
            Self {
                _tmp: tmp,
                base,
                dev_root,
                by_id,
                owners: HashMap::new(),
                names: HashMap::new(),
            }
        }

        fn paths(&self) -> LinkPaths<'_> {
            LinkPaths {
                base: &self.base,
                dev_root: &self.dev_root,
            }
        }

        /// A "live kernel device" is a plain file at dev_root/ublkb<id>,
        /// stamped as owned by the volume dir `by_id/<ulid>` claiming `name`.
        fn add_device(&mut self, id: i32, ulid: &str, name: &str) -> PathBuf {
            std::fs::write(self.dev_root.join(format!("ublkb{id}")), b"").expect("device node");
            let vol_dir = self.by_id.join(ulid);
            self.owners.insert(id, vol_dir.clone());
            self.names.insert(vol_dir.clone(), name.to_owned());
            vol_dir
        }

        fn read_owner(&self) -> impl Fn(i32) -> Option<PathBuf> + '_ {
            |id| self.owners.get(&id).cloned()
        }

        fn read_name(&self) -> impl Fn(&Path) -> Option<String> + '_ {
            |dir| self.names.get(dir).cloned()
        }

        fn publish(&self, name: &str, id: i32, our_vol_dir: &Path) -> io::Result<()> {
            publish(
                &self.paths(),
                name,
                id,
                our_vol_dir,
                self.read_owner(),
                self.read_name(),
            )
        }

        fn link_target(&self, name: &str) -> Option<PathBuf> {
            std::fs::read_link(self.base.join(name)).ok()
        }
    }

    #[test]
    fn publish_creates_link_when_absent() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(0, "01VOL", "vol1");
        fx.publish("vol1", 0, &ours).expect("publish");
        assert_eq!(
            fx.link_target("vol1"),
            Some(fx.dev_root.join("ublkb0")),
            "link points at the device node"
        );
    }

    #[test]
    fn publish_replaces_dangling_link() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(3, "01VOL", "vol1");
        std::fs::create_dir_all(&fx.base).expect("base");
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb9"), fx.base.join("vol1"))
            .expect("dangling link");
        fx.publish("vol1", 3, &ours).expect("publish");
        assert_eq!(fx.link_target("vol1"), Some(fx.dev_root.join("ublkb3")));
    }

    #[test]
    fn publish_refreshes_own_link_to_new_id() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(0, "01VOL", "vol1");
        fx.publish("vol1", 0, &ours).expect("first publish");
        // Same volume relocated to a fresh id; the old node is still live.
        fx.owners.insert(7, ours.clone());
        std::fs::write(fx.dev_root.join("ublkb7"), b"").expect("new node");
        fx.publish("vol1", 7, &ours).expect("refresh");
        assert_eq!(fx.link_target("vol1"), Some(fx.dev_root.join("ublkb7")));
    }

    #[test]
    fn publish_fails_on_held_name_and_names_the_holder() {
        let mut fx = Fixture::new();
        let theirs = fx.add_device(0, "01THEIRS", "vol1");
        let ours = fx.add_device(1, "01OURS", "vol1");
        fx.publish("vol1", 0, &theirs).expect("holder publish");
        let err = fx.publish("vol1", 1, &ours).expect_err("collision");
        assert!(
            err.to_string().contains("01THEIRS"),
            "error names the holder: {err}"
        );
        assert_eq!(
            fx.link_target("vol1"),
            Some(fx.dev_root.join("ublkb0")),
            "holder's link is untouched"
        );
    }

    #[test]
    fn publish_replaces_link_to_renumbered_foreign_device() {
        let mut fx = Fixture::new();
        // A reboot handed device 0 to a volume that claims a different
        // name; our stale link still points at it.
        let foreign = fx.add_device(0, "01FOREIGN", "other");
        let ours = fx.add_device(1, "01OURS", "vol1");
        fx.publish("other", 0, &foreign).expect("foreign publish");
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb0"), fx.base.join("vol1"))
            .expect("stale link");
        fx.publish("vol1", 1, &ours)
            .expect("stale link is replaceable");
        assert_eq!(fx.link_target("vol1"), Some(fx.dev_root.join("ublkb1")));
    }

    #[test]
    fn publish_replaces_link_to_unstamped_device() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(1, "01OURS", "vol1");
        // Live node with no ownership stamp: nothing claims the name.
        std::fs::write(fx.dev_root.join("ublkb0"), b"").expect("bare node");
        std::fs::create_dir_all(&fx.base).expect("base");
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb0"), fx.base.join("vol1")).expect("link");
        fx.publish("vol1", 1, &ours).expect("publish");
        assert_eq!(fx.link_target("vol1"), Some(fx.dev_root.join("ublkb1")));
    }

    #[test]
    fn publish_refuses_foreign_artefacts() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(1, "01OURS", "vol1");
        std::fs::create_dir_all(&fx.base).expect("base");
        std::os::unix::fs::symlink("/somewhere/else", fx.base.join("vol1")).expect("odd link");
        fx.publish("vol1", 1, &ours)
            .expect_err("non-device-root target is not ours to replace");

        std::fs::write(fx.base.join("vol2"), b"not a link").expect("plain file");
        fx.publish("vol2", 1, &ours)
            .expect_err("non-symlink is not ours to replace");
    }

    #[test]
    fn publish_rejects_unsafe_names() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(0, "01VOL", "vol1");
        for bad in [".", "..", "a/b", ""] {
            fx.publish(bad, 0, &ours).expect_err(bad);
        }
    }

    #[test]
    fn retract_removes_only_matching_target() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(0, "01VOL", "vol1");
        fx.publish("vol1", 0, &ours).expect("publish");
        assert!(!retract(&fx.paths(), "vol1", 9).expect("mismatched id"));
        assert!(fx.link_target("vol1").is_some(), "link survives mismatch");
        assert!(retract(&fx.paths(), "vol1", 0).expect("matching id"));
        assert!(fx.link_target("vol1").is_none());
        assert!(!retract(&fx.paths(), "vol1", 0).expect("already gone"));
    }

    #[test]
    fn sweep_drops_dangling_and_renamed_keeps_live_and_foreign() {
        let mut fx = Fixture::new();
        let ours = fx.add_device(0, "01OURS", "vol1");
        fx.publish("vol1", 0, &ours).expect("publish good");

        // Dangling: device node gone.
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb9"), fx.base.join("gone"))
            .expect("dangling");

        // Renamed: our volume at id 2 claims "renamed", link says "old".
        let renamed = fx.add_device(2, "01RENAMED", "renamed");
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb2"), fx.base.join("old"))
            .expect("old-name link");
        assert_eq!(fx.names.get(&renamed).map(String::as_str), Some("renamed"));

        // Foreign: a live device stamped with a volume dir outside by_id.
        std::fs::write(fx.dev_root.join("ublkb5"), b"").expect("node");
        fx.owners.insert(5, PathBuf::from("/other/coord/by_id/01X"));
        std::os::unix::fs::symlink(fx.dev_root.join("ublkb5"), fx.base.join("theirs"))
            .expect("foreign link");

        sweep(&fx.paths(), &fx.by_id, fx.read_owner(), fx.read_name());

        assert!(fx.link_target("vol1").is_some(), "live link kept");
        assert!(fx.link_target("gone").is_none(), "dangling swept");
        assert!(fx.link_target("old").is_none(), "renamed swept");
        assert!(fx.link_target("theirs").is_some(), "foreign kept");
    }
}
