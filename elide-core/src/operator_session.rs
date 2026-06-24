//! The per-user operator-identity store at `~/.config/elide`, written by
//! `elide login` and read by `elide coord enroll`.
//!
//! In the shared-key demo (`docs/design-auth-service.md` § *Proposed:
//! distributed demo — shared K_M-A*) the only artifact is the operator
//! `subject` that enrollment stamps into the `sub` caveat of the discharges
//! it self-issues; the shared `K_M-A` itself comes from `coordinator.toml
//! [auth.demo]`, not from here. A standalone auth service will later add a
//! `session` bearer + transport alongside it.

use std::io;
use std::path::{Path, PathBuf};

const SUBJECT_FILE: &str = "subject";

/// The config directory: `$XDG_CONFIG_HOME/elide`, else `$HOME/.config/elide`.
pub fn config_dir() -> io::Result<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => Ok(PathBuf::from(x).join("elide")),
        _ => match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => Ok(PathBuf::from(h).join(".config").join("elide")),
            _ => Err(io::Error::other(
                "no config home — set HOME or XDG_CONFIG_HOME",
            )),
        },
    }
}

/// Record the logged-in operator `subject`, creating `~/.config/elide` if
/// needed. Overwrites any prior subject — one login per machine.
pub fn save_subject(subject: &str) -> io::Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(SUBJECT_FILE);
    std::fs::write(&path, subject.trim().as_bytes())?;
    set_0600(&path)
}

/// The logged-in operator subject, or a clear "not logged in" error.
pub fn load_subject() -> io::Result<String> {
    let path = config_dir()?.join(SUBJECT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().to_owned()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(io::Error::other(
            "not logged in (run `elide login --subject <operator>`)",
        )),
        Err(e) => Err(e),
    }
}

/// Clear the stored subject. Returns whether one was present (idempotent).
pub fn clear() -> io::Result<bool> {
    let path = config_dir()?.join(SUBJECT_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn set_0600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_0600(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The env is process-global; serialise the env-mutating tests.
    static ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn save_load_clear_round_trip() {
        let _g = ENV.lock().expect("lock");
        let tmp = tempfile::tempdir().expect("tempdir");
        // SAFETY: guarded by ENV; no other thread reads the env here.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };

        assert!(load_subject().is_err(), "absent → not logged in");
        save_subject("  01OPERATOR  ").expect("save");
        assert_eq!(load_subject().expect("load"), "01OPERATOR");
        assert!(clear().expect("clear"), "present on first clear");
        assert!(!clear().expect("clear"), "absent on second clear");
        assert!(load_subject().is_err(), "cleared → not logged in");

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }
}
