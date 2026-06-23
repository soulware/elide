//! Pidfile handling for the coordinator.
//!
//! Two distinct concerns live here:
//!
//! - [`PidFileGuard`] — a remove-on-drop guard for coordinator-spawned
//!   *subprocesses* (`import`, `fetch`). `Drop` removes the file on every exit
//!   path including panic, so a stale pidfile never outlives the worker it
//!   names. Intentionally minimal: it owns the file's lifecycle, nothing else.
//!
//! - [`lock_instance`] — the coordinator's own single-instance guard, an
//!   exclusive `flock` held for the process lifetime.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};

/// Coordinator-process pidfile. Lives at `<data_dir>/coordinator.pid` so a
/// second `elide coord start` for the same data directory is refused and
/// `elide coord stop` can fall back to PID-based liveness if the IPC reply
/// never arrives.
pub const COORDINATOR_PID_FILE: &str = "coordinator.pid";

/// Acquire the coordinator's single-instance lock for `data_dir`.
///
/// Holds an exclusive advisory `flock` on `<data_dir>/coordinator.pid` for the
/// returned guard's lifetime. The kernel releases an flock when the holder
/// exits by any means — clean shutdown, panic, `kill -9`, or a host reboot —
/// so the lock can never go stale. That is why the coordinator locks rather
/// than checking pid liveness: its data dir is often a durable volume that
/// survives reboots, and pids are recycled across a reboot, so a
/// recorded-but-dead pid reads as "alive" and would falsely block startup.
///
/// The pid written into the file is informational; the lock — not the file's
/// contents — is the guard, so the file is never removed (a stable inode keeps
/// the lock reliable across restarts). Returns [`io::ErrorKind::AlreadyExists`]
/// when another live coordinator already holds the lock.
pub fn lock_instance(data_dir: &Path) -> io::Result<Flock<File>> {
    let path = data_dir.join(COORDINATOR_PID_FILE);
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    let mut lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
        let held_by = std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default();
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "another coordinator is already serving {}{held_by}: {errno}",
                data_dir.display()
            ),
        )
    })?;
    // Record our pid for humans and tooling, now that the lock is held — so a
    // failed acquisition never truncates the live holder's pidfile.
    {
        use std::io::{Seek, Write};
        let _ = lock.set_len(0);
        let _ = lock.rewind();
        let _ = lock.write_all(std::process::id().to_string().as_bytes());
        let _ = lock.flush();
    }
    Ok(lock)
}

#[derive(Debug)]
pub struct PidFileGuard {
    path: PathBuf,
}

impl PidFileGuard {
    pub fn write(path: PathBuf, pid: u32) -> io::Result<Self> {
        std::fs::write(&path, pid.to_string())?;
        Ok(Self { path })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_creates_file_with_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.pid");
        let _guard = PidFileGuard::write(path.clone(), 4242).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "4242");
    }

    #[test]
    fn drop_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.pid");
        {
            let _guard = PidFileGuard::write(path.clone(), 1).unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    #[test]
    fn drop_tolerates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.pid");
        let guard = PidFileGuard::write(path.clone(), 1).unwrap();
        std::fs::remove_file(&path).unwrap();
        drop(guard);
    }

    #[test]
    fn write_propagates_io_error() {
        let path = PathBuf::from("/definitely/does/not/exist/worker.pid");
        let err = PidFileGuard::write(path, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn instance_lock_is_exclusive_and_reacquirable_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join(COORDINATOR_PID_FILE);

        // First holder acquires and records its pid.
        let held = lock_instance(dir.path()).expect("first acquire");
        assert_eq!(
            std::fs::read_to_string(&pid_path).unwrap(),
            std::process::id().to_string()
        );

        // A second acquire fails while the first is held (flock conflicts
        // across separate open descriptions, even within one process).
        let err = lock_instance(dir.path()).expect_err("second must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // Releasing — as the kernel does on crash / kill / reboot — lets the
        // next start re-acquire with no stale block, though the file remains.
        drop(held);
        assert!(pid_path.exists());
        let _relock = lock_instance(dir.path()).expect("re-acquire after release");
    }
}
