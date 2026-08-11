//! A panic off the main thread ends the volume process, and preserves
//! the volume's on-disk state on its way out.
//!
//! Unwinding takes the panicking thread and leaves the rest of the
//! process running: the ublk queue workers keep taking guest I/O and
//! complete each command with EIO, and the supervisor, which watches
//! for process exit, has nothing to report. Observed live as a volume
//! serving EIO for 83 seconds against a mounted ext4 (#938).
//!
//! The abort makes the state a panic names short-lived instead: the
//! supervisor restarts the volume within milliseconds and the restart
//! folds pending segments away. The freeze runs inside the hook, ahead
//! of both.
//!
//! The property is about the process, so the test runs one: it re-execs
//! this binary with `CHILD_ENV` set, panics on a spawned thread there,
//! and reads the child's wait status.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Set on the child, which makes it the child and gives it the volume
/// directory to freeze.
const VOLUME_DIR_ENV: &str = "ELIDE_PANIC_ABORT_VOLUME_DIR";
const TEST_NAME: &str = "a_panic_off_the_main_thread_ends_the_process";

#[test]
fn a_panic_off_the_main_thread_ends_the_process() {
    if let Some(dir) = std::env::var_os(VOLUME_DIR_ENV) {
        elide::serve::abort_on_panic(Path::new(&dir));
        let _ = std::thread::spawn(|| panic!("panic from a spawned thread")).join();
        // Reached only if the hook let the process carry on; the sleep
        // holds the child open long enough for the parent to read a
        // status that says so.
        std::thread::sleep(Duration::from_secs(5));
        return;
    }

    let tmp = tempfile::tempdir().expect("temp dir");
    let volume_dir = tmp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let freeze_root = tmp.path().join("freeze");
    std::fs::create_dir_all(volume_dir.join("index")).expect("index dir");
    std::fs::create_dir_all(volume_dir.join("wal")).expect("wal dir");
    std::fs::create_dir_all(&freeze_root).expect("freeze root");
    std::fs::write(volume_dir.join("index/seg.idx"), b"segment").expect("segment");
    std::fs::write(volume_dir.join("wal/log"), b"records").expect("wal");
    std::fs::write(volume_dir.join("volume.toml"), b"size = 1").expect("volume.toml");

    let exe = std::env::current_exe().expect("path of the running test binary");
    let child = Command::new(exe)
        .args(["--exact", TEST_NAME])
        .env(VOLUME_DIR_ENV, &volume_dir)
        .env("ELIDE_PANIC_FREEZE_DIR", &freeze_root)
        .output()
        .expect("re-exec this test binary");

    assert_eq!(
        child.status.signal(),
        Some(libc::SIGABRT),
        "child status was {:?}; stderr: {}",
        child.status,
        String::from_utf8_lossy(&child.stderr),
    );

    let frozen = std::fs::read_dir(&freeze_root)
        .expect("freeze root")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .next()
        .unwrap_or_else(|| {
            panic!(
                "no freeze under {}; child stderr: {}",
                freeze_root.display(),
                String::from_utf8_lossy(&child.stderr)
            )
        });

    assert_eq!(
        std::fs::read(frozen.join("index/seg.idx")).expect("frozen segment"),
        b"segment"
    );
    assert_eq!(
        std::fs::read(frozen.join("wal/log")).expect("frozen wal"),
        b"records"
    );
    assert_eq!(
        std::fs::read(frozen.join("volume.toml")).expect("frozen volume.toml"),
        b"size = 1"
    );
}

/// The WAL is appended to across a restart, so its freeze holds bytes of
/// its own rather than sharing the original's inode. A segment's freeze
/// shares, which is what survives the original's unlink.
#[test]
fn the_freeze_links_segments_and_copies_the_wal() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let volume_dir = tmp.path().join("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let freeze_root = tmp.path().join("freeze");
    std::fs::create_dir_all(volume_dir.join("index")).expect("index dir");
    std::fs::create_dir_all(volume_dir.join("wal")).expect("wal dir");
    std::fs::create_dir_all(&freeze_root).expect("freeze root");
    std::fs::write(volume_dir.join("index/seg.idx"), b"segment").expect("segment");
    std::fs::write(volume_dir.join("wal/log"), b"records").expect("wal");

    let frozen = elide::serve::freeze_volume_dir(&volume_dir, &freeze_root).expect("freeze");

    std::fs::remove_file(volume_dir.join("index/seg.idx")).expect("unlink segment");
    std::fs::write(volume_dir.join("wal/log"), b"records-and-more").expect("append wal");

    assert_eq!(
        std::fs::read(frozen.join("index/seg.idx")).expect("frozen segment"),
        b"segment"
    );
    assert_eq!(
        std::fs::read(frozen.join("wal/log")).expect("frozen wal"),
        b"records"
    );
}
