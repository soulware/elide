//! A panic off the main thread ends the volume process.
//!
//! Unwinding takes the panicking thread and leaves the rest of the
//! process running: the ublk queue workers keep taking guest I/O and
//! complete each command with EIO, and the supervisor, which watches
//! for process exit, has nothing to report. Observed live as a volume
//! serving EIO for 83 seconds against a mounted ext4 (#938).
//!
//! The property is about the process, so the test runs one: it re-execs
//! this binary with `CHILD_ENV` set, panics on a spawned thread there,
//! and reads the child's wait status.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::Duration;

const CHILD_ENV: &str = "ELIDE_PANIC_ABORT_CHILD";
const TEST_NAME: &str = "a_panic_off_the_main_thread_ends_the_process";

#[test]
fn a_panic_off_the_main_thread_ends_the_process() {
    if std::env::var_os(CHILD_ENV).is_some() {
        elide::serve::abort_on_panic();
        let _ = std::thread::spawn(|| panic!("panic from a spawned thread")).join();
        // Reached only if the hook let the process carry on; the sleep
        // holds the child open long enough for the parent to read a
        // status that says so.
        std::thread::sleep(Duration::from_secs(5));
        return;
    }

    let exe = std::env::current_exe().expect("path of the running test binary");
    let child = Command::new(exe)
        .args(["--exact", TEST_NAME])
        .env(CHILD_ENV, "1")
        .output()
        .expect("re-exec this test binary");

    assert_eq!(
        child.status.signal(),
        Some(libc::SIGABRT),
        "child status was {:?}; stderr: {}",
        child.status,
        String::from_utf8_lossy(&child.stderr),
    );
}
