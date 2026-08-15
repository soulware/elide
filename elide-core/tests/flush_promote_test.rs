// Regression tests for the FLUSH / promote interaction (see
// `execute_promote` and the `VolumeRequest::Flush` handler).
//
// The worker fsyncs the old WAL as the first step of each promote,
// and `VolumeRequest::Flush` fsyncs the current WAL plus every
// rotated WAL the promote pipeline still owns, all on the actor
// thread.  These tests verify that contract: after `handle.flush()`
// returns, every prior write is durable, and promotes complete on
// the worker in their own time.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use elide_core::actor::spawn;
use elide_core::volume::Volume;

mod common;

fn open_actor(dir: &Path) -> (elide_core::actor::VolumeClient, thread::JoinHandle<()>) {
    common::write_test_keypair(dir);
    let vol = Volume::open(dir, dir).unwrap();
    let (actor, handle) = spawn(vol);
    let t = thread::spawn(move || actor.run());
    (handle, t)
}

fn incompressible_block(i: u64) -> Vec<u8> {
    let mut b = vec![0u8; 1024 * 1024];
    blake3::Hasher::new()
        .update(&i.to_le_bytes())
        .finalize_xof()
        .fill(&mut b);
    b
}

/// After writing enough to cross the 32 MiB threshold and then
/// issuing FLUSH, the flush returns on its own fsyncs while the
/// dispatched promote completes on the worker in its own time: the
/// pending/ segment lands and the old WAL is deleted shortly after.
#[test]
fn promote_completes_after_flush_returns() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    let (handle, actor_thread) = open_actor(&fork_dir);

    // 33 × 1 MiB of incompressible writes — exceeds the 32 MiB
    // FLUSH_THRESHOLD, so the actor dispatches a promote to the worker
    // after one of these writes returns.
    for i in 0..33u64 {
        handle
            .write(i * 256, &incompressible_block(i), false)
            .unwrap();
    }

    // FLUSH: fsyncs the current WAL and the promote's rotated WAL on
    // the actor, independent of the promote's progress.
    handle.flush().unwrap();

    // The promote drains on the worker: pending/<ulid> committed, old
    // WAL deleted, one fresh WAL remaining.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let pending_count = fs::read_dir(elide_core::segment::pending_open_dir(&fork_dir))
            .unwrap()
            .filter(|e| {
                let e = e.as_ref().unwrap();
                let name = e.file_name();
                let s = name.to_string_lossy();
                !s.ends_with(".tmp") && !s.starts_with('.')
            })
            .count();
        let wal_count = fs::read_dir(fork_dir.join("wal"))
            .unwrap()
            .filter(|e| e.is_ok())
            .count();
        if pending_count >= 1 && wal_count == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "promote never drained: pending={pending_count} wal={wal_count}"
        );
        thread::sleep(std::time::Duration::from_millis(10));
    }

    drop(handle);
    actor_thread.join().unwrap();
}

/// FLUSH with no promote in flight takes the fast path: WAL fsync on
/// the active WAL and immediate reply.  No pending/ segments should be
/// produced.
#[test]
fn flush_without_pending_promote_is_fast_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    let (handle, actor_thread) = open_actor(&fork_dir);

    // One small write — far below the 32 MiB threshold.
    handle.write(0, &[0xABu8; 4096], false).unwrap();
    handle.flush().unwrap();

    // No promote was triggered, so pending/ should still be empty.
    let pending_count = fs::read_dir(elide_core::segment::pending_open_dir(&fork_dir))
        .unwrap()
        .filter(|e| e.is_ok())
        .count();
    assert_eq!(
        pending_count, 0,
        "expected no pending/ segments when write is below threshold"
    );

    drop(handle);
    actor_thread.join().unwrap();
}

/// Writes that happened before FLUSH must be readable after a
/// simulated crash + reopen, even though the WAL fsync now happens
/// asynchronously on the worker.
///
/// This is the durability contract FLUSH protects: every write before
/// the FLUSH reply must survive a crash, regardless of whether the
/// worker or actor performed the fsync.
#[test]
fn data_survives_crash_after_flush_with_deferred_fsync() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();

    let probe_a = vec![0xABu8; 4096];
    let probe_b = vec![0xCDu8; 4096];

    {
        let (handle, actor_thread) = open_actor(&fork_dir);

        // Cross the threshold so a promote is in flight.
        for i in 0..33u64 {
            handle
                .write(i * 256, &incompressible_block(i), false)
                .unwrap();
        }
        // Writes whose durability must survive reopen.
        handle.write(10_000, &probe_a, false).unwrap();
        handle.write(10_001, &probe_b, false).unwrap();
        handle.flush().unwrap();

        // Drop the handle to close the channel, then join the actor
        // — this is the cleanest "simulated crash+reopen" boundary
        // available at the library level.
        drop(handle);
        actor_thread.join().unwrap();
    }

    // Reopen and verify the post-flush writes are still there.
    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    let got_a = vol.read(10_000, 1).unwrap();
    let got_b = vol.read(10_001, 1).unwrap();
    assert_eq!(
        got_a.as_slice(),
        probe_a.as_slice(),
        "LBA 10_000 must survive reopen after flush"
    );
    assert_eq!(
        got_b.as_slice(),
        probe_b.as_slice(),
        "LBA 10_001 must survive reopen after flush"
    );
}

/// A promote that fails on the worker (here: pending/ momentarily
/// missing) must fail the `PromoteWal` reply rather than hanging it,
/// keep the old WAL on disk as the durable copy of the epoch, and be
/// retried by the next promote trigger without a daemon restart.
///
/// Reproduces the 2026-07-16 vol8 stall: an ENOSPC promote stranded an
/// on-disk WAL the running daemon never resealed — `pending` showed
/// non-zero forever until a manual stop/start replayed it.
#[test]
fn failed_promote_is_retried_without_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    let (handle, actor_thread) = open_actor(&fork_dir);

    let block = incompressible_block(1);
    handle.write(0, &block, false).unwrap();

    let pending = elide_core::segment::pending_open_dir(&fork_dir);
    let blocked = fork_dir.join("pending.blocked");
    fs::rename(&pending, &blocked).unwrap();

    // The promote fails (pending/ missing): the reply must be the
    // error, not a hang.
    assert!(handle.promote_wal().is_err());
    // The WAL file is still on disk — durable copy of the failed epoch.
    assert_eq!(fs::read_dir(fork_dir.join("wal")).unwrap().count(), 1);

    fs::rename(&blocked, &pending).unwrap();

    // The next PromoteWal re-dispatches the stashed job; its reply is
    // parked on that retry, so success here means the epoch landed.
    handle.promote_wal().unwrap();
    assert_eq!(fs::read_dir(fork_dir.join("wal")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&pending).unwrap().count(), 1);

    drop(handle);
    actor_thread.join().unwrap();

    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    assert_eq!(vol.read(0, 256).unwrap(), block);
}

/// A GC-checkpoint promote failure must resolve the parked checkpoint
/// reply with the error (previously it hung forever and every later
/// checkpoint was rejected as "concurrent gc_checkpoint not allowed"),
/// and the stashed epoch must land via a later checkpoint's retry.
#[test]
fn failed_gc_checkpoint_promote_unblocks_later_checkpoints() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    let (handle, actor_thread) = open_actor(&fork_dir);

    let block = incompressible_block(2);
    handle.write(0, &block, false).unwrap();

    let pending = elide_core::segment::pending_open_dir(&fork_dir);
    let blocked = fork_dir.join("pending.blocked");
    fs::rename(&pending, &blocked).unwrap();

    // Checkpoint promote fails: the parked reply resolves with the error.
    assert!(handle.gc_checkpoint(2).is_err());

    // Not rejected as concurrent — the failed checkpoint cleared its
    // parked slot. This call re-dispatches the stashed job (which fails
    // again); its own WAL view is empty, so the reply parks on the
    // retry and reports its failure, leaving the job back on the stash.
    assert!(handle.gc_checkpoint(2).is_err());

    fs::rename(&blocked, &pending).unwrap();

    // This checkpoint re-dispatches the stashed epoch; its reply parks
    // on that retry, so success means the epoch landed.
    handle.gc_checkpoint(2).unwrap();
    assert_eq!(fs::read_dir(fork_dir.join("wal")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&pending).unwrap().count(), 1);

    drop(handle);
    actor_thread.join().unwrap();

    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    assert_eq!(vol.read(0, 256).unwrap(), block);
}

/// The synchronous promote path restores the WAL handle and pending
/// entries when the promote fails, so writes continue into the same
/// WAL and a later attempt promotes the whole epoch.
#[test]
fn failed_inline_promote_restores_wal_state() {
    let dir = tempfile::TempDir::new().unwrap();
    let base: PathBuf = dir.path().to_owned();
    common::write_test_keypair(&base);
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write(0, &incompressible_block(3)).unwrap();

    let pending = elide_core::segment::pending_open_dir(&base);
    let blocked = base.join("pending.blocked");
    fs::rename(&pending, &blocked).unwrap();
    assert!(vol.promote_for_test().is_err());
    fs::rename(&blocked, &pending).unwrap();

    // State restored: the next write appends to the same WAL rather
    // than opening a second one.
    vol.write(256, &incompressible_block(4)).unwrap();
    assert_eq!(fs::read_dir(base.join("wal")).unwrap().count(), 1);

    vol.promote_for_test().unwrap();
    assert_eq!(fs::read_dir(base.join("wal")).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&pending).unwrap().count(), 1);
    assert_eq!(vol.read(0, 256).unwrap(), incompressible_block(3));
    assert_eq!(vol.read(256, 256).unwrap(), incompressible_block(4));
}
