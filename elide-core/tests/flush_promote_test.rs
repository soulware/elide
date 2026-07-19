// Regression tests for the FLUSH / promote interaction after moving
// the old-WAL fsync off the actor thread (see `execute_promote` and
// `VolumeActor::park_or_resolve_flush`).
//
// The actor no longer fsyncs the old WAL at the 32 MiB threshold.
// Instead the fsync happens on the worker as the first step of the
// promote, and `VolumeRequest::Flush` parks on a promote generation
// counter until every promote dispatched before the flush has
// completed.  These tests verify that property: after `handle.flush()`
// returns, any promote triggered by a prior write is on disk and the
// old WAL file has been cleaned up.

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
/// issuing FLUSH, the pending/ segment must be on disk and the old
/// WAL file deleted before `handle.flush()` returns.
///
/// This is the load-bearing property of the off-actor fsync change:
/// FLUSH still guarantees durability of every prior write even though
/// the fsync + segment write now happen on the worker thread.
#[test]
fn flush_waits_for_in_flight_promote_to_complete() {
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

    // FLUSH: must wait for the dispatched promote's old-WAL fsync
    // (and, in this implementation, the entire promote) to complete.
    handle.flush().unwrap();

    // After flush returns we expect:
    //   - pending/<ulid> exists (segment committed by the worker)
    //   - exactly one wal/ file (the fresh one opened during prep)
    let pending_count = fs::read_dir(fork_dir.join("pending"))
        .unwrap()
        .filter(|e| {
            let e = e.as_ref().unwrap();
            let name = e.file_name();
            let s = name.to_string_lossy();
            !s.ends_with(".tmp") && !s.starts_with('.')
        })
        .count();
    assert!(
        pending_count >= 1,
        "expected at least one committed pending/ segment after flush, got {pending_count}"
    );

    let wal_count = fs::read_dir(fork_dir.join("wal"))
        .unwrap()
        .filter(|e| e.is_ok())
        .count();
    assert_eq!(
        wal_count, 1,
        "expected exactly one WAL file after flush (old one should be deleted)"
    );

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
    let pending_count = fs::read_dir(fork_dir.join("pending"))
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

    let pending = fork_dir.join("pending");
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

    let pending = fork_dir.join("pending");
    let blocked = fork_dir.join("pending.blocked");
    fs::rename(&pending, &blocked).unwrap();

    // Checkpoint promote fails: the parked reply resolves with the error.
    assert!(handle.gc_checkpoint(2).is_err());

    // Not rejected as concurrent — the failed checkpoint cleared its
    // parked slot. This call re-dispatches the stashed job (which fails
    // again); its own WAL view is empty so it completes immediately.
    handle.gc_checkpoint(2).unwrap();
    // Barrier: flush parks on the promote generation, so once it
    // returns the retry's failure has been processed and the job is
    // back on the stash.
    handle.flush().unwrap();

    fs::rename(&blocked, &pending).unwrap();

    // This checkpoint re-dispatches the stashed epoch, which now lands.
    handle.gc_checkpoint(2).unwrap();
    handle.flush().unwrap();
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

    let pending = base.join("pending");
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
