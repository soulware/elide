// Concurrent integration test: coordinator GC + live volume reads.
//
// Verifies that reads never fail during a coordinator GC pass.  The failure
// mode under test: if the coordinator deletes old segment files before the
// volume has applied the GC handoff, any read of a cold LBA (one whose
// extent index entry still points at the now-deleted file) returns a
// file-not-found error.
//
// The fix: the coordinator must not delete old local segment files until after
// the volume has acknowledged the handoff. Under the self-describing handoff
// protocol the ack is the rename of `gc/<ulid>.staged` to bare `gc/<ulid>` —
// that rename is the commit point at which the volume's extent index has
// flipped to the new compacted segment, making the old files safe to delete.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use elide_core::actor::spawn;
use elide_core::volume::Volume;

mod common;

/// Concurrent coordinator GC must not create a window where reads fail.
///
/// Seeds two segments of data, then runs a coordinator thread (GC pass) and a
/// reader thread (continuous reads of seeded LBAs) concurrently.  The
/// coordinator GC emits a `gc/<new>.plan` handoff which the volume materialises
/// into a bare `gc/<new>` segment; the reader must never observe a
/// file-not-found error regardless of when the handoff is applied relative to
/// the deletion of the old files.
#[test]
fn coordinator_gc_does_not_create_read_failures() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    common::write_test_keypair(&fork_dir);

    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    let (actor, handle) = spawn(vol);
    let actor_thread = thread::spawn(move || actor.run());

    let mut oracle: HashMap<u64, Vec<u8>> = HashMap::new();

    // Seed phase: write two separate batches, flush each to a distinct
    // segment, then drain both to index/ + cache/.  This gives the coordinator
    // two candidates to compact.
    for lba in 0u64..4 {
        let data = vec![(lba as u8).wrapping_mul(11); 4096];
        handle.write(lba, &data, false).unwrap();
        oracle.insert(lba, data);
    }
    handle.flush().unwrap();
    common::drain_via_handle(&handle, &fork_dir);

    for lba in 4u64..8 {
        let data = vec![(lba as u8).wrapping_mul(13); 4096];
        handle.write(lba, &data, false).unwrap();
        oracle.insert(lba, data);
    }
    handle.flush().unwrap();
    common::drain_via_handle(&handle, &fork_dir);

    // Reader thread: continuously reads all seeded LBAs.  These are cold —
    // they are in cache/, not in the WAL.  A read failure here means the
    // extent index still points at a file the coordinator has already deleted.
    let read_reader = handle.reader();
    let oracle_snap = oracle.clone();
    let read_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let read_errors_clone = Arc::clone(&read_errors);

    let reader = thread::spawn(move || {
        for _ in 0..500 {
            for lba in 0u64..8 {
                match read_reader.read(lba, 1) {
                    Ok(actual) => {
                        if let Some(expected) = oracle_snap.get(&lba)
                            && actual != *expected
                        {
                            read_errors_clone
                                .lock()
                                .unwrap()
                                .push(format!("lba {lba}: wrong data"));
                        }
                    }
                    Err(e) => {
                        read_errors_clone
                            .lock()
                            .unwrap()
                            .push(format!("lba {lba}: read error: {e}"));
                    }
                }
            }
            thread::sleep(Duration::from_micros(200));
        }
    });

    // Coordinator thread: compact the two seeded segments.
    // simulate_coord_gc_local returns the paths of the consumed input segments
    // rather than deleting them inline — deletion must happen only after the
    // handoff is applied.
    let gc_handle = handle.clone();
    let fork_dir_gc = fork_dir.clone();

    let coordinator = thread::spawn(move || {
        // Brief pause so the reader has time to start.
        thread::sleep(Duration::from_millis(5));

        let gc_ulid = gc_handle.gc_checkpoint(1).unwrap().bucket_ulids[0];
        if let Some((_, _, to_delete)) = common::simulate_coord_gc_local(&fork_dir_gc, gc_ulid, 2) {
            // Apply the handoff before deleting old files.  This updates the
            // volume's extent index to point at the new compacted segment,
            // ensuring reads find valid data before the old files disappear.
            gc_handle.apply_gc_handoffs().unwrap();

            // Old files are safe to delete only after the handoff is applied.
            for path in &to_delete {
                let _ = std::fs::remove_file(path);
            }
        }
    });

    coordinator.join().unwrap();
    reader.join().unwrap();

    let errors = read_errors.lock().unwrap();
    assert!(
        errors.is_empty(),
        "reads failed during concurrent GC: {:?}",
        *errors
    );

    // Full oracle check after everything settles.
    let final_reader = handle.reader();
    for (lba, expected) in &oracle {
        let actual = final_reader.read(*lba, 1).unwrap();
        assert_eq!(actual, *expected, "lba {lba} wrong in final check");
    }

    handle.shutdown();
    actor_thread.join().unwrap();
}

/// Regression: two `apply_gc_handoffs` calls arriving close together must
/// not drop either reply channel.
///
/// The actor's internal `idle_tick` also calls `start_gc_handoffs` (with
/// `reply=None`), so an IPC caller's reply can collide with it in exactly
/// the same way two IPC callers collide. Prior to the fix, the second
/// invocation unconditionally overwrote `self.parked_handoffs`, dropping
/// the first caller's reply sender — the receiver saw
/// `"volume actor reply channel closed"`, matching the coordinator warning
/// users observed on a running volume with a pending handoff.
///
/// The fix rejects a concurrent call when a batch is already in flight;
/// the first caller always gets `Ok(n)`. The second caller sees either
/// `Ok(n)` (if its message arrived after the first batch drained) or an
/// `"apply_gc_handoffs already in progress"` error (the coordinator
/// retries next tick). What must never happen is "reply channel closed".
#[test]
fn concurrent_apply_gc_handoffs_does_not_drop_replies() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    common::write_test_keypair(&fork_dir);

    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    let (actor, handle) = spawn(vol);
    let actor_thread = thread::spawn(move || actor.run());

    // Seed two committed segments in index/ so the GC simulator has
    // candidates. Each segment comes from: write → promote_wal (WAL →
    // pending/) → drain_via_handle (pending/ → index/ + cache/).
    for lba in 0u64..4 {
        let data = vec![(lba as u8).wrapping_mul(11); 4096];
        handle.write(lba, &data, false).unwrap();
    }
    handle.promote_wal().unwrap();
    common::drain_via_handle(&handle, &fork_dir);

    for lba in 4u64..8 {
        let data = vec![(lba as u8).wrapping_mul(13); 4096];
        handle.write(lba, &data, false).unwrap();
    }
    handle.promote_wal().unwrap();
    common::drain_via_handle(&handle, &fork_dir);

    // Stage a GC handoff (gc/<new>.plan) without applying it yet — the
    // coordinator-side plan emitter runs, but no one has called
    // apply_gc_handoffs on the volume.
    let gc_ulid = handle.gc_checkpoint(1).unwrap().bucket_ulids[0];
    common::simulate_coord_gc_local(&fork_dir, gc_ulid, 2)
        .expect("GC simulation must produce a plan");

    // Two threads race to apply the handoff. Before the fix, the second
    // call would drop the first caller's reply sender.
    let h1 = handle.clone();
    let h2 = handle.clone();
    let t1 = thread::spawn(move || h1.apply_gc_handoffs());
    let t2 = thread::spawn(move || h2.apply_gc_handoffs());

    let r1 = t1.join().expect("thread 1 panicked");
    let r2 = t2.join().expect("thread 2 panicked");

    for (label, result) in [("r1", &r1), ("r2", &r2)] {
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("reply channel closed"),
                "{label} saw dropped reply: {msg}"
            );
            assert!(
                msg.contains("already in progress"),
                "{label} got unexpected error: {msg}"
            );
        }
    }
    assert!(
        r1.is_ok() || r2.is_ok(),
        "at least one apply_gc_handoffs must succeed: r1={r1:?} r2={r2:?}"
    );

    handle.shutdown();
    actor_thread.join().unwrap();
}

/// `SegmentFetcher` that parks the worker thread inside its first
/// `fetch_extent` call: sends on `stalled`, then blocks on `release`
/// until the test drops the paired sender, after which every call
/// passes straight through to the wrapped `CapturedBodyFetcher`.
struct GatedFetcher {
    inner: common::CapturedBodyFetcher,
    stalled: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl elide_core::segment::SegmentFetcher for GatedFetcher {
    fn fetch_extent(
        &self,
        segment_id: ulid::Ulid,
        owner_vol_id: ulid::Ulid,
        index_dir: &std::path::Path,
        body_dir: &std::path::Path,
        extent: &elide_core::segment::ExtentFetch,
        presence: Option<Arc<elide_core::extentindex::SegmentPresence>>,
    ) -> std::io::Result<()> {
        let _ = self.stalled.send(());
        let _ = self.release.lock().unwrap().recv();
        self.inner.fetch_extent(
            segment_id,
            owner_vol_id,
            index_dir,
            body_dir,
            extent,
            presence,
        )
    }

    fn fetch_delta_body(
        &self,
        segment_id: ulid::Ulid,
        owner_vol_id: ulid::Ulid,
        index_dir: &std::path::Path,
        body_dir: &std::path::Path,
    ) -> std::io::Result<()> {
        self.inner
            .fetch_delta_body(segment_id, owner_vol_id, index_dir, body_dir)
    }
}

/// 4 KiB of keyed-BLAKE3 output — never compresses below the inline
/// threshold, so writes land as body entries whose bytes a GC apply
/// must materialise (and demand-fetch once the cache body is evicted).
fn incompressible_block(seed: u8) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let key = [seed; 32];
    let mut hasher = blake3::Hasher::new_keyed(&key);
    for (i, chunk) in buf.chunks_mut(32).enumerate() {
        hasher.update(&(i as u64).to_le_bytes());
        let hash = hasher.finalize();
        chunk.copy_from_slice(&hash.as_bytes()[..chunk.len()]);
        hasher.reset();
    }
    buf
}

/// The coordinator's timeout-abandon-replan sequence, driven for real:
/// a handoff apply is parked mid-materialise on the worker thread while
/// an impatient coordinator retries the apply, checkpoints, and emits a
/// second plan over the same inputs.
///
/// Pinned properties: the volume rejects the concurrent apply with
/// "already in progress" instead of interleaving; the checkpoint served
/// mid-apply carries an own-segment commitment that matches the disk
/// scan (the apply commits atomically on the actor, so no torn state is
/// observable); and once both plans have been processed every LBA reads
/// its oracle value, live and across a reopen.
#[test]
fn plan_emitted_during_inflight_apply_is_safe() {
    let tmp = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = tmp.path().join(ulid::Ulid::new().to_string());
    std::fs::create_dir_all(&fork_dir).unwrap();
    common::write_test_keypair(&fork_dir);
    let store_dir = tmp.path().join("_store");

    // Seed two committed segments of incompressible (body-entry) data,
    // then evict both cache bodies so the apply must go through the
    // gated fetcher.
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    let mut oracle: HashMap<u64, Vec<u8>> = HashMap::new();
    for lba in 0u64..4 {
        let data = incompressible_block(lba as u8);
        vol.write(lba, &data).unwrap();
        oracle.insert(lba, data);
    }
    vol.flush_wal().unwrap();
    common::drain_with_repack(&mut vol);
    for lba in 4u64..8 {
        let data = incompressible_block(0x40 + lba as u8);
        vol.write(lba, &data).unwrap();
        oracle.insert(lba, data);
    }
    vol.flush_wal().unwrap();
    common::drain_with_repack(&mut vol);
    assert!(common::capture_and_evict_cache_body(&vol, &fork_dir, &store_dir).is_some());
    assert!(common::capture_and_evict_cache_body(&vol, &fork_dir, &store_dir).is_some());

    let (stalled_tx, stalled_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    vol.set_fetcher(Arc::new(GatedFetcher {
        inner: common::CapturedBodyFetcher {
            store_dir: store_dir.clone(),
        },
        stalled: stalled_tx,
        release: Mutex::new(release_rx),
    }));
    let (actor, handle) = spawn(vol);
    let actor_thread = thread::spawn(move || actor.run());

    // Plan P1 over both segments and start its apply; the worker parks
    // inside the first demand-fetch.
    let p1 = handle.gc_checkpoint(1).unwrap().bucket_ulids[0];
    let (_, _, to_delete) = common::simulate_coord_gc_local(&fork_dir, p1, 2).unwrap();
    let apply_handle = handle.clone();
    let first_apply = thread::spawn(move || apply_handle.apply_gc_handoffs());
    stalled_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("apply never reached the fetcher");

    // Impatient coordinator, mid-apply. Collect outcomes and release the
    // gate before asserting so a failure can't leave the worker parked.
    let concurrent_apply = handle.apply_gc_handoffs();
    let checkpoint2 = handle.gc_checkpoint(1);
    let disk_commitment_mid_apply = elide_core::volume_ipc::SegmentSetCommitment::from_ulids(
        elide_core::segment::committed_tier_ulids(&fork_dir).unwrap(),
    );
    let p2_emitted = checkpoint2.as_ref().ok().map(|reply| {
        // Production's planner bails while a .plan is pending; emitting
        // anyway models the TOCTOU race where the apply's commit removes
        // the plan file between that check and emission.
        common::simulate_coord_gc_local(&fork_dir, reply.bucket_ulids[0], 2)
    });
    drop(release_tx);

    assert_eq!(first_apply.join().unwrap().unwrap(), 1, "P1 must apply");
    let err = concurrent_apply.expect_err("concurrent apply must be rejected, not interleaved");
    assert!(
        err.to_string().contains("already in progress"),
        "unexpected rejection: {err}"
    );
    let checkpoint2 = checkpoint2.expect("checkpoint must stay available mid-apply");
    assert_eq!(
        checkpoint2.own_segments,
        Some(disk_commitment_mid_apply),
        "mid-apply commitment must match the disk scan — applies commit atomically"
    );

    // Process P2 (drawn against pre-P1 state, over the same inputs).
    // The volume's commit-point guards decide it; whatever the verdict,
    // the plan must be consumed and reads must hold.
    let (_, p2_ulid, _) = p2_emitted
        .expect("checkpoint2 must succeed")
        .expect("both inputs are still committed mid-apply, so P2 must be plannable");
    handle.apply_gc_handoffs().unwrap();
    assert!(
        !fork_dir.join("gc").join(format!("{p2_ulid}.plan")).exists(),
        "second plan must be consumed (applied or cancelled)"
    );
    for path in &to_delete {
        let _ = std::fs::remove_file(path);
    }

    let reader = handle.reader();
    for (lba, expected) in &oracle {
        let actual = reader.read(*lba, 1).unwrap();
        assert_eq!(actual, *expected, "lba {lba} wrong after overlapping GC");
    }

    handle.shutdown();
    actor_thread.join().unwrap();

    let vol = common::open_with_captured_body_fetcher(&fork_dir, &store_dir);
    for (lba, expected) in &oracle {
        let actual = vol.read(*lba, 1).unwrap();
        assert_eq!(actual, *expected, "lba {lba} wrong after reopen");
    }
}
