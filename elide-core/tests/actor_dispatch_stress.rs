// Liveness stress for the actor/worker dispatch path.
//
// The worker job and result channels are both bounded. If the actor ever
// blocks sending a job while worker results are queued undrained, the
// pair deadlocks: the worker parks sending a result, stops taking jobs,
// and the actor's send never completes — the whole volume (IO and IPC)
// wedges. Observed live on 2026-07-13: a 2-way parallel-cp load test
// froze one volume mid-drain with 24 block requests stranded in flight.
//
// This test floods the actor with the same shape of traffic — sustained
// writes forcing promote dispatches, plus a coordinator-style thread
// hammering promote_wal / repack / gc_checkpoint / apply_gc_handoffs /
// reclaim — and requires the whole run to finish within a deadline.
// Single-flight rejections and empty-WAL no-ops are expected; the only
// assertion is liveness.

use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use elide_core::actor::spawn;
use elide_core::volume::Volume;

mod common;

const DEADLINE: Duration = Duration::from_secs(120);

/// splitmix64 — incompressible block content so writes stay Data-kind
/// and promotes carry real body bytes.
fn incompressible_block(seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; 4096];
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    for chunk in out.chunks_exact_mut(8) {
        x = x.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out
}

#[test]
fn actor_survives_dispatch_flood() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    common::write_test_keypair(&fork_dir);

    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    let (actor, handle) = spawn(vol);
    let actor_thread = thread::spawn(move || actor.run());

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    let mut expected = 0usize;

    // Writers: sustained unique-content writes across disjoint LBA
    // ranges. Each write can trip needs_promote and dispatch a promote,
    // and the volume keeps the actor's mailbox saturated so worker
    // results have to compete for drain slots.
    for w in 0u64..4 {
        let h = handle.clone();
        let tx = done_tx.clone();
        expected += 1;
        thread::spawn(move || {
            for i in 0..300u64 {
                let lba = w * 4096 + (i % 512) * 4;
                for b in 0..4u64 {
                    let block = incompressible_block(w * 1_000_003 + i * 7 + b);
                    let _ = h.write(lba + b, &block, false);
                }
                if i % 32 == 0 {
                    let _ = h.flush();
                }
            }
            let _ = tx.send("writer");
        });
    }

    // Promote hammer: every call on a non-empty WAL dispatches a promote
    // job, so this keeps the bounded job queue saturated.
    for _ in 0..2 {
        let h = handle.clone();
        let tx = done_tx.clone();
        expected += 1;
        thread::spawn(move || {
            for _ in 0..400 {
                let _ = h.promote_wal();
            }
            let _ = tx.send("promoter");
        });
    }

    // Coordinator-style mixed compaction traffic. Errors (single-flight
    // rejections, nothing-to-do) are expected and ignored.
    {
        let h = handle.clone();
        let tx = done_tx.clone();
        expected += 1;
        thread::spawn(move || {
            for i in 0..200u64 {
                let _ = h.repack();
                let _ = h.apply_gc_handoffs();
                let _ = h.gc_checkpoint(2);
                let _ = h.reclaim_alias_merge((i % 16) * 64, 64);
            }
            let _ = tx.send("compactor");
        });
    }
    drop(done_tx);

    for _ in 0..expected {
        done_rx
            .recv_timeout(DEADLINE)
            .expect("actor dispatch wedged: a stress thread failed to finish in time");
    }

    // The volume must still answer requests after the flood.
    handle.flush().expect("flush after flood");
    handle.shutdown();
    actor_thread.join().unwrap();
}
