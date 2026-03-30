// Property-based tests for the actor + snapshot layer.
//
// Tests two invariants:
//
// 1. Read-your-writes: after handle.write() returns Ok, handle.read() of the
//    same LBA immediately returns the written data. This exercises the ArcSwap
//    snapshot publication path — reads bypass the channel and load the current
//    snapshot directly, with no flush required.
//
// 2. Crash recovery: after shutting down the actor and reopening the Volume,
//    every LBA reads back the value last written to it. Volume::open() calls
//    recover_wal(), so writes that were never flushed to a pending segment are
//    still recoverable from the WAL.
//
// Together these verify that the actor correctly publishes snapshots and that
// no combination of writes, flushes, and crashes loses data visible through
// the handle.

use std::collections::HashMap;
use std::thread;

use elide_core::actor::spawn;
use elide_core::volume::Volume;
use proptest::prelude::*;

// --- strategy ---

#[derive(Debug, Clone)]
enum ActorOp {
    Write { lba: u8, seed: u8 },
    Flush,
    Crash,
}

fn arb_actor_op() -> impl Strategy<Value = ActorOp> {
    prop_oneof![
        4 => (0u8..8, any::<u8>()).prop_map(|(lba, seed)| ActorOp::Write { lba, seed }),
        2 => Just(ActorOp::Flush),
        1 => Just(ActorOp::Crash),
    ]
}

fn arb_actor_ops() -> impl Strategy<Value = Vec<ActorOp>> {
    prop::collection::vec(arb_actor_op(), 1..30)
}

// --- property ---

proptest! {
    /// Actor correctness: read-your-writes and crash recovery.
    ///
    /// After every Write: immediately read the same LBA and assert the data
    /// matches (read-your-writes via ArcSwap snapshot, no flush needed).
    ///
    /// After every Crash: shut down the actor, reopen the Volume (triggering
    /// WAL recovery), spawn a new actor, then assert that every oracle entry
    /// is still readable.
    #[test]
    fn actor_correctness(ops in arb_actor_ops()) {
        let dir = tempfile::TempDir::new().unwrap();
        let fork_dir = dir.path();

        let vol = Volume::open(fork_dir).unwrap();
        let (actor, mut handle) = spawn(vol);
        let mut actor_thread = Some(
            thread::Builder::new()
                .name("volume-actor".into())
                .spawn(move || actor.run())
                .unwrap(),
        );

        let mut oracle: HashMap<u64, [u8; 4096]> = HashMap::new();

        for op in &ops {
            match op {
                ActorOp::Write { lba, seed } => {
                    let data = vec![*seed; 4096];
                    if handle.write(*lba as u64, data).is_ok() {
                        let expected = [*seed; 4096];
                        // Read-your-writes: snapshot must reflect this write
                        // immediately, before any flush to pending/.
                        let actual = handle.read(*lba as u64, 1).unwrap();
                        prop_assert_eq!(
                            actual.as_slice(),
                            &expected[..],
                            "read-your-writes failed for lba {}",
                            lba
                        );
                        oracle.insert(*lba as u64, expected);
                    }
                }
                ActorOp::Flush => {
                    let _ = handle.flush();
                }
                ActorOp::Crash => {
                    // Shut down the actor and wait for it to exit before
                    // reopening the volume directory.
                    handle.shutdown();
                    if let Some(t) = actor_thread.take() {
                        let _ = t.join();
                    }

                    let vol = Volume::open(fork_dir).unwrap();
                    let (new_actor, new_handle) = spawn(vol);
                    actor_thread = Some(
                        thread::Builder::new()
                            .name("volume-actor".into())
                            .spawn(move || new_actor.run())
                            .unwrap(),
                    );
                    handle = new_handle;

                    for (&lba, expected) in &oracle {
                        let actual = handle.read(lba, 1).unwrap();
                        prop_assert_eq!(
                            actual.as_slice(),
                            expected.as_slice(),
                            "lba {} wrong after crash+rebuild",
                            lba
                        );
                    }
                }
            }
        }

        // Graceful shutdown after the property run completes.
        handle.shutdown();
        if let Some(t) = actor_thread {
            let _ = t.join();
        }
    }
}
