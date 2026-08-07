// The two windows inside a reap pass that only a crash reaches.
//
// On the actor the apply, the publish and the unlinks run back to back,
// so nothing but a process death lands between them. `ReapStop` stops a
// pass at each boundary and the test crashes there, which is the shape
// the soak takes when the volume server is killed mid-tick.
//
// Both windows must lose nothing: the apply's removals live only in
// memory until the files are gone, so a rebuild that still finds the
// files restores the entries it dropped.

use std::thread;

use elide_core::actor::{ReapStop, spawn};
use elide_core::volume::Volume;

mod common;

fn block(seed: u8) -> Vec<u8> {
    vec![seed; 4096]
}

/// Leave a whole-dead segment in the open generation, stop a reap pass
/// at `stop`, crash, and require the surviving write to read back
/// through the rebuild.
fn crash_at(stop: ReapStop) {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();
    common::write_test_keypair(fork_dir);

    let vol = Volume::open(fork_dir, fork_dir).unwrap();
    let (actor, handle) = spawn(vol);
    let actor_thread = thread::spawn(move || actor.run());

    // Two segments over one LBA: the first goes whole-dead when the
    // second lands, which is what the pass takes.
    handle.write(0, &block(1), false).unwrap();
    handle.promote_wal().unwrap();
    handle.write(0, &block(2), false).unwrap();
    handle.promote_wal().unwrap();

    let stats = handle.reap_stopping(stop).unwrap();
    assert!(
        stats.segments_reaped > 0,
        "the pass reaped nothing, so the {stop:?} window was never entered"
    );

    handle.shutdown();
    actor_thread.join().unwrap();

    let reopened = Volume::open(fork_dir, fork_dir).unwrap();
    let (actor2, handle2) = spawn(reopened);
    let actor2_thread = thread::spawn(move || actor2.run());
    let got = handle2.reader().read(0, 1).unwrap();
    assert_eq!(
        got.as_slice(),
        block(2).as_slice(),
        "lba 0 wrong after a crash at {stop:?}"
    );
    handle2.shutdown();
    actor2_thread.join().unwrap();
}

#[test]
fn a_crash_between_the_apply_and_the_publish_loses_nothing() {
    crash_at(ReapStop::BeforePublish);
}

#[test]
fn a_crash_between_the_publish_and_the_unlink_loses_nothing() {
    crash_at(ReapStop::BeforeUnlink);
}
