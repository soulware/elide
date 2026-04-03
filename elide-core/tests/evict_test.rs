// Regression tests for eviction correctness.
//
// `evict` (the `elide volume evict` command) deletes segment files from
// `segments/` to reclaim local disk space.  For a volume that has S3 backing,
// evicted segments must still be accessible after a crash+reopen: the LBA map
// is rebuilt at `Volume::open` from `pending/`, `segments/`, and
// `fetched/*.idx`.  If `evict` does not write `fetched/<ulid>.idx` before
// deleting `segments/<ulid>`, those LBAs are absent from the rebuilt map and
// reads silently return zeros.

use std::fs;
use std::path::PathBuf;

use elide_core::volume::Volume;

mod common;

/// Evicting all local segment bodies must not lose data after a crash+reopen.
///
/// The LBA map must survive via `fetched/<ulid>.idx` (header+index section)
/// written by evict before the segment body is deleted.  Subsequent reads fall
/// through to the `SegmentFetcher` for the body bytes.
///
/// **Currently fails**: `evict_segments` deletes `segments/` files without
/// writing `.idx`, so the LBA map has no record of those LBAs after restart
/// and reads return zeros.
#[test]
fn evict_then_crash_data_survives() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir: PathBuf = dir.path().to_owned();
    common::write_test_keypair(&fork_dir);
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();

    vol.write(0, &[0xAB; 4096]).unwrap();
    vol.write(1, &[0xCD; 4096]).unwrap();
    vol.flush_wal().unwrap();
    common::drain_local(&fork_dir); // pending/ → segments/

    // Simulate the current (broken) evict behaviour: delete segment files
    // without writing .idx to fetched/.
    let segments_dir = fork_dir.join("segments");
    for entry in fs::read_dir(&segments_dir).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }

    // Crash + reopen (triggers full LBA map rebuild from disk).
    drop(vol);
    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();

    // After the fix: evict will have written fetched/<ulid>.idx before
    // deleting, so rebuild picks up the LBA map entries and reads correctly
    // fall through to the SegmentFetcher for the body.
    //
    // Without the fix: no .idx exists → LBA map is empty → reads return zeros.
    let r0 = vol.read(0, 1).unwrap();
    assert_eq!(r0.as_slice(), &[0xAB; 4096], "lba 0 lost after evict+crash");

    let r1 = vol.read(1, 1).unwrap();
    assert_eq!(r1.as_slice(), &[0xCD; 4096], "lba 1 lost after evict+crash");
}
