use super::test_util::*;
use super::*;

#[test]
fn open_creates_directories() {
    let base = keyed_temp_dir();
    let _ = Volume::open(&base, &base).unwrap();
    assert!(base.join("wal").is_dir());
    assert!(base.join("pending").is_dir());
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn open_is_idempotent() {
    let base = keyed_temp_dir();
    let _ = Volume::open(&base, &base).unwrap();
    // Second open on the same dir should succeed (dirs already exist).
    let _ = Volume::open(&base, &base).unwrap();
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_single_block() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    vol.write(0, &vec![0x42u8; 4096]).unwrap();
    vol.fsync().unwrap();
    assert_eq!(vol.lbamap_len(), 1);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_multi_block_extent() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    // Write 8 LBAs (32 KiB) as a single call.
    vol.write(10, &vec![0xabu8; 8 * 4096]).unwrap();
    assert_eq!(vol.lbamap_len(), 1);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn noop_skip_same_lba_same_content() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let data = vec![0x42u8; 4096];

    vol.write(0, &data).unwrap();
    let before = vol.noop_stats();
    assert_eq!(before.skipped_writes, 0);
    assert_eq!(before.skipped_bytes, 0);

    // Same LBA, same content — short-circuited by the LBA-map hash check.
    vol.write(0, &data).unwrap();
    let after = vol.noop_stats();
    assert_eq!(after.skipped_writes, 1);
    assert_eq!(after.skipped_bytes, 4096);

    // Data still reads back correctly.
    assert_eq!(vol.read(0, 1).unwrap(), data);
    // LBA map still has exactly one entry.
    assert_eq!(vol.lbamap_len(), 1);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn noop_skip_different_content_falls_through() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let a = vec![0x42u8; 4096];
    let b = vec![0x99u8; 4096];

    vol.write(0, &a).unwrap();
    vol.write(0, &b).unwrap();
    let stats = vol.noop_stats();
    assert_eq!(stats.skipped_writes, 0);
    // Latest write wins.
    assert_eq!(vol.read(0, 1).unwrap(), b);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn noop_skip_after_promotion() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let data = vec![0xaau8; 4 * 4096];

    vol.write(10, &data).unwrap();
    vol.flush_wal().unwrap(); // promote WAL → pending/
    // Body now lives in a pending segment file (BodySource::Local).
    vol.write(10, &data).unwrap();

    let stats = vol.noop_stats();
    assert_eq!(stats.skipped_writes, 1);
    assert_eq!(stats.skipped_bytes, 4 * 4096);
    assert_eq!(vol.read(10, 4).unwrap(), data);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn noop_skip_multi_block_same_content() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let data: Vec<u8> = (0..8 * 4096).map(|i| (i as u8).wrapping_mul(17)).collect();

    vol.write(32, &data).unwrap();
    vol.write(32, &data).unwrap();

    let stats = vol.noop_stats();
    assert_eq!(stats.skipped_writes, 1);
    assert_eq!(stats.skipped_bytes, 8 * 4096);
    assert_eq!(vol.read(32, 8).unwrap(), data);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn noop_skip_does_not_fire_on_fragmented_match() {
    // The hash check keys on a single LBA-map entry that exactly
    // covers the incoming range. When the existing content is split
    // into two entries whose concatenation matches, no single map
    // entry hashes the whole range — the skip cannot fire and the
    // write commits normally. (Earlier designs added a body
    // byte-compare tier to catch this; see
    // `docs/design/noop-write-skip.md § Why no byte-compare tier`.)
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let a = vec![0xa1u8; 4096];
    let b = vec![0xb2u8; 4096];

    vol.write(0, &a).unwrap();
    vol.write(1, &b).unwrap();

    let mut combined = Vec::with_capacity(8192);
    combined.extend_from_slice(&a);
    combined.extend_from_slice(&b);
    vol.write(0, &combined).unwrap();

    let stats = vol.noop_stats();
    assert_eq!(stats.skipped_writes, 0);
    // The fresh 8 KiB write replaces the two split entries with one.
    assert_eq!(vol.lbamap_len(), 1);
    // Read still returns the expected concatenation.
    assert_eq!(vol.read(0, 2).unwrap(), combined);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_rejects_empty() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let err = vol.write(0, &[]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_rejects_misaligned() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    let err = vol.write(0, &[0u8; 1000]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_sets_needs_promote_after_threshold() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Write 33 × 1 MiB of incompressible data to exceed FLUSH_THRESHOLD (32 MiB).
    // blake3 XOF yields bytes with no pattern lz4 can exploit, so the WAL
    // grows by the full payload size on each write.
    let mut block = vec![0u8; 1024 * 1024];
    for i in 0u64..33 {
        blake3::Hasher::new()
            .update(&i.to_le_bytes())
            .finalize_xof()
            .fill(&mut block);
        vol.write(i * 256, &block).unwrap();
    }

    // writes no longer auto-promote; needs_promote() should be true.
    assert!(
        vol.needs_promote(),
        "expected needs_promote() after 33 MiB of writes"
    );

    // Explicit flush_wal() should promote to pending/.
    vol.flush_wal().unwrap();

    // At least one segment should have been promoted to pending/.
    let has_pending = fs::read_dir(base.join("pending"))
        .unwrap()
        .any(|e| e.is_ok());
    assert!(
        has_pending,
        "expected at least one promoted segment in pending/"
    );

    // After promotion the WAL is left closed — the next write lazily
    // opens a fresh one. wal/ should therefore be empty until we write
    // again.
    let wal_count = fs::read_dir(base.join("wal"))
        .unwrap()
        .filter(|e| e.is_ok())
        .count();
    assert_eq!(
        wal_count, 0,
        "expected no WAL file after promotion (lazy open)"
    );
    vol.write(0, &vec![0xAB; 4096]).unwrap();
    let wal_count = fs::read_dir(base.join("wal"))
        .unwrap()
        .filter(|e| e.is_ok())
        .count();
    assert_eq!(
        wal_count, 1,
        "expected exactly one WAL file after first post-promote write"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn entry_count_threshold_triggers_needs_promote() {
    // FLUSH_ENTRY_THRESHOLD must trip even when the WAL byte size is far
    // below FLUSH_THRESHOLD. Use Zero writes — each appends a single
    // entry of zero body bytes — so we cap on entry count, not byte size.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Write FLUSH_ENTRY_THRESHOLD - 1 zero entries, each one block
    // wide at a unique LBA. After this the WAL is one entry below
    // the cap; needs_promote() must still return false.
    for i in 0..(FLUSH_ENTRY_THRESHOLD as u64 - 1) {
        vol.write_zeroes(i, 1).unwrap();
    }
    assert!(
        !vol.needs_promote(),
        "needs_promote() should be false at {} entries (cap is {})",
        FLUSH_ENTRY_THRESHOLD - 1,
        FLUSH_ENTRY_THRESHOLD,
    );

    // One more entry pushes the WAL to exactly FLUSH_ENTRY_THRESHOLD;
    // needs_promote() must now return true even though WAL bytes are
    // a tiny fraction of FLUSH_THRESHOLD.
    vol.write_zeroes(FLUSH_ENTRY_THRESHOLD as u64 - 1, 1)
        .unwrap();
    assert!(
        vol.needs_promote(),
        "needs_promote() should be true at {} entries",
        FLUSH_ENTRY_THRESHOLD,
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn recovery_rebuilds_lbamap() {
    let base = keyed_temp_dir();

    // Write two blocks, fsync, then drop (simulates clean shutdown before promotion).
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &vec![1u8; 4096]).unwrap();
        vol.write(1, &vec![2u8; 4096]).unwrap();
        vol.fsync().unwrap();
    }

    // Reopen — lbamap should contain both blocks.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.lbamap_len(), 2);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn read_unwritten_returns_zeros() {
    let base = keyed_temp_dir();
    let vol = Volume::open(&base, &base).unwrap();
    let data = vol.read(0, 4).unwrap();
    assert_eq!(data.len(), 4 * 4096);
    assert!(data.iter().all(|&b| b == 0));
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_zeroes_reads_back_as_zeros() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Write real data, then zero it out.
    vol.write(0, &vec![0xabu8; 4096]).unwrap();
    vol.write_zeroes(0, 4).unwrap();

    let result = vol.read(0, 4).unwrap();
    assert_eq!(result.len(), 4 * 4096);
    assert!(result.iter().all(|&b| b == 0));

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_zeroes_no_data_in_segment() {
    // After write_zeroes + promote, the segment has a zero entry with no body bytes.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write_zeroes(0, 16).unwrap();
    vol.flush_wal().unwrap();

    let seg_path = segment::collect_segment_files(&base.join("pending"))
        .unwrap()
        .into_iter()
        .next()
        .expect("expected one pending segment");

    let (_, entries, _) = segment::read_segment_index(&seg_path).unwrap();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.kind, segment::EntryKind::Zero);
    assert_eq!(e.stored_length, 0);
    assert_eq!(e.start_lba, 0);
    assert_eq!(e.lba_length, 16);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_after_zeroes_overrides() {
    // Data written after write_zeroes should be readable.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write_zeroes(0, 4).unwrap();
    let payload = vec![0x77u8; 4096];
    vol.write(0, &payload).unwrap();

    let result = vol.read(0, 1).unwrap();
    assert_eq!(result, payload);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_zeroes_survives_wal_recovery() {
    let base = keyed_temp_dir();

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write_zeroes(5, 8).unwrap();
        vol.fsync().unwrap();
        // Drop without promoting — WAL remains.
    }

    // Reopen: WAL is replayed; zeroed range should read as zeros.
    let vol = Volume::open(&base, &base).unwrap();
    let result = vol.read(5, 8).unwrap();
    assert!(result.iter().all(|&b| b == 0));

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn write_zeroes_masks_ancestor_data() {
    // An explicit zero in the child masks ancestor data at those LBAs.
    let by_id = temp_dir();
    let ancestor_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&ancestor_dir);

    // Write data in ancestor, promote, snapshot.
    {
        let mut vol = Volume::open(&ancestor_dir, &by_id).unwrap();
        vol.write(0, &vec![0xbbu8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.snapshot().unwrap();
    }

    // Fork and zero the LBA in the child.
    fork_volume(&child_dir, &ancestor_dir).unwrap();
    let mut child_vol = Volume::open(&child_dir, &by_id).unwrap();
    child_vol.write_zeroes(0, 1).unwrap();

    let result = child_vol.read(0, 1).unwrap();
    assert!(
        result.iter().all(|&b| b == 0),
        "zero extent should mask ancestor data"
    );

    fs::remove_dir_all(by_id).unwrap();
}

#[test]
fn read_written_data_same_session() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let payload = vec![0x42u8; 4096];
    vol.write(5, &payload).unwrap();

    // Written block reads back correctly.
    let result = vol.read(5, 1).unwrap();
    assert_eq!(result, payload);

    // Adjacent unwritten blocks are zero.
    let before = vol.read(4, 1).unwrap();
    assert!(before.iter().all(|&b| b == 0));

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn read_multi_block_extent() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Write 4 blocks with distinct fill bytes so we can verify each block.
    let mut payload = Vec::with_capacity(4 * 4096);
    for fill in [0xAAu8, 0xBB, 0xCC, 0xDD] {
        payload.extend_from_slice(&[fill; 4096]);
    }
    vol.write(10, &payload).unwrap();

    let result = vol.read(10, 4).unwrap();
    assert_eq!(result, payload);

    // Reading a sub-range within the extent.
    let mid = vol.read(11, 2).unwrap();
    assert_eq!(mid, payload[4096..3 * 4096]);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn read_after_promote() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let payload = vec![0x55u8; 4096];
    vol.write(0, &payload).unwrap();
    vol.promote_for_test().unwrap();

    // After promotion, data lives in pending/<ulid>; reads must still work.
    let result = vol.read(0, 1).unwrap();
    assert_eq!(result, payload);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn read_after_reopen() {
    let base = keyed_temp_dir();

    let payload = vec![0x77u8; 4096];
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(3, &payload).unwrap();
        vol.fsync().unwrap();
    }

    // Reopen: WAL recovery must restore both the LBA map and extent index.
    let vol = Volume::open(&base, &base).unwrap();
    let result = vol.read(3, 1).unwrap();
    assert_eq!(result, payload);

    fs::remove_dir_all(base).unwrap();
}

/// Regression: compressed WAL entries must be promoted with the correct
/// SegmentFlags::COMPRESSED so reads after recovery+promote work.
///
/// WalFlags::COMPRESSED=0x01; SegmentFlags::COMPRESSED=0x04.
/// recover_wal must translate between them before calling new_data().
#[test]
fn compressed_entry_survives_recover_and_promote() {
    let base = keyed_temp_dir();

    // Write compressible data (zeros compress very well).
    let payload = vec![0u8; 4096];
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &payload).unwrap();
        vol.fsync().unwrap();
        // Drop without promoting — WAL contains the compressed entry.
    }

    // Reopen (recover_wal runs) then promote (writes segment).
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Reopen again and read — must not fail with "failed to fill whole buffer".
    let vol = Volume::open(&base, &base).unwrap();
    let result = vol.read(0, 1).unwrap();
    assert_eq!(result, payload);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn ulid_is_unique_and_sortable() {
    let u1 = Ulid::new().to_string();
    let u2 = Ulid::new().to_string();
    assert_eq!(u1.len(), 26);
    assert_ne!(u1, u2);
    // ULIDs generated in sequence should sort correctly (same millisecond
    // is not guaranteed, but two different values prove uniqueness).
}

#[test]
fn recovery_after_promotion() {
    // Write enough to trigger a promotion, drop, reopen — the LBA map must
    // be rebuilt from both pending/ segments and the remaining WAL.
    let base = keyed_temp_dir();

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        let block = vec![0u8; 1024 * 1024]; // 1 MiB = 256 LBAs
        for i in 0u64..33 {
            vol.write(i * 256, &block).unwrap();
        }
        vol.fsync().unwrap();
    }

    // All 33 extents should survive across the promotion boundary.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.lbamap_len(), 33);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn promotion_after_wal_recovery() {
    // Write to the WAL, drop (simulating a crash), reopen (WAL recovery),
    // promote, then reopen again — verifies that pending_entries is correctly
    // rebuilt from the recovered WAL so the segment contains the pre-crash writes.
    let base = keyed_temp_dir();

    // Phase 1: write two blocks, fsync, drop.
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &vec![1u8; 4096]).unwrap();
        vol.write(1, &vec![2u8; 4096]).unwrap();
        vol.fsync().unwrap();
    }

    // Phase 2: recover and immediately promote.
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.lbamap_len(), 2); // confirm recovery
        vol.promote_for_test().unwrap();
    }

    // Phase 3: reopen — both blocks must now come from the pending/ segment.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.lbamap_len(), 2);

    // Confirm the promoted segment landed correctly: one file in pending/.
    let pending_count = fs::read_dir(base.join("pending"))
        .unwrap()
        .filter(|e| e.is_ok())
        .count();
    assert_eq!(pending_count, 1, "expected one segment file in pending/");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn wal_deleted_when_pending_segment_exists() {
    // Simulate a crash between the segment rename and the WAL delete:
    // both wal/<ulid> and pending/<ulid> exist. On reopen, the WAL must
    // be silently discarded and data read from the committed segment.
    let base = keyed_temp_dir();

    // Phase 1: write two blocks and promote so a segment lands in pending/.
    let ulid;
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &vec![0xaau8; 4096]).unwrap();
        vol.write(1, &vec![0xbbu8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        // Grab the segment ULID (there is exactly one file in pending/).
        let entry = fs::read_dir(base.join("pending"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let filename = entry.file_name();
        ulid = filename.to_string_lossy().into_owned();
    }

    // Simulate the crash: copy the segment back as a WAL file so both exist.
    fs::copy(
        base.join("pending").join(&ulid),
        base.join("wal").join(&ulid),
    )
    .unwrap();

    // Reopen — should delete the stale WAL and load cleanly from the segment.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.lbamap_len(), 2);
    assert!(
        vol.read(0, 1).unwrap().iter().all(|&b| b == 0xaa),
        "LBA 0 should be 0xaa"
    );
    assert!(
        vol.read(1, 1).unwrap().iter().all(|&b| b == 0xbb),
        "LBA 1 should be 0xbb"
    );
    // The stale WAL file should be gone.
    assert!(
        !base.join("wal").join(&ulid).exists(),
        "stale WAL was not removed"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn recovery_replays_all_wals_promoting_non_latest() {
    // Multiple WAL files on disk — e.g. left by a crash between
    // `segment::write_and_commit` and the old-WAL unlink, or
    // produced by the upcoming off-actor worker — must be
    // collapsed back to a single active WAL before `Volume::open`
    // returns. Every non-latest WAL is promoted to a fresh pending
    // segment; the highest-ULID WAL stays active.
    let base = keyed_temp_dir();

    // Bootstrap to create the standard directory layout + keypair.
    // The bootstrap open leaves an empty WAL that we then strip so
    // we can build our own two-WAL state from scratch.
    {
        let _vol = Volume::open(&base, &base).unwrap();
    }
    let wal_dir = base.join("wal");
    for entry in fs::read_dir(&wal_dir).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }

    // Two ULIDs with a strict ordering. Fixed strings keep the
    // test deterministic independently of the system clock.
    let low_ulid = Ulid::from_string("01AAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let high_ulid = Ulid::from_string("01BBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
    assert!(low_ulid < high_ulid);

    // Low WAL: one DATA record covering LBA 0.
    let payload_low = vec![0x11u8; 4096];
    let hash_low = blake3::hash(&payload_low);
    {
        let mut wl = writelog::WriteLog::create(&wal_dir.join(low_ulid.to_string())).unwrap();
        wl.append_data(0, 1, &hash_low, writelog::WalFlags::empty(), &payload_low)
            .unwrap();
        wl.fsync().unwrap();
    }

    // High WAL: one DATA record covering LBA 1.
    let payload_high = vec![0x22u8; 4096];
    let hash_high = blake3::hash(&payload_high);
    {
        let mut wl = writelog::WriteLog::create(&wal_dir.join(high_ulid.to_string())).unwrap();
        wl.append_data(1, 1, &hash_high, writelog::WalFlags::empty(), &payload_high)
            .unwrap();
        wl.fsync().unwrap();
    }

    // Reopen — recovery must promote `low_ulid` to a fresh segment
    // and keep `high_ulid` as the active WAL.
    let vol = Volume::open(&base, &base).unwrap();

    // Exactly one WAL remains: the high one.
    let wal_files: Vec<_> = fs::read_dir(&wal_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
        .collect();
    assert_eq!(
        wal_files.len(),
        1,
        "expected one active WAL after recovery, got {wal_files:?}"
    );
    assert_eq!(wal_files[0], high_ulid.to_string());

    // Exactly one segment in pending/ — the recovery-promoted low
    // WAL, at a freshly-minted ULID strictly above the wal floor.
    let pending_files: Vec<_> = fs::read_dir(base.join("pending"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().into_string().unwrap()))
        .filter(|n| !n.ends_with(".tmp"))
        .collect();
    assert_eq!(
        pending_files.len(),
        1,
        "expected one recovery-promoted segment in pending/, got {pending_files:?}"
    );
    let seg_ulid = Ulid::from_string(&pending_files[0]).unwrap();
    assert!(
        seg_ulid > high_ulid,
        "recovery-promoted segment ULID {seg_ulid} must sort above wal floor {high_ulid}"
    );

    // Both LBAs read back correctly. LBA 0 comes from the promoted
    // segment; LBA 1 from the active WAL's pending_entries.
    assert_eq!(vol.read(0, 1).unwrap(), payload_low);
    assert_eq!(vol.read(1, 1).unwrap(), payload_high);
    assert_eq!(vol.lbamap_len(), 2);

    fs::remove_dir_all(base).unwrap();
}

// --- durability guarantee tests ---
//
// These tests make the crash-recovery guarantees from docs/formats.md explicit
// and executable. They simulate the intermediate filesystem states that can
// arise from a machine crash at each step of the promotion commit sequence,
// and verify that Volume::open() recovers correctly in each case.
//
// What these tests cannot cover: whether sync_data() / fsync_dir() actually
// flush to physical media. That requires hardware fault injection (dm-flakey,
// CrashMonkey, etc.) and is out of scope for a unit test suite.

#[test]
fn recovery_reads_data_after_promotion_and_reopen() {
    // Guarantee: after flush_wal() completes (WAL promoted to pending/),
    // a subsequent Volume::open() reads the correct data from the segment.
    // This covers the common path: crash after a guest fsync, before the
    // coordinator uploads the segment to S3.
    let base = keyed_temp_dir();

    let payload_a = vec![0xAAu8; 4096];
    let payload_b = vec![0xBBu8; 4096];
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &payload_a).unwrap();
        vol.write(1, &payload_b).unwrap();
        // promote_for_test flushes the WAL to pending/ and opens a fresh WAL.
        vol.promote_for_test().unwrap();
        // Drop without explicit shutdown — simulates a process crash after promotion.
    }

    // On reopen, data must come from the pending/ segment.
    // The fresh empty WAL (opened after promotion) contributes nothing.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), payload_a);
    assert_eq!(vol.read(1, 1).unwrap(), payload_b);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn recovery_removes_tmp_orphans() {
    // Guarantee: a .tmp file left in pending/ by a crashed segment write
    // (crash between write_segment and rename — the rename never committed)
    // is removed by Volume::open() and does not affect recovery.
    // The WAL is intact as a fallback and is replayed normally.
    let base = keyed_temp_dir();

    let payload = vec![0xCCu8; 4096];
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &payload).unwrap();
        vol.fsync().unwrap();
        // Drop with WAL intact — simulates crash before/during promotion.
    }

    // Simulate a crash mid-promotion: a .tmp file exists in pending/ but
    // no completed segment (the rename never happened).
    let orphan = base.join("pending").join("01AAAAAAAAAAAAAAAAAAAAAAAAA.tmp");
    fs::write(&orphan, b"incomplete segment bytes").unwrap();

    // Recovery must succeed, data must be correct, and the orphan removed.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.lbamap_len(), 1);
    assert_eq!(vol.read(0, 1).unwrap(), payload);
    assert!(!orphan.exists(), ".tmp orphan should be cleaned up on open");

    fs::remove_dir_all(base).unwrap();
}

// --- compression helper unit tests ---

/// Build a 4096-byte pseudo-random block deterministic in `seed`.
///
/// Output is a blake3 XOF stream — the bytes have no exploitable pattern
/// for lz4, so `maybe_compress` will fail the 1.5× ratio gate and the
/// volume will store them raw.
fn high_entropy_block(seed: u8) -> Vec<u8> {
    let mut out = vec![0u8; 4096];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut out);
    out
}

#[test]
fn maybe_compress_compresses_compressible_data() {
    // All-zeros compresses to almost nothing.
    let data = vec![0u8; 4096];
    let compressed = maybe_compress(&data).expect("expected compression to succeed");
    // Must achieve at least 1.5× ratio.
    assert!(compressed.len() * MIN_COMPRESSION_RATIO_NUM / MIN_COMPRESSION_RATIO_DEN < data.len());
}

#[test]
fn maybe_compress_skips_incompressible_data() {
    // High-entropy permutation: lz4 cannot compress it below the 1.5× ratio.
    let data = high_entropy_block(0);
    assert!(maybe_compress(&data).is_none());
}

// --- volume read/write tests for compressed and uncompressed paths ---

#[test]
fn read_incompressible_data() {
    // High-entropy data must not be compressed, and must read back correctly.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let payload = high_entropy_block(0x5A);
    assert!(
        maybe_compress(&payload).is_none(),
        "test data must be incompressible"
    );

    vol.write(0, &payload).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), payload);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn compressed_and_uncompressed_extents_coexist() {
    // Write one compressible and one incompressible extent; both must read back correctly.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let compressible = vec![0xCCu8; 4096];
    let incompressible = high_entropy_block(0xA3);

    vol.write(0, &compressible).unwrap();
    vol.write(1, &incompressible).unwrap();

    assert_eq!(vol.read(0, 1).unwrap(), compressible);
    assert_eq!(vol.read(1, 1).unwrap(), incompressible);

    fs::remove_dir_all(base).unwrap();
}

// --- write-path dedup tests ---

#[test]
fn dedup_write_same_data_same_lba() {
    // Writing identical data to the same LBA twice: second write is a dedup hit.
    // The LBA map must have exactly one entry, reads must return the correct data.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0x42u8; 4096];
    vol.write(0, &data).unwrap();
    vol.write(0, &data).unwrap();

    assert_eq!(vol.lbamap_len(), 1);
    assert_eq!(vol.read(0, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn dedup_write_same_data_different_lba() {
    // Identical data written to two different LBAs: second write is a dedup hit.
    // Both LBA entries exist in the map; reads return the correct data from both.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0x77u8; 4096];
    vol.write(0, &data).unwrap();
    vol.write(5, &data).unwrap();

    assert_eq!(vol.lbamap_len(), 2);
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(5, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn dedup_ref_survives_promote_and_reopen() {
    // Write data, promote so it lands in pending/, then write the same data
    // to a new LBA (full DATA record; the canonical keeps owning the hash).
    // Reopen and verify both LBAs read back.
    let base = keyed_temp_dir();

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        let data = vec![0xABu8; 4096];
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        // Second write: same data, different LBA — resolves through the
        // promoted canonical on read.
        vol.write(1, &data).unwrap();
        vol.fsync().unwrap();
    }

    let vol = Volume::open(&base, &base).unwrap();
    let data = vec![0xABu8; 4096];
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(1, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn dedup_ref_in_segment_survives_reopen() {
    // Write data, promote, write same data, promote again so formation
    // mints a DedupRef into the second segment. Reopen and verify reads.
    let base = keyed_temp_dir();

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        let data = vec![0xCDu8; 4096];
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(1, &data).unwrap();
        vol.promote_for_test().unwrap(); // minted as DedupRef here
    }

    let vol = Volume::open(&base, &base).unwrap();
    let data = vec![0xCDu8; 4096];
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(1, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn same_epoch_duplicate_minted_as_dedup_ref_at_formation() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Incompressible so the stored body is full-size and the WAL carries
    // real bytes for both writes.
    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.write(4, &data).unwrap();

    // The write path performs no dedup: both pending entries carry bodies.
    assert!(
        vol.pending_entries
            .iter()
            .all(|e| e.kind == segment::EntryKind::Data),
        "write path must append full Data entries for duplicate content"
    );
    assert_eq!(vol.dedup_mint_stats().minted_entries, 0);

    vol.promote_for_test().unwrap();

    // Formation classified the duplicate: one Data owner + one DedupRef,
    // same hash, in the same segment.
    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_path = base.join("pending").join(ulids[0].to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    let hash = blake3::hash(&data);
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.hash == hash));
    let owner = entries
        .iter()
        .find(|e| e.kind == segment::EntryKind::Data)
        .expect("one Data owner");
    let minted = entries
        .iter()
        .find(|e| e.kind == segment::EntryKind::DedupRef)
        .expect("one minted DedupRef");
    assert_eq!(owner.start_lba, 0);
    assert_eq!(minted.start_lba, 4);

    let stats = vol.dedup_mint_stats();
    assert_eq!(stats.minted_entries, 1);
    assert_eq!(
        stats.wal_body_bytes, owner.stored_length as u64,
        "foregone WAL bytes are the duplicate's stored body"
    );

    // The extent index owner is the segment's Data entry, not a stale WAL
    // location (the pre-promote CAS pairing must survive the duplicate).
    let loc = vol.extent_index.lookup(&hash).expect("hash resolvable");
    assert_eq!(loc.segment_id, ulids[0]);

    assert_eq!(vol.read(0, 2).unwrap(), data);
    assert_eq!(vol.read(4, 2).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn duplicate_of_promoted_canonical_minted_at_formation() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..4096).map(|i| (i * 11 + 3) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();
    let s1 = pending_ulids(&base)[0];

    vol.write(10, &data).unwrap();
    vol.promote_for_test().unwrap();

    let s2 = *pending_ulids(&base).iter().find(|u| **u != s1).unwrap();
    let seg_path = base.join("pending").join(s2.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, segment::EntryKind::DedupRef);
    assert_eq!(vol.dedup_mint_stats().minted_entries, 1);

    // The canonical stays owned by the first segment.
    let loc = vol.extent_index.lookup(&blake3::hash(&data)).unwrap();
    assert_eq!(loc.segment_id, s1);

    assert_eq!(vol.read(10, 1).unwrap(), data);
    fs::remove_dir_all(base).unwrap();
}

fn set_journal_ranges(base: &Path, ranges: Vec<(u64, u64)>) {
    let mut cfg = crate::config::VolumeConfig::read(base).unwrap();
    cfg.journal_ranges = Some(crate::journal::JournalRanges::new(ranges));
    cfg.write(base).unwrap();
}

/// Write the synthetic ext4 image's populated blocks onto the volume —
/// the in-test equivalent of running mkfs on the device.
fn write_ext4_image(vol: &mut Volume, img: &[u8]) {
    for (i, block) in img.chunks(4096).enumerate() {
        if block.iter().any(|&b| b != 0) {
            vol.write(i as u64, block).unwrap();
        }
    }
}

/// Mid-session derivation end to end: a fresh volume is never-derived,
/// polls harmlessly while blank, flips the window live at the first
/// promote take after the filesystem appears, and classifies with the
/// activation marker so pre-flip stamps survive rebuild. The next open
/// clears the marker and reclassifies uniformly.
#[test]
fn format_mid_session_flips_window_at_promote_take() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    assert!(
        crate::config::VolumeConfig::read(&base)
            .unwrap()
            .journal_ranges
            .is_none(),
        "fresh volume must start never-derived",
    );

    // Pre-format write into what will become the journal window: the
    // blank-device poll at this promote must not derive anything.
    let pre_flip = high_entropy_block(0xD1);
    vol.write(40, &pre_flip).unwrap();
    vol.promote_for_test().unwrap();
    assert!(
        crate::config::VolumeConfig::read(&base)
            .unwrap()
            .journal_ranges
            .is_none(),
        "no filesystem yet — still never-derived",
    );

    write_ext4_image(&mut vol, &crate::ext4_scan::test_support::journal_image());
    vol.promote_for_test().unwrap();

    let cfg = crate::config::VolumeConfig::read(&base).unwrap();
    let ranges = cfg.journal_ranges.expect("window derived at take");
    assert_eq!(ranges.as_slice(), &[(40, 8), (56, 4)]);
    let activation = cfg.journal_activation.expect("activation marker persisted");
    assert_eq!(vol.journal.activation, Some(activation));
    assert_eq!(vol.journal.ranges, ranges);

    // The pre-flip window-LBA entry keeps its non-journal stamp: its
    // segment sorts below the activation marker.
    let pre_hash = blake3::hash(&pre_flip);
    let pre_loc = vol.extent_index.lookup(&pre_hash).unwrap().clone();
    assert!(!pre_loc.journal);
    assert!(pre_loc.segment_id < activation);

    // A post-flip window write partitions into a journal segment above
    // the marker.
    let post_flip = high_entropy_block(0xD2);
    vol.write(56, &post_flip).unwrap();
    let home = high_entropy_block(0xD3);
    vol.write(200, &home).unwrap();
    vol.promote_for_test().unwrap();
    let post_loc = vol
        .extent_index
        .lookup(&blake3::hash(&post_flip))
        .unwrap()
        .clone();
    assert!(post_loc.journal);
    assert!(post_loc.segment_id > activation);

    // A mid-session rebuild honouring the marker (what the coordinator's
    // GC pass and a readonly open do) reproduces the live stamps.
    let window = crate::journal::JournalWindow {
        ranges: ranges.clone(),
        activation: Some(activation),
    };
    let disk = extentindex::rebuild(&[(base.clone(), None)], &window).unwrap();
    assert!(!disk.lookup(&pre_hash).unwrap().journal);
    assert!(disk.lookup(&blake3::hash(&post_flip)).unwrap().journal);

    // Reopen: marker cleared, uniform reclassification under the plain
    // window heals the pre-flip stamp.
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert!(
        crate::config::VolumeConfig::read(&base)
            .unwrap()
            .journal_activation
            .is_none(),
        "open must clear the activation marker",
    );
    assert!(vol.extent_index.lookup(&pre_hash).unwrap().journal);

    fs::remove_dir_all(base).unwrap();
}

/// An authoritative "no internal journal" parse persists as
/// derived-empty — distinct from never-derived — and ends the polling.
#[test]
fn derived_empty_window_persists_and_stops_polling() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let mut img = crate::ext4_scan::test_support::journal_image();
    // Clear COMPAT_HAS_JOURNAL: valid ext4, no internal journal.
    crate::ext4_scan::test_support::put_u32(&mut img, 1024 + 0x5c, 0);
    write_ext4_image(&mut vol, &img);
    vol.promote_for_test().unwrap();

    let cfg = crate::config::VolumeConfig::read(&base).unwrap();
    assert_eq!(
        cfg.journal_ranges,
        Some(crate::journal::JournalRanges::default()),
        "authoritative empty answer must persist as derived",
    );
    assert_eq!(cfg.journal_activation, None);
    assert!(vol.journal_derived);
    assert!(vol.journal.ranges.is_empty());

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn journal_write_loses_ownership_to_same_epoch_home_write() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    // Journal copy first (jbd2 commit order), home checkpoint second,
    // same epoch. The write path re-owns the hash to the home copy, so
    // formation mints the journal entry as the DedupRef — canonical
    // bytes live at the stable LBA, the journal claim dies at wrap.
    let data: Vec<u8> = (0..4096).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(100, &data).unwrap();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    // Segregation splits the epoch: the home copy owns as Data in the
    // data segment (lower ULID), the journal copy is the DedupRef in the
    // journal segment (higher ULID) — pointing backward as DedupRefs
    // must.
    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 2);
    let (data_seg, journal_seg) = (ulids[0], ulids[1]);
    let read_entries = |seg: Ulid| {
        let seg_path = base.join("pending").join(seg.to_string());
        let (_, entries, _) =
            segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
        entries
    };
    let data_entries = read_entries(data_seg);
    assert_eq!(data_entries.len(), 1);
    assert_eq!(data_entries[0].kind, segment::EntryKind::Data);
    assert_eq!(data_entries[0].start_lba, 0, "home copy owns");
    let journal_entries = read_entries(journal_seg);
    assert_eq!(journal_entries.len(), 1);
    assert_eq!(journal_entries[0].kind, segment::EntryKind::DedupRef);
    assert_eq!(
        journal_entries[0].start_lba, 100,
        "journal copy is the DedupRef"
    );

    let seg = data_seg;
    let loc = vol.extent_index.lookup(&blake3::hash(&data)).unwrap();
    assert_eq!(loc.segment_id, seg);
    assert!(!loc.journal);

    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(100, 1).unwrap(), data);

    // Rebuild picks the same owner.
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    let loc = vol.extent_index.lookup(&blake3::hash(&data)).unwrap();
    assert_eq!(loc.segment_id, seg);
    assert!(!loc.journal);
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(100, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn home_write_displaces_committed_journal_canonical() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    // Journal copy commits in epoch 1 and becomes canonical; the home
    // checkpoint write lands in epoch 2 and displaces it.
    let data: Vec<u8> = (0..4096).map(|i| (i * 11 + 5) as u8).collect();
    vol.write(100, &data).unwrap();
    vol.promote_for_test().unwrap();
    let s1 = pending_ulids(&base)[0];
    let hash = blake3::hash(&data);
    let loc = vol.extent_index.lookup(&hash).unwrap();
    assert_eq!(loc.segment_id, s1);
    assert!(loc.journal, "journal copy owns while no stable copy exists");

    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();
    let s2 = *pending_ulids(&base).iter().find(|u| **u != s1).unwrap();

    // The epoch-2 segment carries a full Data owner, not a DedupRef
    // into the journal-claimed body.
    let seg_path = base.join("pending").join(s2.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, segment::EntryKind::Data);

    let loc = vol.extent_index.lookup(&hash).unwrap();
    assert_eq!(
        loc.segment_id, s2,
        "home copy displaced the journal canonical"
    );
    assert!(!loc.journal);

    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(100, 1).unwrap(), data);

    // Rebuild walks s1 (lower ULID, journal) before s2 and still picks
    // s2 — the displacement rule is identical live and at rebuild.
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    let loc = vol.extent_index.lookup(&hash).unwrap();
    assert_eq!(loc.segment_id, s2, "rebuild agrees with the live path");
    assert!(!loc.journal);
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(100, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn journal_write_dedups_against_stable_canonical() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    // Home copy already canonical; a journal write of the same bytes
    // dedups against it (journal → stable direction is the good one).
    let data: Vec<u8> = (0..4096).map(|i| (i * 13 + 9) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();
    let s1 = pending_ulids(&base)[0];

    vol.write(100, &data).unwrap();
    vol.promote_for_test().unwrap();
    let s2 = *pending_ulids(&base).iter().find(|u| **u != s1).unwrap();

    let seg_path = base.join("pending").join(s2.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, segment::EntryKind::DedupRef);

    let loc = vol.extent_index.lookup(&blake3::hash(&data)).unwrap();
    assert_eq!(loc.segment_id, s1, "stable canonical keeps ownership");

    assert_eq!(vol.read(100, 1).unwrap(), data);
    fs::remove_dir_all(base).unwrap();
}

fn entry_lbas(base: &Path, vol: &Volume, seg: Ulid) -> Vec<u64> {
    let seg_path = base.join("pending").join(seg.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    entries.iter().map(|e| e.start_lba).collect()
}

#[test]
fn mixed_epoch_forms_data_and_journal_segments() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    let a: Vec<u8> = (0..4096).map(|i| (i * 3 + 1) as u8).collect();
    let b: Vec<u8> = (0..4096).map(|i| (i * 5 + 2) as u8).collect();
    let c: Vec<u8> = (0..4096).map(|i| (i * 7 + 4) as u8).collect();
    vol.write(0, &a).unwrap();
    vol.write(100, &b).unwrap();
    vol.write(5, &c).unwrap();
    vol.promote_for_test().unwrap();

    // One data segment (lower ULID) and one journal segment (higher).
    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 2, "mixed epoch forms a segment pair");
    let (data_seg, journal_seg) = (ulids[0], ulids[1]);
    let mut data_lbas = entry_lbas(&base, &vol, data_seg);
    data_lbas.sort_unstable();
    assert_eq!(data_lbas, vec![0, 5]);
    assert_eq!(entry_lbas(&base, &vol, journal_seg), vec![100]);

    assert_eq!(vol.read(0, 1).unwrap(), a);
    assert_eq!(vol.read(100, 1).unwrap(), b);
    assert_eq!(vol.read(5, 1).unwrap(), c);

    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), a);
    assert_eq!(vol.read(100, 1).unwrap(), b);
    assert_eq!(vol.read(5, 1).unwrap(), c);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn all_journal_epoch_forms_single_journal_segment() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    let a: Vec<u8> = (0..4096).map(|i| (i * 3 + 7) as u8).collect();
    let b: Vec<u8> = (0..4096).map(|i| (i * 5 + 9) as u8).collect();
    vol.write(100, &a).unwrap();
    vol.write(101, &b).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(
        ulids.len(),
        1,
        "all-journal epoch writes no empty data segment"
    );
    let mut lbas = entry_lbas(&base, &vol, ulids[0]);
    lbas.sort_unstable();
    assert_eq!(lbas, vec![100, 101]);

    assert_eq!(vol.read(100, 1).unwrap(), a);
    assert_eq!(vol.read(101, 1).unwrap(), b);

    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(100, 1).unwrap(), a);
    assert_eq!(vol.read(101, 1).unwrap(), b);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn failed_promote_restore_reparks_both_partitions() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    let a: Vec<u8> = (0..4096).map(|i| (i * 11 + 1) as u8).collect();
    let b: Vec<u8> = (0..4096).map(|i| (i * 13 + 2) as u8).collect();
    vol.write(0, &a).unwrap();
    vol.write(100, &b).unwrap();
    vol.gc_checkpoint_with_failed_flush_for_test().unwrap();

    assert_eq!(vol.read(0, 1).unwrap(), a, "read after restore");
    assert_eq!(vol.read(100, 1).unwrap(), b, "read after restore");

    vol.promote_for_test().unwrap();
    assert_eq!(pending_ulids(&base).len(), 2);
    assert_eq!(vol.read(0, 1).unwrap(), a);
    assert_eq!(vol.read(100, 1).unwrap(), b);

    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), a, "read after reopen");
    assert_eq!(vol.read(100, 1).unwrap(), b, "read after reopen");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn recovery_promote_partitions_journal_writes() {
    // A crash-leftover extra WAL holding both stable and journal writes
    // must partition at the recovery promote exactly like a live one.
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let a: Vec<u8> = (0..4096).map(|i| (i * 17 + 3) as u8).collect();
    let b: Vec<u8> = (0..4096).map(|i| (i * 19 + 5) as u8).collect();
    let fresh: Vec<u8> = (0..4096).map(|i| (i * 23 + 7) as u8).collect();

    let last_ulid = {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(2, &fresh).unwrap();
        vol.promote_for_test().unwrap();
        pending_ulids(&base)[0]
    };

    let mut mint = crate::ulid_mint::UlidMint::new(last_ulid);
    let wal_a_ulid = mint.next();
    let wal_b_ulid = mint.next();
    let mut wal_a =
        writelog::WriteLog::create(&base.join("wal").join(wal_a_ulid.to_string())).unwrap();
    wal_a
        .append_data(0, 1, &blake3::hash(&a), writelog::WalFlags::empty(), &a)
        .unwrap();
    wal_a
        .append_data(100, 1, &blake3::hash(&b), writelog::WalFlags::empty(), &b)
        .unwrap();
    drop(wal_a);
    let mut wal_b =
        writelog::WriteLog::create(&base.join("wal").join(wal_b_ulid.to_string())).unwrap();
    wal_b
        .append_data(
            4,
            1,
            &blake3::hash(&fresh),
            writelog::WalFlags::empty(),
            &fresh,
        )
        .unwrap();
    drop(wal_b);

    let vol = Volume::open(&base, &base).unwrap();
    // The extra WAL promoted into a data + journal segment pair.
    let ulids = pending_ulids(&base);
    assert!(
        ulids
            .iter()
            .any(|u| entry_lbas(&base, &vol, *u) == vec![100]),
        "journal write promoted into its own segment"
    );
    assert_eq!(vol.read(0, 1).unwrap(), a);
    assert_eq!(vol.read(100, 1).unwrap(), b);
    assert_eq!(vol.read(4, 1).unwrap(), fresh);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn journal_lba_never_deltas() {
    let base = keyed_temp_dir();
    set_journal_ranges(&base, vec![(100, 16)]);
    let mut vol = Volume::open(&base, &base).unwrap();

    // A sealed same-LBA near-duplicate is the delta tier's prime case;
    // on a journal LBA it must stay Data (journal partition is never
    // delta'd, and journal runs are excluded from the source map).
    vol.write(100, &delta_base_block(9)).unwrap();
    vol.snapshot().unwrap();

    let variant = delta_variant_block(9, 0x5A);
    vol.write(100, &variant).unwrap();
    vol.promote_for_test().unwrap();

    let seg = *pending_ulids(&base).last().unwrap();
    assert_eq!(
        pending_entry_kinds(&base, &vol, seg),
        vec![segment::EntryKind::Data],
        "journal-window entry must not be minted as Delta"
    );
    assert_eq!(vol.read(100, 1).unwrap(), variant);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn failed_promote_restore_keeps_formation_minted_dedup_ref() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..4096).map(|i| (i * 13 + 7) as u8).collect();
    let fresh: Vec<u8> = (0..4096).map(|i| (i * 17 + 5) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    // Duplicate + fresh content in one WAL epoch, taken through a failed
    // flush: take classifies the duplicate, restore re-parks both entries.
    vol.write(4, &data).unwrap();
    vol.write(6, &fresh).unwrap();
    vol.gc_checkpoint_with_failed_flush_for_test().unwrap();

    assert_eq!(vol.read(4, 1).unwrap(), data, "read after restore");
    assert_eq!(vol.read(6, 1).unwrap(), fresh, "read after restore");

    // The retried promote writes the segment with the converted entry.
    vol.promote_for_test().unwrap();
    assert_eq!(vol.read(4, 1).unwrap(), data);
    assert_eq!(vol.read(6, 1).unwrap(), fresh);

    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(4, 1).unwrap(), data, "read after reopen");
    assert_eq!(vol.read(6, 1).unwrap(), fresh, "read after reopen");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn recovery_promote_of_extra_wal_classifies_dedup() {
    // A crash can leave multiple WAL files; open promotes every non-latest
    // WAL directly. That path must classify duplicates like a live promote.
    let base = keyed_temp_dir();
    let data: Vec<u8> = (0..4096).map(|i| (i * 23 + 9) as u8).collect();
    let fresh: Vec<u8> = (0..4096).map(|i| (i * 29 + 17) as u8).collect();

    let canonical_ulid = {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        pending_ulids(&base)[0]
    };

    // Two hand-written WALs: the older holds a duplicate of the canonical,
    // the newer holds fresh content and stays the live WAL after open.
    let mut mint = crate::ulid_mint::UlidMint::new(canonical_ulid);
    let wal_a_ulid = mint.next();
    let wal_b_ulid = mint.next();
    let mut wal_a =
        writelog::WriteLog::create(&base.join("wal").join(wal_a_ulid.to_string())).unwrap();
    wal_a
        .append_data(
            8,
            1,
            &blake3::hash(&data),
            writelog::WalFlags::empty(),
            &data,
        )
        .unwrap();
    drop(wal_a);
    let mut wal_b =
        writelog::WriteLog::create(&base.join("wal").join(wal_b_ulid.to_string())).unwrap();
    wal_b
        .append_data(
            12,
            1,
            &blake3::hash(&fresh),
            writelog::WalFlags::empty(),
            &fresh,
        )
        .unwrap();
    drop(wal_b);

    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(
        vol.dedup_mint_stats().minted_entries,
        1,
        "recovery promote of the extra WAL must classify the duplicate"
    );

    let recovery_seg = *pending_ulids(&base)
        .iter()
        .find(|u| **u != canonical_ulid)
        .expect("recovery-promoted segment in pending/");
    let seg_path = base.join("pending").join(recovery_seg.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, segment::EntryKind::DedupRef);

    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(8, 1).unwrap(), data);
    assert_eq!(vol.read(12, 1).unwrap(), fresh);

    fs::remove_dir_all(base).unwrap();
}

/// Distinct, incompressible 4 KiB block per seed (keyed-BLAKE3 stream) —
/// stays a body-section Data entry, the shape the delta tier converts.
fn delta_base_block(seed: u8) -> Vec<u8> {
    let mut out = vec![0u8; 4096];
    let mut hasher = blake3::Hasher::new_keyed(&[seed; 32]);
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        hasher.update(&(i as u64).to_le_bytes());
        chunk.copy_from_slice(&hasher.finalize().as_bytes()[..chunk.len()]);
        hasher.reset();
    }
    out
}

/// `delta_base_block(seed)` with the first 32 bytes overwritten — a
/// near-duplicate whose zstd-dict delta against the base is tiny.
fn delta_variant_block(seed: u8, tweak: u8) -> Vec<u8> {
    let mut out = delta_base_block(seed);
    out[..32].fill(tweak);
    out
}

fn pending_entry_kinds(base: &Path, vol: &Volume, seg: Ulid) -> Vec<segment::EntryKind> {
    let seg_path = base.join("pending").join(seg.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    entries.iter().map(|e| e.kind).collect()
}

#[test]
fn formation_deltas_post_seal_near_duplicate() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write(0, &delta_base_block(1)).unwrap();
    vol.snapshot().unwrap();

    let variant = delta_variant_block(1, 0x7E);
    vol.write(0, &variant).unwrap();
    vol.promote_for_test().unwrap();

    let seg = *pending_ulids(&base).last().unwrap();
    assert_eq!(
        pending_entry_kinds(&base, &vol, seg),
        vec![segment::EntryKind::Delta],
        "post-seal near-duplicate must be minted as a thin Delta at formation"
    );
    assert_eq!(vol.read(0, 1).unwrap(), variant, "delta read-back");

    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(
        vol.read(0, 1).unwrap(),
        variant,
        "delta read-back after reopen"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn formation_without_sealed_snapshot_stays_data() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write(0, &delta_base_block(2)).unwrap();
    vol.promote_for_test().unwrap();
    vol.write(0, &delta_variant_block(2, 0x11)).unwrap();
    vol.promote_for_test().unwrap();

    for seg in pending_ulids(&base) {
        for kind in pending_entry_kinds(&base, &vol, seg) {
            assert_eq!(kind, segment::EntryKind::Data, "no snapshot, no delta tier");
        }
    }

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn formation_skips_delta_when_source_body_evicted() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write(0, &delta_base_block(3)).unwrap();
    vol.snapshot().unwrap();

    // Evict the sealed source bodies (snapshot() promoted them into
    // cache/): the delta tier is best-effort and must fall through to a
    // plain Data entry.
    for entry in fs::read_dir(base.join("cache")).unwrap().flatten() {
        if entry.path().extension().is_some_and(|x| x == "body") {
            fs::remove_file(entry.path()).unwrap();
        }
    }

    let variant = delta_variant_block(3, 0x22);
    vol.write(0, &variant).unwrap();
    vol.promote_for_test().unwrap();

    let seg = *pending_ulids(&base).last().unwrap();
    assert_eq!(
        pending_entry_kinds(&base, &vol, seg),
        vec![segment::EntryKind::Data],
        "evicted source must skip conversion, never fetch"
    );
    assert_eq!(vol.read(0, 1).unwrap(), variant);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn formation_exact_hash_beats_delta() {
    // Post-seal write of bytes identical to a sealed extent at another
    // LBA: the exact tier mints a DedupRef and the delta tier never
    // sees the entry.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = delta_base_block(4);
    vol.write(0, &data).unwrap();
    vol.snapshot().unwrap();

    vol.write(8, &data).unwrap();
    vol.promote_for_test().unwrap();

    let sealed = pending_ulids(&base);
    let seg = *sealed.last().unwrap();
    assert_eq!(
        pending_entry_kinds(&base, &vol, seg),
        vec![segment::EntryKind::DedupRef],
        "exact-hash hit wins over any delta"
    );
    assert_eq!(vol.read(8, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn legacy_ref_wal_record_replays_and_promotes() {
    let base = keyed_temp_dir();
    let data: Vec<u8> = (0..4096).map(|i| (i * 19 + 11) as u8).collect();
    let hash = blake3::hash(&data);

    let canonical_ulid = {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        pending_ulids(&base)[0]
    };

    // Hand-write a WAL holding a REF record, as a binary with write-path
    // dedup would have left behind at a crash.
    let wal_ulid = crate::ulid_mint::UlidMint::new(canonical_ulid).next();
    let wal_path = base.join("wal").join(wal_ulid.to_string());
    let mut wal = writelog::WriteLog::create(&wal_path).unwrap();
    wal.append_ref(20, 1, &hash).unwrap();
    drop(wal);

    let mut vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(20, 1).unwrap(), data, "replayed REF resolves");
    vol.promote_for_test().unwrap();
    assert_eq!(
        vol.dedup_mint_stats().minted_entries,
        0,
        "replayed REF entries are already DedupRef; formation mints nothing"
    );
    assert_eq!(vol.read(20, 1).unwrap(), data, "read after promote");

    fs::remove_dir_all(base).unwrap();
}

// --- dedup-ref redact / promote regression tests ---

/// Helper: collect all pending segment ULIDs (excluding sidecars and tmps).
fn pending_ulids(base: &Path) -> Vec<ulid::Ulid> {
    let pending_dir = base.join("pending");
    let mut ulids: Vec<ulid::Ulid> = Vec::new();
    for entry in fs::read_dir(&pending_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.contains('.') {
            continue;
        }
        ulids.push(ulid::Ulid::from_string(&name).unwrap());
    }
    ulids.sort();
    ulids
}

/// Run `vol.repack()` and return the post-repack ULID for `input_ulid`
/// (input ULID on no-op, smallest fresh ULID on rewrite — repack
/// pre-mints `u_repack_i < u_flush`, so the rewrite output sorts below
/// any WAL-flush peer). For single-input test scenarios.
fn repack_for_input(vol: &mut Volume, base: &Path, input_ulid: ulid::Ulid) -> ulid::Ulid {
    use std::collections::HashSet;
    let pre: HashSet<_> = pending_ulids(base).into_iter().collect();
    vol.repack().unwrap();
    let post: HashSet<_> = pending_ulids(base).into_iter().collect();
    if post.contains(&input_ulid) {
        return input_ulid;
    }
    let mut fresh: Vec<_> = post.difference(&pre).copied().collect();
    fresh.sort();
    *fresh
        .first()
        .expect("expected at least one freshly-minted pending ULID after repack")
}

#[test]
fn repack_drops_hash_dead_data_entry() {
    // An entry whose LBA has been overwritten and whose hash is no longer
    // referenced anywhere must be dropped from `pending/<ulid>`'s index
    // entirely so deleted data never leaves the host. The surviving
    // segment contains only live entries; the dropped entry's body is
    // not in the file at all.
    // High-entropy data avoids compression below the inline threshold,
    // guaranteeing the entry lands in the body section (not inline).
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let secret: Vec<u8> = (0..8192).map(|i| (i * 17 + 31) as u8).collect();
    vol.write(0, &secret).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_ulid = ulids[0];

    // Overwrite LBA 0-1 with different content. Hash of `secret` is no
    // longer referenced anywhere → fully dead. Do not promote so the
    // overwrite stays in the WAL and the pending segment still holds the
    // now-dead entry.
    let replacement: Vec<u8> = (0..8192).map(|i| (i * 23 + 41) as u8).collect();
    vol.write(0, &replacement).unwrap();

    let secret_hash = blake3::hash(&secret);

    let new_ulid = repack_for_input(&mut vol, &base, seg_ulid);
    assert_ne!(
        new_ulid, seg_ulid,
        "slow-path redact must return a freshly minted ULID"
    );

    // Old pending file is removed; new ULID's file exists; no .tmp leftover.
    let pending_dir = base.join("pending");
    assert!(
        !pending_dir.join(seg_ulid.to_string()).exists(),
        "pending/<old_ulid> must be removed after redact"
    );
    let new_seg_path = pending_dir.join(new_ulid.to_string());
    assert!(
        new_seg_path.exists(),
        "pending/<new_ulid> must hold the rewritten segment"
    );
    assert!(
        !pending_dir.join(format!("{}.tmp", new_ulid)).exists(),
        "no .tmp should survive redact"
    );

    let (_, entries, _) =
        segment::read_and_verify_segment_index(&new_seg_path, &vol.verifying_key).unwrap();
    assert!(
        entries.iter().all(|e| e.hash != secret_hash),
        "redact must drop the hash-dead entry from the index"
    );

    // The dropped secret's high-entropy bytes must not be findable
    // anywhere in the rewritten segment.
    let bytes = fs::read(&new_seg_path).unwrap();
    let needle: &[u8] = &secret[..64];
    assert!(
        bytes.windows(needle.len()).all(|w| w != needle),
        "dropped entry body bytes must not remain in the segment file"
    );

    let _ = replacement; // replacement is never flushed; used only to update lbamap

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn promote_segment_after_repack_produces_correct_idx_and_present() {
    // After redact + promote, the .idx contains DedupRef entries and the
    // .present bitset marks only Data entries as present.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0xDDu8; 4096];
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let after_first = pending_ulids(&base);
    let s1_ulid = after_first[0];

    vol.write(1, &data).unwrap(); // dedup hit
    vol.promote_for_test().unwrap();

    let after_second = pending_ulids(&base);
    let s2_ulid = *after_second.iter().find(|u| **u != s1_ulid).unwrap();

    // Promote S1 first (lower ULID) so we don't leave a lower-ULID pending
    // peer alongside the about-to-be-promoted S2 — that would trip the
    // pending-above-committed invariant. Production drain (`upload.rs`)
    // sorts pending by ULID for the same reason.
    vol.promote_segment(s1_ulid).unwrap();

    // Redact and promote S2 (simulating the coordinator drain path).
    repack_for_input(&mut vol, &base, s2_ulid);
    vol.promote_segment(s2_ulid).unwrap();

    // The .idx should exist and contain DedupRef entries.
    let idx_path = base.join("index").join(format!("{}.idx", s2_ulid));
    assert!(
        idx_path.exists(),
        "index/<ulid>.idx must exist after promote"
    );

    let (_, idx_entries, _) =
        segment::read_and_verify_segment_index(&idx_path, &vol.verifying_key).unwrap();
    assert!(
        idx_entries.iter().any(|e| e.kind == EntryKind::DedupRef),
        "idx should contain DedupRef entries"
    );

    // The .present bitset should mark DedupRef entries as not-present.
    let present_path = base.join("cache").join(format!("{}.present", s2_ulid));
    assert!(present_path.exists(), ".present must exist after promote");
    for (i, entry) in idx_entries.iter().enumerate() {
        let present = segment::check_present_bit(&present_path, i as u32).unwrap_or(false);
        if entry.kind.is_data() {
            assert!(present, "Data-shaped entry {i} should be marked present");
        } else if entry.kind == EntryKind::DedupRef {
            assert!(!present, "DedupRef entry {i} should NOT be marked present");
        }
    }

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn reads_work_after_repack_and_promote() {
    // After redact + promote, reads must still work correctly.
    // DedupRef reads go through the extent index to the canonical segment.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0xBBu8; 4096];
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let after_first = pending_ulids(&base);
    let s1_ulid = after_first[0];

    vol.write(1, &data).unwrap(); // dedup hit → DedupRef
    vol.promote_for_test().unwrap();

    let after_second = pending_ulids(&base);
    let s2_ulid = *after_second.iter().find(|u| **u != s1_ulid).unwrap();

    // Promote S1 first to keep pending ULIDs above committed ULIDs (the
    // pending-above-committed invariant production drain relies on).
    vol.promote_segment(s1_ulid).unwrap();
    repack_for_input(&mut vol, &base, s2_ulid);
    vol.promote_segment(s2_ulid).unwrap();

    assert_eq!(vol.read(0, 1).unwrap(), data, "LBA 0 after redact+promote");
    assert_eq!(vol.read(1, 1).unwrap(), data, "LBA 1 after redact+promote");

    // Also verify after reopen (extent index rebuilt from .idx files).
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data, "LBA 0 after reopen");
    assert_eq!(vol.read(1, 1).unwrap(), data, "LBA 1 after reopen");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_idempotent() {
    // The first redact rewrites the segment under a freshly minted
    // ULID and removes the input. A second redact against the new
    // ULID is a no-op (no hash-dead entries remain) and returns the
    // same ULID unchanged.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let secret: Vec<u8> = (0..8192).map(|i| (i * 17 + 31) as u8).collect();
    vol.write(0, &secret).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    let seg_ulid = ulids[0];

    let replacement: Vec<u8> = (0..8192).map(|i| (i * 23 + 41) as u8).collect();
    vol.write(0, &replacement).unwrap();

    // First redact: slow path, mints new ULID. Second redact on the
    // new ULID: fast path, returns the same ULID with no rewrite.
    let new_ulid = repack_for_input(&mut vol, &base, seg_ulid);
    assert_ne!(new_ulid, seg_ulid);
    let new_ulid_again = repack_for_input(&mut vol, &base, new_ulid);
    assert_eq!(new_ulid_again, new_ulid);

    let pending_dir = base.join("pending");
    assert!(
        !pending_dir.join(seg_ulid.to_string()).exists(),
        "input ULID's pending file must be removed after slow-path redact"
    );
    assert!(
        pending_dir.join(new_ulid.to_string()).exists(),
        "new ULID's pending file must exist"
    );
    assert!(
        !pending_dir.join(format!("{}.tmp", new_ulid)).exists(),
        "no .tmp should remain"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_no_op_when_all_live() {
    // A segment with no hash-dead DATA entries is untouched by redact:
    // the file is unchanged, no sidecar is produced.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0x77u8; 4096];
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    let ulid = ulids[0];
    let seg_path = base.join("pending").join(ulid.to_string());
    let before = fs::read(&seg_path).unwrap();

    repack_for_input(&mut vol, &base, ulid);

    let after = fs::read(&seg_path).unwrap();
    assert_eq!(
        before, after,
        "redact with no dead DATA must not modify file"
    );
    assert!(
        !base
            .join("pending")
            .join(format!("{}.materialized", ulid))
            .exists(),
        "no sidecar should be produced"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_preserves_body_for_lba_dead_but_hash_alive_entry() {
    // Regression test: if a Data entry's LBA is overwritten but the same
    // hash is alive at another LBA, redact must NOT punch the body.
    // GC's collect_stats keeps such entries via extent+hash liveness, so
    // punching the body would cause GC to copy zeros into its output.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Use high-entropy data that won't compress below INLINE_THRESHOLD.
    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    // LBA 0-1 → DATA(hash=H). Also dedup-indexed.
    vol.write(0, &data).unwrap();
    // LBA 2-3 → dedup hit → DedupRef(hash=H). Hash H is now alive at LBAs 0 and 2.
    vol.write(2, &data).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_ulid = ulids[0];

    // Overwrite LBA 0-1 with different data. The DATA entry at LBA 0 is
    // now LBA-dead, but hash H is still alive at LBA 2.
    let other: Vec<u8> = (0..8192).map(|i| (i * 11 + 3) as u8).collect();
    vol.write(0, &other).unwrap();

    let new_ulid = repack_for_input(&mut vol, &base, seg_ulid);

    // Verify the DATA entry at LBA 0 still has real body bytes (not zeros)
    // in the rewritten output (or the in-place file when repack was a no-op).
    use std::io::{Read as _, Seek as _, SeekFrom};
    let seg_path = base.join("pending").join(new_ulid.to_string());
    let (bss, entries, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    let data_entry = entries
        .iter()
        .find(|e| e.kind.is_data() && e.start_lba == 0)
        .expect("should have a Data entry at LBA 0");
    assert!(data_entry.stored_length > 0);

    let mut f = fs::File::open(&seg_path).unwrap();
    let mut body = vec![0u8; data_entry.stored_length as usize];
    f.seek(SeekFrom::Start(bss + data_entry.stored_offset))
        .unwrap();
    f.read_exact(&mut body).unwrap();
    assert!(
        body.iter().any(|&b| b != 0),
        "redact must NOT punch body of LBA-dead but hash-alive Data entry"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_drops_entry_when_hash_fully_dead() {
    // When both the LBA and the hash are dead (no LBA references the hash),
    // redact must drop the entry from the index. The dropped hash's body
    // bytes do not appear anywhere in the resulting pending file.
    // Uses high-entropy data that won't compress below INLINE_THRESHOLD.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_ulid = ulids[0];

    // Overwrite LBA 0-1 with different data. Hash H is no longer alive
    // at any LBA.
    let other: Vec<u8> = (0..8192).map(|i| (i * 11 + 3) as u8).collect();
    vol.write(0, &other).unwrap();

    let dead_hash = blake3::hash(&data);

    let new_ulid = repack_for_input(&mut vol, &base, seg_ulid);
    assert_ne!(new_ulid, seg_ulid);

    let new_seg_path = base.join("pending").join(new_ulid.to_string());
    let (_, entries, _) =
        segment::read_and_verify_segment_index(&new_seg_path, &vol.verifying_key).unwrap();
    assert!(
        entries.iter().all(|e| e.hash != dead_hash),
        "redact must drop the fully-dead entry from the index"
    );

    // The original body bytes must not be findable in the rewritten segment.
    let bytes = fs::read(&new_seg_path).unwrap();
    let needle: &[u8] = &data[..64];
    assert!(
        bytes.windows(needle.len()).all(|w| w != needle),
        "dead entry body bytes must not remain in the segment file"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_keeps_extent_index_offsets_in_sync_for_surviving_entries() {
    // Regression: redact rewrites pending/<ulid> with the hash-dead Data
    // entries removed, which shrinks the index section AND reassigns
    // body_offset for every surviving Data entry. Before the fix, the
    // in-memory extent index kept the pre-redact body_section_start and
    // body_offset values, so a subsequent read of any surviving entry
    // seeked past its real body bytes — producing garbage that failed
    // lz4 decompression downstream (observed in production as ublk
    // EIO + rustc SIGBUS during a real workload).
    //
    // The test writes two body-section Data entries, makes the first
    // hash-dead, redacts, then reads the surviving entry. Without the
    // fix, the in-memory extent index records body_section_start sized
    // for two entries while the on-disk file has body_section_start
    // sized for one, so the read fails or returns wrong bytes.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Two distinct, high-entropy payloads — must stay in the body
    // section (not inline) so body_offset shifts on redact.
    let payload_a: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    let payload_b: Vec<u8> = (0..8192).map(|i| (i * 11 + 3) as u8).collect();

    // Two Data entries in one segment.
    vol.write(0, &payload_a).unwrap();
    vol.write(4, &payload_b).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_ulid = ulids[0];

    // Overwrite LBA 0-1 so the first Data entry is fully hash-dead.
    let payload_c: Vec<u8> = (0..8192).map(|i| (i * 13 + 5) as u8).collect();
    vol.write(0, &payload_c).unwrap();

    // Redact drops the dead entry and rewrites the segment under a
    // freshly minted ULID with a smaller index section + reassigned
    // body offsets for the survivor.
    let new_ulid = repack_for_input(&mut vol, &base, seg_ulid);
    assert_ne!(new_ulid, seg_ulid);

    // Read the surviving entry. With the in-memory extent index
    // refreshed (segment_id flipped to new_ulid; body_section_start
    // and body_offset reassigned), this returns payload_b. Without
    // the fix, the read either errors with a decompression failure
    // or returns garbage.
    assert_eq!(
        vol.read(4, 2).unwrap(),
        payload_b,
        "surviving body-section entry must read back correctly after redact \
         compacts body offsets"
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn repack_invalidates_extent_index_for_dropped_hash() {
    // Regression: after redact punches a hash-dead DATA body, a later write
    // whose content hashes to the same value must not use the dedup
    // shortcut — the canonical body bytes are gone. Before the fix, the
    // surviving extent-index entry caused `write_commit` to emit a thin
    // DedupRef pointing at zero-punched bytes, so subsequent reads of the
    // new LBA returned zeros.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // High-entropy payloads so they stay in the body section (no inline).
    let payload_a: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    let payload_b: Vec<u8> = (0..8192).map(|i| (i * 11 + 3) as u8).collect();

    // Seed LBA 28 with payload_A, flush so it lives in pending/.
    vol.write(28, &payload_a).unwrap();
    vol.promote_for_test().unwrap();

    let ulids = pending_ulids(&base);
    assert_eq!(ulids.len(), 1);
    let seg_ulid = ulids[0];

    // Overwrite LBA 28 with payload_B. Hash of payload_A is now LBA-dead
    // and no other LBA references it — hash-fully-dead.
    vol.write(28, &payload_b).unwrap();

    // Drain: redact (drops payload_A, rewrites under fresh ULID) then
    // promote to index/ + cache/. Mirrors the coordinator upload flow.
    let redacted_ulid = repack_for_input(&mut vol, &base, seg_ulid);
    vol.promote_segment(redacted_ulid).unwrap();

    // A fresh write with content matching payload_A. Without the fix, the
    // surviving extent-index entry for H_A makes `write_commit` emit a
    // DedupRef pointing at the (now zero) location in cache/<seg>.body.
    vol.write(100, &payload_a).unwrap();

    assert_eq!(
        vol.read(100, 2).unwrap(),
        payload_a,
        "new write of redacted content must read back correctly"
    );
    // Existing reads unaffected.
    assert_eq!(vol.read(28, 2).unwrap(), payload_b, "LBA 28 (overwrite)");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn wal_recovery_with_thin_ref() {
    // Write data to LBA 0, promote to pending, then write same data to
    // LBA 1 (dedup hit → thin ref in WAL). Do NOT flush — leave the thin
    // ref in the WAL. Drop (crash), reopen, verify both LBAs read back.
    let base = keyed_temp_dir();
    let data = vec![0x99u8; 4096];

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        // Second write: same data, different LBA → dedup hit → REF in WAL.
        vol.write(1, &data).unwrap();
        vol.fsync().unwrap();
        // Drop without promote — thin ref stays in WAL only.
    }

    // Reopen triggers WAL recovery.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(
        vol.read(0, 1).unwrap(),
        data,
        "LBA 0 must survive crash with thin ref in WAL"
    );
    assert_eq!(
        vol.read(1, 1).unwrap(),
        data,
        "LBA 1 (thin ref) must survive crash with thin ref in WAL"
    );

    fs::remove_dir_all(base).unwrap();
}

/// Proptest regression: DedupWrite → Flush → DedupWrite (overwrite) →
/// Repack → DrainWithRedact.
///
/// Repack finds all entries in the first segment dead (overwritten by the
/// second DedupWrite) and removes the hash from the extent index. Before
/// the fix, repack left the segment file behind; the subsequent drain
/// then tried to process it, hit a DedupRef whose canonical hash was
/// gone, and panicked. The fix: repack deletes the segment file when all
/// entries are dead.
#[test]
fn repack_deletes_fully_dead_segment_before_drain() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Pre-snapshot segments (frozen by snapshot, skipped by repack).
    let data_a = vec![17u8; 4096];
    vol.write(2, &data_a).unwrap();
    vol.flush_wal().unwrap();
    vol.repack().unwrap();
    for ulid in pending_ulids(&base) {
        vol.promote_segment(ulid).unwrap();
    }

    let data_b = vec![34u8; 4096];
    vol.write(3, &data_b).unwrap();
    vol.flush_wal().unwrap();
    vol.repack().unwrap();
    for ulid in pending_ulids(&base) {
        vol.promote_segment(ulid).unwrap();
    }

    vol.snapshot().unwrap();

    // DedupWrite seed=0: LBA 0 (Data) + LBA 6 (DedupRef), same hash.
    let dedup_data_0 = vec![0u8; 4096];
    vol.write(0, &dedup_data_0).unwrap();
    vol.write(6, &dedup_data_0).unwrap();
    vol.flush_wal().unwrap();
    let pre_repack: std::collections::HashSet<_> = pending_ulids(&base).into_iter().collect();

    // DedupWrite seed=1: overwrite both LBAs with new data.
    let dedup_data_1 = vec![1u8; 4096];
    vol.write(0, &dedup_data_1).unwrap();
    vol.write(6, &dedup_data_1).unwrap();

    // Repack: the post-snapshot segment (seed=0) is now fully dead.
    vol.repack().unwrap();

    // The fully-dead seed=0 segment must have been deleted. Repack's
    // prep also flushes the WAL (the seed=1 writes) into a fresh
    // pending/<u_flush>, so check that the original input is gone
    // rather than asserting an empty pending dir.
    let after_repack: std::collections::HashSet<_> = pending_ulids(&base).into_iter().collect();
    let surviving_inputs: Vec<_> = pre_repack.intersection(&after_repack).collect();
    assert!(
        surviving_inputs.is_empty(),
        "repack should delete fully-dead segment, but it survived: {surviving_inputs:?}"
    );

    // DrainWithRedact: redact + promote each remaining pending segment.
    // (The WAL was already flushed during prepare_repack.)
    vol.flush_wal().unwrap();
    vol.repack().unwrap();
    for ulid in pending_ulids(&base) {
        vol.promote_segment(ulid).unwrap();
    }

    // Verify reads.
    assert_eq!(vol.read(0, 1).unwrap(), dedup_data_1, "LBA 0");
    assert_eq!(vol.read(6, 1).unwrap(), dedup_data_1, "LBA 6");
    assert_eq!(vol.read(2, 1).unwrap(), data_a, "LBA 2 (pre-snapshot)");
    assert_eq!(vol.read(3, 1).unwrap(), data_b, "LBA 3 (pre-snapshot)");

    fs::remove_dir_all(base).unwrap();
}

/// Known failure: proptest minimal reproducer for dedup canonical overwrite
/// data loss. When PopulateFetched overwrites the extent index entry for a
/// hash that a DedupRef depends on, then DrainLocal removes pending/, then
/// GC runs, the thin ref's canonical body is lost. After crash, LBA 4
/// reads zeros instead of the expected data.
///
/// Un-ignore when the fix lands.
#[test]
#[ignore]
fn proptest_minimal_dedup_overwrite_data_loss() {
    let base = keyed_temp_dir();
    let fork_dir = base.clone();
    let mut vol = Volume::open(&base, &base).unwrap();

    // DedupWrite: write [1u8; 4096] to LBA 0 and LBA 4 (dedup hit on LBA 4).
    let data = [1u8; 4096];
    vol.write(0, &data).unwrap();
    vol.write(4, &data).unwrap();

    // Flush — promotes WAL to pending/.
    vol.flush_wal().unwrap();

    // PopulateFetched: write different data to cache for LBA 0,
    // overwriting the extent index entry for the original hash.
    let pop_ulid = vol.gc_checkpoint_for_test().unwrap();
    {
        // Use the common helper pattern from tests/common/mod.rs.
        let index_dir = fork_dir.join("index");
        let cache_dir = fork_dir.join("cache");
        let _ = fs::create_dir_all(&index_dir);
        let _ = fs::create_dir_all(&cache_dir);

        let seed = 128u8;
        let pop_data = vec![seed; 4096];
        let pop_hash = blake3::hash(&pop_data);
        let entries = vec![segment::SegmentEntry::new_data(
            pop_hash,
            0,
            1,
            segment::SegmentFlags::empty(),
            pop_data,
        )];

        let signer =
            crate::signing::load_signer(&fork_dir, crate::signing::VOLUME_KEY_FILE).unwrap();
        let tmp = cache_dir.join(format!("{pop_ulid}.tmp"));
        let (bss, _) = segment::write_segment(&tmp, entries, signer.as_ref()).unwrap();
        let bytes = fs::read(&tmp).unwrap();
        fs::remove_file(&tmp).unwrap();

        let s = pop_ulid.to_string();
        fs::write(index_dir.join(format!("{s}.idx")), &bytes[..bss as usize]).unwrap();
        fs::write(cache_dir.join(format!("{s}.body")), &bytes[bss as usize..]).unwrap();
        segment::set_present_bit(&cache_dir.join(format!("{s}.present")), 0, 1).unwrap();
    }

    // DrainLocal: promote all pending segments to index/ + cache/.
    {
        let pending = fork_dir.join("pending");
        let index_dir = fork_dir.join("index");
        let cache_dir = fork_dir.join("cache");
        let _ = fs::create_dir_all(&index_dir);
        let _ = fs::create_dir_all(&cache_dir);
        if let Ok(entries) = fs::read_dir(&pending) {
            for entry in entries.flatten() {
                let name = entry.file_name().into_string().unwrap();
                if name.contains('.') {
                    continue;
                }
                let file_data = fs::read(entry.path()).unwrap();
                if file_data.len() < 96 {
                    continue;
                }
                let entry_count =
                    u32::from_le_bytes([file_data[8], file_data[9], file_data[10], file_data[11]]);
                let index_length = u32::from_le_bytes([
                    file_data[12],
                    file_data[13],
                    file_data[14],
                    file_data[15],
                ]);
                let inline_length = u32::from_le_bytes([
                    file_data[16],
                    file_data[17],
                    file_data[18],
                    file_data[19],
                ]);
                let bss = 96 + index_length as usize + inline_length as usize;
                if file_data.len() < bss {
                    continue;
                }
                let _ = fs::write(index_dir.join(format!("{name}.idx")), &file_data[..bss]);
                let _ = fs::write(cache_dir.join(format!("{name}.body")), &file_data[bss..]);
                let bitset_len = (entry_count as usize).div_ceil(8);
                let _ = fs::write(
                    cache_dir.join(format!("{name}.present")),
                    vec![0xFFu8; bitset_len],
                );
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    // CoordGcLocal: run GC.
    {
        let gc_ulid = vol.gc_checkpoint_for_test().unwrap();
        vol.flush_wal().unwrap();
        // Need at least 2 segments for GC; use all available.
        let idx_files = segment::collect_idx_files(&fork_dir.join("index")).unwrap();
        if idx_files.len() >= 2 {
            let to_delete = {
                use crate::{extentindex, lbamap};
                let rebuild_chain = vec![(fork_dir.clone(), None)];
                let lba_map = lbamap::rebuild_segments(&rebuild_chain).unwrap();
                let _live_hashes = lba_map.lba_referenced_hashes();
                let extent_index =
                    extentindex::rebuild(&rebuild_chain, &crate::journal::NO_WINDOW).unwrap();

                let vk =
                    crate::signing::load_verifying_key(&fork_dir, crate::signing::VOLUME_PUB_FILE)
                        .unwrap();
                let (ephemeral_signer, _) = crate::signing::generate_ephemeral_signer();

                let gc_dir = fork_dir.join("gc");
                let _ = fs::create_dir_all(&gc_dir);

                // Build candidates from all .idx files
                let mut candidates: Vec<(Ulid, PathBuf)> = idx_files
                    .iter()
                    .filter_map(|p| {
                        let stem = p.file_stem()?.to_str()?;
                        let ulid = Ulid::from_string(stem).ok()?;
                        Some((ulid, p.clone()))
                    })
                    .collect();
                candidates.sort_by_key(|(u, _)| *u);

                // Classify each candidate's entries and build a plan:
                // emit one `Keep` per entry that's still LBA-live or
                // extent-canonical. Mirrors the coordinator's `collect_stats`
                // → `PlanOutput::Keep` path for the fully-alive case.
                use crate::rewrite_plan::{PlanOutput, RewritePlan};

                let mut outputs: Vec<PlanOutput> = Vec::new();
                let mut kept_any = false;
                for (ulid, path) in &candidates {
                    let Ok((_bss, seg_entries, _)) =
                        segment::read_and_verify_segment_index(path, &vk)
                    else {
                        continue;
                    };
                    for (entry_idx, e) in seg_entries.iter().enumerate() {
                        if e.kind == EntryKind::DedupRef {
                            continue;
                        }
                        let lba_live = lba_map.hash_at(e.start_lba) == Some(e.hash);
                        let extent_live = extent_index
                            .lookup(&e.hash)
                            .is_some_and(|loc| loc.segment_id == *ulid);
                        if lba_live || extent_live {
                            outputs.push(PlanOutput::Keep {
                                input: *ulid,
                                entry_idx: entry_idx as u32,
                            });
                            kept_any = true;
                        }
                    }
                }

                if kept_any {
                    let plan = RewritePlan {
                        new_ulid: gc_ulid,
                        outputs,
                    };
                    let plan_path = gc_dir.join(format!("{gc_ulid}.plan"));
                    plan.write_atomic(&plan_path).unwrap();
                }
                let _ = ephemeral_signer;

                candidates
                    .iter()
                    .map(|(_, p)| p.clone())
                    .collect::<Vec<_>>()
            };
            let applied = vol.apply_gc_handoffs().unwrap_or(0);
            if applied > 0 {
                for path in &to_delete {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    // Crash: drop and reopen.
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();

    // Assert LBA 4 reads [1u8; 4096] — the dedup ref target.
    // This is the assertion that currently fails due to the known bug.
    assert_eq!(
        vol.read(4, 1).unwrap(),
        vec![1u8; 4096],
        "LBA 4 (dedup ref) must read back original data after GC + crash"
    );

    fs::remove_dir_all(base).unwrap();
}
// --- ancestor-aware open / read integration test ---

/// Write data into a root volume, snapshot it, create a child volume via
/// fork_volume, and verify the child can read the ancestor's data.
#[test]
fn open_reads_ancestor_segments() {
    let by_id = temp_dir();
    let default_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&default_dir);

    // Write data into the root volume and promote to a segment.
    let data = vec![0xABu8; 4096];
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
        vol.snapshot().unwrap();
    }

    // Create a child volume branched from default.
    fork_volume(&child_dir, &default_dir).unwrap();

    // Child should see the ancestor's data through layer merge.
    let vol = Volume::open(&child_dir, &by_id).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data);

    fs::remove_dir_all(by_id).unwrap();
}

/// Ancestor data is shadowed by a write in the live child volume.
#[test]
fn child_write_shadows_ancestor() {
    let by_id = temp_dir();
    let default_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&default_dir);
    let ancestor_data = vec![0xAAu8; 4096];
    let child_data = vec![0xBBu8; 4096];

    // Write into the root volume, promote, snapshot.
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &ancestor_data).unwrap();
        vol.promote_for_test().unwrap();
        vol.snapshot().unwrap();
    }

    // Create child volume, write different data at the same LBA, promote.
    fork_volume(&child_dir, &default_dir).unwrap();
    {
        let mut vol = Volume::open(&child_dir, &by_id).unwrap();
        vol.write(0, &child_data).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Re-open child and verify child data wins.
    let vol = Volume::open(&child_dir, &by_id).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), child_data);

    fs::remove_dir_all(by_id).unwrap();
}

// --- lock tests ---

#[test]
fn double_open_same_fork_fails() {
    let fork_dir = keyed_temp_dir();
    let _vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    // Second open on the same live fork must fail (lock already held).
    assert!(Volume::open(&fork_dir, &fork_dir).is_err());
    fs::remove_dir_all(fork_dir).unwrap();
}

// --- snapshot() tests ---

#[test]
fn snapshot_writes_manifest_and_stays_live() {
    let fork_dir = keyed_temp_dir();
    let data = vec![0xAAu8; 4096];

    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.write(0, &data).unwrap();
    let snap_ulid = vol.snapshot().unwrap();

    // Fork still has wal/ (still live).
    assert!(fork_dir.join("wal").is_dir());
    // Signed manifest is the snapshot record.
    assert!(
        fork_dir
            .join("snapshots")
            .join(format!("{snap_ulid}.manifest"))
            .exists()
    );

    // Writes after snapshot still go to the same fork.
    let new_data = vec![0xBBu8; 4096];
    vol.write(1, &new_data).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(1, 1).unwrap(), new_data);

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_ulid_matches_last_segment_ulid() {
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.write(0, &vec![0xAAu8; 4096]).unwrap();
    let snap_ulid = vol.snapshot().unwrap().to_string();

    // Snapshot promotes segments from pending/ to index/ + cache/, so
    // the segment shows up as `index/<ulid>.idx` after the call.
    let idx_files: Vec<_> = fs::read_dir(fork_dir.join("index"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(idx_files.len(), 1);
    let idx_name = idx_files[0].file_name().into_string().unwrap();
    assert_eq!(idx_name, format!("{snap_ulid}.idx"));

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_empty_wal_no_segment_written() {
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    // No writes — WAL is empty.
    vol.snapshot().unwrap();

    // pending/ should be empty (no segment written for empty WAL).
    let pending: Vec<_> = fs::read_dir(fork_dir.join("pending")).unwrap().collect();
    assert!(pending.is_empty());

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_idempotent_when_no_new_data() {
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.write(0, &vec![0xAAu8; 4096]).unwrap();

    let ulid1 = vol.snapshot().unwrap();
    // No new writes — second snapshot must return the same ULID.
    let ulid2 = vol.snapshot().unwrap();
    assert_eq!(ulid1, ulid2);

    // Still only one signed manifest on disk.
    let manifest_count = fs::read_dir(fork_dir.join("snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|s| s.ends_with(".manifest"))
        })
        .count();
    assert_eq!(manifest_count, 1);

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_not_idempotent_after_new_write() {
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.write(0, &vec![0xAAu8; 4096]).unwrap();

    let ulid1 = vol.snapshot().unwrap();
    vol.write(1, &vec![0xBBu8; 4096]).unwrap();
    vol.promote_for_test().unwrap();

    let ulid2 = vol.snapshot().unwrap();
    assert_ne!(ulid1, ulid2);

    let manifest_count = fs::read_dir(fork_dir.join("snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|s| s.ends_with(".manifest"))
        })
        .count();
    assert_eq!(manifest_count, 2);

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_idempotent_after_auto_promoted_data_already_snapshotted() {
    // Data promoted via FLUSH_THRESHOLD (pending_entries empty at snapshot
    // time) but that segment was already covered by a prior snapshot.
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.write(0, &vec![0xAAu8; 4096]).unwrap();
    vol.promote_for_test().unwrap(); // lands in pending/ with wal_ulid_1
    let ulid1 = vol.snapshot().unwrap(); // snapshot covers pending/wal_ulid_1
    // pending_entries is now empty; pending/ has one file but it's <= ulid1.
    let ulid2 = vol.snapshot().unwrap();
    assert_eq!(ulid1, ulid2);

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn snapshot_lock_held_after_snapshot() {
    let fork_dir = keyed_temp_dir();
    let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    vol.snapshot().unwrap();

    // Fork is still locked (still live); second open must fail.
    assert!(Volume::open(&fork_dir, &fork_dir).is_err());
    drop(vol); // now released

    // After drop, a fresh open succeeds.
    assert!(Volume::open(&fork_dir, &fork_dir).is_ok());

    fs::remove_dir_all(fork_dir).unwrap();
}

// --- multi-snapshot read tests ---

#[test]
fn two_snapshots_data_readable_after_reopen() {
    let fork_dir = keyed_temp_dir();
    let data_a = vec![0xAAu8; 4096];
    let data_b = vec![0xBBu8; 4096];

    {
        let mut vol = Volume::open(&fork_dir, &fork_dir).unwrap();
        vol.write(0, &data_a).unwrap();
        vol.snapshot().unwrap();
        vol.write(1, &data_b).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Re-open the same fork: both writes visible.
    let vol = Volume::open(&fork_dir, &fork_dir).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data_a);
    assert_eq!(vol.read(1, 1).unwrap(), data_b);

    fs::remove_dir_all(fork_dir).unwrap();
}

#[test]
fn fork_data_visible_across_ancestry() {
    let by_id = temp_dir();
    let default_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&default_dir);
    let data_a = vec![0xAAu8; 4096];
    let data_b = vec![0xBBu8; 4096];

    // Write to default, snapshot, create fork, write to fork.
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &data_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.snapshot().unwrap();
    }

    fork_volume(&child_dir, &default_dir).unwrap();
    {
        let mut vol = Volume::open(&child_dir, &by_id).unwrap();
        vol.write(1, &data_b).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Re-open child: sees both ancestor and own data.
    let vol = Volume::open(&child_dir, &by_id).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data_a);
    assert_eq!(vol.read(1, 1).unwrap(), data_b);
    assert_eq!(vol.ancestor_count(), 1);

    fs::remove_dir_all(by_id).unwrap();
}

// --- ULID cutoff tests ---

/// Segments written to an ancestor volume *after* the branch point must not
/// be visible to a child volume. This is the core correctness property of
/// the per-ancestor ULID cutoff stored in `origin`.
#[test]
fn ulid_cutoff_hides_post_branch_ancestor_writes() {
    let by_id = temp_dir();
    let default_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&default_dir);

    let pre_branch = vec![0xAAu8; 4096];
    let post_branch = vec![0xBBu8; 4096];

    // Write pre-branch data to ancestor, snapshot, then branch.
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &pre_branch).unwrap();
        vol.snapshot().unwrap();
    }
    fork_volume(&child_dir, &default_dir).unwrap();

    // Write post-branch data to the ancestor volume at LBA 1 (a new LBA).
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(1, &post_branch).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Child must see pre-branch data at LBA 0 and zeros at LBA 1.
    let vol = Volume::open(&child_dir, &by_id).unwrap();
    assert_eq!(
        vol.read(0, 1).unwrap(),
        pre_branch,
        "pre-branch data must be visible"
    );
    assert_eq!(
        vol.read(1, 1).unwrap(),
        vec![0u8; 4096],
        "post-branch ancestor write must be invisible"
    );

    fs::remove_dir_all(by_id).unwrap();
}

/// A post-branch write to an ancestor that *overwrites* a pre-branch LBA
/// must also be invisible — the child must still see the original value.
#[test]
fn ulid_cutoff_overwrite_stays_invisible() {
    let by_id = temp_dir();
    let default_dir = by_id.join("01AAAAAAAAAAAAAAAAAAAAAAAA");
    let child_dir = by_id.join("01BBBBBBBBBBBBBBBBBBBBBBBB");
    write_test_keypair(&default_dir);

    let original = vec![0xAAu8; 4096];
    let overwrite = vec![0xBBu8; 4096];

    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &original).unwrap();
        vol.snapshot().unwrap();
    }
    fork_volume(&child_dir, &default_dir).unwrap();

    // Ancestor overwrites LBA 0 after the branch.
    {
        let mut vol = Volume::open(&default_dir, &by_id).unwrap();
        vol.write(0, &overwrite).unwrap();
        vol.promote_for_test().unwrap();
    }

    // Child must still see the original pre-branch value.
    let vol = Volume::open(&child_dir, &by_id).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), original);

    fs::remove_dir_all(by_id).unwrap();
}

// --- apply_gc_handoffs tests ---
//
// These tests simulate the coordinator GC workflow:
//   write → flush → drain (pending→cache + index) → coordinator emits
//   gc/<new>.plan → volume applies handoff (writes .staged → bare gc/<new>).

#[test]
fn gc_handoff_applies_and_renames() {
    // End-to-end: stage a GC output, apply it (volume re-signs and
    // commits to bare), promote it (coordinator writes new idx and
    // deletes old idx via the inputs field), evict caches.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let old_ulid = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    simulate_upload(&mut vol);

    let new_ulid = simulate_coord_gc_staged(&mut vol, &base, &old_ulid);

    // Apply the handoff: volume re-signs `gc/<new>.staged` to `gc/<new>`.
    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);

    let gc_dir = base.join("gc");
    assert!(
        !gc_dir.join(format!("{new_ulid}.plan")).exists(),
        "plan file must be removed after commit"
    );
    assert!(
        gc_dir.join(&new_ulid).exists(),
        "bare gc/<new> must exist after commit"
    );

    // After apply_gc_handoffs the old idx is still present — promote_segment
    // is the step that deletes it (after the coordinator confirms upload).
    let cache_dir = base.join("cache");
    let index_dir = base.join("index");
    assert!(
        index_dir.join(format!("{old_ulid}.idx")).exists(),
        "old idx must persist until promote_segment runs"
    );
    assert!(
        !index_dir.join(format!("{new_ulid}.idx")).exists(),
        "new idx must not exist before promote_segment (not yet S3-confirmed)"
    );

    // Promote: coordinator confirms upload and asks the volume to write
    // index/<new>.idx + cache/<new>.body. promote_segment derives the
    // list of input ulids from the new segment's header and deletes
    // their idx files.
    let new_ulid_parsed = Ulid::from_string(&new_ulid).unwrap();
    vol.promote_segment(new_ulid_parsed).unwrap();

    assert!(
        index_dir.join(format!("{new_ulid}.idx")).exists(),
        "promote_segment must write index/<new>.idx"
    );
    assert!(
        !index_dir.join(format!("{old_ulid}.idx")).exists(),
        "promote_segment must delete index/<old>.idx for each input"
    );

    // Reads still work via cache/<new>.body.
    assert_eq!(vol.read(0, 2).unwrap(), data);

    // Coordinator finalize: deletes the bare gc/<new> file.
    vol.finalize_gc_handoff(new_ulid_parsed).unwrap();
    assert!(
        !gc_dir.join(&new_ulid).exists(),
        "finalize_gc_handoff must delete bare gc/<new>"
    );
    // Reads still work — cache/<new>.body covers it.
    assert_eq!(vol.read(0, 2).unwrap(), data);

    // Note: under the new protocol cache/<old>.* is dropped by
    // promote_segment's input cleanup path, not by a separate evict step.
    let _ = cache_dir;

    fs::remove_dir_all(base).unwrap();
}

/// Simulate a coordinator GC pass: read the old segment's entries and
/// write a `gc/<new>.plan` file holding one `keep` per entry.
///
/// Matches what the real coordinator emits for fully-alive inputs under
/// the plan handoff protocol (see `docs/design/gc-plan-handoff.md`).
fn simulate_coord_gc_staged(vol: &mut Volume, fork_dir: &Path, old_ulid: &str) -> String {
    use crate::rewrite_plan::{PlanOutput, RewritePlan};
    use crate::segment;

    let idx_path = fork_dir.join("index").join(format!("{old_ulid}.idx"));
    let (_bss, entries, _) =
        segment::read_and_verify_segment_index(&idx_path, &vol.verifying_key).unwrap();

    let new_ulid = vol.gc_checkpoint_for_test().unwrap();
    let new_ulid_str = new_ulid.to_string();

    let gc_dir = fork_dir.join("gc");
    fs::create_dir_all(&gc_dir).unwrap();

    let old_ulid_parsed = Ulid::from_string(old_ulid).unwrap();
    let outputs: Vec<PlanOutput> = (0..entries.len() as u32)
        .map(|entry_idx| PlanOutput::Keep {
            input: old_ulid_parsed,
            entry_idx,
        })
        .collect();
    let plan = RewritePlan { new_ulid, outputs };
    let plan_path = gc_dir.join(format!("{new_ulid_str}.plan"));
    plan.write_atomic(&plan_path).unwrap();

    new_ulid_str
}

#[test]
fn gc_staged_handoff_applies_and_commits_bare() {
    // Step 4a: derive-at-apply path. Coordinator writes gc/<ulid>.staged
    // with inputs in the segment header; volume walks `.staged`, re-signs,
    // commits by renaming tmp → bare, removes `.staged`.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let old_ulid = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    simulate_upload(&mut vol);

    let new_ulid = simulate_coord_gc_staged(&mut vol, &base, &old_ulid);

    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);

    let gc_dir = base.join("gc");
    assert!(
        !gc_dir.join(format!("{new_ulid}.plan")).exists(),
        "`.plan` must be removed after commit"
    );
    assert!(
        gc_dir.join(&new_ulid).exists(),
        "bare <ulid> must exist after commit"
    );

    // Reads go through the extent index → new segment.
    assert_eq!(vol.read(0, 2).unwrap(), data);

    // Re-running is a no-op: bare exists, nothing to apply.
    let again = vol.apply_gc_handoffs().unwrap();
    assert_eq!(again, 0);

    fs::remove_dir_all(base).unwrap();
}

/// Write a `gc/<new>.plan` keeping every entry of each input, like
/// `simulate_coord_gc_staged` but over multiple inputs — the shape the
/// coordinator emits when a bucket folds several segments.
fn write_multi_input_plan(vol: &mut Volume, fork_dir: &Path, inputs: &[Ulid]) -> Ulid {
    use crate::rewrite_plan::{PlanOutput, RewritePlan};
    use crate::segment;

    let mut outputs = Vec::new();
    for input in inputs {
        let idx_path = fork_dir.join("index").join(format!("{input}.idx"));
        let (_bss, entries, _) =
            segment::read_and_verify_segment_index(&idx_path, &vol.verifying_key).unwrap();
        outputs.extend((0..entries.len() as u32).map(|entry_idx| PlanOutput::Keep {
            input: *input,
            entry_idx,
        }));
    }
    let new_ulid = vol.gc_checkpoint_for_test().unwrap();
    let gc_dir = fork_dir.join("gc");
    fs::create_dir_all(&gc_dir).unwrap();
    let plan = RewritePlan { new_ulid, outputs };
    plan.write_atomic(&gc_dir.join(format!("{new_ulid}.plan")))
        .unwrap();
    new_ulid
}

#[test]
#[cfg_attr(
    feature = "volume-invariants",
    ignore = "deliberately diverges the daemon's read state from disk — the per-op rebuild checkers flag exactly that"
)]
fn gc_plan_with_unknown_input_diverges_and_reopen_recovers() {
    // Re-enacts the 2026-07-02 incident shape: a committed segment lands
    // in index/ + cache/ behind a running daemon's back (there: force-claim
    // re-own; here: idx moved aside across a reopen and restored after).
    // A GC plan folding that segment must be refused as Diverged — with
    // the plan retained — and a fresh open must then apply it cleanly.
    // See docs/design/read-state-divergence-check.md.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data_a: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data_a).unwrap();
    vol.promote_for_test().unwrap();
    simulate_upload(&mut vol);

    let data_b: Vec<u8> = (0..8192).map(|i| (i * 11 + 5) as u8).collect();
    vol.write(16, &data_b).unwrap();
    vol.promote_for_test().unwrap();
    simulate_upload(&mut vol);

    let mut committed: Vec<Ulid> = vol.own_segments.iter().copied().collect();
    committed.sort();
    let [s1, s2] = committed[..] else {
        panic!("expected exactly two committed segments, got {committed:?}");
    };

    // Reopen with s2's idx hidden: this daemon's read state never loads s2.
    drop(vol);
    let index_dir = base.join("index");
    let s2_idx = index_dir.join(format!("{s2}.idx"));
    let hidden = base.join(format!("{s2}.idx.hidden"));
    fs::rename(&s2_idx, &hidden).unwrap();
    let mut vol = Volume::open(&base, &base).unwrap();
    assert_eq!(
        vol.own_segments.iter().copied().collect::<Vec<_>>(),
        vec![s1]
    );
    fs::rename(&hidden, &s2_idx).unwrap();

    let new_ulid = write_multi_input_plan(&mut vol, &base, &[s1, s2]);
    let gc_dir = base.join("gc");

    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 0, "diverged plan must not be counted as applied");
    assert!(
        gc_dir.join(format!("{new_ulid}.plan")).exists(),
        "diverged plan must be retained for the post-rebuild retry"
    );
    assert!(
        !gc_dir.join(new_ulid.to_string()).exists(),
        "no bare output may be committed on divergence"
    );
    assert!(
        !gc_dir.join(format!("{new_ulid}.tmp")).exists(),
        "worker scratch must not outlive the divergence rejection"
    );

    // The fail-stop's recovery: a fresh open loads s2 and the retained
    // plan applies cleanly.
    drop(vol);
    let mut vol = Volume::open(&base, &base).unwrap();
    assert!(vol.own_segments.contains(&s2));
    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);
    assert!(gc_dir.join(new_ulid.to_string()).exists());
    assert_eq!(vol.read(0, 2).unwrap(), data_a);
    assert_eq!(vol.read(16, 2).unwrap(), data_b);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn own_segments_mirrors_committed_lifecycle() {
    // own_segments tracks the committed tier (gc/ ∪ index/) through the
    // full segment lifecycle: pending segments are excluded, promote adds,
    // GC apply adds the output, the output's promote removes the consumed
    // inputs, and a fresh open rebuilds the same set from disk.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    assert!(vol.own_segments.is_empty());

    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();
    assert!(
        vol.own_segments.is_empty(),
        "pending segments are not committed-tier"
    );

    simulate_upload(&mut vol);
    assert_eq!(vol.own_segments.len(), 1);
    let old_ulid = *vol.own_segments.iter().next().unwrap();

    let new_ulid_str = simulate_coord_gc_staged(&mut vol, &base, &old_ulid.to_string());
    let new_ulid = Ulid::from_string(&new_ulid_str).unwrap();
    vol.apply_gc_handoffs().unwrap();
    assert!(vol.own_segments.contains(&old_ulid));
    assert!(
        vol.own_segments.contains(&new_ulid),
        "GC apply commits the bare output into the committed tier"
    );

    vol.promote_segment(new_ulid).unwrap();
    assert!(
        !vol.own_segments.contains(&old_ulid),
        "the output's promote deletes the consumed input's idx"
    );
    assert!(vol.own_segments.contains(&new_ulid));

    vol.finalize_gc_handoff(new_ulid).unwrap();
    assert!(vol.own_segments.contains(&new_ulid));

    let expected: Vec<Ulid> = vol.own_segments.iter().copied().collect();
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(
        vol.own_segments.iter().copied().collect::<Vec<_>>(),
        expected
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn gc_staged_crash_recovery_bare_wins() {
    // Crash state: rename tmp→bare succeeded, but `.plan` removal
    // failed. On next apply: detect the bare file, drop `.plan`,
    // count the handoff as recovered.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data: Vec<u8> = (0..8192).map(|i| (i * 5 + 17) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let old_ulid = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    simulate_upload(&mut vol);

    // Stage + commit once to produce a bare file.
    let new_ulid = simulate_coord_gc_staged(&mut vol, &base, &old_ulid);
    vol.apply_gc_handoffs().unwrap();

    // Inject the crash state: re-create a `.plan` next to the bare file.
    let gc_dir = base.join("gc");
    let bare_path = gc_dir.join(&new_ulid);
    let plan_path = gc_dir.join(format!("{new_ulid}.plan"));
    fs::copy(&bare_path, &plan_path).unwrap();

    // Apply: bare wins, `.plan` is removed, count=1 (crash-recovered).
    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);
    assert!(bare_path.exists());
    assert!(!plan_path.exists());

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn gc_staged_sweeps_stale_tmp_files() {
    // Stray volume-owned `<ulid>.tmp` files from crashed apply writes
    // are swept at the start of the apply pass. Coordinator-owned
    // `<ulid>.plan.tmp` scratch is deliberately preserved — the
    // coord may still be writing to it, and deleting it here would
    // race its plan emission rename to ENOENT.
    let base = keyed_temp_dir();
    let vol = Volume::open(&base, &base).unwrap();
    let gc_dir = base.join("gc");
    fs::create_dir_all(&gc_dir).unwrap();

    let ulid = Ulid::new();
    let volume_tmp = gc_dir.join(format!("{ulid}.tmp"));
    let coord_tmp = gc_dir.join(format!("{ulid}.plan.tmp"));
    fs::write(&volume_tmp, b"garbage").unwrap();
    fs::write(&coord_tmp, b"coord in-flight").unwrap();

    let mut vol = vol;
    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 0);
    assert!(!volume_tmp.exists(), "<ulid>.tmp must be swept");
    assert!(
        coord_tmp.exists(),
        "<ulid>.plan.tmp must be preserved (coord may still be writing)"
    );

    fs::remove_dir_all(base).unwrap();
}

/// Build a `.plan` GC handoff that compacts two input segments,
/// emitting Keep outputs only for the entries from `seg_b_ulid` (the
/// live ones); entries from `seg_a_ulid` are intentionally omitted, so
/// they become "removed" hashes from the apply path's perspective.
/// Inputs list = [a, b] sorted.
fn simulate_coord_gc_staged_two_inputs(
    vol: &mut Volume,
    fork_dir: &Path,
    seg_a_ulid: &str,
    seg_b_ulid: &str,
) -> String {
    use crate::rewrite_plan::{PlanOutput, RewritePlan};
    use crate::segment;

    let idx_b = fork_dir.join("index").join(format!("{seg_b_ulid}.idx"));
    let (_bss, entries_b, _) =
        segment::read_and_verify_segment_index(&idx_b, &vol.verifying_key).unwrap();

    let new_ulid = vol.gc_checkpoint_for_test().unwrap();
    let new_ulid_str = new_ulid.to_string();

    let gc_dir = fork_dir.join("gc");
    fs::create_dir_all(&gc_dir).unwrap();

    let seg_a_parsed = Ulid::from_string(seg_a_ulid).unwrap();
    let seg_b_parsed = Ulid::from_string(seg_b_ulid).unwrap();
    // seg_a is consumed but contributes no output (its entries become
    // "removed" during apply) — signal this with a Drop record.
    let mut outputs: Vec<PlanOutput> = vec![PlanOutput::Drop {
        input: seg_a_parsed,
    }];
    outputs.extend(
        (0..entries_b.len() as u32).map(|entry_idx| PlanOutput::Keep {
            input: seg_b_parsed,
            entry_idx,
        }),
    );
    let plan = RewritePlan { new_ulid, outputs };
    plan.write_atomic(&gc_dir.join(format!("{new_ulid_str}.plan")))
        .unwrap();

    new_ulid_str
}

#[test]
fn gc_staged_crash_in_bare_phase_drops_removed_extents() {
    // Regression for a bug found by the TLA+ model (HandoffProtocol.tla):
    //
    // Sequence:
    //   1. Write D0 to lba 0, drain → seg_a with hash h0.
    //   2. Overwrite lba 0 with D1, drain → seg_b with hash h1.
    //      h0 is now LBA-dead; extent_index still has h0 → seg_a.
    //   3. Stage a GC output that carries h1 only. h0 is "removed".
    //   4. apply_gc_handoffs commits bare gc/<new>; in-memory
    //      extent_index now has h1 → new_ulid and h0 removed entirely.
    //   5. Crash + reopen. Rebuild reconstructs the extent_index from
    //      on-disk state — bare gc/<new> + index/<seg_a>.idx + index/<seg_b>.idx.
    //
    // Bug: rebuild uses insert_if_absent in pass order [bare, idx]. The
    // bare body inserts h1 → new_ulid (winning the later seg_b.idx).
    // But h0 is NOT in the bare body, so when the rebuild processes
    // index/<seg_a>.idx, it inserts h0 → seg_a — re-introducing the
    // entry the apply path explicitly removed.
    //
    // Fix: extentindex::rebuild reads the inputs field of every bare
    // gc/<ulid> file and skips the .idx files for those input segments.
    //
    // This test asserts the fixed behaviour: after restart, the
    // in-memory extent_index has no entry for h0.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let d0: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    let h0 = blake3::hash(&d0);
    vol.write(0, &d0).unwrap();
    vol.promote_for_test().unwrap();
    let pending_dir = base.join("pending");
    let seg_a_ulid = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    simulate_upload(&mut vol);

    let d1: Vec<u8> = (0..8192).map(|i| (i * 11 + 17) as u8).collect();
    let h1 = blake3::hash(&d1);
    vol.write(0, &d1).unwrap();
    vol.promote_for_test().unwrap();
    let seg_b_ulid = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    simulate_upload(&mut vol);

    // Sanity: both hashes are in the extent_index, h0 → seg_a, h1 → seg_b.
    assert!(
        vol.extent_index.lookup(&h0).is_some(),
        "h0 should be in extent_index pre-GC"
    );
    assert!(
        vol.extent_index.lookup(&h1).is_some(),
        "h1 should be in extent_index pre-GC"
    );

    // Stage a GC output that carries h1 and "removes" h0 (by omitting it).
    let _new_ulid = simulate_coord_gc_staged_two_inputs(&mut vol, &base, &seg_a_ulid, &seg_b_ulid);

    // Apply: the in-memory extent_index now has h1 → new and h0 removed.
    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);
    assert!(
        vol.extent_index.lookup(&h0).is_none(),
        "h0 should be removed from extent_index after apply"
    );
    assert!(
        vol.extent_index.lookup(&h1).is_some(),
        "h1 should still be in extent_index after apply"
    );

    // Crash + reopen. Rebuild from disk.
    drop(vol);
    let vol = Volume::open(&base, &base).unwrap();

    // h1 must still be in the extent_index (carried by the bare GC body).
    assert!(
        vol.extent_index.lookup(&h1).is_some(),
        "h1 should be in extent_index after restart"
    );

    // h0 must NOT be in the extent_index. Before the fix, the rebuild
    // would re-introduce it via index/<seg_a>.idx because insert_if_absent
    // doesn't know that seg_a was consumed by the bare GC body.
    assert!(
        vol.extent_index.lookup(&h0).is_none(),
        "h0 must be gone after restart — was a Removed entry in the GC handoff. \
             A stale entry here means index/<seg_a>.idx was processed without consulting \
             the bare gc body's `inputs` field. See HandoffProtocol.tla counterexample."
    );

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn gc_handoff_idempotent_after_crash() {
    // Simulate a crash between coordinator writing `.staged` and the
    // volume processing it. After reopen, the extent index is rebuilt
    // from index/*.idx (old segment still has its .idx), so reads are
    // correct before the handoff is applied. apply_gc_handoffs then
    // commits the bare `gc/<new>` and updates the extent index.
    let base = keyed_temp_dir();

    let old_ulid;
    let new_ulid;
    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();

    {
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();

        let pending_dir = base.join("pending");
        old_ulid = fs::read_dir(&pending_dir)
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .file_name()
            .into_string()
            .unwrap();
        simulate_upload(&mut vol);

        new_ulid = simulate_coord_gc_staged(&mut vol, &base, &old_ulid);

        // "Crash" — drop the volume before apply_gc_handoffs runs.
    }

    let mut vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 2).unwrap(), data);

    let count = vol.apply_gc_handoffs().unwrap();
    assert_eq!(count, 1);

    let gc_dir = base.join("gc");
    assert!(!gc_dir.join(format!("{new_ulid}.plan")).exists());
    assert!(gc_dir.join(&new_ulid).exists());

    let index_dir = base.join("index");
    assert!(
        index_dir.join(format!("{old_ulid}.idx")).exists(),
        "old idx must persist until promote_segment runs"
    );
    assert!(
        !index_dir.join(format!("{new_ulid}.idx")).exists(),
        "new idx must not exist before promote_segment"
    );

    let new_ulid_parsed = Ulid::from_string(&new_ulid).unwrap();
    vol.promote_segment(new_ulid_parsed).unwrap();

    assert!(
        index_dir.join(format!("{new_ulid}.idx")).exists(),
        "promote_segment must write index/<new>.idx"
    );
    assert!(
        !index_dir.join(format!("{old_ulid}.idx")).exists(),
        "promote_segment must delete index/<old>.idx for each input"
    );

    // Reads still correct: extent index points to new_ulid, body in cache/.
    assert_eq!(vol.read(0, 2).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

// --- FileCache (CLOCK) tests ---

fn dummy_file() -> fs::File {
    fs::File::open("/dev/null").unwrap()
}

fn ulid(n: u128) -> Ulid {
    Ulid::from(n)
}

#[test]
fn file_cache_hit_and_miss() {
    let mut cache = FileCache::new(4);
    assert!(cache.get(ulid(1)).is_none());

    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    assert!(cache.get(ulid(1)).is_some());
    assert!(cache.get(ulid(2)).is_none());
}

#[test]
fn file_cache_returns_correct_layout() {
    let mut cache = FileCache::new(4);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::BodyOnly, dummy_file());

    let (layout, _) = cache.get(ulid(1)).unwrap();
    assert_eq!(layout, SegmentLayout::Full);

    let (layout, _) = cache.get(ulid(2)).unwrap();
    assert_eq!(layout, SegmentLayout::BodyOnly);
}

#[test]
fn file_cache_replace_in_place() {
    let mut cache = FileCache::new(4);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(1), SegmentLayout::BodyOnly, dummy_file());

    let (layout, _) = cache.get(ulid(1)).unwrap();
    assert_eq!(layout, SegmentLayout::BodyOnly);
}

#[test]
fn file_cache_fills_empty_slots_before_evicting() {
    let mut cache = FileCache::new(3);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(3), SegmentLayout::Full, dummy_file());

    // All three should be present — no eviction yet.
    assert!(cache.get(ulid(1)).is_some());
    assert!(cache.get(ulid(2)).is_some());
    assert!(cache.get(ulid(3)).is_some());
}

#[test]
fn file_cache_clock_evicts_unreferenced() {
    let mut cache = FileCache::new(3);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(3), SegmentLayout::Full, dummy_file());

    // Touch 2 and 3 so their referenced bits are set.
    cache.get(ulid(2));
    cache.get(ulid(3));

    // Insert a 4th — should evict ulid(1) (unreferenced after insert,
    // since insert sets referenced but the CLOCK sweep clears it).
    // Actually: all three were inserted with referenced=true. Then we
    // called get() on 2 and 3 (re-setting their bits). The hand starts
    // at 0. On sweep: slot 0 (ulid 1) has referenced=true from insert,
    // so it gets cleared and hand advances. Slot 1 (ulid 2) has
    // referenced=true from get, cleared, hand advances. Slot 2 (ulid 3)
    // has referenced=true from get, cleared, hand advances. Back to
    // slot 0 (ulid 1) — now unreferenced — evicted.
    cache.insert(ulid(4), SegmentLayout::Full, dummy_file());

    assert!(
        cache.get(ulid(1)).is_none(),
        "ulid(1) should have been evicted"
    );
    assert!(cache.get(ulid(4)).is_some());
}

#[test]
fn file_cache_recently_accessed_survives_eviction() {
    // With 3 slots, insert three entries. Access ulid(2) to refresh its
    // referenced bit, then insert a 4th. The CLOCK sweep clears all
    // referenced bits on the first pass, then evicts the entry at the
    // hand position (slot 0 = ulid(1)) on the second pass.
    // Crucially, get() on ulid(2) refreshes its bit *after* insert set it,
    // so when the sweep clears it on the first pass, ulid(2) gets cleared
    // like everyone else — but if we access it *between* two inserts, the
    // second sweep finds it referenced again.
    let mut cache = FileCache::new(3);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(3), SegmentLayout::Full, dummy_file());

    // First overflow: inserts ulid(4). The sweep clears all three
    // referenced bits (first pass), then evicts slot 0 (ulid(1)) on
    // the second pass. Hand ends at slot 1.
    cache.insert(ulid(4), SegmentLayout::Full, dummy_file());
    assert!(cache.get(ulid(1)).is_none(), "ulid(1) evicted");

    // Now touch ulid(2) — refreshes its referenced bit.
    cache.get(ulid(2));

    // Second overflow: inserts ulid(5). Hand is at slot 1.
    // Slot 1 (ulid(2)) ref=true → cleared, hand→2.
    // Slot 2 (ulid(3)) ref=false (cleared by first sweep, never re-accessed) → evicted.
    cache.insert(ulid(5), SegmentLayout::Full, dummy_file());
    assert!(cache.get(ulid(3)).is_none(), "ulid(3) evicted");
    assert!(
        cache.get(ulid(2)).is_some(),
        "ulid(2) survived — was accessed"
    );
    assert!(cache.get(ulid(4)).is_some());
    assert!(cache.get(ulid(5)).is_some());
}

#[test]
fn file_cache_evict_by_id() {
    let mut cache = FileCache::new(4);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());

    cache.evict(ulid(1));
    assert!(cache.get(ulid(1)).is_none());
    assert!(cache.get(ulid(2)).is_some());
}

#[test]
fn file_cache_clear() {
    let mut cache = FileCache::new(4);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());

    cache.clear();
    assert!(cache.get(ulid(1)).is_none());
    assert!(cache.get(ulid(2)).is_none());
}

#[test]
fn file_cache_evict_frees_slot_for_reuse() {
    let mut cache = FileCache::new(2);
    cache.insert(ulid(1), SegmentLayout::Full, dummy_file());
    cache.insert(ulid(2), SegmentLayout::Full, dummy_file());

    cache.evict(ulid(1));

    // The freed slot should be reused without evicting ulid(2).
    cache.insert(ulid(3), SegmentLayout::Full, dummy_file());
    assert!(cache.get(ulid(2)).is_some());
    assert!(cache.get(ulid(3)).is_some());
}

// --- inline extent tests ---

#[test]
fn inline_write_and_read_roundtrip() {
    // Small writes that compress below INLINE_THRESHOLD should be
    // readable immediately (from WAL) and after promotion (from inline_data).
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // All-same-byte 4KB data compresses to a few bytes → inline.
    let data = vec![0xAAu8; 4096];
    vol.write(0, &data).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data, "read before promotion");

    vol.promote_for_test().unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), data, "read after promotion");

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn inline_survives_reopen() {
    // After close+reopen, inline data is rebuilt from the segment's
    // inline section and reads still work.
    let base = keyed_temp_dir();
    {
        let mut vol = Volume::open(&base, &base).unwrap();
        let data = vec![0xBBu8; 4096];
        vol.write(0, &data).unwrap();
        vol.promote_for_test().unwrap();
    }
    // Reopen: extent index is rebuilt from pending/ segments.
    let vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.read(0, 1).unwrap(), vec![0xBBu8; 4096]);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn inline_coexists_with_body_entries() {
    // A segment with both inline and body entries: both are readable.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Small write → inline (compresses below threshold).
    let small = vec![0xCCu8; 4096];
    vol.write(0, &small).unwrap();

    // Large high-entropy write → body (doesn't compress below threshold).
    let large: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(1, &large).unwrap();

    vol.promote_for_test().unwrap();

    assert_eq!(vol.read(0, 1).unwrap(), small);
    assert_eq!(vol.read(1, 2).unwrap(), large);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn inline_dedup_as_canonical_source() {
    // An inline extent can serve as the canonical source for dedup.
    // Write the same small data at two different LBAs: first is DATA/Inline,
    // second should dedup (REF).
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = vec![0xDDu8; 4096]; // compresses → inline
    vol.write(0, &data).unwrap();
    vol.write(1, &data).unwrap(); // dedup hit → REF

    vol.promote_for_test().unwrap();

    // Both LBAs should read correctly — the REF resolves via the
    // inline canonical entry.
    assert_eq!(vol.read(0, 1).unwrap(), data);
    assert_eq!(vol.read(1, 1).unwrap(), data);

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn inline_repack_preserves_data() {
    // GC repack of a segment containing inline entries must preserve
    // inline data through the rewrite.
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let d0 = vec![0xEEu8; 4096]; // inline
    let d1 = vec![0xFFu8; 4096]; // inline
    vol.write(0, &d0).unwrap();
    vol.write(1, &d1).unwrap();
    vol.promote_for_test().unwrap();

    // Overwrite LBA 0 to make d0 dead, creating GC opportunity.
    let d2 = vec![0x11u8; 4096];
    vol.write(0, &d2).unwrap();
    vol.promote_for_test().unwrap();

    // Repack: the segment with d0+d1 should be compacted; d1 survives.
    // Threshold 1.0 → compact any segment with dead extents.
    let stats = vol.repack().unwrap();
    assert!(stats.segments_compacted > 0);

    // Reads still correct after repack.
    assert_eq!(vol.read(0, 1).unwrap(), d2);
    assert_eq!(vol.read(1, 1).unwrap(), d1);

    fs::remove_dir_all(base).unwrap();
}

/// Simulates a crash window in `promote_segment`: the segment's cache body
/// and idx have been committed on disk, but the extent-index CAS + pending
/// delete have not run (in the offloaded design these live in a separate
/// actor-side apply phase). The next `promote_segment` call for the same
/// ULID must complete the half-done work — delete `pending/<ulid>` and
/// transition extent-index entries to `BodySource::Cached` — not silently
/// early-return.
///
/// Today (synchronous in-actor `promote_segment`) the window is narrow but
/// still observable because `extract_idx` and `promote_to_cache` commit
/// their files via atomic rename before the pending delete runs. Under the
/// planned worker offload the window widens, so this test is also a
/// regression guard for the offload landing.
#[test]
fn promote_segment_recovers_mid_apply_crash() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let data = [42u8; 4096];
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let ulid_str = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (!name.contains('.')).then_some(name)
        })
        .unwrap();
    let ulid = Ulid::from_string(&ulid_str).unwrap();
    let pending_path = pending_dir.join(&ulid_str);

    // Perform only the "worker" half of promote_segment — extract_idx +
    // promote_to_cache. Skip the extent-index CAS + pending delete.
    let cache_dir = base.join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let body_path = cache_dir.join(format!("{ulid_str}.body"));
    let present_path = cache_dir.join(format!("{ulid_str}.present"));
    let index_dir = base.join("index");
    fs::create_dir_all(&index_dir).unwrap();
    let idx_path = index_dir.join(format!("{ulid_str}.idx"));
    segment::extract_idx(&pending_path, &idx_path).unwrap();
    segment::promote_to_cache(&pending_path, &body_path, &present_path).unwrap();

    assert!(pending_path.exists(), "precondition: pending survives");
    assert!(body_path.exists(), "precondition: cache body committed");
    assert!(idx_path.exists(), "precondition: idx committed");

    // Simulate the process crash: drop and reopen.
    drop(vol);
    let mut vol = Volume::open(&base, &base).unwrap();

    // Coordinator retries promote_segment on its next tick.
    vol.promote_segment(ulid).unwrap();

    // Invariant 1: pending/<ulid> is gone after the retry.
    assert!(
        !pending_path.exists(),
        "pending/<ulid> survived retry — half-done promote not recovered",
    );

    // Invariant 2: the extent-index entry for the written hash now points
    // at Cached, not Local.
    let hash = blake3::hash(&data);
    let loc = vol
        .extent_index
        .lookup(&hash)
        .expect("hash still present in extent index");
    assert!(
        matches!(loc.body_source, BodySource::Cached(_)),
        "extent-index entry still BodySource::Local after retry: {:?}",
        loc.body_source
    );

    // Invariant 3: data still reads back correctly.
    let actual = vol.read(0, 1).unwrap();
    assert_eq!(actual.as_slice(), data.as_slice(), "data readback wrong");

    fs::remove_dir_all(base).unwrap();
}

/// Simulates the crash window one step earlier than
/// `promote_segment_recovers_mid_apply_crash`: the kill lands after
/// `extract_idx` but before `promote_to_cache` completes. On reopen the
/// leaked idx classifies the entries `Cached`, so the fetch paths may
/// start building `cache/<ulid>.body` incrementally — here simulated by
/// a short partial file with no `.present` bits. The promote retry must
/// rebuild the complete cache form from the surviving pending source,
/// not early-return on the partial fetch-created body and then serve
/// short reads from it.
#[test]
fn promote_segment_retry_rebuilds_partial_fetch_created_body() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    let block_a = high_entropy_block(0xB1);
    let block_b = high_entropy_block(0xB2);
    vol.write(0, &block_a).unwrap();
    vol.write(1, &block_b).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let ulid_str = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (!name.contains('.')).then_some(name)
        })
        .unwrap();
    let ulid = Ulid::from_string(&ulid_str).unwrap();
    let pending_path = pending_dir.join(&ulid_str);

    let index_dir = base.join("index");
    fs::create_dir_all(&index_dir).unwrap();
    segment::extract_idx(&pending_path, &index_dir.join(format!("{ulid_str}.idx"))).unwrap();

    let cache_dir = base.join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let body_path = cache_dir.join(format!("{ulid_str}.body"));
    fs::write(&body_path, b"partial fetch in flight").unwrap();

    drop(vol);
    let mut vol = Volume::open(&base, &base).unwrap();
    vol.promote_segment(ulid).unwrap();

    assert!(!pending_path.exists(), "pending source survived retry");
    assert_eq!(vol.read(0, 1).unwrap(), block_a, "LBA 0 readback wrong");
    assert_eq!(vol.read(1, 1).unwrap(), block_b, "LBA 1 readback wrong");

    fs::remove_dir_all(base).unwrap();
}

/// A completed promote whose source has already been reaped must stay a
/// no-op: `promote_to_cache` on a missing source with the cache form in
/// place returns Ok without touching the files.
#[test]
fn promote_to_cache_noop_after_source_reaped() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    vol.write(0, &high_entropy_block(0xC7)).unwrap();
    vol.promote_for_test().unwrap();

    let pending_dir = base.join("pending");
    let ulid_str = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (!name.contains('.')).then_some(name)
        })
        .unwrap();
    let pending_path = pending_dir.join(&ulid_str);

    let cache_dir = base.join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    let body_path = cache_dir.join(format!("{ulid_str}.body"));
    let present_path = cache_dir.join(format!("{ulid_str}.present"));
    segment::promote_to_cache(&pending_path, &body_path, &present_path).unwrap();

    fs::remove_file(&pending_path).unwrap();
    segment::promote_to_cache(&pending_path, &body_path, &present_path).unwrap();
    assert!(body_path.exists());

    fs::remove_dir_all(base).unwrap();
}

#[test]
fn all_inline_segment_readable() {
    // A segment where every entry is inline (body_length = 0).
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();

    // Write several small extents — all compress to inline.
    for lba in 0..4u64 {
        let data = vec![lba as u8; 4096];
        vol.write(lba, &data).unwrap();
    }
    vol.promote_for_test().unwrap();

    // Verify all reads.
    for lba in 0..4u64 {
        let expected = vec![lba as u8; 4096];
        assert_eq!(vol.read(lba, 1).unwrap(), expected, "LBA {lba} mismatch");
    }

    // Verify the segment has body_length = 0.
    let pending_dir = base.join("pending");
    let seg_path = fs::read_dir(&pending_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let (bss, _, _) =
        segment::read_and_verify_segment_index(&seg_path, &vol.verifying_key).unwrap();
    let file_len = fs::metadata(&seg_path).unwrap().len();
    assert_eq!(file_len, bss, "all-inline segment should have no body");

    fs::remove_dir_all(base).unwrap();
}

/// A Delta entry whose declared content hash does not match the bytes
/// its materialisation produces must fail the read loudly. Without the
/// hash check the zstd-dict decompress silently serves the mismatched
/// bytes — the wrong-dictionary failure shape of the 2026-07-06
/// quickstart incident.
#[test]
fn delta_materialisation_hash_mismatch_errors() {
    let base = keyed_temp_dir();
    let signer = crate::signing::load_signer(&base, crate::signing::VOLUME_KEY_FILE).unwrap();

    // Parent extent: the delta's dictionary source.
    let parent = vec![0x11u8; 4096];
    let parent_hash = blake3::hash(&parent);
    let mut vol = Volume::open(&base, &base).unwrap();
    vol.write(0, &parent).unwrap();
    vol.flush_wal().unwrap();
    drop(vol);

    // The blob materialises to `child`, but the entry declares a hash
    // of different content — the shape a wrong source dictionary
    // produces.
    let mut child = parent.clone();
    child[0..64].fill(0xCC);
    let wrong_hash = blake3::hash(b"not the child bytes");

    let blob = zstd::bulk::Compressor::with_dictionary(3, &parent)
        .unwrap()
        .compress(&child)
        .unwrap();
    let delta_ulid = ulid::Ulid::new();
    let pending = base.join("pending").join(delta_ulid.to_string());
    let entries = vec![segment::PendingEntry::from_entry(
        segment::SegmentEntry::new_delta(
            wrong_hash,
            100,
            1,
            vec![segment::DeltaOption {
                source_hash: parent_hash,
                delta_offset: 0,
                delta_length: blob.len() as u32,
                delta_hash: blake3::hash(&blob),
            }],
        ),
    )];
    segment::write_segment_with_delta_body(&pending, entries, &blob, signer.as_ref()).unwrap();

    // Reopen so the rebuild registers the hand-written pending segment.
    let vol = Volume::open(&base, &base).unwrap();
    let err = vol
        .read(100, 1)
        .expect_err("mismatched delta materialisation must error, not serve bytes");
    assert!(
        err.to_string().contains("hashed"),
        "unexpected error: {err}"
    );

    fs::remove_dir_all(base).unwrap();
}

/// A hash mapped in the lbamap but absent from both the data and delta
/// extent indexes is read-state divergence, not a hole. `read_extents`
/// must error loudly — serving zeros masks corruption (and did, in the
/// 2026-07-06 quickstart incident's failure family).
#[test]
fn read_extents_errors_on_hash_missing_from_both_indexes() {
    let tmp = keyed_temp_dir();
    let mut map = lbamap::LbaMap::new();
    map.insert(0, 1, blake3::hash(b"orphan"), ulid::Ulid::new());
    let index = extentindex::ExtentIndex::new();
    let file_cache = std::cell::RefCell::new(read::FileCache::new(4));
    let dmat_cache: read::DmatCache = Default::default();
    let dmat_stats = Arc::new(crate::dmat::DmatStats::default());
    let mut out = vec![0u8; 4096];
    let err = read::read_extents(
        0,
        &mut out,
        &map,
        &index,
        &file_cache,
        &dmat_cache,
        &dmat_stats,
        &tmp,
        |_, _, _| Err(io::Error::other("find_segment must not be consulted")),
        |_| Err(io::Error::other("open_delta_body must not be consulted")),
    )
    .expect_err("mapped hash absent from both indexes must error");
    assert!(
        err.to_string().contains("not in extent index"),
        "unexpected error: {err}"
    );
    fs::remove_dir_all(tmp).unwrap();
}

/// The drift checker's stale-location branch: a hash validly owned on
/// disk whose in-memory location names a segment no disk walk can see
/// (the carried-Delta dangle shape) must trip the invariant — the
/// ownership check alone passes.
#[cfg(feature = "volume-invariants")]
#[test]
#[should_panic(expected = "stale inner: points at deleted segment")]
fn invariant_catches_stale_location_at_deleted_segment() {
    let base = keyed_temp_dir();
    let mut vol = Volume::open(&base, &base).unwrap();
    vol.write(0, &vec![0x42u8; 4096]).unwrap();
    vol.flush_wal().unwrap();

    let (hash, mut stale) = {
        let (h, l) = vol.extent_index.iter().next().expect("flushed entry");
        (*h, l.clone())
    };
    stale.segment_id = ulid::Ulid::from_parts(u64::MAX, u128::MAX);
    Arc::make_mut(&mut vol.extent_index).insert(hash, stale);

    vol.assert_volume_invariants("stale_location_test");
}

#[test]
fn own_segments_commitment_matches_disk_scan_through_lifecycle() {
    // Both sides of the gc-tick divergence check derive from the same
    // committed-tier definition: the daemon's live set must produce the
    // same commitment as a `committed_tier_ulids` disk scan at every
    // settled lifecycle point.
    let base = keyed_temp_dir();
    let scan = |base: &std::path::Path| {
        crate::volume_ipc::SegmentSetCommitment::from_ulids(
            segment::committed_tier_ulids(base).unwrap(),
        )
    };
    let mut vol = Volume::open(&base, &base).unwrap();
    assert_eq!(vol.own_segments_commitment(), scan(&base));
    assert_eq!(vol.own_segments_commitment().count, 0);

    let data: Vec<u8> = (0..8192).map(|i| (i * 7 + 13) as u8).collect();
    vol.write(0, &data).unwrap();
    vol.promote_for_test().unwrap();
    assert_eq!(
        vol.own_segments_commitment(),
        scan(&base),
        "pending tier is outside the commitment on both sides"
    );

    simulate_upload(&mut vol);
    assert_eq!(vol.own_segments_commitment(), scan(&base));
    assert_eq!(vol.own_segments_commitment().count, 1);
    let old_ulid = *vol.own_segments.iter().next().unwrap();

    let new_ulid_str = simulate_coord_gc_staged(&mut vol, &base, &old_ulid.to_string());
    let new_ulid = Ulid::from_string(&new_ulid_str).unwrap();
    vol.apply_gc_handoffs().unwrap();
    assert_eq!(vol.own_segments_commitment(), scan(&base));

    vol.promote_segment(new_ulid).unwrap();
    assert_eq!(vol.own_segments_commitment(), scan(&base));

    vol.finalize_gc_handoff(new_ulid).unwrap();
    assert_eq!(vol.own_segments_commitment(), scan(&base));

    fs::remove_dir_all(base).unwrap();
}
