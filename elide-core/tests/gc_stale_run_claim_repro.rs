// Deterministic materialisation of volume_proptest::ulid_monotonicity seed
// 9729f33595c8de6e6ac9b18979cb89b7724555c811fb93a67e8d2e86d76bfab3,
// minimised to:
//
//   JournalStraddleWrite { start_lba: 96, lba_count: 6, seed: 0 }
//   DeltaCycleWrite { lba: 0, base_seed: 0, tweak: 0 }
//   CoordGcLocal { n: 2 }
//   HalfRepack { apply: false, remove_inputs: 0 }
//   Snapshot
//   JournalDupWrite { journal_first: false, seed: 0 }
//   CoordGcLocal { n: 2 }
//
// The journal window is [96, 100), so the straddle write splits at 100 and
// LBA 101 lands in the stable share.
//
// Two segments end up holding the same hash over LBA 101, and only the
// higher-ULID one holds the claim. The segment without the claim has to
// classify that entry dead. Reading it live puts an output entry in the
// plan for LBAs the segment does not own; the apply refuses that claim —
// `insert_consuming_inputs` sees an owner outside the consumed set — while
// the committed output keeps it at a higher ULID, so the live map and a
// rebuild disagree from then on.

use elide_core::volume::Volume;

mod common;

fn block(seed: u8) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let mut hasher = blake3::Hasher::new_keyed(&[seed; 32]);
    for (i, chunk) in buf.chunks_mut(32).enumerate() {
        hasher.update(&(i as u64).to_le_bytes());
        chunk.copy_from_slice(&hasher.finalize().as_bytes()[..chunk.len()]);
        hasher.reset();
    }
    buf
}

/// `block(base_seed)` with the first 32 bytes replaced by `tweak`, so the
/// pair delta-compresses — the shape `DeltaCycleWrite` exercises.
fn variant_block(base_seed: u8, tweak: u8) -> Vec<u8> {
    let mut buf = block(base_seed);
    buf[..32].copy_from_slice(&[tweak; 32]);
    buf
}

fn stamp_journal_window(fork_dir: &std::path::Path) {
    let mut cfg = elide_core::config::VolumeConfig::read(fork_dir).unwrap();
    cfg.journal = Some(elide_core::config::JournalConfig {
        ranges: elide_core::journal::JournalRanges::new(vec![(96, 4)]),
    });
    cfg.write(fork_dir).unwrap();
}

#[test]
fn gc_run_claim_refused_in_memory_must_not_win_the_rebuild() {
    let tmp = tempfile::TempDir::new().unwrap();
    let fork_dir = tmp.path();
    common::write_test_keypair(fork_dir);
    stamp_journal_window(fork_dir);

    let mut oracle: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    // JournalStraddleWrite { start_lba: 96, lba_count: 6, seed: 0 }
    let mut payload = Vec::new();
    for i in 0..6u8 {
        payload.extend_from_slice(&block(i));
    }
    vol.write(96, &payload).unwrap();
    for i in 0..6u64 {
        oracle.insert(96 + i, payload[i as usize * 4096..][..4096].to_vec());
    }

    // DeltaCycleWrite { lba: 0, base_seed: 0, tweak: 0 }
    let a_prime = variant_block(0, 0);
    let mid = variant_block(0, 1);
    vol.write(52, &a_prime).unwrap();
    vol.write(52, &mid).unwrap();
    vol.write(52, &a_prime).unwrap();
    oracle.insert(52, a_prime.clone());

    // CoordGcLocal { n: 2 }
    common::drain_with_reap(&mut vol);
    let gc_ulid = vol.gc_checkpoint_for_test().unwrap();
    let to_delete = common::simulate_coord_gc_local(fork_dir, gc_ulid, 2)
        .map(|(_, _, paths)| paths)
        .unwrap_or_default();
    if vol.apply_gc_handoffs().unwrap_or(0) > 0 {
        for path in &to_delete {
            let _ = std::fs::remove_file(path);
        }
    }

    // HalfRepack { apply: false, remove_inputs: 0 } — the offload window,
    // taken as a crash.
    let _ = vol.repack_crash_for_test(false, 0);
    drop(vol);
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();
    common::assert_promote_recovery(&mut vol, fork_dir);

    // Snapshot
    let _ = vol.snapshot();

    // JournalDupWrite { journal_first: false, seed: 0 }
    let dup = block(0);
    vol.write(100, &dup).unwrap();
    vol.write(96, &dup).unwrap();
    oracle.insert(96, dup.clone());
    oracle.insert(100, dup.clone());

    // CoordGcLocal { n: 2 }
    common::drain_with_reap(&mut vol);
    let gc_ulid = vol.gc_checkpoint_for_test().unwrap();
    let to_delete = common::simulate_coord_gc_local(fork_dir, gc_ulid, 2)
        .map(|(_, _, paths)| paths)
        .unwrap_or_default();
    if vol.apply_gc_handoffs().unwrap_or(0) > 0 {
        for path in &to_delete {
            let _ = std::fs::remove_file(path);
        }
    }

    // The live map serves every LBA correctly — the refusal protected it.
    for (&lba, expected) in &oracle {
        assert_eq!(
            vol.read(lba, 1).unwrap(),
            *expected,
            "lba {lba} wrong before the restart"
        );
    }

    // A restart rebuilds the lbamap from disk, where the GC output's claim
    // outranks the segment the apply protected.
    drop(vol);
    let vol = Volume::open(fork_dir, fork_dir).unwrap();
    for (&lba, expected) in &oracle {
        assert_eq!(
            vol.read(lba, 1).unwrap(),
            *expected,
            "lba {lba} wrong after crash+rebuild"
        );
    }
}
