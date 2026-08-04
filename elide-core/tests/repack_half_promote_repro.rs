// Deterministic materialisation of crash_recovery_oracle seed
// 13787da3531f26212fbb49a9e6aa6b8beec92f9b6daaa302a319dd7a20245531,
// minimised to:
//
//   WriteLarge { lba: 4, seed: 0 }     // LBA 28 <- incompressible_block(0)
//   WriteLarge { lba: 4, seed: 1 }     // LBA 28 <- incompressible_block(1) (overwrites)
//   PopulateFetched { lba: 0, seed: 0 } // writes index/<u_gc>.idx + cache/<u_gc>.body for LBA 16
//   HalfPromotePending                  // writes index/<u_flush>.idx + cache/<u_flush>.body+present
//   Repack
//   Crash
//
// Both LBAs must read back their most recent bytes after the crash: LBA 28
// through the repacked segment, LBA 16 through the demand-fetched one whose
// sibling promote files the half-promote left half-written.

use elide_core::volume::Volume;
use tempfile::TempDir;

mod common;

/// 4 KiB of pseudo-random bytes keyed on `seed`. Matches
/// `volume_proptest::incompressible_block`.
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

#[test]
fn repack_after_half_promote_preserves_oracle_across_crash() {
    let tmp = TempDir::new().unwrap();
    let fork_dir = tmp.path();
    common::write_test_keypair(fork_dir);

    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    // WriteLarge { lba: 4, seed: 0 } — LBA 28
    let block0 = incompressible_block(0);
    vol.write(28, &block0).unwrap();

    // WriteLarge { lba: 4, seed: 1 } — LBA 28, overwrites
    let block1 = incompressible_block(1);
    vol.write(28, &block1).unwrap();

    // PopulateFetched { lba: 0, seed: 0 } — LBA 16 with effective_seed 0x80.
    // `gc_checkpoint_for_test` mints (u_gc, u_flush) and flushes the WAL to
    // `pending/<u_flush>`, then `populate_cache` writes `index/<u_gc>.idx`
    // + `cache/<u_gc>.body` directly (simulating a demand-fetch).
    let u_gc = vol.gc_checkpoint_for_test().unwrap();
    let effective_seed: u8 = 0x80;
    common::populate_cache(fork_dir, u_gc, 16, effective_seed);

    // `populate_cache` writes index/ + cache/ behind the live volume's
    // back, so drop+reopen to let the rebuild pick the claim at LBA 16
    // up — the same compensation every other caller of it makes.
    drop(vol);
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    // HalfPromotePending — lowest-ULID pending segment is `<u_flush>`.
    // Writes sibling index/<u_flush>.idx + cache/<u_flush>.body+present from
    // the pre-repack pending body. Does NOT delete pending/<u_flush>.
    let u_flush = common::half_promote_first_pending(fork_dir).unwrap();

    // Repack — consumes pending/<u_flush> into a fresh-ULID output,
    // leaving the half-promote's siblings naming a segment that is gone.
    vol.repack().unwrap();

    // Repack invalidates a consumed input's promote siblings, so the
    // rebuild below finds no segment `<u_flush>` at all. Reads survive
    // either way — the output's ULID is minted above the input's, so a
    // resurrected `<u_flush>` loses every claim it makes — which is why
    // the oracle assertions further down cannot see this.
    for sibling in [
        fork_dir.join("index").join(format!("{u_flush}.idx")),
        fork_dir.join("cache").join(format!("{u_flush}.body")),
        fork_dir.join("cache").join(format!("{u_flush}.present")),
    ] {
        assert!(
            !sibling.exists(),
            "repack must invalidate the promote sibling {}",
            sibling.display()
        );
    }

    // Crash + reopen + finish the half-promoted segment.
    drop(vol);
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();
    common::assert_promote_recovery(&mut vol, fork_dir);

    assert_eq!(
        vol.read(28, 1).unwrap(),
        block1,
        "LBA 28 must read back the most-recent write after crash+rebuild"
    );
    assert_eq!(
        vol.read(16, 1).unwrap(),
        vec![effective_seed; 4096],
        "LBA 16 (PopulateFetched) must read back the fetched bytes after crash+rebuild"
    );
}
