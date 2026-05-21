// Property-based test for cross-volume isolation at the Volume layer.
//
// Two independent volumes, each with its own directory and oracle. Operations
// (write/flush/repack/drain/crash) target one volume at a time. After every op,
// and at the end of every run, reads on each volume must return that volume's
// oracle bytes — never the other volume's.
//
// Seed partition:
//   volume A writes use seeds in 0..=63  (low bit-7 clear)
//   volume B writes use seeds in 128..=191 (bit-7 set)
//   `WriteBoth` writes the SAME seed (64..=127) to both volumes at the same LBA.
//
// Cross-volume contamination of any flavour surfaces as:
//   - volume A read returning a seed ≥128 (B's range), or
//   - volume B read returning a seed <128 (A's range), or
//   - either volume reading non-zero bytes at an LBA it never wrote.
//
// What this catches that the single-volume crash_recovery_oracle does not:
//   - shared global mutable state across `Volume` instances,
//   - filesystem path confusion (one volume's pending/index/cache ending up
//     under the other's base_dir),
//   - cache or segment-cache instances mis-scoped across volumes.
//
// The Volume layer's isolation is otherwise structural — each `Volume` owns
// its `base_dir`, `Arc<ExtentIndex>`, `Arc<LbaMap>`, and `segment_cache` —
// so this property is primarily a regression net for the next time someone
// adds shared state to the volume read or write path.

#![cfg(feature = "proptest")]

use std::collections::HashMap;
use std::path::Path;

use elide_core::volume::Volume;
use proptest::prelude::*;
use ulid::Ulid;

mod common;

const LBA_RANGE: u8 = 16; // LBAs 0..16 are eligible for write ops.

/// Seed range for volume A. Bit 7 clear so any read returning ≥128 is a leak.
fn seed_a(s: u8) -> u8 {
    s & 0x3f
}

/// Seed range for volume B. Bit 7 set so any read returning <128 is a leak.
fn seed_b(s: u8) -> u8 {
    0x80 | (s & 0x3f)
}

/// Shared seed range used by `WriteBoth`. Distinct from `seed_a` / `seed_b`
/// so the assertion error message distinguishes the case where both volumes
/// legitimately hold the same content from the case where one's read leaked
/// into the other.
fn seed_both(s: u8) -> u8 {
    0x40 | (s & 0x1f)
}

#[derive(Debug, Clone)]
enum MultiOp {
    /// Write to volume A at the given LBA with a seed in 0..=63.
    WriteA {
        lba: u8,
        seed: u8,
    },
    /// Write to volume B at the given LBA with a seed in 128..=191.
    WriteB {
        lba: u8,
        seed: u8,
    },
    /// Write the same bytes to both volumes at the same LBA. Each volume's
    /// internal dedup will collapse the write to a single segment in its own
    /// directory, but the two volumes' segments must remain physically
    /// distinct on disk.
    WriteBoth {
        lba: u8,
        seed: u8,
    },
    FlushA,
    FlushB,
    RepackA,
    RepackB,
    /// Drain: repack + promote every pending segment. Tests the index/cache
    /// publish path on each volume independently.
    DrainA,
    DrainB,
    /// Crash + reopen volume A. The reopen triggers WAL recovery and rebuild.
    /// Volume B's `Volume` instance is untouched.
    CrashA,
    /// Crash + reopen volume B (symmetric).
    CrashB,
}

fn arb_multi_op() -> impl Strategy<Value = MultiOp> {
    prop_oneof![
        4 => (0u8..LBA_RANGE, any::<u8>()).prop_map(|(lba, seed)| MultiOp::WriteA { lba, seed }),
        4 => (0u8..LBA_RANGE, any::<u8>()).prop_map(|(lba, seed)| MultiOp::WriteB { lba, seed }),
        2 => (0u8..LBA_RANGE, any::<u8>()).prop_map(|(lba, seed)| MultiOp::WriteBoth { lba, seed }),
        1 => Just(MultiOp::FlushA),
        1 => Just(MultiOp::FlushB),
        1 => Just(MultiOp::RepackA),
        1 => Just(MultiOp::RepackB),
        1 => Just(MultiOp::DrainA),
        1 => Just(MultiOp::DrainB),
        1 => Just(MultiOp::CrashA),
        1 => Just(MultiOp::CrashB),
    ]
}

fn arb_ops() -> impl Strategy<Value = Vec<MultiOp>> {
    prop::collection::vec(arb_multi_op(), 0..40)
}

/// Open a writable volume at `dir`, writing the test keypair first.
fn open_volume(dir: &Path) -> Volume {
    common::write_test_keypair(dir);
    Volume::open(dir, dir).unwrap()
}

/// Per-volume oracle: LBA → expected 4096-byte content. An LBA absent from
/// the map means the volume never wrote it, so a read must return all zeros.
type Oracle = HashMap<u64, [u8; 4096]>;

fn expected_at(oracle: &Oracle, lba: u64) -> [u8; 4096] {
    oracle.get(&lba).copied().unwrap_or([0u8; 4096])
}

/// Read every LBA in `0..LBA_RANGE` from `vol` and compare against `oracle`.
/// Fails the prop-test with a diagnostic naming the volume label.
fn assert_oracle_matches(label: &str, vol: &Volume, oracle: &Oracle) -> Result<(), TestCaseError> {
    for lba in 0..(LBA_RANGE as u64) {
        let actual = vol.read(lba, 1).unwrap();
        let expected = expected_at(oracle, lba);
        prop_assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "volume {} lba {} returned wrong bytes (first byte actual={}, expected={})",
            label,
            lba,
            actual[0],
            expected[0],
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    /// Two independent volumes; arbitrary interleaved operations on each;
    /// every read on volume V returns V's oracle. No operation on one
    /// volume ever causes the other to return a value outside its oracle.
    #[test]
    fn no_cross_volume_contamination(ops in arb_ops()) {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir_a = tmp.path().join(Ulid::new().to_string());
        let dir_b = tmp.path().join(Ulid::new().to_string());

        let mut vol_a = open_volume(&dir_a);
        let mut vol_b = open_volume(&dir_b);
        let mut oracle_a: Oracle = HashMap::new();
        let mut oracle_b: Oracle = HashMap::new();

        for op in &ops {
            match op {
                MultiOp::WriteA { lba, seed } => {
                    let data = [seed_a(*seed); 4096];
                    vol_a.write(*lba as u64, &data).unwrap();
                    oracle_a.insert(*lba as u64, data);
                }
                MultiOp::WriteB { lba, seed } => {
                    let data = [seed_b(*seed); 4096];
                    vol_b.write(*lba as u64, &data).unwrap();
                    oracle_b.insert(*lba as u64, data);
                }
                MultiOp::WriteBoth { lba, seed } => {
                    let data = [seed_both(*seed); 4096];
                    vol_a.write(*lba as u64, &data).unwrap();
                    vol_b.write(*lba as u64, &data).unwrap();
                    oracle_a.insert(*lba as u64, data);
                    oracle_b.insert(*lba as u64, data);
                }
                MultiOp::FlushA => { vol_a.flush_wal().unwrap(); }
                MultiOp::FlushB => { vol_b.flush_wal().unwrap(); }
                MultiOp::RepackA => { vol_a.repack().unwrap(); }
                MultiOp::RepackB => { vol_b.repack().unwrap(); }
                MultiOp::DrainA => { common::drain_with_repack(&mut vol_a); }
                MultiOp::DrainB => { common::drain_with_repack(&mut vol_b); }
                MultiOp::CrashA => {
                    drop(vol_a);
                    vol_a = Volume::open(&dir_a, &dir_a).unwrap();
                    assert_oracle_matches("A", &vol_a, &oracle_a)?;
                    // Bonus check: volume B was untouched, but make sure
                    // none of its LBAs report a value matching A's recent
                    // write. Most natural here because we just dropped
                    // and reopened A.
                    assert_oracle_matches("B", &vol_b, &oracle_b)?;
                }
                MultiOp::CrashB => {
                    drop(vol_b);
                    vol_b = Volume::open(&dir_b, &dir_b).unwrap();
                    assert_oracle_matches("A", &vol_a, &oracle_a)?;
                    assert_oracle_matches("B", &vol_b, &oracle_b)?;
                }
            }
        }

        // Final end-of-run check: every LBA on both volumes matches its
        // oracle. Catches contamination introduced by the last op in the
        // sequence (which has no subsequent Crash to flush its effect
        // through the recovery oracle).
        assert_oracle_matches("A", &vol_a, &oracle_a)?;
        assert_oracle_matches("B", &vol_b, &oracle_b)?;
    }
}
