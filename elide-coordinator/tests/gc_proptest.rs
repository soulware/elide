// Property-based tests for the coordinator GC path.
//
// Invariant: after any sequence of writes, flushes, and GC sweeps, every
// LBA reads back the value last written to it.
//
// Unlike the proptest suite in elide-core (which uses a hand-rolled GC
// simulation in tests/common/mod.rs), this suite calls the real coordinator
// code: gc_fork() → vol.apply_gc_handoffs() → apply_done_handoffs().
// That closes the structural gap where the simulation could be correct while
// the production implementation had a bug.
//
// GcSweep runs the full coordinator round-trip:
//   1. gc_fork()              — real compact_segments / collect_stats
//   2. apply_gc_handoffs()    — volume re-signs and updates extent index
//   3. promote_gc_outputs()   — simulates coordinator promote IPC, coordinator-
//                               side cache/<input>.* delete, and finalize IPC
//   4. apply_done_handoffs()  — uploads to InMemory store, deletes old S3 objects
// Then asserts all oracle LBAs are readable with correct data.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use elide_coordinator::config::GcConfig;
use elide_coordinator::gc::{GcStrategy, apply_done_handoffs, gc_fork};
use elide_core::volume::Volume;
use object_store::ObjectStore;
use object_store::memory::InMemory;
use proptest::prelude::*;

/// Mirror the production drain: repack, then promote in ULID-ascending
/// order. Preserves `max(committed) < min(pending)` throughout —
/// see `coordinator/src/upload.rs::drain_pending`.
fn simulate_upload(vol: &mut Volume, dir: &Path) {
    let pending_dir = dir.join("pending");
    let cache_dir = dir.join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    let _ = vol.repack();

    let pending_after_repack =
        elide_core::segment::read_ulid_dir_sorted(&pending_dir).unwrap_or_default();
    for ulid in pending_after_repack {
        let _ = vol.promote_segment(ulid);
    }
}

/// Simulate the coordinator promote+finalize sequence for each volume-applied
/// gc output: under the self-describing handoff protocol, those are the bare
/// `gc/<ulid>` files (no extension). promote_segment writes index/<new>.idx
/// and cache/<new>.body; the coordinator then deletes cache/<input>.* for
/// every consumed input; finalize_gc_handoff deletes the bare body.
fn promote_gc_outputs(vol: &mut Volume, dir: &Path) {
    let gc_dir = dir.join("gc");
    let cache_dir = dir.join("cache");
    let vk = elide_core::signing::load_verifying_key(dir, elide_core::signing::VOLUME_PUB_FILE)
        .expect("loading volume verifying key");
    let Ok(entries) = fs::read_dir(&gc_dir) else {
        return;
    };
    let mut bare: Vec<ulid::Ulid> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            if name.contains('.') {
                return None;
            }
            ulid::Ulid::from_string(name).ok()
        })
        .collect();
    bare.sort();
    for ulid in bare {
        // Inputs list has to be read before finalize_gc_handoff deletes
        // the bare file.
        let bare_path = gc_dir.join(ulid.to_string());
        let inputs: Vec<ulid::Ulid> =
            elide_core::segment::read_and_verify_segment_index(&bare_path, &vk)
                .map(|(_, _, inputs)| inputs)
                .unwrap_or_default();
        let _ = vol.promote_segment(ulid);
        for old in &inputs {
            let s = old.to_string();
            let _ = fs::remove_file(cache_dir.join(format!("{s}.body")));
            let _ = fs::remove_file(cache_dir.join(format!("{s}.present")));
        }
        let _ = vol.finalize_gc_handoff(ulid);
    }
}

/// Promote the WAL with the `pick`-th sealed cache body hidden,
/// restoring it afterwards. The formation delta tier treats an
/// unreadable source as "skip, delta is best-effort". Falls back to a
/// plain promote when there is nothing to hide.
fn flush_with_evicted_source(vol: &mut Volume, dir: &Path, pick: u8) {
    let cache_dir = dir.join("cache");
    let mut bodies: Vec<std::path::PathBuf> = fs::read_dir(&cache_dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "body"))
                .collect()
        })
        .unwrap_or_default();
    bodies.sort();
    let target = bodies
        .get(pick as usize % bodies.len().max(1))
        .cloned()
        .filter(|t| fs::rename(t, dir.join("evicted-source.aside")).is_ok());
    let _ = vol.flush_wal();
    if let Some(t) = target {
        fs::rename(dir.join("evicted-source.aside"), t).unwrap();
    }
}

/// One block of incompressible, hash-derived bytes per seed. Mirrors
/// `common::incompressible_block` in the elide-core test suite. Stored
/// raw (lz4 can't shrink it), so the write lands as a body-section
/// Data entry rather than Inline — the shape the delta tier converts.
fn incompressible_block(seed: u8) -> [u8; 4096] {
    let mut buf = [0u8; 4096];
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

/// `incompressible_block(base_seed)` with the first 32 bytes replaced
/// by `tweak`: a near-duplicate whose zstd-dict delta against the base
/// is tiny, so the delta tier's smaller-than-stored gate passes.
fn variant_block(base_seed: u8, tweak: u8) -> [u8; 4096] {
    let mut buf = incompressible_block(base_seed);
    buf[..32].fill(tweak);
    buf
}

/// Keypair + default (root) `volume.provenance`, matching production
/// volume setup. The provenance file is required by the verified
/// manifest walk (`SnapshotSourceMap::build`), which the formation
/// delta tier runs.
fn write_keypair_and_provenance(dir: &Path) {
    let key = elide_core::signing::generate_keypair(
        dir,
        elide_core::signing::VOLUME_KEY_FILE,
        elide_core::signing::VOLUME_PUB_FILE,
    )
    .unwrap();
    elide_core::signing::write_provenance(
        dir,
        &key,
        elide_core::signing::VOLUME_PROVENANCE_FILE,
        &elide_core::signing::ProvenanceLineage::default(),
    )
    .unwrap();
}

#[derive(Debug, Clone)]
enum SimOp {
    /// Write [seed; 4096] to lba.
    Write { lba: u8, seed: u8 },
    /// Write one incompressible body-section Data block at `lba` — a
    /// future delta candidate's dictionary source once sealed.
    BaseWrite { lba: u8, base_seed: u8 },
    /// Write a near-duplicate of `base_seed`'s block at `lba`. When the
    /// LBA's sealed prior content shares the base, the next promote's
    /// formation delta tier converts this write to a thin Delta entry
    /// against it.
    VariantWrite { lba: u8, base_seed: u8, tweak: u8 },
    /// Seal: snapshot (flushes the WAL) + sign the manifest. Gives
    /// the formation delta tier its prior reader and activates the GC
    /// floor — sealed segments are excluded from compaction.
    SnapshotSign,
    /// Promote the WAL: post-seal single-block Data overwrites convert
    /// to Delta entries against the sealed snapshot at formation.
    /// Content-neutral; no oracle change.
    PromoteWal,
    /// `PromoteWal` with one sealed cache body hidden for the duration
    /// of the promote (restored afterwards — content-neutral). The
    /// formation delta tier treats an unreadable source as "skip, delta
    /// is best-effort", so which entries convert varies.
    PromoteEvictedSource { pick: u8 },
    /// Two incompressible bases sealed in separate segments (flush
    /// between them), then near-duplicate overwrites of both in one WAL
    /// window. The next flush yields one pending segment holding two
    /// convertible Data entries whose dictionary sources live in
    /// different sealed segments — so a `PromoteEvictedSource` pass
    /// converts one and carries the other, and a follow-up pass
    /// rewrites a segment that already holds a Delta entry. Packaged as
    /// one op (like `SplitDedupWrite`) because the shape is a
    /// conjunction random primitives rarely assemble.
    SealedBaseVariantPair {
        lba_a: u8,
        lba_b: u8,
        base_seed: u8,
        tweak: u8,
    },
    /// Write [seed; 4096] to lba_a then lba_b (disjoint ranges 0..4 / 4..8).
    /// Because the data is identical, lba_b's WAL entry is a DEDUP_REF.
    DedupWrite { lba_a: u8, lba_b: u8, seed: u8 },
    /// Like `DedupWrite`, but with a flush between the two writes so the
    /// canonical DATA and the DedupRef land in *separate* segments. This
    /// is the precondition for the bug H class: once a later `Write`
    /// overwrites `lba_a`, the DATA's segment has a dead LBA whose hash
    /// is still live via `lba_b` — `collect_stats` must demote the entry
    /// to `canonical_only` rather than preserve it at its original LBA.
    SplitDedupWrite { lba_a: u8, lba_b: u8, seed: u8 },
    /// Write a multi-LBA Zero over [start_lba..start_lba+span), flush, then
    /// overwrite one interior LBA with Data and flush. The Zero entry's
    /// LBA span straddles a later Data hole — `collect_stats` must split
    /// the Zero into surviving ZERO_HASH sub-runs rather than re-emit the
    /// whole span at the GC-output ULID (bug I).
    ZeroThenPartialWrite {
        start_lba: u8,
        span: u8,
        inner_off: u8,
        seed: u8,
    },
    /// Write a multi-LBA Data entry `[seed_big; span * 4096]` to
    /// `start_lba`, flush, then write a single-LBA `[seed_small; 4096]` to
    /// `start_lba + overlap_off` and flush. The second write punches a
    /// hole at head / tail / interior depending on `overlap_off`, leaving
    /// the first segment with a bloated multi-LBA claim whose live range
    /// has splits. `collect_stats` must mark the segment has_partial_death
    /// and exclude it from compaction; otherwise the re-emitted claim at
    /// the GC output's higher ULID shadows or erases the overwriter on
    /// rebuild. See docs/design/gc-overlap-correctness.md.
    MultiLbaWriteThenOverwrite {
        start_lba: u8,
        span: u8,
        overlap_off: u8,
        seed_big: u8,
        seed_small: u8,
    },
    /// Write multi-LBA Data `[seed_big; span*4096]` at [0..span), flush,
    /// then write the same bytes at [4..4+span) — because the hash is
    /// already in extent_index this second write produces a multi-LBA
    /// *DedupRef*. A single-LBA `[seed_small; 4096]` write at
    /// `4 + overlap_off` then punches a hole in the DedupRef's span,
    /// creating a partial-LBA-death DedupRef.
    ///
    /// Under step 3a of `docs/design/gc-partial-death-compaction.md`,
    /// `collect_stats` routes this into `partial_death_runs` (not the
    /// segment-level defer) and `expand_partial_death` resolves the
    /// composite body via `resolve_body_by_hash` on the DedupRef's own
    /// hash — the canonical lives in the first segment. Sub-runs are
    /// re-emitted, with hashes matching the extent_index so each becomes
    /// a fresh single-LBA DedupRef pointing at the canonical.
    MultiLbaDedupRefOverwrite {
        span: u8,
        overlap_off: u8,
        seed_big: u8,
        seed_small: u8,
    },
    /// Flush the WAL to a pending/ segment.
    Flush,
    /// Run the full real coordinator GC round-trip, then assert the oracle.
    ///
    /// Mirrors the coordinator tick order: drain pending/ → segments/ first
    /// (Upload, step 4), then gc_checkpoint + gc_fork + apply (GC, step 5).
    /// This ordering is an invariant of the production coordinator — GC always
    /// runs after pending/ is empty — and is enforced here to keep the model
    /// faithful.  Generating GcSweep before a drain would exercise a sequence
    /// the coordinator never produces and masks a structurally distinct bug
    /// (pre-existing pending segments with ULIDs below the GC output ULID).
    GcSweep,
    /// Simulate a coordinator/volume restart.
    ///
    /// Drops the current Volume and reopens it from disk (rebuilding the
    /// extent index from .idx files plus any bare gc/<ulid> apply outputs).
    /// Mirrors the production invariant: the coordinator calls
    /// apply_gc_handoffs (IPC) immediately after restart as a cheap
    /// idempotent safety net before apply_done_handoffs can delete old
    /// segments.
    ///
    /// After reopen, asserts that all oracle LBAs are still readable.  This
    /// catches the Bug E class: extent index rebuilt to stale state, then old
    /// segment deleted → "segment not found".
    Restart,
}

fn arb_sim_op() -> impl Strategy<Value = SimOp> {
    prop_oneof![
        4 => (0u8..8, any::<u8>()).prop_map(|(lba, seed)| SimOp::Write { lba, seed }),
        2 => (0u8..8, 0u8..4).prop_map(|(lba, base_seed)| SimOp::BaseWrite { lba, base_seed }),
        3 => (0u8..8, 0u8..4, any::<u8>())
            .prop_map(|(lba, base_seed, tweak)| SimOp::VariantWrite { lba, base_seed, tweak }),
        2 => Just(SimOp::SnapshotSign),
        2 => Just(SimOp::PromoteWal),
        2 => any::<u8>().prop_map(|pick| SimOp::PromoteEvictedSource { pick }),
        2 => (0u8..4, 4u8..8, 0u8..4, any::<u8>()).prop_map(|(lba_a, lba_b, base_seed, tweak)| {
            SimOp::SealedBaseVariantPair { lba_a, lba_b, base_seed, tweak }
        }),
        2 => (0u8..4, 4u8..8, any::<u8>()).prop_map(|(lba_a, lba_b, seed)| SimOp::DedupWrite {
            lba_a,
            lba_b,
            seed
        }),
        2 => (0u8..4, 4u8..8, any::<u8>())
            .prop_map(|(lba_a, lba_b, seed)| SimOp::SplitDedupWrite { lba_a, lba_b, seed }),
        2 => (0u8..4, 2u8..=4, 1u8..=3, any::<u8>()).prop_map(
            |(start_lba, span, inner_off, seed)| SimOp::ZeroThenPartialWrite {
                start_lba,
                span,
                inner_off,
                seed,
            },
        ),
        2 => (0u8..4, 2u8..=4, 0u8..=3, any::<u8>(), any::<u8>()).prop_map(
            |(start_lba, span, overlap_off, seed_big, seed_small)| {
                SimOp::MultiLbaWriteThenOverwrite {
                    start_lba,
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                }
            },
        ),
        2 => (2u8..=3, 0u8..=2, any::<u8>(), any::<u8>()).prop_map(
            |(span, overlap_off, seed_big, seed_small)| {
                SimOp::MultiLbaDedupRefOverwrite {
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                }
            },
        ),
        2 => Just(SimOp::Flush),
        1 => Just(SimOp::GcSweep),
        1 => Just(SimOp::Restart),
    ]
}

fn arb_sim_ops() -> impl Strategy<Value = Vec<SimOp>> {
    prop::collection::vec(arb_sim_op(), 1..30)
}

/// The BaseWrite → seal → VariantWrite → promote chain must actually
/// mint a Delta entry — asserted on the promoted segment's `.idx` so a
/// future change to the conversion gates cannot silently regress the
/// suite's Delta coverage to a structural no-op (the gap that hid the
/// #681 fold mis-registration).
#[test]
fn delta_ops_mint_a_delta_entry() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();
    write_keypair_and_provenance(fork_dir);
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    vol.write(0, &incompressible_block(0)).unwrap();
    vol.flush_wal().unwrap();
    simulate_upload(&mut vol, fork_dir);
    let snap = vol.snapshot().unwrap();
    vol.sign_snapshot_manifest(snap).unwrap();

    vol.write(0, &variant_block(0, 0x01)).unwrap();
    vol.flush_wal().unwrap();
    let vk =
        elide_core::signing::load_verifying_key(fork_dir, elide_core::signing::VOLUME_PUB_FILE)
            .unwrap();
    let minted = fs::read_dir(fork_dir.join("pending"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_none())
        .filter_map(|p| elide_core::segment::read_and_verify_segment_index(&p, &vk).ok())
        .flat_map(|(_, entries, _)| entries)
        .filter(|e| e.kind == elide_core::segment::EntryKind::Delta)
        .count();
    assert!(
        minted >= 1,
        "near-duplicate post-seal overwrite must convert to a Delta entry at formation"
    );
    assert_eq!(
        vol.read(0, 1).unwrap().as_slice(),
        variant_block(0, 0x01).as_slice(),
        "delta LBA must read back the post-conversion bytes"
    );
}

/// Deterministic materialisation of the minimal sequence the Delta-op
/// proptest found on its first run: `[SplitDedupWrite, GcSweep,
/// SplitDedupWrite, GcSweep, SnapshotSign]`. A snapshot minted right
/// after a GC apply — no intervening WAL flush — must place its marker
/// at or above the fold output: `Volume::snapshot`'s first-snapshot
/// pinning debug invariant requires every own-segment extent-index
/// target to sit at or below the marker, and the fold output's ULID is
/// above every flushed segment by construction.
#[test]
fn snapshot_after_gc_apply_covers_fold_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();
    write_keypair_and_provenance(fork_dir);
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gc_config = GcConfig {
        density_threshold: 0.0,
        interval: Duration::ZERO,
        ..GcConfig::default()
    };

    for seed in [0u8, 1] {
        let data = [seed; 4096];
        vol.write(0, &data).unwrap();
        vol.flush_wal().unwrap();
        vol.write(4, &data).unwrap();
        vol.flush_wal().unwrap();

        simulate_upload(&mut vol, fork_dir);
        let u_gc = vol.gc_checkpoint_for_test().unwrap();
        let _ = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);
        let _ = vol.apply_gc_handoffs();
        promote_gc_outputs(&mut vol, fork_dir);
        let _ = rt.block_on(apply_done_handoffs(fork_dir, ulid::Ulid::nil(), &store));
    }

    let snap = vol.snapshot().unwrap();
    vol.sign_snapshot_manifest(snap).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Segment cleanup: after GC runs, every consumed input segment must be
    /// deleted from segments/.
    ///
    /// With density_threshold=0.0 every segment is admitted to sweep; the
    /// proptest writes are short enough that all segments fit under
    /// SWEEP_SMALL_THRESHOLD, so the sweep pass packs them all into one
    /// output when ≥2 exist. After apply_done_handoffs, segments/ must
    /// contain ≤1 file.
    ///
    /// Catches Bug A: DEDUP_REF-only segments were never deleted because
    /// compact_segments emitted no handoff line for them.
    #[test]
    fn gc_segment_cleanup(ops in arb_sim_ops()) {
        let dir = tempfile::TempDir::new().unwrap();
        let fork_dir = dir.path();

        write_keypair_and_provenance(fork_dir);

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let gc_config = GcConfig {
            density_threshold: 0.0,
            interval: Duration::ZERO,
            ..GcConfig::default()
        };

        let cache_dir = fork_dir.join("cache");
        let index_dir = fork_dir.join("index");

        // Segments sealed by the most recent SnapshotSign sit below the
        // GC floor and are excluded from compaction — they stay in
        // index/ and cache/ across sweeps, so the post-sweep bounds
        // below must admit them.
        let mut frozen: usize = 0;

        for op in &ops {
            match op {
                SimOp::Write { lba, seed } => {
                    let _ = vol.write(*lba as u64, &[*seed; 4096]);
                }
                SimOp::BaseWrite { lba, base_seed } => {
                    let _ = vol.write(*lba as u64, &incompressible_block(*base_seed));
                }
                SimOp::VariantWrite {
                    lba,
                    base_seed,
                    tweak,
                } => {
                    let _ = vol.write(*lba as u64, &variant_block(*base_seed, *tweak));
                }
                SimOp::SnapshotSign => {
                    if let Ok(snap) = vol.snapshot() {
                        let _ = vol.sign_snapshot_manifest(snap);
                    }
                    frozen = fs::read_dir(&index_dir)
                        .map(|d| d.flatten().count())
                        .unwrap_or(0);
                }
                SimOp::PromoteWal => {
                    let _ = vol.flush_wal();
                }
                SimOp::PromoteEvictedSource { pick } => {
                    flush_with_evicted_source(&mut vol, fork_dir, *pick);
                }
                SimOp::SealedBaseVariantPair {
                    lba_a,
                    lba_b,
                    base_seed,
                    tweak,
                } => {
                    let (sa, sb) = (*base_seed, *base_seed ^ 1);
                    let _ = vol.write(*lba_a as u64, &incompressible_block(sa));
                    let _ = vol.flush_wal();
                    let _ = vol.write(*lba_b as u64, &incompressible_block(sb));
                    if let Ok(snap) = vol.snapshot() {
                        let _ = vol.sign_snapshot_manifest(snap);
                    }
                    frozen = fs::read_dir(&index_dir)
                        .map(|d| d.flatten().count())
                        .unwrap_or(0);
                    let _ = vol.write(*lba_a as u64, &variant_block(sa, *tweak));
                    let _ = vol.write(*lba_b as u64, &variant_block(sb, *tweak));
                }
                SimOp::DedupWrite { lba_a, lba_b, seed } => {
                    let data = [*seed; 4096];
                    let _ = vol.write(*lba_a as u64, &data);
                    let _ = vol.write(*lba_b as u64, &data);
                }
                SimOp::SplitDedupWrite { lba_a, lba_b, seed } => {
                    let data = [*seed; 4096];
                    let _ = vol.write(*lba_a as u64, &data);
                    let _ = vol.flush_wal();
                    let _ = vol.write(*lba_b as u64, &data);
                    let _ = vol.flush_wal();
                }
                SimOp::ZeroThenPartialWrite {
                    start_lba,
                    span,
                    inner_off,
                    seed,
                } => {
                    let _ = vol.write_zeroes(*start_lba as u64, *span as u32);
                    let _ = vol.flush_wal();
                    let inner = (*start_lba as u64) + (*inner_off as u64).min(*span as u64 - 1);
                    let _ = vol.write(inner, &[*seed; 4096]);
                    let _ = vol.flush_wal();
                }
                SimOp::MultiLbaWriteThenOverwrite {
                    start_lba,
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                } => {
                    let big = vec![*seed_big; *span as usize * 4096];
                    let _ = vol.write(*start_lba as u64, &big);
                    let _ = vol.flush_wal();
                    let hit =
                        (*start_lba as u64) + (*overlap_off as u64).min(*span as u64 - 1);
                    let _ = vol.write(hit, &[*seed_small; 4096]);
                    let _ = vol.flush_wal();
                }
                SimOp::MultiLbaDedupRefOverwrite {
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                } => {
                    let big = vec![*seed_big; *span as usize * 4096];
                    // Original multi-LBA Data at [0..span).
                    let _ = vol.write(0, &big);
                    let _ = vol.flush_wal();
                    // Same bytes at [4..4+span) — extent_index already has
                    // the hash, so this produces a multi-LBA DedupRef.
                    let _ = vol.write(4, &big);
                    let _ = vol.flush_wal();
                    // Overwrite a single LBA inside the DedupRef's range.
                    let hit = 4u64 + (*overlap_off as u64).min(*span as u64 - 1);
                    let _ = vol.write(hit, &[*seed_small; 4096]);
                    let _ = vol.flush_wal();
                }
                SimOp::Flush => {
                    let _ = vol.flush_wal();
                }
                SimOp::GcSweep => {
                    // Drain: volume already wrote index/ at flush; simulate
                    // coordinator drain (upload + promote IPC) by calling
                    // promote_segment directly on the volume.
                    simulate_upload(&mut vol, fork_dir);

                    // Count idx files before gc_checkpoint so we can detect
                    // any new segments it writes (WAL flush).  Those segments
                    // land in pending/ without a cache body, so collect_stats
                    // skips them — they will not be compacted this sweep and
                    // legitimately remain in index/ after GC.
                    let idx_pre_checkpoint: usize = fs::read_dir(&index_dir)
                        .map(|d| d.flatten().count())
                        .unwrap_or(0);

                    let u_gc = vol.gc_checkpoint_for_test().unwrap();

                    let idx_before: usize = fs::read_dir(&index_dir)
                        .map(|d| d.flatten().count())
                        .unwrap_or(0);
                    // Segments added by gc_checkpoint (WAL flush) are excluded
                    // from this GC pass and survive into the next tick.
                    let checkpoint_extra = idx_before.saturating_sub(idx_pre_checkpoint);

                    let gc_stats = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);

                    // Volume applies the handoff: re-signs gc body, updates extent
                    // index, writes index/<new>.idx, deletes index/<old>.idx.
                    let _ = vol.apply_gc_handoffs();

                    // Simulate coordinator promote + cache-evict + finalize IPCs:
                    // promote_gc_outputs covers promote, deletes cache/<input>.*
                    // for each consumed input (coordinator-owned), then finalize.
                    promote_gc_outputs(&mut vol, fork_dir);

                    // Coordinator: upload new segment to S3, delete old S3 objects.
                    // cache/<new>.body already exists (seg_promoted=true), so
                    // apply_done_handoffs skips the upload+promote branch.
                    let _ = rt.block_on(apply_done_handoffs(
                        fork_dir,
                        ulid::Ulid::nil(),
                        &store,
                                            ));

                    if let Ok(stats) = gc_stats
                        && !matches!(stats.strategy, GcStrategy::None(_))
                    {
                        // After GC, index/ should have ≤1 .idx file from
                        // the compacted set, plus any segments that
                        // gc_checkpoint wrote this tick (they were excluded
                        // from compaction because their cache body is not
                        // yet present and will be drained next tick), plus
                        // any segments held back by the partial-LBA-death
                        // deferral (see docs/design/gc-overlap-correctness.md —
                        // bloated multi-LBA entries stay on disk at their
                        // original ULID).
                        let idx_after_names: Vec<String> = fs::read_dir(&index_dir)
                            .map(|d| {
                                d.flatten()
                                    .map(|e| e.file_name().to_string_lossy().into_owned())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let idx_after = idx_after_names.len();
                        let idx_max = 1 + checkpoint_extra + stats.deferred + frozen;
                        prop_assert!(
                            idx_after <= idx_max,
                            "after GcSweep on {} segments, {} .idx files remain \
                             (expected ≤{}: 1 GC output + {} checkpoint segment(s) \
                             + {} deferred + {} sealed below the GC floor); \
                             files=[{}]; strategy={:?} candidates={}",
                            idx_before,
                            idx_after,
                            idx_max,
                            checkpoint_extra,
                            stats.deferred,
                            frozen,
                            idx_after_names.join(", "),
                            stats.strategy,
                            stats.candidates,
                        );
                        // cache/ .body files: 1 GC output + any deferred
                        // segments (their bodies are still in cache/) +
                        // sealed segments below the GC floor.
                        let bodies_after: usize = fs::read_dir(&cache_dir)
                            .map(|d| {
                                d.flatten()
                                    .filter(|e| {
                                        e.path().extension().is_some_and(|x| x == "body")
                                    })
                                    .count()
                            })
                            .unwrap_or(0);
                        prop_assert!(
                            bodies_after <= 1 + stats.deferred + frozen,
                            "after GcSweep, {} .body files remain in cache/ \
                             (expected ≤{}: 1 GC output + {} deferred + {} sealed)",
                            bodies_after,
                            1 + stats.deferred + frozen,
                            stats.deferred,
                            frozen,
                        );
                    }
                }
                SimOp::Restart => {
                    // Drop and reopen the volume, mirroring a coordinator/volume
                    // restart.  Volume::open's rebuild folds in any bare
                    // gc/<ulid> apply outputs alongside .idx files;
                    // apply_gc_handoffs then runs as an idempotent safety net
                    // (Bug E class).  No oracle mutation: restart is invisible
                    // to the logical data model.
                    drop(vol);
                    vol = Volume::open(fork_dir, fork_dir).unwrap();
                    let _ = vol.apply_gc_handoffs();
                }
            }
        }
    }

    /// GC oracle: after any sequence of writes + GC sweeps, every LBA that
    /// has ever been written reads back its last-written value.
    #[test]
    fn gc_oracle(ops in arb_sim_ops()) {
        let dir = tempfile::TempDir::new().unwrap();
        let fork_dir = dir.path();

        write_keypair_and_provenance(fork_dir);

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut vol = Volume::open(fork_dir, fork_dir).unwrap();
        let mut oracle: HashMap<u64, [u8; 4096]> = HashMap::new();

        // Single runtime reused across all GcSweep ops in this sequence.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let gc_config = GcConfig {
            density_threshold: 0.0,
            interval: Duration::ZERO,
            ..GcConfig::default()
        };

        for op in &ops {
            match op {
                SimOp::Write { lba, seed } => {
                    let data = [*seed; 4096];
                    let _ = vol.write(*lba as u64, &data);
                    oracle.insert(*lba as u64, data);
                }
                SimOp::BaseWrite { lba, base_seed } => {
                    let data = incompressible_block(*base_seed);
                    let _ = vol.write(*lba as u64, &data);
                    oracle.insert(*lba as u64, data);
                }
                SimOp::VariantWrite {
                    lba,
                    base_seed,
                    tweak,
                } => {
                    let data = variant_block(*base_seed, *tweak);
                    let _ = vol.write(*lba as u64, &data);
                    oracle.insert(*lba as u64, data);
                }
                SimOp::SnapshotSign => {
                    // Content-neutral: sealing changes which segments GC
                    // may touch and arms the formation delta tier, not
                    // logical bytes.
                    if let Ok(snap) = vol.snapshot() {
                        let _ = vol.sign_snapshot_manifest(snap);
                    }
                }
                SimOp::PromoteWal => {
                    // Content-neutral: Data entries become thin Delta
                    // entries materialising to identical bytes.
                    let _ = vol.flush_wal();
                }
                SimOp::PromoteEvictedSource { pick } => {
                    // Content-neutral: the hidden body is restored
                    // before the op returns.
                    flush_with_evicted_source(&mut vol, fork_dir, *pick);
                }
                SimOp::SealedBaseVariantPair {
                    lba_a,
                    lba_b,
                    base_seed,
                    tweak,
                } => {
                    let (sa, sb) = (*base_seed, *base_seed ^ 1);
                    let _ = vol.write(*lba_a as u64, &incompressible_block(sa));
                    let _ = vol.flush_wal();
                    let _ = vol.write(*lba_b as u64, &incompressible_block(sb));
                    if let Ok(snap) = vol.snapshot() {
                        let _ = vol.sign_snapshot_manifest(snap);
                    }
                    let va = variant_block(sa, *tweak);
                    let vb = variant_block(sb, *tweak);
                    let _ = vol.write(*lba_a as u64, &va);
                    let _ = vol.write(*lba_b as u64, &vb);
                    oracle.insert(*lba_a as u64, va);
                    oracle.insert(*lba_b as u64, vb);
                }
                SimOp::DedupWrite { lba_a, lba_b, seed } => {
                    let data = [*seed; 4096];
                    let _ = vol.write(*lba_a as u64, &data);
                    let _ = vol.write(*lba_b as u64, &data);
                    oracle.insert(*lba_a as u64, data);
                    oracle.insert(*lba_b as u64, data);
                }
                SimOp::SplitDedupWrite { lba_a, lba_b, seed } => {
                    let data = [*seed; 4096];
                    let _ = vol.write(*lba_a as u64, &data);
                    let _ = vol.flush_wal();
                    let _ = vol.write(*lba_b as u64, &data);
                    let _ = vol.flush_wal();
                    oracle.insert(*lba_a as u64, data);
                    oracle.insert(*lba_b as u64, data);
                }
                SimOp::ZeroThenPartialWrite {
                    start_lba,
                    span,
                    inner_off,
                    seed,
                } => {
                    let _ = vol.write_zeroes(*start_lba as u64, *span as u32);
                    let _ = vol.flush_wal();
                    let zeros = [0u8; 4096];
                    let end = *start_lba as u64 + *span as u64;
                    for lba in (*start_lba as u64)..end {
                        oracle.insert(lba, zeros);
                    }
                    let inner = (*start_lba as u64) + (*inner_off as u64).min(*span as u64 - 1);
                    let data = [*seed; 4096];
                    let _ = vol.write(inner, &data);
                    let _ = vol.flush_wal();
                    oracle.insert(inner, data);
                }
                SimOp::MultiLbaWriteThenOverwrite {
                    start_lba,
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                } => {
                    let big = vec![*seed_big; *span as usize * 4096];
                    let _ = vol.write(*start_lba as u64, &big);
                    let _ = vol.flush_wal();
                    let end = *start_lba as u64 + *span as u64;
                    let big_block = [*seed_big; 4096];
                    for lba in (*start_lba as u64)..end {
                        oracle.insert(lba, big_block);
                    }
                    let hit =
                        (*start_lba as u64) + (*overlap_off as u64).min(*span as u64 - 1);
                    let small = [*seed_small; 4096];
                    let _ = vol.write(hit, &small);
                    let _ = vol.flush_wal();
                    oracle.insert(hit, small);
                }
                SimOp::MultiLbaDedupRefOverwrite {
                    span,
                    overlap_off,
                    seed_big,
                    seed_small,
                } => {
                    let big = vec![*seed_big; *span as usize * 4096];
                    let big_block = [*seed_big; 4096];
                    // Original multi-LBA Data at [0..span).
                    let _ = vol.write(0, &big);
                    let _ = vol.flush_wal();
                    for lba in 0..(*span as u64) {
                        oracle.insert(lba, big_block);
                    }
                    // Same bytes at [4..4+span) — multi-LBA DedupRef.
                    let _ = vol.write(4, &big);
                    let _ = vol.flush_wal();
                    for lba in 4..(4 + *span as u64) {
                        oracle.insert(lba, big_block);
                    }
                    // Overwrite a single LBA inside the DedupRef's range.
                    let hit = 4u64 + (*overlap_off as u64).min(*span as u64 - 1);
                    let small = [*seed_small; 4096];
                    let _ = vol.write(hit, &small);
                    let _ = vol.flush_wal();
                    oracle.insert(hit, small);
                }
                SimOp::Flush => {
                    let _ = vol.flush_wal();
                }
                SimOp::GcSweep => {
                    // Drain: volume already wrote index/ at flush; simulate
                    // coordinator drain (upload + promote IPC) by calling
                    // promote_segment directly on the volume.
                    simulate_upload(&mut vol, fork_dir);

                    // gc_checkpoint flushes the WAL under a pre-minted ULID
                    // (u_flush > u_gc) and returns u_gc from
                    // the volume's own mint, so future WAL segments always sort
                    // above GC outputs on rebuild.
                    let u_gc = vol.gc_checkpoint_for_test().unwrap();

                    // Step 1: real GC compaction (no-ops if nothing to compact).
                    let _ = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);

                    // Step 2: volume re-signs GC output, updates extent index.
                    let _ = vol.apply_gc_handoffs();

                    // Step 3: simulate coordinator promote IPC + cache-evict + finalize.
                    promote_gc_outputs(&mut vol, fork_dir);

                    // Step 4: upload new segment to S3, delete old S3 objects.
                    let _ = rt.block_on(apply_done_handoffs(
                        fork_dir,
                        ulid::Ulid::nil(),
                        &store,
                                            ));

                    // Assert: every oracle LBA still reads its expected value.
                    for (&lba, expected) in &oracle {
                        match vol.read(lba, 1) {
                            Ok(data) => prop_assert_eq!(
                                data.as_slice(),
                                expected.as_slice(),
                                "lba {} reads wrong data after GcSweep",
                                lba
                            ),
                            Err(e) => prop_assert!(
                                false,
                                "lba {} read failed after GcSweep: {}",
                                lba,
                                e
                            ),
                        }
                    }
                }
                SimOp::Restart => {
                    // Drop and reopen the volume, mirroring a coordinator/volume
                    // restart.  Volume::open's rebuild folds in any bare
                    // gc/<ulid> apply outputs alongside .idx files;
                    // apply_gc_handoffs runs as an idempotent safety net
                    // (Bug E class) before any subsequent GcSweep can call
                    // apply_done_handoffs and delete old segments.
                    drop(vol);
                    vol = Volume::open(fork_dir, fork_dir).unwrap();
                    let _ = vol.apply_gc_handoffs();

                    // Assert: every oracle LBA is still readable after restart.
                    // The segment bodies have not been deleted yet (no
                    // apply_done_handoffs since restart), so both old and new
                    // segments are present — reads must succeed regardless of
                    // which one the extent index points to.
                    for (&lba, expected) in &oracle {
                        match vol.read(lba, 1) {
                            Ok(data) => prop_assert_eq!(
                                data.as_slice(),
                                expected.as_slice(),
                                "lba {} reads wrong data after Restart",
                                lba
                            ),
                            Err(e) => prop_assert!(
                                false,
                                "lba {} read failed after Restart: {}",
                                lba,
                                e
                            ),
                        }
                    }
                }
            }
        }
    }
}

/// Bug H: promote_segment with .materialized sidecar did not evict the file
/// handle cache.  After materialise + promote, the extent index has offsets
/// from the .materialized segment (larger index section → different
/// body_section_start), but the file cache may still hold an fd to the
/// deleted pending/ file with is_body=false.  The next read computes
/// bss_materialized + body_offset against the old file, seeking past the
/// body section → "failed to fill whole buffer".
///
/// Nondeterministic in the proptest because HashMap iteration order
/// determines whether the file cache happens to hold the affected segment.
///
/// Sequence: DedupWrite creates a segment with a thin DedupRef.  GcSweep
/// materialises + promotes it (replacing pending/ with cache/).  A
/// subsequent read of the dedup-ref LBA uses the stale cached fd.
#[test]
fn gc_oracle_repro_bug_h() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();

    write_keypair_and_provenance(fork_dir);

    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let gc_config = GcConfig {
        density_threshold: 0.0,
        interval: Duration::ZERO,
        ..GcConfig::default()
    };

    // DedupWrite: lba 3 gets DATA, lba 6 gets thin DEDUP_REF (same hash).
    let data_235 = [235u8; 4096];
    vol.write(3, &data_235).unwrap();
    vol.write(6, &data_235).unwrap();

    // GcSweep drains pending (none), then gc_checkpoint flushes the WAL
    // to pending/S1 (DATA + DEDUP_REF).  No index files yet → gc_fork is
    // a no-op.  The oracle read here populates the file cache with
    // (S1, is_body=false, fd→pending/S1).
    simulate_upload(&mut vol, fork_dir);
    let u_gc = vol.gc_checkpoint_for_test().unwrap();
    let _ = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);
    let _ = vol.apply_gc_handoffs();
    promote_gc_outputs(&mut vol, fork_dir);
    let _ = rt.block_on(apply_done_handoffs(fork_dir, ulid::Ulid::nil(), &store));
    // Read both LBAs to populate file cache with the pending/ segment.
    assert_eq!(&vol.read(3, 1).unwrap(), &data_235);
    assert_eq!(&vol.read(6, 1).unwrap(), &data_235);

    // Write another LBA so gc_checkpoint has something to flush.
    vol.write(1, &[195u8; 4096]).unwrap();

    // Second GcSweep: simulate_upload materialises S1 (DedupRef → fat
    // DedupRef (filled)) and promotes it — pending/S1 is deleted, replaced by
    // cache/S1.body.  The extent index is updated with offsets from the
    // .materialized segment.  Without the Bug H fix, the file cache still
    // holds the stale fd to pending/S1.
    simulate_upload(&mut vol, fork_dir);
    let u_gc = vol.gc_checkpoint_for_test().unwrap();
    let _ = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);
    let _ = vol.apply_gc_handoffs();
    promote_gc_outputs(&mut vol, fork_dir);
    let _ = rt.block_on(apply_done_handoffs(fork_dir, ulid::Ulid::nil(), &store));

    // These reads triggered "failed to fill whole buffer" before the fix.
    assert_eq!(&vol.read(3, 1).unwrap(), &data_235);
    assert_eq!(&vol.read(6, 1).unwrap(), &data_235);
    assert_eq!(&vol.read(1, 1).unwrap(), &[195u8; 4096]);
}

/// Deterministic materialisation of the minimal gc_oracle sequence CI
/// found 2026-07-10 (seed 68cb98…): a sealed variant base, a split
/// dedup pair, a near-duplicate overwrite of the sealed LBA promoted
/// into a Delta entry, then a drain. The drain's promote trips the
/// volume-invariants extent-index rebuild check with a phantom inner
/// entry — an in-memory DATA hash no on-disk index owns.
#[test]
fn gc_oracle_repro_delta_repack_phantom_inner() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();

    write_keypair_and_provenance(fork_dir);

    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    // VariantWrite { lba: 6, base_seed: 0, tweak: 0 }
    vol.write(6, &variant_block(0, 0)).unwrap();

    // SnapshotSign
    let snap = vol.snapshot().unwrap();
    vol.sign_snapshot_manifest(snap).unwrap();

    // SplitDedupWrite { lba_a: 0, lba_b: 4, seed: 0 }
    let data = [0u8; 4096];
    vol.write(0, &data).unwrap();
    vol.flush_wal().unwrap();
    vol.write(4, &data).unwrap();
    vol.flush_wal().unwrap();

    // VariantWrite { lba: 6, base_seed: 0, tweak: 1 }, promoted — the
    // formation delta tier converts it against the sealed snapshot.
    vol.write(6, &variant_block(0, 1)).unwrap();
    vol.flush_wal().unwrap();

    // GcSweep's drain: repack + promote each pending segment.
    simulate_upload(&mut vol, fork_dir);

    assert_eq!(&vol.read(6, 1).unwrap(), &variant_block(0, 1));
    assert_eq!(&vol.read(0, 1).unwrap(), &data);
    assert_eq!(&vol.read(4, 1).unwrap(), &data);
}

/// Deterministic materialisation of the minimal gc_oracle sequence CI
/// found 2026-07-10 on the #696 merge run: a sealed base, a
/// near-duplicate overwrite converted to a Delta at promote, then a
/// plain overwrite of the same LBA before the drain. The drain's promote
/// trips the volume-invariants rebuild check with a phantom delta —
/// an in-memory Delta hash no on-disk index owns.
///
///   BaseWrite { lba: 5, base_seed: 3 }
///   SnapshotSign
///   VariantWrite { lba: 5, base_seed: 3, tweak: 0 }
///   Flush
///   BaseWrite { lba: 5, base_seed: 0 }
///   GcSweep
#[test]
fn gc_oracle_repro_overwritten_delta_phantom() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();

    write_keypair_and_provenance(fork_dir);

    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();

    // BaseWrite { lba: 5, base_seed: 3 }
    vol.write(5, &incompressible_block(3)).unwrap();

    // SnapshotSign
    let snap = vol.snapshot().unwrap();
    vol.sign_snapshot_manifest(snap).unwrap();

    // VariantWrite { lba: 5, base_seed: 3, tweak: 0 }
    vol.write(5, &variant_block(3, 0)).unwrap();

    // Flush — the formation delta tier converts the variant write.
    vol.flush_wal().unwrap();

    // BaseWrite { lba: 5, base_seed: 0 } — supersedes the delta's claim.
    let last = incompressible_block(0);
    vol.write(5, &last).unwrap();

    // GcSweep's drain: repack + promote each pending segment.
    simulate_upload(&mut vol, fork_dir);

    assert_eq!(&vol.read(5, 1).unwrap(), &last);
}

/// Deterministic regression for a proptest failure under the plan-based
/// GC handoff: after two `GcSweep` passes the `index/` directory should
/// hold exactly 1 .idx (the final GC output) — but the test was finding 3.
///
/// Minimal input from proptest shrinking:
///   MultiLbaDedupRefOverwrite { span: 2, overlap_off: 0, seed_big: 0, seed_small: 0 }
///   GcSweep
///   ZeroThenPartialWrite { start_lba: 0, span: 2, inner_off: 1, seed: 0 }
///   GcSweep
///
/// Per `feedback_proptest_deterministic_repro`: materialise the minimal
/// failing sequence as a named deterministic test so it can be debugged
/// without re-running the full proptest shrinker.
#[test]
fn gc_segment_cleanup_minimal_dedup_then_zero_partial() {
    let dir = tempfile::TempDir::new().unwrap();
    let fork_dir = dir.path();
    write_keypair_and_provenance(fork_dir);
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let mut vol = Volume::open(fork_dir, fork_dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gc_config = GcConfig {
        density_threshold: 0.0,
        interval: Duration::ZERO,
        ..GcConfig::default()
    };
    let index_dir = fork_dir.join("index");
    let gc_dir = fork_dir.join("gc");

    // Op 1: MultiLbaDedupRefOverwrite span=2 overlap_off=0 seed=0/0.
    let big = vec![0u8; 2 * 4096];
    vol.write(0, &big).unwrap();
    vol.flush_wal().unwrap();
    vol.write(4, &big).unwrap();
    vol.write(4, &[0u8; 4096]).unwrap();
    vol.flush_wal().unwrap();

    // Op 2: GcSweep.
    simulate_upload(&mut vol, fork_dir);
    let u_gc = vol.gc_checkpoint_for_test().unwrap();
    let _ = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]);
    let applied_1 = vol.apply_gc_handoffs().unwrap();
    eprintln!("apply_1 applied={applied_1}");
    eprintln!("gc/ after apply_1: [{}]", list_dir(&gc_dir).join(", "));
    promote_gc_outputs(&mut vol, fork_dir);
    let _ = rt.block_on(apply_done_handoffs(fork_dir, ulid::Ulid::nil(), &store));
    eprintln!(
        "index/ after sweep 1: [{}]",
        list_dir(&index_dir).join(", ")
    );

    // Op 3: ZeroThenPartialWrite start_lba=0 span=2 inner_off=1 seed=0.
    vol.write_zeroes(0, 2).unwrap();
    vol.flush_wal().unwrap();
    vol.write(1, &[0u8; 4096]).unwrap();
    vol.flush_wal().unwrap();

    // Op 4: GcSweep.
    simulate_upload(&mut vol, fork_dir);
    eprintln!(
        "index/ before sweep 2: [{}]",
        list_dir(&index_dir).join(", ")
    );
    let u_gc = vol.gc_checkpoint_for_test().unwrap();
    let stats_2 = gc_fork(fork_dir, fork_dir.parent().unwrap(), &gc_config, vec![u_gc]).unwrap();
    eprintln!(
        "stats_2: strategy={:?} candidates={} deferred={}",
        stats_2.strategy, stats_2.candidates, stats_2.deferred
    );
    eprintln!("gc/ after gc_fork 2: [{}]", list_dir(&gc_dir).join(", "));
    let applied_2 = vol.apply_gc_handoffs().unwrap();
    eprintln!("apply_2 applied={applied_2}");
    eprintln!("gc/ after apply_2: [{}]", list_dir(&gc_dir).join(", "));
    promote_gc_outputs(&mut vol, fork_dir);
    let _ = rt.block_on(apply_done_handoffs(fork_dir, ulid::Ulid::nil(), &store));
    let final_idx = list_dir(&index_dir);
    eprintln!("index/ final: [{}]", final_idx.join(", "));

    assert!(
        final_idx.len() <= 1,
        "expected ≤1 .idx after two sweeps, got {}: [{}]",
        final_idx.len(),
        final_idx.join(", "),
    );
}

fn list_dir(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}
