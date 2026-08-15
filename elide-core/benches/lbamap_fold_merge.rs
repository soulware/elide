//! Benchmark: the lbamap half of a GC fold's `merge` phase.
//!
//! `Volume::apply_plan_apply_result` holds the volume mutex while it
//! re-registers every entry of the fold output into the extent index and
//! the lbamap. Phase timing from the rig (v0.1.57, 462 applies) puts
//! `merge` at 71% of that hold, scaling at ~7.8 us per output entry
//! against a plan capped at 8192 entries by `SWEEP_ENTRY_CAP`.
//!
//! A fold carries live extents forward unchanged, so the dominant shape
//! is: same hash, same LBA range, new claimant ULID, with the previous
//! claimant among the inputs the apply consumes.
//!
//! The actor publishes a `ReadSnapshot` after every apply, so the map a
//! merge mutates is always shared. `map.clone()` per iteration
//! reproduces that: `imbl`'s structural sharing makes the clone O(1) and
//! pushes the copying into the mutation path, exactly as in production.
//!
//! Run with:
//!   cargo bench -p elide-core --bench lbamap_fold_merge
//!
//! What to look for:
//!   * `fold_merge/carry/N` — per-entry cost of the production shape.
//!   * `fold_merge/scattered/N` — same, with the fold's extents spread
//!     across the device rather than in one run.

use std::collections::HashSet;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ulid::Ulid;

use elide_core::lbamap::LbaMap;
use elide_core::segment::{Codec, EntryKind, SegmentEntry};

/// Blocks per extent. Postgres writes 8 KiB pages over a 4 KiB LBA.
const EXTENT_BLOCKS: u32 = 2;

/// Distinct segment ULIDs the resident map's claims are spread over.
const RESIDENT_SEGMENTS: u64 = 64;

fn seg_ulid(i: u64) -> Ulid {
    Ulid::from_parts(i, i as u128)
}

fn entry(start_lba: u64, hash: blake3::Hash) -> SegmentEntry {
    SegmentEntry {
        hash,
        start_lba,
        lba_length: EXTENT_BLOCKS,
        codec: Codec::None,
        kind: EntryKind::Data,
        stored_offset: 0,
        stored_length: EXTENT_BLOCKS * 4096,
        inline: None,
        delta_options: Vec::new(),
        journal: false,
        sketch: None,
        stored_hash: None,
    }
}

fn extent_hash(i: u64) -> blake3::Hash {
    blake3::hash(&i.to_le_bytes())
}

/// A volume-sized lbamap: `n` extents laid end to end, claims spread
/// across `RESIDENT_SEGMENTS` segments the way a churned volume's are.
fn resident_map(n: u64) -> LbaMap {
    let mut map = LbaMap::new();
    for i in 0..n {
        map.insert(
            i * EXTENT_BLOCKS as u64,
            EXTENT_BLOCKS,
            extent_hash(i),
            seg_ulid(i % RESIDENT_SEGMENTS),
        );
    }
    map
}

/// The fold's output entries and the input ULIDs it consumes.
///
/// `stride` of 1 takes one contiguous run; a larger stride spreads the
/// same count across the device, which is what folding the live extents
/// of a few scattered segments actually looks like.
///
/// `lba_offset` shifts the output entries off the resident extent
/// boundaries so each one straddles two of them. A fold that slices a
/// partial-death run emits entries of exactly that shape, and they are
/// the ones that must walk the full overlap-trimming path.
fn fold_output(
    resident: u64,
    count: u64,
    stride: u64,
    lba_offset: u64,
) -> (Vec<SegmentEntry>, HashSet<Ulid>) {
    let mut entries = Vec::with_capacity(count as usize);
    for k in 0..count {
        let i = (k * stride) % resident;
        entries.push(entry(i * EXTENT_BLOCKS as u64 + lba_offset, extent_hash(i)));
    }
    // Every resident claimant is consumed, so a straddling entry installs
    // across both neighbours instead of being half-blocked by one — the
    // shapes stay comparable.
    let consumed = (0..RESIDENT_SEGMENTS).map(seg_ulid).collect();
    (entries, consumed)
}

fn bench_fold_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_merge");
    group.sample_size(20);

    // Entry counts either side of the 8192 `SWEEP_ENTRY_CAP`.
    const RESIDENT: u64 = 200_000;
    let resident = resident_map(RESIDENT);
    // The fold output's claimant sorts above every resident claim.
    let new_ulid = seg_ulid(RESIDENT_SEGMENTS + 1);

    for &count in &[1_024u64, 4_096, 8_192] {
        for (name, stride, offset) in [
            ("carry", 1u64, 0u64),
            ("scattered", 17, 0),
            ("resliced", 17, 1),
        ] {
            let (entries, consumed) = fold_output(RESIDENT, count, stride, offset);
            group.throughput(Throughput::Elements(count));
            group.bench_with_input(BenchmarkId::new(name, count), &count, |b, _| {
                b.iter_batched(
                    || resident.clone(),
                    |mut map| {
                        for e in &entries {
                            map.register_entry_consuming_inputs(e, new_ulid, &consumed);
                        }
                        std::hint::black_box(map);
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_fold_merge);
criterion_main!(benches);
