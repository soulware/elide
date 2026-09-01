//! Benchmark: the journal flip in `apply_promote_segment_result`, which
//! resolves each journal hash to its first entry position.
//!
//! `promote_journal_segment_to_cache` returns at its first line for a
//! segment that holds no journal body, so a data segment calls the
//! resolver zero times. The two shapes below are the two a drain sees:
//!
//!   data segment    J = 0, and the index build is the whole cost
//!   journal segment J = E, and every hash resolves
//!
//! `scan` is a linear `position` per hash. `blake3::Hash` equality is
//! constant-time, so a scan compares all 32 bytes per entry with no early
//! exit. `index` builds a `Blake3HashMap` once and looks up through it.
//!
//! Run with:
//!   cargo bench -p elide-core --bench journal_flip_apply

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use elide_core::blake3_id_hasher::Blake3HashMap;
use elide_core::segment::{Codec, SegmentEntry};

/// `n` entries carrying distinct hashes, at the real `SegmentEntry`
/// stride — the walk's cache behaviour is part of what is measured.
fn entries(n: usize) -> Vec<SegmentEntry> {
    (0..n as u32)
        .map(|i| {
            let hash = blake3::hash(&i.to_le_bytes());
            SegmentEntry::new_data(hash, i as u64, 1, Codec::None, vec![0u8; 4096]).entry
        })
        .collect()
}

/// The hashes the flip resolves: every entry for a journal segment, none
/// for a data segment.
fn journal_hashes(entries: &[SegmentEntry], j: usize) -> Vec<blake3::Hash> {
    entries.iter().take(j).map(|e| e.hash).collect()
}

fn scan(entries: &[SegmentEntry], hashes: &[blake3::Hash]) -> u64 {
    let mut acc = 0u64;
    for h in hashes {
        if let Some(p) = entries.iter().position(|e| &e.hash == h) {
            acc += p as u64;
        }
    }
    acc
}

fn index(entries: &[SegmentEntry], hashes: &[blake3::Hash]) -> u64 {
    let mut entry_idx = Blake3HashMap::<u32>::default();
    for (i, e) in entries.iter().enumerate() {
        entry_idx.entry(e.hash).or_insert(i as u32);
    }
    let mut acc = 0u64;
    for h in hashes {
        if let Some(p) = entry_idx.get(h).copied() {
            acc += p as u64;
        }
    }
    acc
}

fn bench_flip(c: &mut Criterion) {
    // 118 and 858 are real segment sizes off a soak volume; 8192 is
    // `FLUSH_ENTRY_THRESHOLD`, the largest a drain applies.
    for &e in &[118usize, 858, 8192] {
        let entries = entries(e);

        // A data segment: the resolver is never called, so the whole
        // cost is the index build the apply pays unconditionally.
        let mut group = c.benchmark_group("data_segment_j0");
        let none = journal_hashes(&entries, 0);
        group.bench_with_input(BenchmarkId::new("scan", e), &e, |b, _| {
            b.iter(|| std::hint::black_box(scan(&entries, &none)));
        });
        group.bench_with_input(BenchmarkId::new("index", e), &e, |b, _| {
            b.iter(|| std::hint::black_box(index(&entries, &none)));
        });
        group.finish();

        // A journal segment: every entry is journal tier, so the flip
        // resolves each one.
        let mut group = c.benchmark_group("journal_segment_j_eq_e");
        let all = journal_hashes(&entries, e);
        group.bench_with_input(BenchmarkId::new("scan", e), &e, |b, _| {
            b.iter(|| std::hint::black_box(scan(&entries, &all)));
        });
        group.bench_with_input(BenchmarkId::new("index", e), &e, |b, _| {
            b.iter(|| std::hint::black_box(index(&entries, &all)));
        });
        group.finish();
    }
}

criterion_group!(benches, bench_flip);
criterion_main!(benches);
