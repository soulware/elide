//! Benchmark: the drop of the base a swap retired.
//!
//! An apply folds a clone of `base` with the mutex released and swaps the
//! fold in. The fold path-copies every map node it changes, so the old
//! `base` and the new one share the rest, and the last holder of the old
//! `base` frees the nodes the fold diverged. On the rig that holder was
//! the read snapshot a guest write dropped after a repack bucket swap, at
//! 43 to 57 ms per bucket (`docs/design/write-phase-split.md`). With
//! `RetiredBase` (`docs/design/retired-base.md`) the actor holds the old
//! `base` until after its publish, so it frees the nodes itself.
//!
//! Each iteration starts from a volume-sized pair of maps with `count`
//! extents re-pointed by a previous fold, so those paths belong to the
//! old `base` alone, then re-points them again with the fold under test
//! and swaps it in.
//!
//! Run with:
//!   cargo bench -p elide-core --bench retired_base_drop
//!
//! What to look for:
//!   * `retired_drop/<shape>/<size>` — the free itself, on the actor
//!     after the fix.
//!   * `snapshot_last_holder/<shape>/<size>` — a guest write's publish
//!     and drop of the previous snapshot as the old base's last holder:
//!     the write's `post` before the fix.
//!   * `snapshot_retired_held/<shape>/<size>` — the same publish and
//!     drop with the `RetiredBase` alive: the write's `post` after the
//!     fix.

use std::sync::Arc;
use std::time::Duration;

use criterion::{
    BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use ulid::Ulid;

use elide_core::actor::ReadSnapshot;
use elide_core::extentindex::{BodySource, ExtentIndex, ExtentLocation};
use elide_core::lbamap::LbaMap;
use elide_core::map_layers::{MapLayers, Maps, RetiredBase};
use elide_core::segment::Codec;

/// Blocks per extent. Postgres writes 8 KiB pages over a 4 KiB LBA.
const EXTENT_BLOCKS: u32 = 2;

/// Distinct segment ULIDs the resident map's claims are spread over.
const RESIDENT_SEGMENTS: u64 = 64;

/// The fold shapes: a name, the extent count, and the stride between the
/// extents across the device. A stride of 1 is one contiguous run; 17
/// spreads the same count the way the live extents of a few segments lie.
const SHAPES: &[(&str, u64, u64)] = &[
    ("scattered", 512, 17),
    ("scattered", 2_048, 17),
    ("scattered", 8_192, 17),
    ("carry", 8_192, 1),
];

/// Resident extent counts. The rig volume, pgbench scale 50, holds about
/// 200k extents of two blocks.
const SIZES: &[u64] = &[50_000, 200_000, 800_000];

fn seg_ulid(i: u64) -> Ulid {
    Ulid::from_parts(i, i as u128)
}

fn extent_hash(i: u64) -> blake3::Hash {
    blake3::hash(&i.to_le_bytes())
}

fn location(segment_id: Ulid) -> ExtentLocation {
    ExtentLocation {
        segment_id,
        body_offset: 0,
        body_length: EXTENT_BLOCKS * 4096,
        codec: Codec::None,
        body_source: BodySource::Local,
        body_section_start: 0,
        inline_data: None,
    }
}

/// A volume-sized base: `n` extents laid end to end, claims spread across
/// `RESIDENT_SEGMENTS` segments the way a churned volume's are.
fn resident(n: u64) -> Maps {
    let mut lbamap = LbaMap::new();
    let mut index = ExtentIndex::new();
    for i in 0..n {
        let hash = extent_hash(i);
        let claimant = seg_ulid(i % RESIDENT_SEGMENTS);
        lbamap.insert(i * EXTENT_BLOCKS as u64, EXTENT_BLOCKS, hash, claimant);
        index.insert(hash, location(claimant));
    }
    Maps::new(lbamap, index)
}

/// One bucket's fold over a clone of `base`: `count` live extents carried
/// forward under `claimant`, `stride` apart across the device.
fn fold(layers: &MapLayers, n: u64, count: u64, stride: u64, claimant: Ulid) -> Maps {
    layers
        .fold_base(|lbamap, index| {
            for k in 0..count {
                let i = (k * stride) % n;
                let hash = extent_hash(i);
                lbamap.insert(i * EXTENT_BLOCKS as u64, EXTENT_BLOCKS, hash, claimant);
                index.insert(hash, location(claimant));
            }
            Ok(())
        })
        .expect("the fold closure returns Ok")
}

/// The state after a bucket's swap.
struct Swapped {
    /// The layers over the new base.
    layers: MapLayers,
    /// The base the swap retired, whose `count` re-pointed paths it holds
    /// alone.
    retired: RetiredBase,
    /// The read snapshot published before the swap, over the old base.
    previous: Arc<ReadSnapshot>,
}

fn snapshot(layers: &MapLayers) -> Arc<ReadSnapshot> {
    Arc::new(ReadSnapshot {
        maps: layers.clone(),
        flush_gen: 0,
        layout_gen: 0,
    })
}

/// Fold and swap twice from `template`: the first swap gives the old base
/// its own copies of the `count` paths, the second is the swap under test.
fn swapped(template: &Maps, n: u64, count: u64, stride: u64) -> Swapped {
    let mut layers = MapLayers::new(template.clone());
    let pre = fold(&layers, n, count, stride, seg_ulid(RESIDENT_SEGMENTS + 1));
    drop(layers.swap_base(template, pre));
    let previous = snapshot(&layers);
    let from = layers.base().clone();
    let new_base = fold(&layers, n, count, stride, seg_ulid(RESIDENT_SEGMENTS + 2));
    let retired = layers.swap_base(&from, new_base);
    drop(from);
    Swapped {
        layers,
        retired,
        previous,
    }
}

fn bench_retired_base(c: &mut Criterion) {
    let templates: Vec<(u64, Maps)> = SIZES.iter().map(|&n| (n, resident(n))).collect();

    let mut arms = |name: &str, run: &dyn Fn(&mut criterion::Bencher<'_>, &Maps, u64, u64, u64)| {
        let mut group = c.benchmark_group(name);
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(10);
        group.warm_up_time(Duration::from_millis(500));
        group.measurement_time(Duration::from_secs(2));
        for &(shape, count, stride) in SHAPES {
            for (n, template) in &templates {
                if *n != 200_000 && (count != 8_192 || stride != 17) {
                    continue;
                }
                group.throughput(Throughput::Elements(count));
                let id = BenchmarkId::new(shape, format!("n{n}_k{count}"));
                group.bench_with_input(id, &(), |b, _| run(b, template, *n, count, stride));
            }
        }
        group.finish();
    };

    arms("retired_drop", &|b, template, n, count, stride| {
        b.iter_batched(
            || {
                let s = swapped(template, n, count, stride);
                drop(s.previous);
                (s.layers, s.retired)
            },
            |(layers, retired)| {
                drop(retired);
                layers
            },
            BatchSize::PerIteration,
        );
    });

    arms("snapshot_last_holder", &|b, template, n, count, stride| {
        b.iter_batched(
            || {
                let s = swapped(template, n, count, stride);
                drop(s.retired);
                (s.layers, s.previous)
            },
            |(layers, previous)| {
                let next = snapshot(&layers);
                drop(previous);
                (layers, next)
            },
            BatchSize::PerIteration,
        );
    });

    arms("snapshot_retired_held", &|b, template, n, count, stride| {
        b.iter_batched(
            || swapped(template, n, count, stride),
            |s| {
                let next = snapshot(&s.layers);
                drop(s.previous);
                (s.layers, s.retired, next)
            },
            BatchSize::PerIteration,
        );
    });
}

criterion_group!(benches, bench_retired_base);
criterion_main!(benches);
