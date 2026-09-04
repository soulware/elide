# Design: a swap returns the base it retired

**Status:** built, bench measured, rig unmeasured. Follows the write phase split
(`write-phase-split.md`), whose rc6 read put the guest write tail in the drop
of the previous read snapshot after a repack bucket swap.

## Problem

An apply on the actor folds a clone of `base` with the mutex released, then
swaps the fold in under a hold. The fold path-copies every map node it
changes, so the old `base` and the new one share the rest. The last holder of
the old `base` frees the nodes the fold diverged, a cost proportional to their
count, and at 43 to 57 ms per repack bucket.

The repack bucket loop and the GC plan apply release their swap hold with the
fair handoff, so a queued guest write takes the mutex next. That write
publishes a read snapshot over the new `base` and drops the previous one. The
bucket's clone of the layers is gone by then, and the actor's own publish
comes after the last bucket, so the previous snapshot is the last holder of
the old `base`, and the guest write frees the nodes on its own thread. The
promote arms keep their clone of the layers alive past their publish, so the
actor frees those nodes by scope alone.

## Design

`MapLayers::swap_base` hands back the `base` it replaced as a `RetiredBase`.
The type is `#[must_use]`, so a swap whose result is discarded fails the
build. Every swap above it passes the value up: `swap_promote` and
`swap_below` in the map layers; the promote, promote-segment, reclaim, reap,
repack-bucket and GC-plan swaps on the volume. A swap that refuses, or that
finds nothing to swap, returns no base: `swap_repack_bucket` returns an
`Option`, `swap_reap` a `ReapSwap` with an optional base, and
`swap_plan_apply` a `PlanSwap` with the base in its `Applied` arm.

The actor holds what a pass retired until after its publish, and drops it on
its own thread:

- `apply_repack_and_publish` collects every bucket's base in a list and drops
  the list after the single publish.
- `apply_gc_plan` publishes next to its swap, then drops the base.
- The promote, promote-segment, reclaim and reap arms drop the base after
  their publish.

The actor's publish drops the previous snapshot while the retired base is
alive, so that drop costs the nodes the guest writes since the last publish
path-copied, and the list drop frees the fold's nodes.

The volume-level applies that hold the mutex across fold and swap drop the
base at once.

## Bench

`elide-core/benches/retired_base_drop.rs` runs the swap on a pair of maps of
`n` extents, with `k` extents re-pointed by a previous fold and again by the
fold under test, and times three drops: the retired base alone, a guest
write's publish and drop of the previous snapshot as the old base's last
holder, and the same publish and drop with the retired base alive. Read on
a MacBook, medians:

| shape | `n` | `k` | retired drop | snapshot, last holder | snapshot, retired held |
|---|---|---|---|---|---|
| scattered | 200k | 512 | 218 us | 211 us | 107 ns |
| scattered | 200k | 2048 | 1.19 ms | 1.21 ms | 126 ns |
| scattered | 200k | 8192 | 2.96 ms | 2.96 ms | 259 ns |
| carry | 200k | 8192 | 2.40 ms | 2.45 ms | 260 ns |
| scattered | 50k | 8192 | 1.80 ms | 1.85 ms | 230 ns |
| scattered | 800k | 8192 | 5.11 ms | 4.93 ms | 530 ns |

The last holder pays the whole free, whichever thread it is, and the write's
drop with the retired base alive costs a quarter of a microsecond. The free
grows with `k` and with `n`, at 0.4 to 0.6 us per re-pointed extent, because
a re-pointed extent copies its path of 64-way map chunks.

The rig's figure for the same drop is 43 to 57 ms per bucket, fifteen times
the bench at the rig's size. The bench frees on a quiet heap under the macOS
allocator; the rig frees under glibc in a process whose worker threads
allocate segment buffers at the same time. The rig arms below carry the
absolute.

## Measurement

Three arms on the rig, read from the `[lock …]` line per loaded window:

1. `maxpost` and the `post` of the `slowest` fields, against the rc6 set.
   The slowest write's `post` should fall from 43 to 57 ms to the cost of its
   own snapshot drop.
2. `maxtotal` and the `[ublk io]` write maximum, which should follow.
3. The `repack-apply` site's hold and the repack apply line, for the cost the
   actor takes over.
