# Design: a swap returns the base it retired

**Status:** measured at v0.1.60-rc7. The guest write's `post` phase is
clear. Follows the write phase split
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

## Result

Three arms at v0.1.60-rc7 on pg35, started nine and a half minutes after the
deploy's boot, 53 loaded windows, against the rc6 set on the same volume and
machine.

| window maximum, ms | rc6 med | rc6 p95 | rc6 max | rc7 med | rc7 p95 | rc7 max |
|---|---|---|---|---|---|---|
| `maxpost` | 26.0 | 50.6 | 56.6 | 1.3 | 6.2 | 17.3 |
| `maxtotal` | 27.4 | 51.1 | 57.7 | 7.0 | 15.4 | 27.2 |
| `[ublk io]` write max | 11.4 | 48.1 | 56.3 | 6.4 | 11.8 | 27.3 |
| `maxwait` | 5.9 | 9.2 | 41.7 | 5.4 | 11.0 | 20.5 |
| `maxheld` | 4.1 | 6.9 | 29.7 | 4.6 | 8.6 | 24.4 |
| `maxpre` | 3.0 | 7.3 | 35.5 | 4.3 | 9.0 | 26.4 |
| `maxfua` | 0.9 | 9.3 | 13.5 | 0.8 | 6.4 | 9.9 |

**The `post` phase is clear.** On rc6 the slowest write's `post` was 20 ms or
more in 30 of 52 windows and carried the slowest write in 35. On rc7 it is
under 20 ms in all 53 windows and carries the slowest write in none. The
mean `post` per write fell from 8.4 to 4.7 us. The slowest write per window
now sits at 7 to 27 ms, and `pre` carries it in 18 windows, `wait` in 17,
`held` in 15 and `fua` in 3.

**The repack hold held.** The `repack-apply` site's hold maximum per window
reads a median of 0.3 ms against 0.4 and a p95 of 1.4 against 2.2, with the
same wait, so the free lands outside the hold. The actor's own time in the
free has no counter, and the guest sees none of it.

**Reads held.** The `[ublk io]` read maximum per busy window reads a median
of 5.7 ms on rc6 and 5.3 ms on rc7. Both sets carry four windows with a read
maximum over 100 ms, and in every one of them the WAL sync maximum of the
same window reads the same value, which is one request the virtio disk
held. Those windows sit at 10.7 to 15 minutes after the boot in both sets.
They are the reboot tail (`segment-write-behind.md`), which runs to fifteen
minutes after the boot.

**Guest.** Arm 3 reads the cleanest arm of any set on this volume: latency
4.5 ms, standard deviation 5.6 ms, worst window 6.0 ms. Arms 1 and 2 carry
the reboot tail: one 650 ms window in arm 2 at fifteen minutes after the
boot holds a 337.5 ms read and a 328.1 ms sync, and the arm reads 59 ms.

## Next

The slowest guest write per window is 7 to 27 ms, split across `pre`,
`wait` and `held`. `pre` is the blake3 hash and the zstd compress of an 8 to
16 KiB write, at 8 to 26 ms in its worst windows against a mean of 38 us, so
those writes lost the CPU. The next read is what runs on the volume's cores
in those windows.
