# Design: the guest write phase split

**Status:** measured at v0.1.60-rc6. The tail is the drop of the previous
read snapshot after a repack bucket swap. Follows the segment write-behind
(`segment-write-behind.md`), whose rc5 read left the guest's write tail as the
largest steady-state figure on the guest side.

## Problem

In every steady arm since v0.1.60-rc4, one guest write per 10 s window takes
25 to 60 ms and about ten take over 5 ms, while the mean write costs 0.43 ms.
On rc3 the window maximum ran 7 to 8 ms. The `[lock …]` line puts the mutex
wait maximum at 5 to 8 ms and the hold maximum at 4 to 5 ms in the same
windows, so the mutex holds a fifth of such a write at most. The FUA count per
window tracks the writes over 5 ms and does not track the writes over 25 ms.
The flush maximum, the queue depth, the read count and the write count per
window each correlate with the write maximum at 0.2 or below.

A guest write, at `elide-core/src/actor.rs` `write`, runs four things outside
the mutex: a blake3 hash and a zstd compress of the payload before it, the
drop of the previous read snapshot after it, and for a FUA write the sync
round. The `[lock …]` line times the mutex and splits the hold into its WAL
and map halves. It times nothing outside the mutex, and it records no sizes.

## Design

The write path runs against a clock that marks the call, the ask for the
mutex, the acquisition, the release, the FUA round and the return. The marks
give six phases per write: `pre`, `wait`, `held`, `post`, `fua` and `total`.
`post` is the remainder of the total after the other five, so it holds the
snapshot drop and the promote signal.

`LockStats::record_write_phases` sums `pre`, `post`, `fua` and `total`, keeps
their window maxima, counts the FUA writes, and keeps the peak total since the
volume opened. The write that sets the window maximum total leaves its six
figures, bytes and the five phase times, so the slowest write of a window
reads as one line. Two writes that set the maximum in the same instant
interleave their fields.

The `[lock …]` line gains:

```
; phase pre=<sum>ms maxpre=<max>ms post=<sum>ms maxpost=<max>ms
  fua n=<count> held=<sum>ms maxfua=<max>ms total=<sum>ms maxtotal=<max>ms peaktotal=<max>ms;
  slowest bytes=<n> pre=<ms> wait=<ms> held=<ms> post=<ms> fua=<ms>
```

`write_zeroes` runs against the same clock with its byte count from the block
count.

## Measurement

Three arms on the rig, read from the `[lock …]` line per loaded window:

1. `maxtotal` against the `[ublk io]` write maximum of the same window. The
   two should agree to within the queue wait in front of the worker.
2. The `slowest` fields. The phase that carries the 25 to 60 ms names the
   tail, and `bytes` says whether it is a merged write.
3. `maxpre` and `maxpost` against `maxheld`, across the windows.

## Result

Three arms at v0.1.60-rc6 on the rig, pgbench at 500 tps, 52 loaded windows.
The guest side matches the rc5 set: latency 6.4, 5.0 and 5.7 ms, worst
windows 11.0, 7.3 and 18.4 ms.

| window maximum | med | p95 | max |
|---|---|---|---|
| `maxpre` | 3.0 | 7.3 | 35.5 |
| `maxwait` | 5.9 | 9.2 | 41.7 |
| `maxheld` | 4.1 | 6.9 | 29.7 |
| `maxpost` | 26.0 | 50.6 | 56.6 |
| `maxfua` | 0.9 | 9.3 | 13.5 |
| `maxtotal` | 27.4 | 51.1 | 57.7 |
| `[ublk io]` write max | 11.4 | 48.1 | 56.3 |

`maxtotal` and the `[ublk io]` write maximum agree to within a millisecond in
every loaded window, so the queue wait in front of the worker carries none of
the tail. The mean phases per write are 39 us pre, 8 us post and 149 us total.

The `post` phase carries the slowest write in 35 of the 52 windows. Its
twelve worst writes hold 43 to 57 ms in `post`, under 0.2 ms in `held`, under
0.8 ms in `wait`, and carry 4 to 40 KiB. `wait` carries 9 windows, `held` 4,
`fua` 2 and `pre` 2.

`post` is the drop of the previous read snapshot. Every one of the 30 windows
whose slowest write holds 20 ms or more in `post` has a `repack-apply` site
count of 7 or 9, and every window with a `repack-apply` count of 0 has a
slowest `post` of 16 ms or less. The `check-promote` count is at most 5 in
any window, so every promote signal lands in the mailbox without a block.

The mechanism is in `VolumeActor::apply_repack_and_publish`. Each bucket
clones the map layers, folds the bucket into a clone of `base` with the
mutex released, and swaps the fold in under a `fair` hold. The `fair`
release hands the mutex to a queued guest write. That write publishes a
snapshot over the new `base` and drops the previous snapshot, which is the
last holder of the old `base`. The bucket's clone of the layers is gone at
the end of the loop iteration, and the actor's own publish comes after the
last bucket. So the guest write frees every map node the fold diverged from
the old `base`, on its own thread, in `post`.

The promote applies keep their clone of the layers alive until after their
publish, so the actor frees a promote's diverged nodes itself.
`VolumeActor::apply_gc_plan` has the repack shape: the clone dies before the
publish and the swap hold is `fair`.

## Next

The actor owns the nodes a swap retires, and frees them after its publish.
Two shapes do that:

1. Each swap returns the `Maps` it replaced, and the apply holds them in a
   list it drops after its publish. Ownership is explicit at the swap.
2. The apply keeps every bucket's clone of the layers in a list it drops
   after its publish. The promote arms have this shape by scope.
