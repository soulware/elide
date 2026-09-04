# Design: the guest write phase split

**Status:** instrument, unmeasured. Follows the segment write-behind
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

## Open questions

- Whether the queue wait in front of the worker, which the clock starts
  after, carries a share. The `[ublk io]` maximum minus `maxtotal` bounds it.
