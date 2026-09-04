# Design: segment write-behind

**Status:** implemented (#1003) and measured on v0.1.60-rc5 (2026-09-04); the
result is at the end. Follows the WAL sync gate (`wal-sync-gate.md`), whose rc4
result put the remaining FLUSH tail in the fdatasync itself under the worker's
segment writes.

## Problem

A FLUSH request's wait equals its fdatasync on the WAL. On v0.1.60-rc4 the
window maximum of that sync runs a median of 15 ms and a p95 of 54 ms, with a
373 ms maximum, and the worst syncs sit in windows where the worker writes a
segment. The wchan sample of rc2 caught the worker's own fsyncs in the
block-layer writeback throttle.

The worker lands each segment twice. `write_segment_full` buffers the whole
segment and syncs once at the end. `promote_to_cache` then copies the body
section into the cache and syncs once at the end. Each sync hands the disk
every dirty page of the file in one burst, and a WAL fdatasync that arrives
in the burst queues behind all of it.

## Design

`elide-core/src/write_behind.rs` bounds the dirty pages behind a large file
write. A cursor follows the high-water mark of the bytes a writer lands. When
a full window lands, the cursor starts writeback on that window with
`sync_file_range(SYNC_FILE_RANGE_WRITE)` and waits for the writeback of the
window before it with `WAIT_BEFORE | WRITE | WAIT_AFTER`. Two windows sit
dirty at a time, so a WAL fdatasync queues behind two windows at most, and the
final `sync_data` finds little left to flush.

The window is 1 MiB. The cost per window is two syscalls, and the wait on the
window before keeps one window in flight, so the writer's throughput is one
window per device write latency.

`WriteBehindFile` wraps the file. A sequential writer goes through its `Write`
impl under a `BufWriter`. A positional writer reports each landed range with
`written(end)`; the cursor keeps the high-water mark, so the sparse cache body
that `promote_to_cache` builds in `stored_offset` order reports the same way.

Three writers take the cursor:

- `write_segment_full`, which lands every promote, repack and GC output, in
  the volume and in the coordinator.
- `rewrite_with_deltas`, which lands a delta rewrite.
- `promote_to_cache`, which lands the cache body copy.

The calls compile to a no-op on a platform other than Linux.

## Measurement

Three arms on the rig against rc4, read from the `[flush …]` line's `sync max`
per loaded window:

1. The `sync max` distribution per arm against rc4's.
2. The repack pass's `write=` phase and the worker's per-job time for promote
   and close-generation. The wait per window serialises the writer with the
   disk, so these are the cost.
3. The WAL half of the write hold in the `[lock …]` line.
4. pgbench latency and the worst 10 s window.

A split of the windows by segment-write overlap gives no control set under
this workload. A promote lands a segment every few seconds at 500 tps, so
every loaded window carries one.

## Result

v0.1.60-rc5 ran the three arms on pg35, 53 loaded windows, against the rc4 set
on the same volume and machine.

**The steady arms lost their sync tail.** In the second and third arms the
window maximum of the sync fell from a p95 of 46.2 / 32.0 ms and a maximum of
49.2 / 44.1 ms to a p95 of 16.0 / 12.4 ms and a maximum of 20.5 / 17.9 ms. The
median across all windows fell from 15.3 to 10.6 ms, and the mean sync held at
0.66 ms against 0.68 ms.

**The first arm's tail is the host's disk after a VM reboot.** A deploy
reboots the rig VM, and both sets ran their first arm in the minutes after it.
Both carry four windows over 50 ms there, with a maximum of 372.8 ms on rc4 and
300.0 ms on rc5, and in those windows a guest read and the WAL fdatasync stall
to the same value (267.4 against 267.0 ms) while the volume mutex, the lock
sites and the coordinator's work look as they do in every other window. This
tail sets the p95 across all windows, 54.0 ms on rc4 against 112.5 ms on rc5.

Four arms with a one-second `/proc/diskstats` sampler on the data disk named
it. An arm after `echo 3 > drop_caches` read 128 MiB from the disk in its first
window at a 1.4 ms await and its worst sync was 35.6 ms; a warm arm and a second
dropped arm had no second with a read or write await over 8 ms. An arm started
45 s after `fly machine restart` reproduced the stalls, sync maxima of 413.2,
382.0 and 447.2 ms, with the disk at 17 to 25% busy and at most three requests
in flight. Its sampler holds four seconds in which a handful of reads took
hundreds of milliseconds between them: 74 reads at a 17.1 ms mean in the
413 ms window, 16 reads at 24.0 ms in the 382 ms window, 22 reads at 20.6 ms in
the 447 ms window, and 4 reads at 35.0 ms in a 69 ms window. Each is one
request of 380 to 450 ms that the virtio disk held, and the fdatasync's own
writes hit the same requests. The stalls sat 100 to 300 s after boot in every
set. The disk serves a request in hundreds of milliseconds now and then in the
first five minutes after the VM boots, and a guest-side page cache drop leaves
that host-side state warm.

So the first arm after a deploy is not an arm. A set that follows a deploy
waits ten minutes after the boot, or discards its first arm.

**The cursor costs nothing the rig resolves.** The repack pass's write phase
ran a median of 111 ms against 115 ms, with a maximum of 162 ms against
305 ms, over 36 passes of three or more outputs each. The promote job ran a
median of 87 ms against 140 ms, and close-generation 996 ms against 1142 ms.
The gc-plan job held at 178 ms.

**The WAL half of the write hold moved with it.** The window maximum of the
WAL append fell from a median of 4.1 ms and a p95 of 7.1 ms to 3.3 and 5.2 ms,
and the window maximum write wait from a median of 5.6 ms, a p95 of 11.4 ms and
a maximum of 19.0 ms to 5.1, 8.3 and 11.2 ms. The lock sites held
(gc-handoff-finalize 2.9 against 2.8 ms median maximum).

**The guest saw the cleanest set of the series.** pgbench mean latency per arm
6.1 / 4.6 / 4.3 ms with worst 10 s windows of 11.9 / 6.2 / 5.5 ms, against rc4's
6.9 / 5.3 / 15.4 ms and 27.7 / 8.8 / 163.6 ms. The latency standard deviation
fell to 16.0 / 6.6 / 5.4 ms from 24.2 / 8.3 / 63.7 ms. Volume CPU per
transaction held at 0.86 / 0.81 / 0.82 ms against 0.84 / 0.83 / 0.99 ms.

The 1 MiB window stands. The cost read gives a wider window nothing to buy.

## Open questions

- Whether the segment fetch paths, which land a whole object from S3 and sync
  once, want the same cursor.
