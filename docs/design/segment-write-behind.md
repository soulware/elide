# Design: segment write-behind

**Status:** implemented, unmeasured. Follows the WAL sync gate
(`wal-sync-gate.md`), whose rc4 result put the remaining FLUSH tail in the
fdatasync itself under the worker's segment writes.

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

- `write_segment_full`, which lands every promote, repack and GC output.
- `rewrite_with_deltas`, which lands a delta rewrite.
- `promote_to_cache`, which lands the cache body copy.

The calls compile to a no-op on a platform other than Linux.

## Measurement

Three arms on the rig against rc4, read from the `[flush …]` line's `sync max`
per loaded window, split by whether a worker segment write overlapped the
window:

1. The with-worker `sync max` against rc4's. A fall toward the without-worker
   figure confirms that the segment burst was the mechanism.
2. The without-worker `sync max`. It is the control, and it should hold.
3. The worker's per-job time for promote and promote-segment. The wait per
   window serialises the writer with the disk, so the job time is the cost.
4. pgbench latency and the worst 10 s window.

A flat with-worker `sync max` says the WAL sync waits on the host journal
commit alone, and the next lever is the WAL's own placement
(`wal-recycling.md`).

## Open questions

- Whether the window earns a wider setting once the job-time cost is read. A
  wider window raises the burst a WAL sync can queue behind.
- Whether the segment fetch paths, which land a whole object from S3 and sync
  once, want the same cursor.
