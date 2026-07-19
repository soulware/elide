# Design: WAL recycling

**Status:** Proposed (2026-07-19). No implementation.

## Problem

Guest FLUSH/FUA reaches `wal_fsync`, which is `sync_data()` on a WAL file that grows by appends. Every append extends the file, so each fdatasync commits extent allocation and the size update through the host filesystem journal in addition to the data itself. The WAL lifecycle repeats this cost every generation: the file is created lazily on first write (`ensure_wal_open`), grows to `FLUSH_THRESHOLD` (32 MiB), is promoted, and is unlinked in `apply_promote`. Since #728 wired FUA through to `wal_fsync` in-lock, this journal traffic sits directly on guest fsync latency.

## Measurement

One benchmark run on the loadtest machine (ext4 on a Fly volume, single-threaded writer, per-op `write` + `fdatasync` latency, three generations per mode, 2026-07-19). Three modes: append to a fresh file per generation (the current lifecycle), append into a file fallocated to full size at create, and overwrite a fully-written fixed-size file from offset zero (recycling).

| chunk  | grow p50 / p99 | fallocate p50 / p99 | recycled p50 / p99 |
|--------|----------------|---------------------|--------------------|
| 64 KiB | 0.49 / 0.75 ms | 0.41 / 0.63 ms      | 0.18 / 0.31 ms     |
| 4 KiB  | 0.29 / 0.45 ms | 0.24 / 0.39 ms      | 0.06 / 0.12 ms     |

Caveats. This is one synthetic run on one box; occasional ~100 ms outliers hit all modes equally (a machine-level stall, not mode-specific). The gap is consistent with the journal-commit explanation but journal activity was not traced directly. The production benefit scales with guest flush frequency, not write volume; a workload that rarely flushes gains little, and the guest-visible improvement will be smaller than the raw fdatasync numbers because the flush path includes work beyond the fsync itself.

The fallocate mode is the informative control: preallocating extents recovered only a small fraction of the gap, consistent with unwritten-extent conversion still requiring journal commits. Preallocation alone is not the design; reuse of already-written blocks is.

## Approach

Recycle promoted WAL files instead of unlinking them, in the style of Postgres WAL segment recycling.

**Spare pool.** `apply_promote` moves the retired WAL file into a spare pool under `wal/` instead of calling `remove_file`. `ensure_wal_open` takes a spare when one exists, renames it to the freshly minted ULID, and overwrites from offset zero; when the pool is empty it creates a fresh file as today. ULID minting, ordering invariants, and the promote CAS are untouched; only the fate of the retired file changes.

**Record-generation binding.** A recycled file holds the previous generation's records past the new tail, and those records carry valid checksums. Recovery's scan-and-truncate would replay them as current data. Each record must therefore be bound to its WAL generation, by mixing the WAL's ULID into the record checksum or by an explicit generation field, so that recovery rejects records from a prior occupant of the file. This is a WAL format break.

**Multiple WALs in flight.** A promote in progress, and stashed failed-promote jobs awaiting retry (#739), mean several WAL files can exist simultaneously. The pool absorbs each file as its promote applies. A stashed job keeps its WAL until its retry succeeds; recycling happens exactly where the unlink happens today, so the retry path's ordering is unchanged.

**Pool trimming and idle volumes.** Lazy open means an idle volume currently has no WAL file at all, and that must be preserved. The GC tick trims the pool: all spares are unlinked when the volume is quiescent, and the pool is capped while active. An actively writing volume parks at most a few 32 MiB spares; an idle one parks none.

**Cached-fd safety.** Unlinking leaves the dead inode readable by any stale cached fd, which has previously been a safety net. Renaming and overwriting the same inode replaces that net with wrong bytes for any reader that retains an fd across the promote. `apply_promote` evicts the cached fd before touching the file, but an audit must establish that no other fd can outlive apply, including the promote worker's reads if streaming promote is adopted.

## Open questions

- Binding form for records: ULID mixed into the checksum (no extra bytes) or an explicit generation field (inspectable in `inspect-wal`).
- Partially written spares. A WAL promoted before reaching the size cap (entry-count cap, explicit flush) is only partly written, so recycling it only helps over the written prefix. Accept the partial benefit, only pool full-size files, or top spares up in the background.
- Pool cap: a small fixed number, or derived from the observed in-flight WAL count.
- Upgrade across the format break: a binary that can't replay the old format requires WALs to be drained at upgrade time, or recovery briefly understands both. Needs a decision against the no-backward-compatibility default.
- Whether to trace host journal commits (e.g. ext4 `jbd2` activity) under the real write path before building, to confirm the attribution rather than relying on the synthetic benchmark alone.
