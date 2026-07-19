# Design: dmat writeback without per-record fsync

**Status:** Proposed (2026-07-19). No implementation.

## Problem

The first read of a delta entry materialises the extent (zstd-dict decompress, hash check) and then writes the result back to `cache/<ULID>.dmat` so later reads skip the decompress. That writeback runs synchronously inside the read path. `Dmat::append` writes the record and calls `sync_data()` before returning, so the guest read blocks on an fdatasync against a file that grows by appends. Each append extends the file, so each fdatasync commits extent allocation and the size update through the host filesystem journal in addition to the data itself.

This is the same journal-commit pattern measured for the WAL in [wal-recycling.md](wal-recycling.md), where per-op append-plus-fdatasync on a growing file cost 0.29–0.49 ms p50 and up to 0.75 ms p99 on the loadtest machine. The dmat path has not been benchmarked separately, but the mechanism is identical and the numbers are indicative. The cost lands exactly where delta compression concentrates reads. A freshly forked volume whose content is mostly delta entries over an ancestor pays the fsync on the first read of every delta extent.

## Why per-record durability buys nothing

The dmat is a local-only cache, fully reconstructible from `.delta` plus the source extent. Losing a record costs one re-materialisation on the next read. `Dmat::open_or_create` already scans every record at open and truncates the file at the first invalid one, so a torn tail after a crash is discarded rather than served. There is no state here that needs to survive a crash.

## Approach

**Wire the real open-scan verifier first.** Both call sites (`dmat_lookup` and `dmat_writeback` in `volume/read.rs`) currently pass `|_, _| true`, so the open scan validates structure only (magic, record lengths, lz4 decompressibility) and a dmat hit is served without any content check. [delta-materialisation.md](delta-materialisation.md) specifies BLAKE3 verification of each record against the segment's signed index at open, and the `verify` parameter exists for it. With a no-op verifier, dropping the fsync would widen the window in which a torn-but-structurally-plausible record survives the scan. With the real verifier, any torn or corrupt tail truncates reliably regardless of sync discipline, and the verifier is what makes the fsync removable.

**Drop `sync_data()` from `Dmat::append`.** Records reach disk on normal kernel writeback. A crash before writeback loses cache records, which re-materialise on demand. The read path keeps the write and lz4 gate inline but no longer waits on the journal.

**Optionally move the whole writeback off the read path.** The reader already holds the materialised bytes in memory when `dmat_writeback` runs, so the lz4 entropy gate and the `write()` itself are also pure added latency. Handing the record to a background task removes them too. This adds machinery (a queue, ordering against dmat open and eviction) for a smaller win than removing the fsync, and can be decided separately.

## Open questions

- Open-scan cost once the verifier is real: every open decompresses and hashes every record. delta-materialisation.md already flags this and sketches a clean-shutdown footer that vouches for the file so the scan can be skipped; that mitigation becomes more attractive once the verifier actually runs.
- Whether the background-writeback step is worth its machinery, or inline write-without-fsync is enough.
