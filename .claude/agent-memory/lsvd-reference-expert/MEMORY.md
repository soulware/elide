# Memory Index

- [LSVD_COMPREHENSIVE_SURVEY.md](LSVD_COMPREHENSIVE_SURVEY.md) — Complete survey: architecture, write/read paths, LBA map design, GC, coordinator role, segment format, range cache, snapshots, dedup, Elide vs LSVD deviations
- [lsvd_s3_fetch_strategy.md](lsvd_s3_fetch_strategy.md) — LSVD fetches by extent via byte-range GETs (1MB chunks), never downloads whole segments
- [lsvd_lba_map_design.md](lsvd_lba_map_design.md) — In-memory ExtentMap (red-black tree of compactPE), CBOR persistence (head.map), rebuild from segments, read/write paths
- [lsvd_demand_fetch_cache.md](lsvd_demand_fetch_cache.md) — RangeCache (1MB chunks, mmap'd, LRU eviction), no "partial presence" markers, S3 byte-range GETs per chunk, optional ExtentCache (unused), uncompressed fast path
- [lsvd_gc_algorithm.md](lsvd_gc_algorithm.md) — GC: segment selection (density-based or small-pack), extent gathering from LBA map, copy-based repacking, atomic LBA map patching, snapshot safety via removeSegmentIfPossible
- [lsvd_sequencing_and_gc.md](lsvd_sequencing_and_gc.md) — LSVD assigns sequence numbers on demand (not pre-assigned), all IDs from same monotonic SeqGen, serial event loop prevents compaction-output-overwrites-WAL bug
- [lsvd_gc_strategies.md](lsvd_gc_strategies.md) — StartGC: density-driven (single worst-offender), SweepSmallSegments: size-driven packing (consolidate ≥2 small segments)
- [lsvd_trim_zero_extent_handling.md](lsvd_trim_zero_extent_handling.md) — No FLAG_ZERO: TRIM is represented as sentinel extent with Size=0; batching at NBD layer; read returns zeroed buffer
- [lsvd_integrity_verification.md](lsvd_integrity_verification.md) — No cryptographic signatures or per-extent hashes; only debug SHA256 logging; import-time whole-disk SHA256 verification optional
