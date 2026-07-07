# dis (Original LSVD Paper Implementation) Notes

[asch/dis](https://github.com/asch/dis) is the EuroSys 2022 LSVD paper authors' own implementation — the paper uses the name LSVD, the code uses DIS ("blockDevice over Immutable Storage"). It is a Linux device-mapper kernel module (`kernel/dm-disbd.c`) plus a Go userspace daemon (`userspace/`), pinned to kernel ≤5.0.

dis is best understood as the paper's benchmarking artefact rather than a full realisation of the paper's design: it proves the performance thesis (acknowledge writes at local NVMe speed, batch to an object store, demand-fetch on read) while most of the durability, layering, and efficiency machinery the paper describes exists only in the paper. [lab47/lsvd](https://github.com/lab47/lsvd) — an independent reimplementation, and our primary studied reference (see [reference-lsvd.md](reference-lsvd.md)) — is closer to the paper's described design than the paper authors' own code.

## Architecture

Responsibility is split across the kernel boundary. The kernel module owns the write cache — a circular journal region on a raw local device, each write prefixed with a 4KB header (magic, sequence number, CRC32, extent metadata) — and maintains in-kernel red-black extent trees for reads and writes. The Go daemon polls the kernel through four ioctls (`IOCTL_DIS_READS` / `WRITES` / `RESOLVE` / `GET_MAP`) to collect completed write extents, assemble them into backend objects, and resolve read misses back into the kernel's read map.

Elide places the same functions entirely in userspace via ublk, and splits along a trust/ownership boundary instead: volume process (I/O, WAL) vs coordinator (S3 writes, GC, supervision). dis's kernel split reflects its era — ublk did not exist until kernel 6.0. The split bought low-latency write acks at the cost of a kernel/userspace map-synchronisation problem the code leaves unresolved (`dm-disbd.c:381`: "not sure how to get the map update properly synchronized").

## Write path

Guest writes land in the kernel write cache; header and data bios are submitted independently with no ordering guarantee between them. The write cache is divided into eight octants for wrap-around reclamation. Userspace accumulates completed extents into objects (configurable size) and uploads when an object fills or after a 5s timer (`userspace/backend/object/write.go`) — the same shape as Elide's 32MB-threshold-or-idle-tick promotion.

## Read path

Read misses surface to userspace, which resolves LBA → (object key, PBA) in an in-memory red-black tree (`userspace/backend/object/extmap/extmap.go`), then fetches at **extent granularity with byte-range GETs** through 20 parallel download workers — never whole-object downloads (`userspace/backend/object/read.go`). Fetched data lands in a userspace-managed circular read cache (direct I/O file); eviction is wrap-around overwrite, no LRU. This extent-granular range-GET read path is the core convergence point among dis, lab47/lsvd, and Elide.

## Metadata and crash consistency

The extent map is a single-level LBA → (object, PBA) red-black tree held only in memory. There is no persistence, checkpointing, or rebuild-from-object-headers: if the daemon dies, the mapping is gone. The write-cache journal headers make recovery possible in principle, but nothing implements it. The README's "crash-consistent, unlike bcache" claim is aspirational.

This is the sharpest contrast with Elide, where rebuild-from-segments *defines* correctness: the LBA map and extent index are deliberately volatile because deterministic rebuild (oldest-first by ULID, WAL tail truncation, concurrent-writes-always-win) is the invariant, validated continuously by the crash-recovery proptest oracle. The same "in-memory map" surface rests on opposite foundations.

## Backend and GC

Three backends (File, S3, Ceph RADOS) behind `Init`/`Read`/`Write`. Objects are sequentially-numbered blobs with embedded 16-byte extent descriptors — no checksums, no signing, no independently fetchable index section. GC runs every 5s: greedily select the most-fragmented objects until garbage fraction drops below 0.3, repack live extents into new objects, patch the live in-memory map, delete the old objects (`userspace/backend/object/gc.go`). Elide's GC is the same greedy pick/repack/delete shape, made rebuild-safe and cross-process by the ULID-ordered handoff protocol.

## Absent from dis

Snapshots/layering, clones, dedup, compression, multi-host operation, integrity checking, and recovery tooling are all absent. Each device is a single flat address space.

| | dis | Elide |
|---|---|---|
| Block frontend | kernel device-mapper module (≤5.0) | userspace ublk |
| Mapping | LBA → (object, PBA), in-memory only | LBA → hash → segment+offset, rebuilt from segments |
| Durability ack | kernel write-cache landing; recovery unimplemented | WAL `sync_data` on guest fsync; deterministic rebuild |
| Backend objects | numbered blobs, no checksums | ULID-named four-section segments, Ed25519-signed |
| GC | in-process live-map patch | coordinator handoff protocol, ULID-ordered |
| Snapshots / forks | absent | directory-tree ancestry, signed provenance |
| Dedup / compression | absent | BLAKE3 dedup; LZ4 body / zstd delta |

## One deliberate divergence worth knowing

dis's write cache is a raw device region with octant-based wear-leveling rather than files on a filesystem — the more aggressive latency play the paper benchmarks. Elide chose filesystem-visible state instead: the `wal/` / `pending/` / `index/` + `cache/` lifecycle is inspectable with `ls`, which is a design principle, not an oversight.
