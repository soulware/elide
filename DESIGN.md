# Design

## Problem Statement

Running many VMs at scale on shared infrastructure presents a storage challenge: base images are largely identical across instances, evolve incrementally over time, and yet are conventionally treated as independent copies. Each VM gets its own full copy of the image, even though 90%+ of the data is shared and most of it is never read at runtime.

The goal is a block storage system that minimises storage cost, minimises cold-start latency, and handles image updates efficiently at scale. The approach combines four techniques that individually exist but have not previously been integrated in this way:

- **Log-structured virtual disk (LSVD)** — write ordering and local durability, with S3 as the large capacity tier
- **Demand-fetch** — only retrieve data from S3 when it is actually needed; data never accessed is never transferred
- **Content-addressed dedup** — identical chunks are stored once regardless of how many volumes reference them
- **Delta compression** — near-identical chunks (e.g. a file updated by a security patch) are stored as small deltas against their predecessors, reducing S3 fetch size for updated images

The combination is particularly effective for the VM-at-scale use case because: base images are highly repetitive across VMs (dedup captures shared content), images evolve incrementally (delta compression captures changed content), most of each image is never read at runtime (demand-fetch avoids fetching unused data), and the same image is booted many times (locality optimisation pays back repeatedly).

## Key Concepts

**Block** — the fundamental unit of a block device, 4KB. This is what the VM sees.

**Chunk** — a fixed-size group of consecutive blocks, the unit of dedup and storage. At 32KB, a chunk covers 8 blocks. All chunks within the system are the same size (stored in the manifest header). Chunks are identified by their BLAKE3 hash.

**Extent** — a variable-size application write. Extents are split into fixed-size chunks on the write path.

**Manifest** — a sorted list of `(LBA, chunk_hash)` pairs describing the complete state of a volume at a point in time. The manifest is the volume's index: given an LBA, it returns the hash of the chunk that should be there. Manifests are small (a few MB for a typical image volume) and held in memory on the host for running volumes.

**Snapshot** — a frozen, immutable manifest. Snapshots and images are the same thing — there is no separate image concept. A snapshot is taken by freezing the current manifest; since chunks are immutable and content-addressed, no data is copied. Snapshots are identified by `blake3(manifest_bytes)`.

**Segment** — a packed collection of chunks, typically ~32MB, stored as a single S3 object. Segments are the unit of S3 I/O.

**Write log** — the local durability boundary. Writes land here first (fsync = durable). Chunks are promoted to segments in the background.

**Chunk index** — maps `chunk_hash → S3 location`. Tells the read path where in S3 a given chunk lives. Maintained by the global service, updated by GC when chunks are repacked.

## Architecture

Two components run on each host:

**Per-volume process** — one per running VM. Owns the ublk/NBD frontend, the live manifest (in memory), the write log (local NVMe), and the per-volume extent index. Classifies chunks by entropy, routes low-entropy chunks to the global service for dedup, stores high-entropy chunks directly in per-volume segments.

**Global service** — one per host. Owns the chunk index (on-disk), the in-memory filter (xor/ribbon), and the host-level read cache. Handles dedup lookups, segment packing, S3 upload/download, and GC.

S3 is shared across all hosts. Segments from any volume on any host land in a single shared namespace. The manifest and chunk index together replace the per-volume segment list of the reference LSVD implementation.

```
VM
 │  block I/O (ublk / NBD)
 ▼
Per-volume process
 │  write path: split → entropy check → chunk → hash
 │  read path:  LBA → manifest → hash → local cache → S3
 │
 ├─ Write log (local NVMe, durability boundary)
 ├─ Live manifest (in memory, LBA → hash)
 └─ Global service client
      │
      ▼
Global service (per host)
 ├─ Chunk index (on-disk, hash → S3 location)
 ├─ Xor/ribbon filter (in memory, ~100MB)
 ├─ Read cache (small, absorbs S3 fetch bursts)
 └─ S3 (shared, all hosts)
      ├─ segments/<id>       — packed chunks
      ├─ snapshots/<id>.snap — frozen manifests
      └─ index/chunk-index   — global chunk hash → location
```

## Write Path

```
1. VM issues write for LBA range
2. Split into fixed-size chunks
3. For each chunk:
   a. Entropy check
      - High entropy → local tier (per-volume segment, no dedup)
      - Low entropy  → continue
   b. Check per-volume extent index (in memory)
      - Hit  → point LBA at existing chunk, done
      - Miss → continue
   c. Check xor/ribbon filter (in memory)
      - Miss → new chunk, store it
      - Hit  → check chunk index on disk to confirm
   d. If new: write to write log (fsync = durable), promote to segment in background
   e. If duplicate: reference existing chunk, no write
4. Update live manifest with new LBA → hash mappings
```

Durability is at the write log. S3 upload is asynchronous and not on the critical path.

## Read Path

```
1. VM reads LBA range
2. Look up LBA in live manifest → chunk hash H
3. Check local cache for H
   - Hit  → return data
   - Miss → look up H in chunk index → S3 location
4. Fetch chunk from S3, populate local cache
5. Return data to VM
```

The kernel page cache sits above the block device and handles most hot reads — the system never sees page cache hits. The local chunk cache is a small S3 fetch buffer, not a general-purpose cache.

## Manifest Format

Binary flat file. Content-addressed: `snapshot_id = blake3(file_bytes)`, used as the filename (`<snapshot_id>.snap`).

**Header (88 bytes):**

| Offset | Size | Field        | Description                          |
|--------|------|--------------|--------------------------------------|
| 0      | 8    | magic        | `PLMPST\x00\x01`                     |
| 8      | 32   | volume_id    | blake3 of all chunk hashes (content-derived) |
| 40     | 32   | parent_id    | snapshot_id of parent; zeros = root  |
| 72     | 4    | chunk_size   | chunk size in bytes (u32 le)         |
| 76     | 4    | entry_count  | number of entries (u32 le)           |
| 80     | 8    | timestamp    | unix seconds (u64 le)                |

**Entries (40 bytes each, sorted by LBA):**

| Offset | Size | Field | Description              |
|--------|------|-------|--------------------------|
| 0      | 8    | lba   | logical block address (u64 le) |
| 8      | 32   | hash  | BLAKE3 chunk hash        |

One entry per chunk. The LBA is chunk-aligned (multiple of `chunk_size / 4096`). Unwritten LBAs have no entry (implicitly zero). At 32KB chunks and a 2GB volume, a fully-written manifest is ~2.5MB.

**Snapshot identity:** `snapshot_id = blake3(entire file)`. Not stored in the file — derived on load. The snapshot filename is its own ID.

**Volume identity:** `volume_id = blake3(all chunk hashes in LBA order)`. Deterministic from content. Two independently-generated snapshots of the same image produce the same `volume_id`. Two snapshots of the same running volume have the same `volume_id`, enabling LBA-level diffing to show what changed.

**Parent chain:** `parent_id` references the `snapshot_id` of the previous snapshot. This enables chain traversal without loading both manifests. A snapshot with `parent_id = [0; 32]` is a root snapshot with no history.

## Chunk Index

Maps `chunk_hash → S3 location`. Separate from the manifest — the manifest is purely logical (what data is at each LBA), the chunk index is physical (where that data lives in S3).

This separation means GC can repack chunks (changing their S3 location) by updating only the chunk index. Manifests are never rewritten after being frozen.

The chunk index also stores delta compression metadata: if chunk B is stored as a delta against chunk A, the index records `hash_B → {segment, offset, delta_source: hash_A}`. The manifest is unaware of this — it just records `lba → hash_B`. The read path fetches the delta and the source chunk, reconstructs B, and caches the full chunk locally.

**In-memory filter:** an xor or ribbon filter (~100MB for 80M entries) guards the on-disk index. Chunks not in the filter are definitively new — no disk lookup needed. False positives fall through to disk. Filter is rebuilt periodically during GC sweep.

## Dedup

**Exact dedup:** two chunks with the same BLAKE3 hash are identical. The second write costs nothing — the manifest is updated to point the new LBA at the existing chunk. No data stored, no S3 upload.

**Delta compression:** chunks that are similar but not identical (e.g. a file updated by a security patch) can be stored as a delta against a known chunk. Applied at S3 upload time — the local cache always holds full reconstructed chunks. The benefit is reduced S3 fetch size, not storage cost. The primary value is latency: fetching a 2KB delta instead of a 32KB chunk from S3 is ~16× faster on the network path.

Delta compression is compelling for point-release image updates; not worth the complexity for cross-version (major version) updates where content is genuinely different throughout.

**Empirically measured (Ubuntu 22.04 point releases, 14 months apart):**
- 70% of chunks are exact matches (zero marginal cost)
- Of the remaining 30%, delta compression achieves ~90% size reduction on similar chunks
- Overall marginal S3 fetch to advance from one point release to the next: ~456MB vs ~700MB for a full fetch (~35% of full image, ~94% saving vs fetching fresh)

## Volume Types and Namespace Scoping

Volumes have a type that determines which chunk namespace they participate in.

**Image volumes** (rootfs, shared base images) — opt into the global dedup namespace. Low-entropy chunks are routed to the global service for dedup check and shared index storage. Boot hint sets are accumulated and repacking for locality applies.

**Data volumes** (databases, application data) — never touch the global chunk namespace. Chunks go directly to per-volume S3 segments with no dedup check. Still benefit from the local NVMe cache tier, free snapshots, and cheap migration. Kept out of the global namespace to avoid index pollution with high-churn, low-hit-rate entries.

Snapshot manifests are uniform across volume types — snapshot management is identical regardless of type. Only the chunk storage routing differs.

**Routing at write time:**
- `volume.type == Image && entropy(chunk) < threshold` → global service (dedup check)
- Everything else → per-volume segments (no dedup)

**Open question:** binary global/non-global routing may not be granular enough. Hierarchical namespaces (global → org → image-family → volume) are a plausible future requirement. The design should treat namespace as an attribute of the volume, not a boolean flag.

## Snapshots

A snapshot is a frozen manifest. Taking a snapshot is cheap: copy the current in-memory manifest, assign a snapshot_id, write to S3. Cost is proportional to manifest size, not volume size.

**Snapshots are images.** There is no separate image concept. Deploying a new image version means taking a snapshot on a configured VM and distributing the manifest. The storage layer handles dedup, delta compression, and locality transparently — the snapshot mechanism is unaware of them.

**GC interaction:** the GC sweep walks all manifests, including frozen snapshots. Chunks referenced by any snapshot are kept alive. Deleting a snapshot releases its chunk references; the next GC sweep reclaims chunks no longer referenced by any remaining manifest.

**Rollback:** replace the live manifest with a snapshot manifest and discard the write log since the snapshot point. Instant at the block device level.

**Migration and disaster recovery** share the snapshot code path: start a volume from a manifest on a new host. One operation, multiple use cases.

## GC and Repacking

**Standard GC:** walk all manifests, build the set of live chunk hashes, delete unreferenced chunks from S3 after a grace period. No per-write refcounting — the manifest scan is the reference count.

**Delta dependency handling:** when a source chunk is about to be deleted and a live delta depends on it, materialize the delta first (fetch source + delta → full chunk, write full chunk to S3, update chunk index). Then delete the source. The dependency map is derived fresh each GC sweep from the chunk index — no persistent reverse index needed.

**Access-pattern-driven repacking:** GC extends beyond space reclamation to also improve data locality. Boot-path chunks — identified from observed access patterns during VM startup — are co-located in dedicated segments. A cold VM boot then fetches one or two S3 segments to get everything needed for boot, rather than many scattered segments.

**Boot hint accumulation:** every VM boot records which chunks were accessed during the boot phase (identified by time window after volume attach, or explicit VM lifecycle signals from the hypervisor). These observations accumulate per snapshot. After sufficient boots (converges quickly at scale — 500 VMs/day = 500 observations/day), the hint set is stable enough to guide repacking decisions.

**Continuous improvement:** first boot is cold; boot access patterns are recorded; next GC repack co-locates those chunks; subsequent boots are faster. The feedback loop strengthens with scale. This is novel in production block storage — most S3-backed systems are write-once and never reorganise for locality.

## Empirical Findings

Measured using `palimpsest` — a Rust tool purpose-built to explore these concepts against real Ubuntu images.

### Demand-fetch: how much of an image is actually read?

Ubuntu 22.04 minimal cloud image (2.1GB root partition, 68,512 × 32KB chunks):

| Stage | Chunks read | Data | % of image |
|---|---|---|---|
| Full systemd boot to login prompt | 4,159 | 130 MB | 6.1% |
| + all shared libraries | 923 | 29 MB | 7.6% cumulative |
| + all of /usr/share | 4,244 | 133 MB | 13.8% cumulative |
| + all executables | 1,289 | 40 MB | 15.7% cumulative |

**93.9% of the image is never read during a full boot.** Even exhaustive use of the system touches only ~16% of the raw image (including unallocated space; ~35% of actual filesystem data).

### Dedup: chunk overlap between image versions

File-content-aware chunking (32KB chunks, per-file boundaries):

| Comparison | Exact chunk overlap |
|---|---|
| 22.04 point releases (14 months apart) | 70% |
| 22.04 vs 24.04 | 6–12% |
| Raw block-level (any comparison) | ~1% |

File-content-aware chunking is essential. Raw block-level dedup across image versions is nearly useless because file content does not align to fixed block offsets consistently.

### Delta compression: marginal S3 cost

| Scenario | Exact dedup | Delta benefit | Marginal fetch |
|---|---|---|---|
| 22.04 point release | 67% exact | 56% of remainder | ~43MB of ~700MB (~94% saving) |
| 22.04 vs 24.04 | 19% exact | 13% of remainder | ~95MB of ~700MB (~86% saving) |

The 22.04 vs 24.04 saving (86%) is almost entirely from compression — delta contributes little. For point releases, delta compression does the heavy lifting.

In production, the relevant comparison is always point-release: continuous deployment means each update is a small delta from the previous. The system always operates in the point-release regime, never the major-version regime.

### Manifest size

Ubuntu 22.04 (~700MB of file data, 32KB chunks): 51,247 entries, ~5MB TSV / ~2MB binary. Well within "a few MB" as expected.

## Open Questions

- **Chunk size:** 32KB proposed but tunable. Smaller = better dedup granularity, larger index. Larger = better compression, coarser dedup.
- **Entropy threshold:** 7.0 bits used in experiments. Optimal value depends on workload mix.
- **Write log format:** not yet designed. Affects recovery, promotion to segments, snapshot consistency.
- **Chunk index implementation:** sled, rocksdb, or custom. Needs random reads and range scans.
- **Shared chunk index:** per-host or shared service? DynamoDB, S3-backed, or dedicated process?
- **Write log → hash transition point:** hash on write (lowest dedup latency), hash on promotion to segment (preferred), or hash at S3 upload (simplest).
- **Delta source selection:** how to find a good reference chunk at upload time efficiently. TLSH or MinHash over a per-image-family index.
- **Namespace granularity:** binary global/non-global may not be sufficient for multi-tenancy.
- **Boot hint persistence:** where are hint sets stored, how are they distributed across hosts?
- **Empirical validation of repacking benefit:** measure segment fetch count before and after access-pattern-driven repacking.
- **ublk integration:** Linux-only, io_uring-based. NBD kept for development and macOS.
