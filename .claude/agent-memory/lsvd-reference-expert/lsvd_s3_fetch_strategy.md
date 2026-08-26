---
name: LSVD S3 Fetch Strategy
description: How LSVD loads volumes from S3 — demand-fetch by extent, never full segment download
type: reference
---

## LSVD S3 Read Path Strategy

**Never downloads entire segment files from S3.** Instead, issues byte-range `GetObject` requests for chunk-sized slices of segment bodies, fetching only the specific extent(s) needed plus spatial neighbors for locality.

### Fetch Unit: Chunks, Not Segments

- **Chunk size**: 1MB chunks (tunable, but standard in reference impl)
- **Chunk LRU cache**: 256 entries of open `SegmentReader` handles (either local file or live S3 connection)
- **Disk cache**: 1GB mmap'd local cache storing recently-fetched chunks with LRU eviction
- **Per-extent fetch**: a single read request for an LBA range is satisfied by:
  1. Looking up extent position in segment index (offset + length)
  2. Determining which 1MB chunk(s) contain the extent
  3. Issuing byte-range GET for that chunk (e.g. bytes 2MB-3MB of a 100MB segment)
  4. Extracting and decompressing the needed extent
  5. Caching the chunk locally for nearby extents

### Impact: Extreme Cold-Boot Efficiency

Empirical validation (from Elide findings):
- Full systemd boot reads ~130MB from a 2.1GB Ubuntu image
- This leaves **93.9% of segment data never fetched from S3**
- Demand-fetch at extent granularity prevents downloading the rest

### When Does S3 Fetch Happen?

LSVD assumes all segments live in S3. The reference implementation:
1. Loads the LBA map at startup (either from persisted `head.map` or by scanning segment indices)
2. For local segments: reads from local file
3. For S3 segments: reads via byte-range GET on first access (or never, if extent never read)

There is no pre-warming or eager bulk download — the entire S3 fetch strategy is on-demand.

### Layer Merging (Snapshots)

When a volume is a snapshot or fork:
1. LBA map is reconstructed by merging all ancestor segments' index sections (oldest ancestor first)
2. Extents are looked up in the extent index, which records which segment holds each hash
3. A miss in local/ancestor segments triggers an S3 fetch; the segment ID is already known, so it's a direct `GetObject` call

## Implications for Elide

Elide uses the same architecture (docs/architecture.md, "Demand-fetch is at extent granularity, not segment granularity").

Key differences from LSVD:
- **Manifest for cold start**: Elide optionally writes a manifest to S3 at snapshot time, allowing a cold-start volume to load the LBA map in one GET without scanning segment index sections
- **Sparse vs delta**: Elide uses sparse (block-level granularity) rather than delta compression, simplifying S3 reconstruction and GC
- **Local promotion first**: Elide separates local promotion (WAL → pending/) from S3 upload; segments are immediately available locally before S3 copy completes

But the core S3 fetch strategy is identical: **demand-fetch at extent granularity via byte-range GETs, chunk-cached locally, never downloading entire segments**.
