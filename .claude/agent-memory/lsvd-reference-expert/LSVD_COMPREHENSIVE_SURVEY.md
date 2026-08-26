---
name: LSVD Comprehensive Survey
description: Complete architectural overview of the lab47/lsvd reference implementation covering all major components, design decisions, and algorithms
type: reference
---

# LSVD Reference Implementation: Comprehensive Survey

## 1. Overall Architecture

LSVD is a **log-structured virtual disk** system that translates block device operations into efficiently-stored segments in object storage (S3). The reference implementation is written in Go and exposes a block device via NBD (Network Block Device).

**Core Philosophy:**
- Write-once segments: data is never overwritten, only new segments are created
- Log-structured: all writes are sequenced and append-only at the WAL level
- Dual-tiered storage: local cache (segments/, writecache) + remote S3 (segments/)
- Copy-on-GC: reclaiming space requires copying live extents to a new segment

**Key Abstractions:**
- **Extent**: (LBA, block_count) tuple representing a contiguous range of blocks
- **Segment**: a unit of write batching; contains multiple extents plus a fixed-size header
- **LBA Map**: in-memory red-black tree mapping logical block addresses to extents
- **SegmentAccess**: pluggable interface for storage backends (local files, S3)

---

## 2. Write Path

**Trigger:** VM writes via NBD interface → `nbdWrapper::WriteAt()`

**Flow:**

1. **Buffering** (in `SegmentCreator.builder`):
   - Writes accumulate in the current `SegmentCreator`'s in-memory buffer
   - Each write extent is recorded in `builder.extents` (array of `ExtentHeader`)
   - Data is compressed (LZ4) if entropy ≤ 7.0 bits AND compression ratio > 1.5×
   - Compression is per-extent, not segment-level

2. **WAL Persistence** (in `SegmentBuilder.writeLog()`):
   - Each extent is written to `writecache.<ULID>` file on disk before ack
   - Format: varint-encoded `ExtentHeader` + raw/compressed data
   - The WAL file is readable and can be recovered if the process crashes

3. **In-Memory Index Update** (in `SegmentCreator.WriteExtent()`):
   - After WAL write, update the local `ExtentMap` (embedded in `SegmentCreator`)
   - Maps LBA → (offset, size, compression flags) for quick in-memory lookups
   - This allows subsequent reads from the write cache before flushing to S3

4. **Flush Trigger** (in `Disk.checkFlush()`):
   - When `builder.offset` (cumulative body size) exceeds `FlushThreshHold` (32 MB)
   - Flush is **asynchronous**: initiated via `closeSegmentAsync()`, runs in controller
   - New WAL is created immediately; old one is promoted to `pending/` in background

5. **Segment Closure** (in `Controller.closeSegment()`):
   - Build segment header (extent count, data offset)
   - Write header + extent index + body to a temporary `.complete` file
   - Upload to S3 (or write locally) via `sa.UploadSegment()`
   - Update segment metadata (add to `segments/<ULID>` list in volume)
   - Delete the temporary `.complete` file
   - Mark segment as created in the live `Segments` tracker with block counts

6. **LBA Map Update**:
   - After upload succeeds, call `lba2pba.UpdateBatch()` with all extents from the new segment
   - This updates the red-black tree with the segment ID and offset information
   - Affected extents (those that were overwritten) have their usage counts decremented

**Durability Guarantee:**
- Write is durable immediately after the WAL is flushed to disk
- S3 upload is asynchronous and not on the critical path
- Crash recovery: restore from WAL file(s) at startup

---

## 3. Read Path

**Trigger:** VM reads via NBD → `nbdWrapper::ReadAt()` → `Disk.ReadExtentInto()`

**Flow:**

1. **Write Cache Check** (in `fillFromWriteCache()`):
   - If a write cache (`curOC`) exists, call its `FillExtent()`
   - The write cache's embedded `ExtentMap` is checked for matching LBAs
   - If found, data is read from `writecache.<ULID>` file
   - Compression is handled on read: decompress LZ4 if needed

2. **Previous Write Cache Check** (in `fillingFromPrevWriteCache()`):
   - Before moving to committed segments, check `prevCache` (recently-closed WAL)
   - Holds the last segment creator; useful for reads immediately after flush but before S3 upload

3. **Committed Segment Lookup** (in `lba2pba.Resolve()`):
   - Query the main LBA map (red-black tree of `compactPE` objects)
   - For a requested range, find all overlapping extents
   - Returns array of `PartialExtent` (extent + segment location + offset)
   - Returns compressed, pre-decompressed, or empty extents as appropriate

4. **Reading from Segments**:
   - **Fast Path** (single uncompressed extent): directly return a `CachePosition` struct pointing to the segment file
   - **General Path**: for each `PartialExtent`:
     - Open the segment file via `ExtentReader` (maintains LRU cache of open handles)
     - Use `RangeCache` to fetch 1 MB chunks on-demand from local segments
     - For S3-backed segments: `RangeCache.fetch()` issues byte-range GET
     - Cache the chunk in mmap'd region; LRU evicts oldest when full

5. **Decompression**:
   - If `FLAG_COMPRESSED` is set, decompress the full extent with LZ4
   - Decompression is per-extent, even for partial reads
   - Decompressed data is not cached; next read decompresses again

6. **Return Data**:
   - Copy relevant byte ranges from cache/segments to the output buffer
   - Range clamping handles the case where an extent only partially covers the requested range

**Cache Hierarchy:**
1. Write cache (in-memory + WAL file)
2. Previous write cache (recently-closed WAL)
3. Local segment file (pending/ or segments/)
4. RangeCache (mmap'd, 1 MB chunks, LRU, 1 GB default size)
5. S3 (byte-range GET, reconstructs from delta if available)

---

## 4. LBA Map Design

The LBA map is the **critical in-memory data structure** for translating reads.

**Data Structure:**
- `ExtentMap`: wraps a **red-black tree** (`TreeMap[LBA, compactPE]`)
- Key: starting LBA (uint64)
- Value: **compactPE** — a compact representation of (physical extent, live range, segment index, offset, size)

**CompactPE Layout:**
```
physX           uint64  → encodes both physical LBA and block count (48-bit LBA + 16-bit block count)
liveLBADiff     uint16  → offset from physical LBA to start of live range
liveBlockDiff   uint16  → difference between physical and live block counts
segIdx          uint32  → index into segment descriptor table
byteSize        uint32  → stored size on disk (compressed or uncompressed)
offset          uint32  → offset within segment body where data starts
rawSize         uint32  → original size before compression (0 if uncompressed)
```

This compact representation saves memory: each entry is ~32 bytes vs. 100+ bytes for the full `PartialExtent`.

**Segment Index Table:**
- `segmentByDesc[segLocations] → uint32`: map from (segment ID, disk ID) to index
- `segmentByIdx[uint32] → segLocations`: reverse map from index to (segment ID, disk ID)
- Allows multiple volumes (via read-only lower layers) to be indexed simultaneously

**Update Algorithm** (in `update()`):
1. For a write to LBA range `R`:
   - Iterate backwards from `Floor(R.LBA)` to handle extents that start before `R`
   - For each overlapping extent `E`:
     - If `R` covers `E` completely: delete `E`
     - If `R` covers `E` partially (hole): split `E` into prefix + live + suffix
     - If `R` is contained in `E`: keep the parts of `E` before and after `R`
   - Add the new extent to the tree
   - Return affected extents (those that were overwritten) for usage tracking

**Rebuild Algorithm**:
- On startup, if no cached LBA map exists, rebuild from all segment files
- For each segment on disk, scan its header + extent table
- Insert each extent into the tree, calling `update()` for each one
- This populates the LBA map from scratch in ~seconds for typical volumes

**Cache:**
- After rebuild, save the LBA map as CBOR-encoded `head.map` file
- On next startup, deserialize from cache (much faster)
- Cache is invalidated if segment list changes (checked via hash)

---

## 5. Garbage Collection

GC reclaims space by copying live extents from sparse segments to new dense segments.

**Trigger Heuristics:**

1. **Density-based** (in `Controller.startGC()`):
   - Auto-trigger if `usage() < GCDensityThreshold` (70%) AND `totalBytes > GCTotalThreshold`
   - After each segment flush, check density and queue GC if needed
   - Manual trigger via `GCOnce()` API

2. **Small-segment Packing** (in `handleLongIdle()`, runs every 1 minute):
   - Find all segments with ≤ 200 blocks used
   - If 2+ such segments exist, pack them together
   - Limit total packed blocks to 20,000 to bound GC segment size

3. **Least-Dense Segment Selection**:
   - Iterate all live segments, find the one with lowest `usage = used / size`
   - Pick that segment for GC

**GC Algorithm** (in `CopyIterator`):

1. **Gather Extents** (in `gatherExtents()`):
   - Scan the LBA map for all extents belonging to the target segment
   - Build list of `gcExtent` structs containing the live ranges
   - Record expected live blocks for validation

2. **Copy Phase** (in `ProcessFromExtents()`):
   - For each live extent in the source segment:
     - Read the compressed extent data from the source segment file
     - Write to a new `SegmentCreator` (which handles compression)
     - Collect the new `ExtentHeader` from each write
     - For zero-block extents: directly write a zero record

3. **Atomic LBA Map Patch** (in `updateDisk()`):
   - After new segment is flushed to S3, hold a lock and patch the LBA map
   - For each copied extent, update the `compactPE` to point to the new segment
   - Verify that the extent hasn't been overwritten (recycle check)
   - After patching, mark the source segment as deleted

4. **Cleanup** (in `Close()`):
   - Remove the source segment from all volumes' segment lists
   - Delete the source segment file
   - Check other volumes to ensure the source segment is no longer referenced

**Write Amplification:**
- GC can write an extent multiple times:
  1. Original write (DATA record in WAL)
  2. Flush to segment (stored in pending/)
  3. S3 upload
  4. GC copy (new segment)
  5. S3 upload of GC output
- Reference extents (REF records) avoid this via dedup (see below)

---

## 6. Deduplication

The reference implementation has **basic block-level deduplication via extent index**, not true content-addressed storage.

**Checksum Calculation** (in `checksum.go`):
- Per-extent SHA256 hash (computed once at write time)
- Stored in the extent header (`ExtentHeader.RawSize` field? No—not actually stored in the current impl)

**Dedup Lookup:**
- Not fully implemented in the reference implementation
- Placeholder infrastructure exists (e.g., `checksum.go` with `rangeSum()`)
- The paper describes dedup via extent-level hashing and a global extent index

**Note on Elide vs. LSVD:**
- Elide's architecture includes a full extent index (BLAKE3 hashes of all extents)
- LSVD reference impl focuses on the segment/WAL structure
- Dedup is listed as a future feature in the reference code

---

## 7. Snapshots

The reference implementation **does not currently support snapshots** in the code. The LSVD paper describes snapshots as:

- A snapshot is a **marker in the segment log** (a ULID that represents a point in time)
- All extents created before the snapshot are immutable
- Forking creates a new write stream starting after the snapshot marker
- The original volume can continue being written after the fork point
- Both volumes have overlapping ancestor segments

**Design Implications for Snapshots:**
- No copy-on-write needed; segments are immutable after creation
- Fork is just a new write stream + new LBA map
- Snapshot ULIDs sort into the segment sequence, so branch points are unambiguous
- Ancestor traversal follows snapshot markers in reverse

---

## 8. Coordinator Role

The reference implementation has a **background Controller** (not a separate process), which handles:

1. **Segment Closure** (in `closeSegment()`):
   - Async flush of segments to S3 when they exceed 32 MB
   - Happens in a background goroutine, not blocking writes

2. **LBA Map Patching** (after GC):
   - GC runs synchronously but patches the in-memory map atomically
   - No distributed coordination needed

3. **Segment Cleanup**:
   - Remove deleted segment files from disk
   - Update the segments list metadata

4. **GC Triggering**:
   - Density-based heuristic (every minute, or on-demand)
   - Queue GC events and process them serially

**Key Design: Serial Event Loop**
- All control operations (close, GC, cleanup) go through a single event queue
- Events are processed serially to avoid race conditions
- Write path is independent; reads and writes can proceed while GC runs
- GC holds the LBA map lock only during the patch phase (very brief)

---

## 9. Segment Format

**On-Disk Layout:**

```
[SEGMENT HEADER (8 bytes)]
  - ExtentCount  uint32 (big-endian)
  - DataOffset   uint32 (big-endian)

[EXTENT INDEX (variable)]
  - For each of ExtentCount extents:
    - ExtentHeader (variable-length, varint-encoded):
      - LBA (varint)
      - Blocks (varint)
      - Size (varint, stored size)
      - Offset (varint, offset in body section)
      - RawSize (varint, original size; 0 if uncompressed)

[DATA SECTION (variable)]
  - Raw or compressed extent bodies, stored contiguously
  - Offset points into this section
```

**ExtentHeader Flags (implicit):**
- `Size == 0`: Empty extent (zero blocks, no data)
- `RawSize != 0`: Compressed extent (Size is compressed size, RawSize is original)
- `RawSize == 0`: Uncompressed extent (Size is the actual data size)

**Header Format:**
- Varint-encoded for space efficiency
- Allows segments to be arbitrarily large without fixed-size overhead

---

## 10. Range Cache (Demand Fetch Layer)

The `RangeCache` is the layer between the LBA map and segment files, implementing chunked caching for S3 reads.

**Design:**
- Chunk size: **1 MB (configurable)**
- Total cache size: **1 GB (configurable)**
- Backing: mmap'd file (not in-memory)
- Eviction: LRU by chunk key `(segment_id, chunk_offset)`

**Algorithm** (in `ReadAt()`):
1. Compute first and last chunk IDs for the requested range
2. For each chunk:
   - Check if it's in the LRU cache
   - If miss: call `fetch()` (async S3 GET or local read)
   - Copy relevant bytes from the chunk to the output buffer
3. Return total bytes read

**Fetch Callback:**
- `fetch(ctx, seg_id, buffer, offset)` reads chunk from segment
- For local segments: direct file read
- For S3 segments: byte-range GET with offset + chunk_size
- Chunk is written atomically; partial chunks are buffered separately

**Uncompressed Fast Path:**
- If segment contains uncompressed extent(s) that fully cover the range
- Return a `CachePosition` struct (file handle + offset + size)
- Caller can read directly from cache file without decompression

---

## 11. Features and Constraints

**Supported:**
- Block-level reads/writes via NBD
- LZ4 compression per-extent
- Basic WAL recovery
- Segment-level GC with copy-based reclamation
- S3 object storage integration
- Multi-layer (snapshot) read support via lower disks
- Fsync-based durability

**Not Fully Implemented:**
- Snapshots (infrastructure present, not used)
- Content-addressable dedup (placeholder code exists)
- Delta compression (no code)
- Extent-granular prefetch (chunks are fixed 1 MB)
- Eviction (RangeCache size is unbounded in practice)

**Constraints:**
- Single writer per volume (enforced by WAL lock)
- No encryption
- No compression algorithm choice (LZ4 only)
- No inline extents (<4KB)
- Block size fixed at 4 KB

---

## 12. Key Deviations Between Elide and LSVD

Based on Elide's documentation:

1. **ULID Assignment**: LSVD assigns segment ULIDs at flush time; Elide pre-assigns at WAL creation to enable crash recovery detection

2. **Compaction Output ULID**: LSVD uses `mint.next()`; Elide uses `max(inputs).increment()` to avoid overwriting newer data

3. **Dedup**: LSVD has placeholder code; Elide builds a full extent index with BLAKE3 hashes

4. **Compression Algorithms**: LSVD uses LZ4 everywhere; Elide proposes LZ4 (body) + zstd (deltas)

5. **Delta Compression**: Elide computes deltas at S3 upload time; LSVD stores full extents

6. **Fetch Unit**: LSVD's RangeCache uses 1 MB chunks; Elide can fetch individual extents (not yet implemented)

7. **Directory Layout**: LSVD has a flat `volumes/` structure; Elide uses named forks under `forks/` with ancestry tracking

8. **Signing**: LSVD has no cryptographic signing; Elide signs segments with Ed25519

---

## 13. Critical Implementation Notes

**Memory Efficiency:**
- `compactPE` is only 32 bytes; red-black tree nodes add ~40 bytes
- For 1M extents: ~70 MB in-memory LBA map (feasible)

**Lock Contention:**
- Reads acquire `ExtentMap.mu` briefly (only for tree lookup)
- Writes acquire the lock for the entire extent update (can be many tree modifications)
- GC patches only hold the lock during the atomic patch phase

**File Handle Caching:**
- `ExtentReader` maintains a single LRU cache of 256 open segments
- Eviction closes the file handle
- Cost: O(1) lookup per segment on cache hit

**Entropy Estimation:**
- Computed on each write via incremental hash
- Threshold 7.0 bits is taken from empirical tuning
- Used to decide whether compression is worth the CPU cost

**Crash Recovery:**
- WAL files are human-readable and can be manually inspected
- Rebuild from segments is always correct (slow but safe)
- Head.map cache is validated against segment list hash

---

## 14. Open Questions / Gaps

1. **No true dedup in reference impl**: checksums computed but not stored or indexed
2. **No snapshot management code**: snapshot markers would need volume-level orchestration
3. **No extent-granular fetch**: RangeCache always fetches 1 MB chunks, not individual extents
4. **No eviction policy**: RangeCache can grow unbounded
5. **No delta compression**: every extent is stored in full
6. **NBD-only frontend**: no ublk (Linux-only, io_uring) implementation
7. **Single-host only**: no coordination for multi-host deployments
8. **No per-extent prefetch hints**: no mechanism to optimize fetch order for sequential workloads

