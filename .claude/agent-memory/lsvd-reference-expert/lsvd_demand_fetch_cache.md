---
name: LSVD Demand-Fetch and Cache Implementation
description: How LSVD handles partial segment fetching, caching, and the read path for demand-loaded data
type: reference
---

## Overview

LSVD implements a **two-tier cache hierarchy** for demand-fetching partial segments from S3:
1. **RangeCache** — mmap'd local file cache storing 1MB chunks (tunable), with LRU eviction
2. **ExtentCache** — (optional) BoltDB in-memory extent cache for whole extents
3. **Segment handle cache** — LRU of 256 open `SegmentReader` objects (local files or S3 connections)

Importantly: **there is no special "partially present" format** on disk. The cache stores raw chunk data.

## RangeCache: Chunk-Based Disk Cache

**File**: `extent_reader.go`, `range_cache.go`

### Structure and Setup

```go
// From extent_reader.go (line 37-45)
rc, err := NewRangeCache(RangeCacheOptions{
    Path:      path,              // Local cache file (e.g., "readcache")
    ChunkSize: 1024 * 1024,        // 1MB chunks (standard)
    MaxSize:   1024 * 1024 * 1024, // 1GB total cache
    Fetch:     er.fetchData,       // Callback to fetch missing chunks
})
```

### Cache File Format

- **Single flat file**, mmap'd at initialization (unix.Mmap)
- **Writes are sequential** until the cache fills (line 229-245 in range_cache.go)
- **When full**: LRU eviction — oldest chunk is overwritten at its old position
- **No metadata**: pure raw chunk data, indexed by `(SegmentId, ChunkNumber)` in an in-memory LRU

### Chunk Lookup and Fetch

**Key entry point**: `RangeCache.ReadAt(ctx, seg, buf, offset)`

1. **Determine chunk range**: map byte offset to chunk numbers
   - `firstChunk = offset / chunk_size`
   - `lastChunk = (offset + len(buf) - 1) / chunk_size`

2. **Per-chunk lookup** (line 104 in range_cache.go):
   - Call `memChunk(seg, chunkNumber)` → checks LRU for `(seg, chunkNumber)` key
   - If hit: return pointer to mmap'd region
   - If miss: call `fetch(ctx, seg, chunkData, chunkNumber * chunk_size)`

3. **On cache miss**:
   - `fetch` callback is triggered (line 109): calls `er.fetchData(ctx, seg, chunkData, chunk_offset)`
   - `fetchData` opens the segment (local file or S3 via `SegmentAccess`) and reads bytes
   - Chunk is then written to cache file via `saveChunk` (line 114)
   - `saveChunk` either appends to file or overwrites evicted chunk

### No Persistent State

The RangeCache file is **not persisted across restarts**. Each volume startup recreates the cache file.

## ExtentCache: Optional Whole-Extent Cache

**File**: `extent_cache.go`

### Structure

```go
type ExtentCache struct {
    log    hclog.Logger
    db     *bbolt.DB           // BoltDB backing store
    inUse  *lru.Cache[string, lruEntry]  // In-memory LRU
    blocks int                  // Total blocks cached
}

type lruEntry struct {
    seg SegmentId
    off uint32
    ext Extent
    data []byte  // Cached data (or nil if on disk)
}
```

- Stores **entire extents** (not chunks) keyed by `(SegmentId, Offset, Extent)`
- Max capacity: 500,000 blocks (tunable)
- Backing store: BoltDB with bucket `extents`
- NoSync/NoFreelistSync enabled for performance

### When Used

The reference implementation code shows ExtentCache commented out (extent_cache.go line 131-136):
```go
// dup := slices.Clone(data)
// e.blocks += int(ext.Blocks)
// e.inUse.Add(string(key), lruEntry{seg, off, ext, dup})
// return nil
```

This suggests ExtentCache was **experimental and not actively used** in the primary read path.

## Segment Handle Cache

**File**: `extent_reader.go` (line 22-25)

```go
openSegments *lru.Cache[SegmentId, SegmentReader]
// Capacity: 256 handles
// Eviction: closes the SegmentReader on removal
```

- **Per-segment LRU** of open handles
- When a segment is needed, the handle is reused across multiple chunk reads
- For S3: the handle is an `S3ObjectReader` that stays open and issues per-chunk byte-range GETs
- For local storage: the handle is a `LocalFile` that stays open

## The Read Path: fetchData

**File**: `extent_reader.go` (line 59-83)

```go
func (d *ExtentReader) fetchData(ctx context.Context, seg SegmentId, data []byte, off int64) error {
    // 1. Look up or open the segment
    ci, ok := d.openSegments.Get(seg)
    if !ok {
        lf, err := d.sa.OpenSegment(ctx, seg)  // Local file or S3 handle
        if err != nil {
            return err
        }
        ci = lf
        d.openSegments.Add(seg, ci)
    }

    // 2. Read from the open segment at the given offset
    _, err := ci.ReadAt(data, off)
    return err
}
```

### For S3 Segments

`S3ObjectReader.ReadAt` issues a **byte-range GET request** (line 59-85 in s3.go):

```go
func (s *S3ObjectReader) ReadAt(dest []byte, off int64) (int, error) {
    rng := fmt.Sprintf("bytes=%d-%d", off, int(off)+len(dest)-1)
    r, err := s.sc.GetObject(s.ctx, &s3.GetObjectInput{
        Bucket: &s.buk,
        Key:    &s.key,
        Range:  &rng,
    })
    // ... read response body into dest
}
```

Each chunk read becomes **one HTTP GET with Range header**, never downloading the whole segment.

## Full Read Path: Extent to Disk

**File**: `disk.go` (line 266-405)

When user reads an LBA range:

1. **Resolve LBA → PartialExtent** (line 311):
   - Look up which segments hold this LBA range from LBA map
   - Returns `PartialExtent` with `(Segment, Offset, Size, Compression flags)`

2. **Fetch extent** (line 484):
   - Call `er.fetchExtent(ctx, pe, ...)` in `extent_reader.go`
   - For **uncompressed extents**: use `rangeCache.CachePositions()` to get file positions (one per chunk)
   - Return an array of `CachePosition{ fd, offset, size }` pointing into the mmap'd cache file
   - For **compressed extents**:
     - `rangeCache.ReadAt()` to fetch chunk(s) into memory
     - Decompress with lz4
     - Return decompressed data

3. **Fast path** (line 326-337):
   - If single uncompressed extent found in cache with full coverage: return `CachePosition` directly
   - Caller reads from cache file at that offset

4. **Slow path** (line 489-520):
   - If extent spans multiple cache chunks: fetch all chunks, assemble into buffer
   - For compressed: decompress the assembled buffer
   - Copy to destination buffer

## Cache Presence Semantics

**There is NO explicit "partially present" marker**. Instead:

- **If extent is needed but not in cache**: `RangeCache.ReadAt` triggers `fetch()` callback on-demand
- **If chunk is on disk**: mmap offset points to valid data
- **If chunk was evicted**: next read fetches it again from S3 (or local storage)
- **Compression is transparent**: cache stores compressed bytes; extent reader decompresses as needed

## Key Observations for Elide

1. **No "partial presence" encoding**: LSVD cache is purely LRU + fetching. No need to track "which bytes are present."

2. **Chunk granularity is fixed at 1MB**: This is tunable but baked into the RangeCache at initialization.

3. **S3 fetch is per-chunk, not per-extent**: If an extent spans 2 chunks and only 1 is cached, the read fetches the missing chunk via `bytes=...` GET.

4. **Compressed data is cached compressed**: The cache stores whatever came from S3 (compressed or not). Decompression happens in memory after fetch.

5. **Two separate caches**:
   - RangeCache (chunk-level, persistent on disk for session lifetime)
   - ExtentCache (extent-level, optional/unused in practice)
   - Both are **session-scoped**, not persistent across restarts

6. **Handle pooling avoids repeated opens**: The `openSegments` LRU keeps S3 connections alive, avoiding connection setup overhead per chunk fetch.

7. **Uncompressed fast path**: If extent is uncompressed and fully cached in one chunk, caller gets an mmap pointer directly, zero-copy read.

8. **Compressed requires materialization**: Compressed extents must be read into buffers, decompressed, then copied to user buffer. No zero-copy path.

**References**:
- `refs/lsvd/extent_reader.go`: ExtentReader, fetchData, fetchExtent
- `refs/lsvd/range_cache.go`: RangeCache, chunk-level caching
- `refs/lsvd/s3.go`: S3ObjectReader, byte-range GET implementation
- `refs/lsvd/disk.go`: ReadExtentInto, readOneExtent, readPartialExtent (full read path)
