---
name: LSVD LBA Map Design and Implementation
description: Complete understanding of the LSVD LBA map structure, persistence format, rebuild process, and read/write paths
type: reference
---

## In-Memory Structure: ExtentMap

**Location**: `extent_map.go` (lines 108–129)

The LBA map is stored as an `ExtentMap`, a thread-safe wrapper around a red-black tree:

```go
type ExtentMap struct {
	mu sync.Mutex
	m  *treemap.TreeMap[LBA, compactPE]

	// Segment ID tracking for compression
	segmentsMu    sync.Mutex
	segmentByDesc map[segLocations]uint32  // (seg, disk) → index
	segmentByIdx  map[uint32]segLocations  // index → (seg, disk)

	// Reusable scratch buffers for range operations
	affected   []PartialExtent
	addScratch []compactPE
	delScratch []LBA
}
```

- **Key**: `LBA` (uint64, max 48 bits for actual LBA, see `extent.go:11`)
- **Value**: `compactPE` (compact extent representation, see below)
- **Backing**: Red-black tree from `pkg/treemap` — provides O(log N) Floor, LowerBound, Set, Del operations

## Compact Extent Representation (compactPE)

**Location**: `extent_map.go` (lines 25–85)

A space-efficient in-memory representation of a physical extent and its live (valid) portion:

```go
type compactPE struct {
	physX         uint64  // phys LBA (48 bits) + phys blocks (16 bits)
	liveLBADiff   uint16  // offset of live LBA from phys LBA
	liveBlockDiff uint16  // reduction in block count (phys - live)

	segIdx   uint32  // index into ExtentMap's segment table
	byteSize uint32  // size of compressed data (0 if empty/uncompressed)
	offset   uint32  // byte offset in segment file
	rawSize  uint32  // original uncompressed size (0 if uncompressed)
}
```

**Bit packing** (lines 20–23):
- `physLBAShift = 16`: phys LBA stored in high 48 bits
- `physBlockMask = (1 << 16) - 1`: phys blocks in low 16 bits
- Example: `physX = (lba << 16) | blocks`

**Why compact**: Stores both physical extent and live (valid data) region, handles garbage collection aftermath. When data is overwritten and becomes "dead", the live region shrinks while the physical extent stays the same (needed for on-disk reconstruction).

## Persistence: head.map Format

**Location**: `rebuild.go` (lines 136–166, 266–286)

The LBA map is serialized to `head.map` (in the volume's working directory) using:

1. **Header** (CBOR-encoded): `lbaCacheMapHeader`
   ```go
   type lbaCacheMapHeader struct {
       CreatedAt    time.Time               // Timestamp
       SegmentsHash string                  // SHA-256 of all segment IDs
       Stats        map[string]segmentStats // Per-segment usage stats
   }

   type segmentStats struct {
       Size uint64  // Total blocks in segment
       Used uint64  // Live blocks in segment
   }
   ```

2. **Entries** (CBOR-encoded): One `PartialExtent` per tree entry
   ```go
   type PartialExtent struct {
       Live           Extent            // Live (valid) portion
       ExtentLocation struct {
           ExtentHeader  // LBA, blocks, size, offset, rawSize
           Segment  SegmentId
           Disk     uint16
       }
   }
   ```

**Format choice**: CBOR (Concise Binary Object Representation) for compact, self-describing serialization

**Validation on load** (lines 183–253):
- Recalculate SHA-256 of current segment list
- Compare against stored `SegmentsHash`
- If mismatch: discard cached map and rebuild from segments
- Rationale: Segments may have been added/deleted; cache must stay consistent

## Building the LBA Map: From Segments

**Rebuild Path** (lines 19–96, `rebuild.go`):

```
NewDisk → loadLBAMap → (if invalid or missing)
    ↓
    rebuildFromSegments → (for each segment):
        ↓
        rebuildFromSegment:
          1. Open segment file
          2. Read SegmentHeader (extent count, data offset)
          3. For each ExtentHeader:
             - Call lba2pba.Update() to insert/merge
             - Track affected extents for usage stats
             - Update Segments tracking (s.SetSegment)
```

**Key detail** (lines 79):
```go
eh.Offset += hdr.DataOffset  // Make offset absolute within segment
```

Each extent header's offset is relative; it's adjusted to be absolute before insertion.

## Extent Map Operations: Update (Merge)

**Location**: `extent_map.go` (lines 253–464)

The critical `Update()` method inserts a new extent into the tree and handles overlaps — crucial during rebuild and writes:

### Algorithm
1. **Floor search** (line 283): Find highest entry with LBA < new range start
2. **Handle lower overlaps** (lines 282–372):
   - If existing entry overlaps, compute coverage relationship
   - `CoverExact`: no change, mark as affected
   - `CoverSuperRange`: new range is a hole; split existing into prefix and suffix
   - `CoverPartly`: shrink existing or split it
3. **LowerBound search** (lines 374–427): Find entries ≥ new range start
4. **Handle upper overlaps**:
   - Delete completely covered entries (mark as affected)
   - Shrink partially covered entries
5. **Insert final entry** (line 449): `e.set(PartialExtent)` adds the new extent to tree

### Return value: `affected` extents
These are the old extents that got overwritten — passed to `Segments.UpdateUsage()` to decrement their live counts.

## Lookup for Reads: Resolve

**Location**: `extent_map.go` (lines 583–653)

The read path uses `Resolve(rng Extent)` to find all extents covering a requested range:

```go
func (e *ExtentMap) Resolve(log logger.Logger, rng Extent, ret []PartialExtent) ([]PartialExtent, error)
```

Returns all overlapping `PartialExtent` objects:
- Floor search to catch entries starting before requested range
- LowerBound search for entries starting within/after range
- Uses `Cover()` enum to classify overlaps

**Used by**: `ReadExtentInto()` in `disk.go` (line 311)
→ For each partial extent, fetch from segment and copy into result buffer

## Read Path: Full Flow

**Location**: `disk.go` (lines 246–405)

```
ReadExtentInto(requested range)
  ├─ fillFromWriteCache() → unflushed segment data
  ├─ (if unflushed data doesn't cover request)
  ├─ for each uncovered hole:
  │   └─ lba2pba.Resolve() → PartialExtent[]
  │   └─ readPartialExtent() → fetch from segment via extentReader
  └─ Copy fetched data into destination
```

**Fast path** (lines 326–338): Single uncompressed extent, direct read
**General path** (lines 387–400): Batch reads across segments

## Write Path

**Location**: `disk.go` (lines 681–734)

```
WriteExtent(data)
  ├─ curOC.WriteExtent() → write to current segment creator
  ├─ checkFlush() → if segment > 32MB, close and start new one
  └─ (LBA map updated when segment closes, see close_segment.go)
```

The LBA map is **NOT** updated directly on every write. Instead:
1. Data goes to in-memory write cache (`SegmentCreator`)
2. When segment closes/flushes → entries are serialized
3. On next open → `restoreWriteCache()` loads unflushed segments
4. `ReadExtentInto()` checks write cache before hitting LBA map

## Segment Statistics Tracking

**Location**: `segments.go`

`Segments` struct maintains per-segment stats:
- `Total` (Size): all blocks ever written
- `Used`: live blocks (unused after overwrites)

When an extent is overwritten (→ affected list), `UpdateUsage()` decrements the old segment's used count. This drives GC heuristics.

## Recovery/Initialization Sequence

**In `NewDisk()`** (lines 68–189, `disk.go`):

```
1. restoreWriteCache() → load unflushed segments as SegmentCreators
2. loadLBAMap() → try to load cached head.map
   ├─ If valid (hash matches): reuse it, populate Segments stats
   └─ If invalid (missing, hash mismatch): return false
3. If loadLBAMap returned false:
   └─ rebuildFromSegments() → scan all segment files, rebuild tree
4. controller.Run() → start background GC/maintenance
```

## Key Design Decisions

1. **Compact in-memory format** (compactPE): 40 bytes vs. much larger full extent + metadata
2. **Red-black tree** (O(log N) lookups): Trade complexity for fast range queries
3. **CBOR serialization**: Human-inspectable (not binary-only), schema-evolution friendly
4. **Hash-based validation**: Catch segment set changes without checksumming entire tree
5. **Scratch buffers**: Reused across calls to avoid allocation churn on hot paths
6. **Segment indexing**: Compress segment references from 16+ bytes (SegmentId) to 32-bit index

## Integration with Garbage Collection

The affected list from `Update()` feeds `Segments.UpdateUsage()`, which decrements segment live counts. Low-density segments become GC candidates (see `gc.go`).

## Limits and Trade-offs

- LBA is uint64 but effectively 48 bits (MaxLBA in extent.go:11)
- Block count is uint32 (up to ~2TB per extent at 4KB blocks)
- Segment indices are uint32 (up to ~4B segments, practically unlimited)
- Live/phys block diffs are uint16 (max 64KB block difference) — enforced with panics
