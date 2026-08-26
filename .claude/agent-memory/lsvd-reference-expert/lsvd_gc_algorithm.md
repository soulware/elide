---
name: lsvd_gc_algorithm
description: LSVD GC algorithm: segment selection, extent identification, copying, patching, deletion coordination
type: reference
---

# LSVD Garbage Collection (GC)

Reference impl: `refs/lsvd/gc.go`, `refs/lsvd/control.go`, `refs/lsvd/close_segment.go`, `refs/lsvd/segments.go`, `refs/lsvd/pack.go`

## Algorithm Overview

LSVD GC is a **copy-based**, **segment-level** algorithm. It does not compact individual extents in-place; instead, it reads a sparsely-populated segment, copies its live extents to a new segment, updates the LBA map, and deletes the source segment.

### Key Design Points

1. **Segments are the unit of GC, not extents.** GC works on whole segments; there is no sub-segment compaction.
2. **Segments track their own utilization.** Each segment stores `Size` (total allocated blocks) and `Used` (live block count). Dead extents are identified via the LBA map, not segment-internal metadata.
3. **No snapshots or lower-disk coordination.** The reference impl uses `lowers` (read-only lower disks) for versioning, but GC is safe because `removeSegmentIfPossible()` checks all volumes before deletion—a segment cannot be deleted if referenced by any volume (including lower disks).
4. **Async background controller orchestrates GC.** The `Controller` runs in a goroutine and processes GC events via an event queue.

---

## Identifying Dead Extents

**Location:** `extent_map.go` (in-memory map), segment `Used` field in `segments.go`.

Dead extents are not explicitly marked. Instead:

1. **The LBA map is the source of truth.** It maps `LBA → SegmentLocation + (PhysicalExtent, LiveExtent, offset, size, compression flag)`.
2. **For a given segment, GC collects all extents currently referencing it** by scanning the LBA map (red-black tree of `compactPE` entries indexed by LBA).
3. **Dead blocks are implicit: the difference between `Size` and `Used`.**
   - `Size` = total block count allocated when the segment was created (e.g., 100 blocks written).
   - `Used` = sum of live block counts from all extents in the LBA map referencing this segment.
   - Dead blocks = `Size - Used` (extents whose live ranges have been overwritten by later writes).

**Example from test:** `gc_test.go` lines 155–243
- Segment 1: 4 blocks written, then only 1 block remains live (overwrite at block 0, later segment touches it).
- After GC, the segment shrinks to 1 block; the "3 garbage blocks" are gone.

### UpdateUsage: Tracking Dead Blocks

When an extent is overwritten, `UpdateUsage()` (`segments.go:130`) decrements the `Used` count for the affected segment:

```go
seg.Used -= uint64(rng.Blocks)  // rng = the live extent of the overwritten region
```

This happens on every write that overlaps an existing extent in a different segment.

---

## Segment Selection for GC

Two strategies in `control.go`:

### 1. Density-Based Selection (StartGC Event)

**Location:** `control.go:304` (`startGC`), `segments.go:312` (`LeastDenseSegment`).

Triggered when:
- Data density drops below `GCDensityThreshold` (70%) AND total size exceeds `GCTotalThreshold` (1MB).
- Automatically after every segment close (lines 276–286 in `control.go`).

Selection process:
1. `PruneDeadSegments()` (`segments.go:223`): First pass—any segment with `Used == 0` is marked deleted immediately (no GC needed, just cleanup).
2. `LeastDenseSegment()`: Picks the segment with the lowest density (`Used / Size`) among remaining live segments.
3. Skip if density is already above threshold.

Density formula: `100 * (Used / Size)` as a percentage.

### 2. Small Segment Packing (SweepSmallSegments Event)

**Location:** `control.go:157` (`sweepSmallSegments`), `segments.go:194` (`FindSmallSegments`).

Triggered:
- Every 5 minutes of idle time (background tick, line 108).
- Explicitly via admin command.

Selection process:
1. `FindSmallSegments(cutoff=200, max=20_000)`: Collects segments with `Used <= 200` blocks until cumulative used bytes exceeds 20K.
2. Reuses `CopyIterator` to pack multiple small segments into one new segment in a single pass.

### 3. Dead Segment Removal (CleanupSegments Event)

**Location:** `close_segment.go:101` (`cleanupDeletedSegments`), `gc.go:348` (`removeSegmentIfPossible`).

Triggered after every GC cycle and segment close.

Cleanup process:
1. `FindDeleted()` (`segments.go:260`): Returns list of segments with `deleted = true`.
2. For each deleted segment:
   - `RemoveSegmentFromVolume()`: Remove from volume's segment list (stored in `volumes/<vol>/segments`).
   - `removeSegmentIfPossible()`: Check if any other volume still references it. If not, delete the segment file.

**Snapshot/Lower-disk coordination:** `removeSegmentIfPossible()` lists all volumes, then checks if the segment appears in any volume's segment list. If yes, abort deletion. This prevents deleting segments that lower disks (read-only ancestor snapshots) depend on.

---

## Extent Copying and Repacking

**Location:** `gc.go` (`CopyIterator`), `pack.go` (multi-segment packing).

### CopyIterator: Single-Segment GC

```go
type CopyIterator struct {
    seg         SegmentId         // source segment to GC
    newSegment  SegmentId         // newly allocated segment ID
    builder     *SegmentBuilder   // writes to new segment
    extents     []gcExtent        // all extents from source segment
    processedExtents []gcExtent   // extents we successfully copied
    results     []ExtentHeader    // header info for copied extents
}
```

**Phase 1: Gather Extents** (`gatherExtents`, lines 67–90)
1. Query segment statistics: `SegmentBlocks(seg)` → `(total, used)`.
2. Scan LBA map for all extents with `segIdx == target_segment_index`.
3. Collect into `extents` slice.

**Phase 2: Copy Live Ranges** (`ProcessFromExtents`, lines 138–183)
1. For each extent in the source segment:
   - If size is 0 (zero extent), call `builder.ZeroBlocks()` to write zeros.
   - Otherwise, fetch the extent data from the source segment (`fetchExtent`).
   - **Extract only the live range** via `SubRange()`: if the physical extent is 4 blocks but only 1 block is live, copy only 1 block.
   - Write to new segment via `builder.WriteExtent()`.
   - Record the new extent header in `results`.

**Phase 3: Update LBA Map and Finalize** (`updateDisk`, lines 195–249)
1. Flush new segment to disk.
2. Lock the LBA map and patch each `compactPE` entry:
   - Verify the entry hasn't been recycled (check `segIdx` and `Live()` fields).
   - Update the entry's segment location, offset, and size from the new header.
3. Mark source segment as deleted (`SetDeleted()`).
4. Only delete the source segment from disk if patching succeeded (`!errorPatching`).

**Error handling:** If any extent's live range changes during patching (concurrent overwrite), the patch is skipped and a warning is logged—the extent will be GC'd again later.

### Packer: Multi-Segment Packing

**Location:** `pack.go`.

When multiple small segments are selected (e.g., `SweepSmallSegments`):
1. Single `CopyIterator` reused across multiple segments.
2. Loop: `ci.Reset(ctx, segment)` → `ProcessFromExtents()` → loop next segment.
3. Single `ci.Close()` at the end flushes the combined result and patches all `compactPE` entries from all source segments.

Result: N small segments → 1 large segment, single LBA map update.

---

## Compression and Decompression

**Extent reading during GC** (`fetchExtent`, lines 92–136):
1. Read raw bytes from source segment.
2. Check compression flag in `ExtentLocation.Flags()`:
   - `Uncompressed = 0`: use raw data.
   - `Compressed = 1`: decompress via `lz4.UncompressBlock()`.
3. Extract live range from decompressed data.
4. Write (possibly recompressed by the new segment builder) to destination.

Note: **GC can re-compress data**. The new segment builder may decide to compress extents based on entropy; an uncompressed extent in the source may become compressed in the output, or vice versa.

---

## Concurrency and Safety

### LBA Map Updates: Atomic Patching

**Location:** `extent_map.go:220` (in `updateDisk`).

```go
d.lba2pba.LockToPatch(func() error {
    for i, pe := range processedExtents {
        if pe.CE.segIdx != pe.Segment {  // recycled?
            continue
        }
        if pe.CE.Live() != pe.Live {      // live range changed?
            continue
        }
        // Safe to patch
        pe.CE.SetFromHeader(eh, newIdx)
    }
    return nil
})
```

The `LockToPatch()` helper acquires a lock, runs the closure, and releases it—ensuring all patches are atomic from the read path's perspective.

### Concurrent Writes During GC

The read path (`resolveSegmentAccess`) and write path (`WriteExtent`) access the LBA map concurrently:
- Writes add new extents to the LBA map.
- GC reads the map to gather extents, then patches entries.
- If an extent in the source segment is overwritten during GC:
  - Its `segIdx` field changes (reuse in new segment).
  - Patching detects the mismatch (`segIdx != pe.Segment`) and skips the patch.
  - The extent remains in the old segment and will be GC'd again later.

### Snapshot Safety

Lower-disk segments (read-only) are protected by `removeSegmentIfPossible()`:
1. Before deleting a source segment, check all volumes (including lower disks).
2. If any volume references the segment, keep it.
3. Only delete when no volume references it.

Example: A snapshot's parent segment is never deleted until all child snapshots are deleted.

---

## GC Triggering and Thresholds

**Constants** (`close_segment.go:96–99`, `control.go:120–124`):

```go
GCDensityThreshold     = 70.0       // density% below which GC is triggered
GCTotalThreshold       = 1024*1024  // 1MB: don't bother GC'ing tiny disks
SmallSegmentCutOff     = 200        // <= 200 blocks is "small"
MaxBlocksPerSmallPack  = 20_000     // pack up to 20K total blocks of small segments
TargetDensity          = 90         // (unused in current code; check lines 148–149)
```

**Automatic triggers:**
1. After segment close: if `density < 70%` and `totalSize > 1MB`, queue `StartGC` event (line 277–285).
2. Every 5 minutes idle: scan for small segments, queue `SweepSmallSegments` if found (line 108, 126–135).
3. Cleanup: after every GC or segment close, queue `CleanupSegments` (line 396–398, 268–270).

**Manual triggers:**
- `Disk.GCOnce(ctx)`: Sends `StartGC` event and waits for result.
- Admin command `sweep-small-segments` via NATS interface (nats.go:136–144).

---

## Key Differences from the Paper

The paper does not explicitly detail GC; the reference impl provides the authoritative design. Key observations:

1. **Segment-level, not page-level.** GC works on whole segments; there is no finer-grained compaction.
2. **Density-driven selection.** The algorithm picks the least-dense segment, not a global compaction threshold.
3. **No explicit live bit map.** Dead extents are implicit (total - used); the algorithm re-reads and re-evaluates liveness on each GC run.
4. **Async background controller.** All GC is non-blocking via event queue; the caller gets a completion channel.
5. **Safe multi-volume deletion.** Segments in lower disks (read-only snapshots) are retained until no volume references them.

---

## Elide Implications

1. **Segment lifespan tracking:** The `Used` field must be updated correctly on every write that overwrites an existing extent in another segment. This is critical for accurate density calculation.
2. **LBA map structure:** Must support iteration over all extents in a segment (to gather extents to GC). A red-black tree indexed by LBA is appropriate.
3. **Safe patching under concurrency:** Must guarantee that LBA map updates during GC don't race with reads. Elide's snapshot-based tree structure (frozen ancestors) should simplify this by limiting which nodes can be GC'd.
4. **Snapshot coordination:** Frozen ancestor nodes should never be selected for GC. GC should target only live nodes with `wal/` present. This is structurally enforced, not via `removeSegmentIfPossible()` checks.
5. **Compression granularity:** GC can change compression state of extents. Re-compression during repacking is allowed; some extents may become compressible/incompressible after overwriting.
