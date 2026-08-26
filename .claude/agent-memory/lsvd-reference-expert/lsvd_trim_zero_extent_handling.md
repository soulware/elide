---
name: LSVD TRIM and Write-Zeroes Handling
description: How LSVD represents trimmed/discarded blocks on-disk; zero-extent sentinel in segment format
type: reference
---

## TRIM and Write-Zeroes Strategy

LSVD does **NOT** have a dedicated zero-extent flag (no FLAG_ZERO or equivalent). Instead, it represents trimmed/discarded blocks using a **sentinel extent with Size=0**.

### On-Disk Format

In the **ExtentHeader** struct (headers.go):
```go
type ExtentHeader struct {
    Extent  `json:"extent" cbor:"1,keyasint"`
    Size    uint32 `json:"size" cbor:"2,keyasint"`           // on-disk size
    Offset  uint32 `json:"offset" cbor:"3,keyasint"`
    RawSize uint32 `json:"raw_size,omitempty" cbor:"4,keyasint,omitempty"`
}
```

The extent flags are determined by a computed property:
```go
func (e *ExtentHeader) Flags() byte {
    switch {
    case e.Size == 0:
        return Empty       // = 2
    case e.RawSize != 0:
        return Compressed  // = 1
    default:
        return Uncompressed // = 0
    }
}
```

**There are only 3 flags: Uncompressed (0), Compressed (1), Empty (2).**

When Size=0, the extent is **Empty**, signifying a trimmed/discarded range. The LBA and Blocks fields still encode the logical extent being zeroed.

### Write Path

**NBD Layer** (nbd.go):
- `ZeroAt()` and `Trim()` methods (which are aliases of each other) queue TRIM extents into `pendingTrim`
- `queueTrim()` batches consecutive TRIM operations to reduce segment entries
- On flush via `flushPendingWrite()`, the pending TRIM extent is passed to `d.ZeroBlocks(ctx, pendingTrim)`

**Disk Layer** (disk.go):
- `ZeroBlocks()` is a simple pass-through that calls `curOC.ZeroBlocks(rng)` if not read-only

**Segment Creation Layer** (segment.go):
- `SegmentCreator.ZeroBlocks()` updates the LBA map and delegates to `SegmentBuilder.ZeroBlocks()`
- `SegmentBuilder.ZeroBlocks()` appends an `ExtentHeader` with Size=0 (and Offset=0, RawSize=0) to the segment's extent list
- On `Flush()`, these zero-extents are written to the segment file just like regular extents, but with no body data

### Read Path

When reading, if a TRIM'd region is requested:
- LBA map resolution returns a `PartialExtent` with `Size == 0`
- The read code checks `if pe.Size == 0` and calls `clear(v.WriteData())` to zero the buffer (disk.go lines 341-348)
- No segment fetch is performed since there's no data body

### In-Segment Representation

A TRIM extent in a segment binary looks like:
- LBA (varint)
- Blocks (varint)
- Size=0 (varint: 0)
- Offset=0 (varint: 0)
- RawSize=0 (varint: 0)

Total: ~5–10 bytes overhead per TRIM extent, no data payload.

### Key Design Notes

1. **No dedicated zero flag** — simplicity; trims are just regular extents with Size=0
2. **Batching at NBD layer** — `pendingTrim` merges consecutive TRIM calls to reduce extent count
3. **Write amplification** — each TRIM is logged to the segment, contributing to segment size (metadata overhead)
4. **GC-friendly** — TRIM extents show up in LBA map as legitimate mappings, so GC can reclaim storage if the TRIM'd range is garbage-collected
5. **Implicit zeroing** — all allocations in LSVD start zero'd, so unread ranges are already zero without needing explicit TRIM entries

### Implication for Elide

If Elide wants to represent TRIM operations, the sentinel-Size=0 approach is simple and proven. However:
- Consider whether Elide needs explicit TRIM representation at all (if the disk is sparse/CoW, TRIM may be implicit)
- If explicit, the sentinel approach avoids needing a separate flag in the segment format
- Batching at the NBD/client layer is critical to avoid excessive segment entries
