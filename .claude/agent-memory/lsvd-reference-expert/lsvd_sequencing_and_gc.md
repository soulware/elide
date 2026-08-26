---
name: lsvd_sequencing_and_gc
description: How LSVD assigns sequence numbers to open WAL vs GC output, and why the class of sequencing bug that hit Elide cannot occur in LSVD
type: reference
---

# LSVD: Sequencing of Open Log vs GC Output

**Question answered:** How does LSVD handle sequencing of compaction output relative to concurrent unflushed writes?

## LSVD Architecture: Key Difference from Elide

Unlike Elide, **LSVD does not have a separate "open WAL" with a pre-assigned ULID**. Instead:

1. **Data is written directly to a segment builder in memory** (`d.curOC`, a `*SegmentCreator`).
2. **The segment builder has no ID until it is closed and flushed** — sequence number is assigned only when the segment is closed (via `CloseSegment` event).
3. **GC output also gets a sequence number when its builder is flushed** — same call path as regular segment flush.

Reference impl: `disk.go:223–236`, `control.go:185–289`.

---

## Sequence Number Assignment Flow

### For Open Write Segments

1. Call `d.newSegmentCreator()` → calls `d.nextSeq()` → gets fresh ULID.
2. Stores result in `d.curSeq` (in-memory variable, **not yet committed**).
3. Builder writes accumulate in memory; no disk identity yet.
4. On `CloseSegment` event: builder is flushed with `d.curSeq` as its segment ID.
5. Flush makes it durable; `d.curSeq` is now a committed segment.

**Key point:** The ULID is generated when the segment *creator* is allocated (on demand), but it only becomes real when flushed.

### For GC Output

1. GC creates a `CopyIterator` with an empty `newSegment` field.
2. On first call to `ci.Reset()`, if `newSegment` is not yet set:
   - Call `d.nextSeq()` → get fresh ULID.
   - Store in `ci.newSegment`.
   - Initialize a `builder` and open it.
3. As extents are copied, they accumulate in the builder (in memory).
4. On `ci.Close()`: builder is flushed with `ci.newSegment` as its ID.

Reference impl: `gc.go:278–309` (`Reset` method).

---

## Why The Sequencing Bug Cannot Occur in LSVD

### Elide's Bug Scenario
1. Open WAL gets pre-assigned ULID U1.
2. Compaction output gets ULID U2 = mint.next() (higher than U1).
3. WAL is later flushed as segment with ULID U1.
4. On crash recovery, segments are replayed in ULID order: U2 before U1.
5. **Compaction output overwrites newer WAL data.**

### LSVD Structural Difference
**LSVD cannot have this problem because GC output and open writes use the same sequencing mechanism.**

1. **At the start of GC:** The open write segment has already been assigned a sequence number (when `curOC` was created).
2. **GC output is created fresh:** `nextSeq()` is called separately for the GC builder.
3. **Both use the same monotonic sequence generator:** Whether you call `nextSeq()` for an open segment or for GC output, the result is always higher than any previous call.
4. **Flushing is ordered by wall-clock time or background controller events:**
   - CloseSegment event processes `d.curOC`, flushes it with its pre-assigned sequence.
   - GC happens in a background controller loop; its output is flushed in a separate event.
   - Events are processed serially by a single controller goroutine (see `control.go:66–105`).

**Result:** If GC is triggered while a write segment is open:
- The open segment's ULID is older (was assigned earlier).
- The GC segment's ULID is newer (assigned later).
- When both are flushed, GC output has a higher ULID.
- **BUT:** The LBA map is updated atomically during GC (via `LockToPatch`), and the old segments are marked deleted immediately.
- There is no "unflushed segment with newer writes that gets overwritten by stale GC output" window.

---

## The Critical Difference: Sequencing Philosophy

| Aspect | LSVD | Elide (pre-fix) |
|--------|------|-----------------|
| **Open segment ID** | Assigned on demand when segment creator is allocated | Pre-assigned from global mint before any writes |
| **GC output ID** | Assigned on demand when GC begins | Assigned from mint.next() (higher than open WAL) |
| **Sequencing guarantee** | All IDs come from same monotonic `SeqGen()` | Two separate pools (mint and WAL) |
| **Update atomicity** | LBA map patched atomically during GC Close; old segments marked deleted | LBA map updated; old WAL entries remain in pending/ |
| **Event ordering** | Controller processes events serially | WAL flush and GC can race; flush must win |

---

## Code Evidence

**Open segment sequencing** (`disk.go:223–236`):
```go
func (d *Disk) newSegmentCreator() (*SegmentCreator, error) {
    seq, err := d.nextSeq()  // fresh ULID, monotonically advancing
    if err != nil {
        return nil, errors.Wrapf(err, "error generating sequence number")
    }
    d.curSeq = seq  // store in-memory; not yet committed
    // ...
    return sc, nil
}
```

**GC output sequencing** (`gc.go:278–309`, in `Reset`):
```go
if !ci.newSegment.Valid() {
    newSeg, err := ci.d.nextSeq()  // same call as open segment
    if err != nil {
        return err
    }
    ci.newSegment = newSeg
}
```

**Serial event processing** (`control.go:66–105`):
```go
for {
    // ...
    select {
    case ev, ok := <-c.events:
        if !ok { return }
        err := c.handleEvent(ctx, ev)  // process one event at a time
        // ...
    }
}
```

---

## Elide's Fix

Elide's solution: **use max(input_ULIDs).increment()** for GC output, not mint.next().

This guarantees GC output ULID is always higher than any input segment but derived from the actual data history, not clock-based. The fix aligns with LSVD's philosophy: sequence numbers reflect causal ordering of data, not wall-clock time or a shared counter.

---

## Relation to LSVD Paper

The paper does not explicitly discuss sequencing or GC output IDs. The reference impl uses ULID (wall-clock + entropy) for all segment IDs, relying on monotonic time and the event loop's serial processing to prevent this class of bug. Elide's explicit max()-based sequencing is a more causal-order approach and is complementary.

