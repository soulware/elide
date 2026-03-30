# Design: GC ULID ordering and the single-mint invariant

Status: **partially resolved** (extent index guard + per-entry tracking committed;
single-mint attempted and reverted; rebuild-time ordering still open)

Date: 2026-03-30

---

## Context

While implementing `.applied` -> `.done` cleanup for the GC handoff protocol,
proptest found a ULID ordering bug that was previously masked by timing.

## The invariant

**Every segment ULID in a fork must come from a single monotonic source.**
Without this, ULID ordering — which is the foundation of crash-recovery
correctness — can be violated.

Currently the volume and coordinator generate ULIDs independently:
- Volume: `UlidMint` seeded from `max(existing ULIDs)` on open
- Coordinator GC: `max(inputs).increment()`

These can collide when two ULIDs share the same millisecond timestamp, because
the 80-bit random portion determines sort order — a coin flip.

## How proptest found it

In production, GC inputs are segments that went through the drain pipeline —
their ULIDs are seconds to minutes old.  `max(inputs).increment()` produces a
ULID from that old timestamp, which is far below the current WAL ULID.  The
invariant holds by time alone.

Proptest collapses time to zero.  Operations that take minutes in production
happen within the same millisecond.  `DrainLocal` -> `CoordGcLocal` back-to-back
means the GC inputs have ULIDs from the same millisecond as the current WAL.
`max(inputs).increment()` lands at or above the WAL ULID roughly 50% of the
time (depending on random bits).

After multiple GC rounds, the effect accumulates: each GC output goes into
`segments/`, gets picked up by the next GC, and `increment()` deterministically
marches forward through the ULID space while the volume's mint draws random
positions.

## Three bugs found

### 1. Extent index guard (TOCTOU between GC liveness check and handoff application)

`apply_gc_handoffs()` unconditionally overwrites extent index entries from the
GC output segment's index.  If a newer write has landed between the
coordinator's liveness check and the volume applying the handoff, the GC
output's stale entry overwrites the correct one.

**Fix:** parse the `.pending` file's `old_ulid` per entry, and only update the
extent index if `extent_index[hash].segment_id == old_ulid`.  Uses
`blake3::Hash::from_hex()` (available in the `blake3` crate, no new deps).

**Status:** committed (07828b2).

### 2. ULID source unification (two-source ordering race)

The coordinator's `compaction_ulid(max_input)` computes ULIDs independently
from the volume's mint.  When ULIDs collide in the same millisecond, the sort
order is determined by random bits — a coin flip.  After a crash, the LBA map
is rebuilt from segment files in ULID order.  If the GC output sorts after a
newer segment, its stale LBA entries shadow the correct ones.

**Attempted fix: single-mint.**  The coordinator requests GC output ULIDs from
the volume's mint via `VolumeRequest::MintUlid`.  This ensures all ULIDs in a
fork come from a single monotonic source.  `compaction_ulid()` is removed.

**Why it was reverted:** the single-mint approach fundamentally breaks rebuild
ordering.  The volume's mint tracks the highest ULID issued.  When a WAL
segment is opened (step N), it gets ULID W from the mint.  When the coordinator
later calls `mint_ulid()` (step N+K), it gets ULID M > W.  The GC output is
named M.  If the WAL is flushed to pending/ and then a crash occurs, rebuild
processes segments in ULID order: W first, then M.  M's stale entries overwrite
W's correct entries — the exact bug we're trying to fix.

The `increment()` approach avoids this because `max(old inputs).increment()`
produces a ULID from the old inputs' timestamp, which is far below any
concurrent WAL ULID.  The GC output sorts before the WAL segment, so the WAL's
entries win on rebuild.

**Current state:** `compaction_ulid(max_input)` remains.  The same-millisecond
collision is theoretically possible but astronomically unlikely in production
(GC inputs are seconds to minutes old).  The extent index guard (bug 1)
protects the live apply_gc_handoffs path.  The rebuild path relies on timestamp
separation between old GC inputs and current writes.

**Open question:** how to close the rebuild-time ordering gap.  Options:

  A. **WAL flush before mint:** `MintUlid` handler flushes the in-flight WAL
     before minting, so no WAL segment can have a ULID below the minted one.
     Adds latency to the GC path and couples volume I/O to coordinator timing.

  B. **GC-aware rebuild:** tag GC output segments (e.g. a header flag or a
     sidecar file) so rebuild knows to apply them at the position of their
     *input* segments, not their output ULID.  Adds complexity to the segment
     format and rebuild logic.

  C. **Rebuild from handoff files:** instead of pure ULID-ordered rebuild, use
     `.pending`/`.applied`/`.done` files to understand GC relationships.
     Rebuild applies the GC output's entries only where the extent index still
     points at the consumed input — the same guard used at runtime.  This
     requires the handoff files to survive across restarts (they already do).

  D. **Accept the gap:** document that the same-millisecond collision requires
     both (a) GC inputs from the current millisecond and (b) random bits that
     happen to sort the wrong way.  In production this requires drain + GC to
     complete within 1ms, which is physically implausible with S3 upload in
     the path.  The proptest exercises it because it collapses time.

### 3. `.pending` file per-entry old_ulid (test helper bug)

The test helper `simulate_coord_gc_local` used `max_input` as the `old_ulid`
for ALL entries in the `.pending` file.  But entries come from two different
input segments.  The correct `old_ulid` is the specific source segment each
entry came from — required for the extent index guard (bug 1) to work.

**Fix:** track per-entry source segment ULID in the test helper.

**Status:** committed (07828b2).

## Additional findings

### Atomic `.pending` write

The `.pending` file was written with `fs::write()` (non-atomic).  A crash
mid-write leaves a partial file.  `apply_done_handoffs` parses this to find
old segment ULIDs — a partial file means some old ULIDs are missed, leaking
S3 objects.

**Fix:** write via tmp + rename.

**Status:** committed (7e8eeec).

### NotFound tolerance in rebuild

`lbamap::rebuild` and `extentindex::rebuild` fail hard if a segment file
disappears between path collection and the read (e.g. coordinator GC deleting
a segment file).  Should skip with a warning — the new compacted segment
(higher ULID) provides the correct entries.  Same fix needed in
`Volume::compact()`.

**Fix:** match on `ErrorKind::NotFound` and continue with a `warn!()`.

**Status:** committed (7e8eeec).

### All-dead segment case

When all extents in GC candidates are dead, no handoff is needed (no extent
index entries reference the segments).  The coordinator should delete S3
objects and local files directly, skipping the handoff protocol.

**Fix:** direct delete in the all-dead branch of `compact_segments`.

**Status:** committed (7e8eeec).

### `.applied` -> `.done` cleanup

The coordinator polls for `.applied` files at the start of each GC tick,
deletes old S3 objects and local segment files, then renames to `.done`.
S3 404 on delete is treated as success (idempotent across coordinator crashes).

**Fix:** `apply_done_handoffs()` in coordinator `gc.rs`.

**Status:** committed (7e8eeec) with 8 unit tests.

## Implementation status

| Fix | Status | Commit |
|-----|--------|--------|
| Extent index guard (bug 1) | Done | 07828b2 |
| Per-entry old_ulid (bug 3) | Done | 07828b2 |
| NotFound tolerance | Done | 7e8eeec |
| Atomic `.pending` write | Done | 7e8eeec |
| All-dead direct cleanup | Done | 7e8eeec |
| `.applied` -> `.done` | Done | 7e8eeec |
| Single-mint (bug 2) | Attempted, reverted | -- |
| Rebuild-time ordering | Open | -- |
