---
rfd: 0002
title: Extent index lowest-ULID-wins
status: implemented
retrospective: true
created: 2026-04-10
references:
  - docs/architecture.md
---

# RFD 0002: Extent index lowest-ULID-wins

## Summary

When multiple segments contain entries for the same extent, the extent index keeps the entry from the segment with the **lowest** ULID. The rule is applied identically at three sites — rebuild, live promote, and GC candidate compaction — so rebuilt and in-memory state cannot disagree.

## Context

Dedup means the same extent can appear as a DATA entry (the original write) *and* as one or more DedupRefs (later writes that matched its hash). The original is always older, so it always has the lowest ULID by construction. A DedupRef points *to* the original; it must not supersede it in the index.

This interacts subtly with GC. When GC repacks the original DATA into a new segment, the new segment's ULID is higher than any outstanding DedupRef — so the write-time "DedupRef → lower ULID" relationship *does not persist* after GC. The invariant that does persist is **canonical-presence**: every live DedupRef hash resolves to a DATA entry somewhere in the index, even if that entry's segment has moved.

## Alternatives considered

### A — Highest-ULID-wins (original)
The index kept the entry from the *newest* segment: rebuild used last-write-wins insert, and live promotion overwrote when the existing entry had a lower ULID.

**Rejected — workable, but required more complex handoff logic.** When GC repacks the original DATA into a new segment, the handoff path re-points the extent index from the old ULID to the new one. Under lowest-wins, a simple `still_at_old` guard is sufficient: either the index still points at the old ULID (update it) or something has already moved it (no-op). Under highest-wins the same guard isn't enough — a concurrent higher-ULID write could have legitimately superseded the old entry, forcing the handoff path to reconcile multiple competing ULIDs rather than just two.

The rule was intentional in a non-dedup world — "newest wins" is intuitive, and it let GC outputs cleanly win over ancestors — but dedup made the same hash appear in multiple segments on the same volume, and the reconciliation bookkeeping compounded.

### B — Lowest-ULID-wins *(chosen)*
Flip the direction. Rebuild processes segments in ascending ULID order with first-write-wins insert; live promotion skips writes that would overwrite an entry with a lower ULID; GC candidate compaction matches. All three sites updated in lockstep.

## Decision

**Option B.** The original DATA entry is canonical for the lifetime of the extent; DedupRefs and GC outputs are resolved against it. The rule is applied identically at every site that chooses between conflicting extent index entries.

## Invariants preserved

- Every live DedupRef hash resolves to a DATA entry present in the extent index.
- Rebuild from segments produces the same extent index as in-memory state, for any valid sequence of writes and GC operations.
- GC's `still_at_old` guard is sufficient to re-point stale entries without overwriting newer writes.
