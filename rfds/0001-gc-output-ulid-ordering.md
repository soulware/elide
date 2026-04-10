---
rfd: 0001
title: GC output ULID ordering
status: implemented
retrospective: true
created: 2026-04-10
references:
  - docs/design-gc-ulid-ordering.md
---

# RFD 0001: GC output ULID ordering

## Summary

GC output segments must sort *below* any concurrent user writes, so the lowest-ULID-wins rule in the extent index gives the correct answer on crash recovery. The current design mints all GC-round ULIDs from the volume's monotonic source in a single `gc_checkpoint` call — after flushing the WAL, before any I/O — guaranteeing `flush < GC output < new WAL`.

## Context

GC and user writes were originally minting ULIDs from independent sources (coordinator vs. volume). Any ordering between them had to be established *logically* before either hit disk, or a crash mid-sequence could leave a GC output shadowing a live write on rebuild.

## Alternatives considered

### A — `max(inputs).increment()` on the coordinator (original)
Coordinator computed `compaction_ulid(max(input_ulids))`, incrementing within the same millisecond. Assumption: input segments are always old (from the drain pipeline), so the result lands below current time and therefore below any new write.

**Rejected.** Two bugs falsified the assumption:
- **Empty WAL at checkpoint**: coordinator minted GC ULIDs before the volume opened a new WAL, so the new WAL could get a *lower* ULID than the GC output (Bug C).
- **Stale WAL ULID**: `compaction_ulid()` operated on the WAL's pre-assigned ULID (from when the WAL was opened), not the current mint state; newly-flushed segments could still sort below the GC output (Bug D).

Root cause: **two independent ULID sources** with no forced ordering between them.

### B — Coordinator mints everything
Move all ULID generation to the coordinator. Rejected: the volume still needs to mint ULIDs for live writes, so two sources would persist — just reversed. Same class of bug.

### C — Volume mints all four ULIDs in one checkpoint call *(chosen)*
`gc_checkpoint()` on the volume flushes the in-flight WAL, then mints `(u_repack, u_sweep, u_flush, u_wal)` in sequence from the monotonic source, *before any I/O*. The first two return to the coordinator for GC; the latter two stay in-process to close the old WAL and open a fresh one that is guaranteed to sort above the GC outputs.

## Decision

**Option C.** All ULIDs in a GC round come from a single monotonic source, minted in a single pre-I/O step. The ordering `flush < GC output < new WAL` is encoded in the mint sequence itself; no subsequent operation can violate it.

## Invariants preserved

- GC output ULIDs sort strictly below any ULID minted by a later user write.
- The four-ULID sequence within a round is monotonic; across rounds, each new WAL ULID exceeds all prior GC outputs.
- TOCTOU on extent index updates is guarded independently by `old_ulid` checks on `.pending` entries.
