---
rfd: 0003
title: Volume owns index/ and cache/; coordinator uses promote IPC
status: implemented
retrospective: true
created: 2026-04-10
references:
  - docs/architecture.md
  - docs/operations.md
---

# RFD 0003: Volume owns `index/` and `cache/`; coordinator uses promote IPC

## Summary

The volume process is the **sole writer** of `index/` and `cache/` within a volume directory. After a confirmed S3 upload, the coordinator sends a `promote <ulid>` IPC message over a Unix domain socket and the volume — not the coordinator — writes `index/<ulid>.idx` and `cache/<ulid>.{body,present}`. The directory structure then acts as a machine-readable record of durability state.

## Context

Elide splits responsibilities between the volume process (owns in-memory state, flushes the WAL, serves reads) and the coordinator (uploads to S3, runs GC, manages snapshots). Both need to agree on which segments are durable in S3, because that agreement is the gate for local eviction, GC liveness analysis, and crash recovery.

The question is: *which process writes the on-disk markers of that agreement?*

## Alternatives considered

### A — Coordinator writes `index/` and `cache/` directly (original)
After a successful S3 upload, the coordinator writes `index/<ulid>.idx` from the uploaded segment and moves the body into `cache/`. The volume reads these files passively.

**Rejected.** Two writers for the same directories, concurrent with the volume's own reads and rebuild scans. Invariants about directory contents — "every `cache/` body is redundant with S3, so eviction is always safe" — have to be maintained by careful cross-process coordination rather than by a single owner, which is harder to reason about and harder to verify by inspection.

### B — Volume owns `index/` and `cache/`; coordinator promotes via IPC *(chosen)*
The coordinator owns `pending/` (freshly flushed segments awaiting upload), `gc/` (pre-publish GC outputs), and S3 metadata. When an upload succeeds, it sends `promote <ulid>\n` on `<vol_dir>/control.sock`; the volume handler extracts the idx file, materialises the cache body, and responds `ok\n`. Only then does the segment appear in `index/` and `cache/`.

## Decision

**Option B.** One writer per directory, with a coordinator-to-volume IPC making the S3 confirmation explicit. The resulting state is directly visible in the filesystem:

- `pending/<ulid>` exists ↔ segment not yet S3-confirmed.
- `index/<ulid>.idx` exists ↔ segment is durable in S3.
- `cache/<ulid>.body` absent ↔ must demand-fetch from S3.

## Invariants preserved

- Single writer per directory; no intra-volume coordination needed to maintain invariants on `index/` or `cache/`.
- Durability state is inspectable with standard tools (`ls`), no binary decoding required.
- Every `cache/` body is redundant with S3, so local eviction is always safe.
