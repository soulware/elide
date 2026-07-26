# Design: evict via volume IPC

**Status:** Proposed (2026-07-26). No implementation.

## Problem

Two processes mutate a volume's `cache/` artefacts. The volume process
writes them (demand-fetch), and the coordinator deletes them
(`evict_bodies` / `evict_one_body` in the per-fork task). The fetcher's
serialisation — per-segment coalescer leases and the `.present` lock
around its read-modify-write — is in-process state the coordinator
cannot see.

Consequences while a volume process is running:

- **A presence race.** The `.present`-first unlink order (#803)
  excludes the single-fetch corruption interleaving, but a multi-leader
  shape survives: one fetch leader's read-modify-write straddles the
  evict and resurrects pre-evict bits into a recreated `.present`; a
  second leader recreates `.body` sparse and merges on top. Bits then
  cover holes. The read-path content verify (#800) turns such a read
  into EIO rather than silent zeros, and formation skips the candidate
  (#801), so the exposure is a transient guest EIO — enforced by
  probability, not structure.
- **Stale in-memory presence.** The daemon's `SegmentPresence` bitset
  is not invalidated by a coordinator evict; it heals only when a later
  fetch rewrites it (`replace_from_bytes`).
- **An ownership anomaly.** The rule everywhere else is that a running
  volume owns `index/` and `cache/`, and the coordinator mutates them
  through IPC (promote, finalize-gc-handoff). Evict is the one
  coordinator-side mutation of a live volume's cache.

## Proposed design

Eviction is performed only by a process that holds the volume's
exclusive lock and serves `control.sock`: the running daemon when
there is one, a short-lived limited volume process otherwise. The
coordinator never unlinks a live segment's cache artefacts itself.

- New `VolumeRequest::Evict { segment_ulid: Option<Ulid> }` on
  `control.sock` (`None` = every S3-confirmed segment, mirroring the
  current all-or-one shapes). Reply carries the evicted count for the
  existing `EvictReply`.
- Volume-side eviction, per segment, under the fetcher's per-segment
  `.present` lock: verify eligibility (`index/<id>.idx` present),
  unlink `.present`, `.dmat`, `.body`, `.delta` in that order, and
  clear the in-memory `SegmentPresence` inside the same critical
  section. One mutator, no window.
- No running daemon: the coordinator brings up a limited volume
  process for the operation, on the precedent of `elide-import`'s
  `serve_promote` — a process that takes the volume's exclusive lock,
  binds `control.sock`, serves the request, and exits. The lock is
  what a check-then-act coordinator arm cannot have: it excludes a
  daemon starting mid-eviction, where "not running" is a stale answer
  by the time the unlinks run.
- Open fds in reader `FileCache`s may pin an unlinked inode's space
  until they cycle out; unchanged from today and safe, since segment
  files are immutable and reads through a stale fd return complete,
  correct bytes.

Out of scope: the GC handoff's consumed-input cleanup stays
coordinator-side. Those segments' `.idx` is already deleted, nothing
resolves to them, and the fetcher never fetches a segment without its
index.

## What this closes

The multi-leader presence race becomes structurally impossible instead
of unlikely; evicting under a running volume stops leaving a stale
in-memory bitset; cache mutation returns to the single-owner model the
promote path already follows; and eviction has one code path — there
is no running/not-running behavioural fork, and no window in which
that distinction can go stale.
