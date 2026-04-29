# Force-release fencing

**Status:** Proposed (2026-04-29). Companion to
[`design-portable-live-volume.md`](design-portable-live-volume.md) §
*`volume release --force`*. The recovery side of `--force` is already
specified there; this doc covers the **previous owner** side: what
must happen on coordinator A's host when A is alive and a peer has
force-released A's volume out from under it.

## Problem

`volume release --force` exists for the case "the previous owner is
unreachable and not coming back." Coordinator B unconditionally
rewrites `names/<name>` to `Released`, having first synthesised a
handoff snapshot from segments observable in S3. A new claimant C
forks from that synthesised snapshot.

The verb's safety contract — "the dead owner's writes that never
reached S3 are lost; nothing else" — assumes A is in fact dead. If A
is **alive** when `--force` runs (a partition that resolves, or a
mistakenly-issued `--force`), nothing in today's code stops A's
coordinator from continuing to mutate `by_id/<V1>/...` in S3. There
is no fencing on the data path.

The dangerous mutations are not new writes (those become orphans
under V1 and are harmless), but **A's reaper deleting segments that
B's synthesised manifest names**. Once a segment named in the
manifest is gone from S3, C's reads against V1 return 404 even
though the volume's logical content survives elsewhere.

## What "one owner per volume" rests on, without `--force`

The "one mutating coordinator per S3 prefix" property is not enforced
by `names/<name>` ownership checks on A's data path. It holds **by
construction**, through a stack of quieter mechanisms:

1. **Directory locality.** The local `<data_dir>/by_id/<V1>/`
   directory exists on exactly one host — the one that created or
   claimed it. A claim from another coordinator mints a *new*
   `vol_ulid` (V2) on its own host, so the V1 prefix is only ever
   mutated by A.
2. **Local volume halt.** `volume release` requires `volume.stopped`
   locally before doing anything. The volume process is down before
   the bucket-side flip. No new WAL records, no new pending
   segments.
3. **Local snapshot floor.** A's GC respects `latest_snapshot(fork_dir)`
   as a floor. The handoff snapshot in normal release is exactly A's
   most recent local snapshot, so segments referenced by the handoff
   are always at-or-below A's GC floor. A's GC pins them implicitly.
4. **Disjoint write prefixes.** Claimants always mint a fresh
   `vol_ulid`; their writes go to V2's prefix, never V1's.

`volume release --force` violates the first three of these:

| Property | Normal release | Force-release |
|---|---|---|
| 1. A's V1 dir locked to one host | ✓ | ✓ (B never has V1 locally) |
| 2. A's volume process halted | ✓ | ✗ (B can't reach A) |
| 3. A's local floor pins handoff segments | ✓ | ✗ (synthesised snapshot exists in S3 only) |
| 4. New claimant uses fresh ULID | ✓ | ✓ (C still mints V2) |

Properties 2 and 3 are the load-bearing ones. Their absence is what
makes `--force` unsafe against a live A.

## The invariant `--force` must preserve

B's synthesised handoff manifest is a list of specific segment
ULIDs. C's read path resolves those ULIDs by GET against
`by_id/<V1>/segments/<ulid>`. **Every ULID named in the manifest
must remain present in S3 for as long as any descendant of V1's
synthesised snap is alive.**

This is a *set membership* requirement at the manifest level.
Whether the same logical bytes happen to be preserved in a later GC
output is irrelevant: C resolves by ULID, not by content. If the
manifest names `<old>` and `<old>` is reaped, C 404s, regardless of
whether `<new>` (a GC output that compacted `<old>`) still holds the
bytes.

The pinned set is exactly "every segment present in S3 under V1 at
the moment B's `list_and_verify_segments` ran." A doesn't know which
ULIDs B chose, so A cannot make any local decision about which
segments are safe to reap. **A's correct post-`--force` behaviour is
to stop mutating V1 entirely.**

## What stops A from doing damage

A's destructive operations against V1 fall into three categories:

| Op | Destructive to manifest? | When it can fire |
|---|---|---|
| Drain upload (`pending/` → `by_id/<V1>/segments/<new_ulid>`) | No — orphans only | Whenever drain ticks |
| GC retention marker write (`by_id/<V1>/retention/<gc_output_ulid>`) | No — deferred | Whenever GC compacts |
| Reaper DELETE of marker inputs (`store.delete(by_id/<V1>/segments/<old_ulid>)`) | **Yes** | Marker deadline elapsed + reaper tick |

The reaper is the only path to actual data loss. The other two write
artefacts under V1 but do not delete anything. Retention deferral
(default `retention_window = 10m`) is the system property that
turns "GC writes a marker" into a non-destructive event with a 10
minute lead time before the corresponding DELETE fires.

## Fence design

The fence is a single check: **A's coordinator reads
`names/<name>` for each owned volume. If `coordinator_id != self_id`
or `state ∉ {Live, Stopped}`, A treats the volume as retired and
skips it from drain / GC / reaper / metadata-republish loops.**

Three places it has to live:

1. **Per-tick** at the start of each background loop tick. A
   coordinator's drain, GC, and reaper ticks all begin by re-reading
   `names/<name>` for every volume they're about to touch. If any
   has been flipped, the loop writes a local `volume.retired` marker
   and skips that directory thereafter — no more S3 cost per op.

2. **Per-op inside the reaper.** Even with per-tick fencing, a tick
   that started before `--force` could be mid-iteration when the
   flip lands. The reaper does an additional cheap HEAD against
   `names/<name>` before each `store.delete()`, so the worst-case
   damage is bounded to in-flight DELETEs at the moment of the
   flip — typically ≤1 for a sequential reaper.

3. **On S3 reachability resume.** When A's coordinator has lost S3
   connectivity and reconnects (the realistic `--force` trigger),
   the first action of every background loop is the per-tick fence
   check, before any S3 mutation. There's no in-flight reaper across
   the partition boundary because the reaper couldn't issue any
   request during the partition.

Plain unsigned reads of `names/<name>` are sufficient. The threat
model is "another legitimate coordinator wrote the bucket"; the
bucket is the trust anchor for ownership decisions. Signing
`names/<name>` is desirable for unrelated reasons (defence against
non-coordinator bucket writers, audit, replay protection) but does
not change the fence's correctness — see *Open questions* below.

## Force-release-side cleanup

The reaper-side fence catches new deletes. To close the
already-armed-marker case (a marker whose deadline has already
elapsed at `--force` time, with the reaper mid-processing), B
proactively cancels V1's pending markers.

The updated `--force` ordering:

1. List `by_id/<V1>/segments/`, verify each, build manifest.
2. Publish the synthesised manifest at
   `by_id/<V1>/snapshots/<date>/<snap>.manifest`.
3. **List `by_id/<V1>/retention/` and DELETE every marker.** Closes
   the deadline-elapsed-but-unfired race for any markers that were
   live during steps 1–2.
4. Unconditional PUT to `names/<name>` flipping to `Released` (or
   `Reserved`).

Step 3 is new. Steps 1, 2, 4 are the existing recovery flow.

The reaper's marker handling is already 404-tolerant
(`reaper.rs:117-128` does `store.get(marker_key)` to read the body;
NotFound returns an error and the iteration continues). With B
deleting markers between A's listing and A's get, A's get fails
cleanly and no inputs are deleted.

## Why retention deferral is what makes this work

Without retention markers, every GC pass would issue immediate
DELETEs and the race window's damage would scale with reaper
throughput. With retention deferral:

- Marker writes are non-destructive. A racing marker write produces
  an artefact but no data loss.
- The 10m grace period is much larger than any plausible fence
  latency. A is fenced out long before its marker deadlines elapse.
- B's step 3 above takes O(markers under V1) — small in steady
  state, bounded even after a long partition.

Retention deferral was introduced for unrelated reasons (decoupling
GC handoff atomicity from S3 delete latency), but it's exactly the
property that makes split-brain force-release survivable.

## Failure-mode walkthrough

**A is partitioned from S3, B runs `--force`, A reconnects later.**

During partition: A's drain fails, segments accumulate in `pending/`.
A's GC may compute plans locally but cannot publish retention
markers. A's reaper cannot list S3. No mutations to V1's S3 prefix.

`--force` runs while A is partitioned: B lists segments (sees only
what A had committed before the partition), publishes manifest,
cancels V1's retention markers (per step 3 above), flips name.

A reconnects: A's first tick of any background loop reads
`names/<name>`, sees not-self ownership, writes
`volume.retired` locally, halts further work on V1. Pending segments
remain in A's local `pending/`; they are never uploaded. No deletes
were ever issued by A against V1.

**A is healthy and `--force` is mistakenly issued.**

A's per-tick fence catches the flip on its next tick (≤ tick
cadence, default ≤ 10s for GC). Up to one in-flight reaper DELETE
may complete during the per-op fence window. Any retention marker
A's GC was about to write is bounded by the same window.

If `--force`'s precondition is tightened to refuse when A's
heartbeat is recent (out of scope for this doc; tracked as an open
question), the trigger is rare to begin with.

## Cleanup of orphaned state

Once A is fenced, V1 accumulates dead state in S3:

- Retention markers whose reaper never fires (orphans under
  `by_id/<V1>/retention/`).
- Segments referenced by orphan markers (still present, never
  reaped).
- New segments A uploaded between the partition resolving and the
  fence catching — orphans under `by_id/<V1>/segments/<post_force_ulid>`.

None of this threatens correctness. Storage grows with the size of
the dead fork's working set plus whatever A wrote post-force.
Reclamation is a separate "retire-`vol_ulid`" path that runs once
no living fork descends from V1's synthesised snap. Out of scope
for this doc.

## What this design does **not** try to do

- **Restore "one owner" as an absolute invariant.** It restores it
  to the same standard normal release has: holds when the system is
  used as designed, degrades gracefully under the failure mode
  `--force` was created for.
- **Make A's writes survive `--force`.** A's post-`--force` writes
  are silently lost from C's perspective. This is the explicit cost
  of forcing.
- **Prevent every possible delete.** Per-op fencing bounds the
  in-flight DELETE race to ≤1 per concurrent reaper request. The
  retention window's distance from the fence latency means this
  case requires a marker whose deadline already elapsed — possible
  in principle, vanishing in practice with healthy A and tightened
  `--force` preconditions.
- **Replace `names/<name>` with a different ownership primitive.**
  The fence reads the existing record. No format change, no new
  bucket-side machinery.

## Open questions

- **Tighten `--force`'s precondition.** Should `--force` refuse when
  A's last-seen heartbeat is recent? Requires a heartbeat key (e.g.
  `coordinators/<id>/heartbeat`) that A refreshes periodically and
  B reads. Reduces the trigger rate to "A is genuinely
  unavailable", complementing the fence rather than replacing it.
- **Sign `names/<name>` records.** Defence in depth against
  non-coordinator bucket writers, plus consistency with the rest of
  the protocol (snapshot manifests are signed). Not load-bearing for
  the fence's correctness.
- **Cross-host orphan reclamation.** A "retire-`vol_ulid`" path that
  sweeps `by_id/<V1>/...` once no living fork pins V1's snap. Needed
  for steady-state storage hygiene; orthogonal to the fence.
- **Should A's volume process refuse writes after the fence trips?**
  Today, A's volume IPC accepts writes regardless of names-record
  state. Plumbing the fence through to surface "you're no longer
  owner" to the application would convert silent post-`--force`
  writes into immediate errors visible to the app. UX improvement,
  not a correctness change.
