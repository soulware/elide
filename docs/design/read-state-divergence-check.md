# Read-state divergence check

The volume daemon's in-memory read state (lbamap, extent index) is
built once, at `open_read_state`, from the volume's own `index/` layer
plus ancestor manifests — and the rebuild defines correctness: at any
moment, the daemon's view must match what a fresh open would build
from disk. Only the daemon (or the coordinator, on a halted volume)
may write the own layer, so the two views never diverge — that is the
single-writer rule the claim-supervision gate
(`claim-supervision-gate.md`) enforces at its known violation site.

This check enforces the rule against unknown violators: at every GC
commit, the daemon verifies it can actually *see* the segments the
plan consumes. A violation means the daemon is provably serving a
subset of its own on-disk state — the silent-stale failure shape — and
the daemon fail-stops.

## The gap in the existing commit-point validation

`apply_plan_apply_result` (elide-core/src/volume/mod.rs) already
re-validates every plan against the daemon's *current* maps at the
atomic commit point: an input entry that is still live in the lbamap
but absent from the materialised output cancels the plan
(stale-liveness cancellation). But that loop only examines hashes the
daemon's extent index locates *at the input segment* — an input
segment the daemon has never loaded fails that lookup for every one of
its hashes and is silently skipped. Body materialisation reads
`cache/<ulid>.body` directly, not through the read state, so the
worker happily copies bytes from a segment the daemon cannot serve.

That is exactly how the 2026-07-02 force-claim incident's divergence
was folded into the durable canonical form: the re-owned head-delta
segment was in `index/` and in the coordinator's disk-derived GC
candidate set, invisible to the already-open daemon, and unprotected
by stale-liveness cancellation. The check validated the liveness of
what the daemon could see; it never validated that the daemon could
see the inputs.

## The invariant

**Every input segment ULID in a GC plan must be a member of the
daemon's own-layer segment set at the commit point.**

The own-layer segment set is a `BTreeSet<Ulid>` on the volume state,
covering the committed tier (`gc/` ∪ `index/`) only — GC candidates
must be cache-resident, so plan inputs are always committed-tier, and
the pending tier never needs tracking:

- populated at open from the `index/*.idx` + bare `gc/` scan — the
  same files the lbamap rebuild loads for the own layer;
- a segment enters at `promote_segment` (after confirmed upload) and
  at GC-handoff commit (the bare-output rename);
- consumed inputs leave when the output's promote deletes their
  `index/<ulid>.idx`.

The maintenance points are exactly the IPC surfaces through which all
own-layer mutations flow on a running volume, so the set is a faithful
mirror of the *applied* view, not a second disk scan. Between a
worker's idx write and the actor's apply phase, disk transiently leads
the set — which is why the check compares against the set, and why the
mirror is not asserted as a runtime equality invariant.

The check runs in `apply_plan_apply_result`, before the stale-liveness
loop: `plan.inputs ⊆ own_segments`, O(|inputs|) set lookups. A miss is
a **divergence** outcome — distinct from stale-liveness cancellation,
which is a benign race with concurrent writes and retries next tick.

## Failure response: fail-stop, self-healing

On divergence the daemon logs the missing ULIDs at ERROR and exits
(exit code 70; the binary installs the exit as a hook on the actor,
so library callers and tests get log-and-continue with the plan
retained instead of a process exit). The supervisor's ordinary
respawn (with its existing fast-failure backoff) rebuilds the read
state from disk; the rebuilt state includes the previously-unseen
segments, so the respawned daemon serves the merged view and the
check passes. Recovery *is* the rebuild — no new serve-path state, no
reload machinery. Accepted writes are already durable in the WAL, so
the hard exit loses nothing.

Continuing to serve after detection is not an option worth having:
every guest write lands at a higher ULID and permanently shadows the
unseen segments' LBAs in any future rebuild, so a
reject-but-keep-serving response compounds the divergence with every
write while preserving only forensic bytes. A read-only serve mode
fails the same test — reads of the affected LBAs are stale, and
serving them is the failure shape this check exists to stop. The
guest sees an IO blip at the fail-stop; the displaced-fork fence set
the precedent that an honest error beats a wrong answer.

A false positive (a set-maintenance bug) costs one visible restart:
the respawn rebuilds the set from disk, so only a bug that
re-corrupts the set at runtime can cycle, and that presents as a
loud, bounded crash-loop — never silent corruption.

## What the check does not do

Detection is at GC cadence, so writes made between the divergence
event and the next GC pass still shadow permanently; the fail-stop
caps the window at one GC interval, it does not eliminate it.
Prevention remains structural — the claim-supervision gate and the
single-writer rule. The rejected plan's inputs are never marked
`Superseded` in HEAD, so the reaper cannot delete the unseen
segments' bytes regardless of how long the condition persists.

## Testing

- `gc_plan_with_unknown_input_diverges_and_reopen_recovers`: a
  committed segment's idx is hidden across a reopen and restored
  after (re-enacting a re-own under a live daemon); a plan folding it
  is refused with the plan retained and no output committed, and a
  fresh open then applies the same plan cleanly — the recovery path,
  exercised end to end.
- `own_segments_mirrors_committed_lifecycle`: the set across
  write → promote → GC apply → output promote → finalize → reopen,
  asserting pending exclusion, input removal, and rebuild equality at
  every settled point. The mirror is asserted here, on the
  synchronous lifecycle, rather than in the runtime invariants
  umbrella — the worker protocol makes disk transiently lead the set
  mid-promote, so runtime equality would false-panic.

## Open questions

- Should the fail-stop also emit an `events/<name>` journal entry so
  the divergence is recorded bucket-side, not only in host logs?
- A second direction at tick cadence: the `gc_checkpoint` reply could
  carry a commitment (count + XOR of ULIDs) of the daemon's set for
  the coordinator to compare against its disk scan each tick,
  catching disk-behind-daemon divergence too. Needs a
  tolerant-schema `volume_ipc` addition (rolling upgrades keep old
  daemons under new coordinators), so it is deliberately not part of
  the first cut.
