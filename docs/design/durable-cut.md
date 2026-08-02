# Durable cuts

**Status: Proposed.** Builds on [segment-index.md](segment-index.md)
(per-volume HEAD, the manifest ∪ HEAD live set, seal-time truncation)
and the drain/GC tick in `elide-coordinator/src/gc_cycle.rs`. Fixes a
live consistency hole in today's publish rules and provides the commit
mechanism the loss-window work needs.

## The problem

Force-claim recovers a lost host's volume from S3 by materialising
`live = manifest ∪ HEAD.added − superseded − tombstoned`
(`force_claim.rs`, `segment_head::live_set`). For that image to be
usable, it must be **crash-consistent**: a state the guest's block
device could actually have been in at some past instant, respecting
write ordering. Three paths in today's code can publish a set that
violates this.

**Partial-drain publish.** Repack rewrites pending segments against
the current lbamap: a body superseded by a *newer pending* segment is
elided from the rewrite, and bin-packing (by live bytes, descending)
assigns output ULIDs with no relation to content write order
(`actor.rs`, `execute_repack`). Input files are unlinked; only outputs
upload. Drain then uploads ULID-ascending, halts at the first failure —
and the tick still publishes the segments that did upload into HEAD
(`gc_cycle.rs::publish_head_delta`). A partial batch can therefore
commit later writes while earlier acked writes sit in a not-yet-uploaded
output, or commit an elision whose superseding write never landed.
Host loss before the retry drains the rest turns either into a durable
image that interleaves and drops acked writes in an order no crash
could produce. The whole sequence fits in one tick; the exposure
window stays open for as long as the S3 failure persists.

**Superset rebuild.** HEAD-loss recovery LISTs `by_id/<vol>/segments/`
and includes every object found, on the stated ground that an
un-indexed segment cannot corrupt a read. Repack's elision and
reshuffling falsify that ground: an uploaded-but-unpublished output is
exactly a segment whose inclusion requires its ULID-order peers. The
rebuild can resurrect the same inconsistent tail the publish rule
guards against.

**GC supersession against uncommitted killers.** The GC pass builds
its liveness map with `pending/` layered at highest priority and the
live WAL replayed on top (`gc.rs::load_pass_state`). A durable input's
block superseded only by a pending or WAL-resident write is dead to
the pass, elided from the GC output, and the same tick's HEAD publishes
`Superseded{input → output}` — removing the input's claim from the
live set while the superseding write is possibly ticks away from
committing. Force-claim in that window resolves the LBA to a version
*older* than the one the removed input held, alongside neighbouring
writes of the same era.

All three are one defect seen from three sides: **HEAD can come to
describe a set that is not a consistent cut of any volume state.**
The segments-before-HEAD crash ordering already protects the common
case (host loss mid-drain leaves the new segments invisible); these
are the paths that leak around it.

## The principle

The remote image advances only by **cuts**. A cut is the volume's
full committed state as of one frontier: every segment the local
directory records as confirmed-in-S3, published together, or nothing.
Between cuts, S3 may hold any partial residue of uploads — invisible
to every reader, because HEAD (∪ anchor manifest) names only whole
cuts, and the rebuild path reconstructs only whole cuts.

Under this rule the volume side needs no ordering discipline at all.
Repack may elide against any pending peer, reshuffle outputs freely,
and delete all-dead segments, because remote visibility is never
partial: a reader sees the state after the whole batch or the state
before it. Intra-batch upload order stops mattering. The consistency
argument moves from "every uploaded object is individually harmless"
(false today) to "the published set is a state the volume actually
had" (enforced at one choke point).

## Design

### The tick anchors at one frontier

The tick currently runs promote-WAL → repack → reclaim → drain → GC,
with `gc_checkpoint` flushing the WAL again mid-GC, so the pass
classifies against state *newer* than what the tick drains. Under
cuts the tick fixes its frontier first: one WAL flush at tick start,
and every sub-step — repack, reclaim, drain, GC candidate selection —
operates on state at or below that frontier. Writes arriving during
the tick land beyond the frontier and belong to the next cut.

### HEAD publishes complete drains only

`publish_head_delta` runs only when the tick's drain fully succeeded.
A partial drain publishes nothing; the tick reports failure and the
next tick retries from the oldest un-drained ULID as it does today
(idempotent re-PUTs).

No new bookkeeping is needed for the carryover. The local directory
already encodes confirmation — `index/<ulid>.idx` exists exactly when
the segment is confirmed in S3 — so the cut's `added` set is derivable
at publish time: every confirmed segment not named by the anchor
manifest or the previous cut. A crash between upload and publish
self-heals the same way; the segments simply join the next complete
cut.

### A cut record precedes the HEAD overwrite

HEAD stays the single-GET read path, whole-object overwrite, exactly
as designed. What changes is durability of the *committed* delta: each
publishing tick first PUTs the identical body to an immutable key,

```
by_id/<vol_ulid>/cuts/<tick_ulid>
```

then overwrites HEAD, then DELETEs the predecessor cut record. Steady
state is one cut record plus HEAD; an ill-timed crash leaves two, and
`max(cuts/)` is always the newest committed cut. The write order makes
the record trustworthy by construction: every segment it names is
durable before the record exists, and the record exists before HEAD
asserts it.

Rebuild after HEAD loss becomes: LIST `cuts/` (one or two keys), GET
the newest, and that *is* HEAD — each record carries its anchor, so a
record raced by a seal still computes the correct live set, the same
argument the seal already makes for HEAD readers. The elevated LIST of
`segments/` is demoted from "reconstructs the live set" to what it can
soundly do: reconcile-and-reap, deleting objects that no committed cut
or manifest reaches once retention passes.

Seal-time truncation extends naturally: the sealer writes the
manifest, overwrites HEAD to empty-at-anchor, writes the matching
empty cut record, and deletes prior cut records. Cost per publishing
tick is one extra small PUT and one DELETE; idle ticks continue to
publish nothing.

### GC supersession waits for its killers

The GC pass must keep classifying against pending and WAL state — the
volume's stale-liveness check at apply time compares against its
current map, and a pass blind to recent writes would emit plans the
volume rejects. The fix is to split what the pass publishes:

- `Added{output}` commits with the tick's cut, as now. The output
  claims only live LBAs; alongside its still-live inputs it is
  harmless duplication.
- `Superseded{input → output}` commits only in a cut whose frontier
  covers every write the pass's liveness view could have classified
  against — concretely, the first cut that includes a WAL flush
  minted after the pass completed. Until then the inputs stay in the
  live set and force-claim resolves through them.

The barrier costs the inputs' storage for the ticks between output
commit and edge commit, which the reaper's retention delay already
dwarfs. After a coordinator crash the held edges are re-derived from
the output's signed `inputs` table — the same authority the rebuild
uses — and published once a post-restart cut satisfies the barrier.

## Crash ordering summary

Per publishing tick, strictly ordered:

1. PUT every segment object of the batch (ULID-ascending, as today)
2. PUT `cuts/<tick>` naming the full delta
3. PUT HEAD (same body)
4. DELETE predecessor cut record; reap per retention

A crash after 1 leaves invisible objects (reconciled later). A crash
after 2 leaves the cut committed with a stale HEAD; rebuild-from-cuts
and the next tick's fold both converge on it. A crash after 3 leaves
an extra cut record that `max()` ignores. Every prefix of the sequence
is a state the protocol already handles.

## What stays unchanged

Force-claim's read path (`live_set` over manifest ∪ HEAD), the drain's
ULID-ascending halt-on-failure, repack/reclaim/sweep semantics and
their local crash recovery, snapshot manifests, the handoff protocol,
and the volume's directory invariants all keep their current shape.
Repack sheds a burden: its outputs no longer carry any remote-ordering
obligation, which is what licenses the cross-segment elision the
loss-window work wants to widen.

## Tradeoffs

- **Staleness under persistent partial failure.** Today a
  half-successful drain makes some recent writes visible
  (inconsistently); under cuts they stay invisible until a drain
  completes. The recoverable image is older and correct. This is the
  same degradation contract as window coalescing in the loss-window
  design.
- **The rebuild invariant changes character.** "Safe superset from a
  bucket scan" becomes "newest cut record, anchored at a manifest".
  One sentence becomes a small protocol, and the reconcile pass takes
  over orphan deletion. The proptest model must assert record-fold ≡
  HEAD ≡ rebuild.
- **Two extra S3 ops per publishing tick** (one small PUT, one
  DELETE).

## Relation to the loss-window work

A cut is the commit primitive the 5-minute loss window needs: the
window design publishes cuts on a period W instead of every tick,
with repack given the window to elide before the cut closes, and the
"previous window durable before the current one closes" contract
expressed as cut N committing before cut N+1's frontier is fixed.
Nothing in this document changes shape when W grows; only the cadence
does.

## Testing

- **Cut consistency oracle.** Extend the crash-recovery proptest: at
  arbitrary points in a simulated tick (between PUTs, before/after the
  cut record, before/after HEAD), materialise the remote image exactly
  as force-claim would and assert it equals a state the write history
  could have produced — every visible write preceded by all writes
  acked before it. This is the invariant all three holes violate
  today, so the test should fail against current publish rules and
  pass under cuts.
- **Record-fold equivalence.** Property test that the incremental
  HEAD fold, the newest cut record, and a from-scratch fold of cut
  records over the anchor compute identical live sets.
- **Barrier test.** A GC pass whose inputs die only via pending/WAL
  writes publishes `Added` in the current cut and `Superseded` only
  after a cut containing a post-pass flush; force-claim between the
  two resolves the affected LBAs through the inputs.

## Open questions

- Whether the supersession barrier should be tracked per pass (exact)
  or approximated as "next cut with a post-pass flush" (simpler,
  slightly later reaping).
- Whether `snapshot` and `stop` seals should force a cut boundary
  synchronously (they already sweep-and-upload; expressing them as
  cuts makes the seal the cut) or remain a separate publish path.
- Whether the reconcile pass needs rate limiting on Tigris, where
  LIST is priced ~10× GET.
