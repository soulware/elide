# Design: upload generations — data rides the cut

**Status: Proposed.** Builds on [durable-cut.md](durable-cut.md) (the
cut as commit primitive, complete-drain publish, HEAD-anchored
recovery) and
[journal-pending-consolidation.md](journal-pending-consolidation.md)
(journal upload deferred to the cut, #844). Sized by the byte-mortality
measurement (2026-08-03, rig pg14, ~100 tps under 52–56% steal):
data-tier bytes dead by 2m 7%, by 5m 33%, by 10m 58%; the journal is a
pure ring that dies only at wrap. Production write rates shift the
data curve left roughly in proportion, so a 5-minute window at
production tps sits nearer the 60–70% mark.

## Problem

Data segments upload eagerly, one drain per tick. Under the cut model
this buys no durability: force-claim anchors at HEAD, and a segment
uploaded but not yet named by a cut is invisible to recovery. RPO is
already the cut cadence. What eager staging costs is bytes: every byte
that dies within the cut window is uploaded, stored, superseded by GC
and deleted, all for nothing — a third of the data tier at the
measured rate, likely two thirds at production rates. Upload bandwidth
is the constrained resource, and eager staging spends more of it than
deferred staging needs.

Journal deferral (#844) fixed this for one tier by holding pure-journal
pending segments between cuts. It also quietly made the system
two-speed: ordinary ticks do local work, and the cut tick does
everything — flush, consolidate, full drain, publish — serially in one
loop iteration (`gc_cycle.rs::run_tick`). Extending deferral to data
under that structure would make the cut tick arbitrarily large.
The design below instead restores a small fast tick and gives each
cadence one job.

## Three cadences

- **Tick** (fast, seconds): local work only. WAL flush, journal
  consolidation, repack, reclaim. Its job is to keep the local segment
  set compact so that what eventually uploads is the minimal surviving
  byte set. It never awaits S3.
- **Upload**: a continuous per-volume flow draining closed generations
  (below), oldest ULID first, at whatever bandwidth allows.
- **Cut** (every `cut_interval`): a predicate and a publish. Verify the
  previous generation is fully confirmed, close the current one, and
  publish HEAD at the closed frontier.

## Generations

Cut boundaries partition the write stream into generations. With
window N spanning `(T0, T1]`:

1. **Open** `(T0 < now ≤ T1)`: generation N is repack's playground.
   Every tick folds its segments — journal consolidation, data repack,
   reclaim — harvesting deaths as they happen. Nothing in an open
   generation uploads.
2. **Closing** (the cut tick at `T1`): the closing WAL flush lands,
   the generation takes one final consolidation among its own
   segments, and its survivor set becomes immutable.
3. **Shipping** `(T1 < now ≤ T2)`: the uploader drains generation N's
   survivors across window N+1, spreading the bytes over the whole
   window. Steady-state bandwidth is `(1 − elided) × write rate`, with
   no burst at the boundary.
4. **Published** (the cut at `T2`): with generation N fully confirmed,
   HEAD publishes at frontier `T1`. Segments and HEAD keep the
   existing crash ordering.

Worst-case durability lag is ~2W: a byte written just after `T0` is
published at `T2`. That is the loss-window semantics already accepted
for the journal tier, now uniform across the stream.

A cut whose previous generation has not finished shipping does not
close: the window stretches, cut age grows past `cut_interval`, and
the `[head]` publish line's `age` field (#848) is the health signal.
Bandwidth below the sustained survivor rate therefore degrades RPO
visibly rather than corrupting anything.

## Content age, never fold identity

An age gate on segment ULIDs starves. Repack mints a fresh ULID for
every fold, so a segment that consolidation keeps absorbing never ages
— observed directly on the rig as the consolidation chain
`X9V → H8N → 0R → EAV`, one fold per tick — while the write-times of
the content it carries grow arbitrarily old. Any eligibility rule
keyed on fold identity lets live claims for old acked writes sit
local forever, and a cut anchored past those write-times would publish
a set missing them.

Eligibility and cut completeness are therefore defined over **content
age**: each segment carries a content ceiling, the newest write it
holds (a flush segment's own ULID; a fold output takes the max of its
inputs). A fold may combine segments only within one generation, so
ceilings stay inside their window and the closing consolidation is the
last fold a generation ever sees. Starvation is structurally
impossible: every acked byte is durable at most one closing plus one
shipping window after write.

## One frontier for both tiers

The published image must hold journal and data at the same frontier.
An image with journal state at `T1` but data at `T0` replays jbd2
metadata that references data blocks older than the metadata records —
a `data=ordered` violation no real crash can produce, and exactly the
class of un-crash-like image the durable cut exists to prevent.

So the journal defers a full window too. Consolidation becomes
per-generation rather than unbounded: each cut ships the closed
window's ring slice, and S3 holds per-window journal slices ordered by
claimant, the same shape the committed tier has today at per-tick
granularity. Journal PUTs stay at one per cut; only the content they
carry lags a window. This amends the single-output merge in
[journal-pending-consolidation.md](journal-pending-consolidation.md)
to generation scope.

## Elision stays inside the generation

A rewrite may elide a victim only against a killer that publishes in
the same cut. Two rules make every elision safe:

- **Segment-resident killers only.** Repack classifies a body dead
  only when the superseding claim is held by a pending or committed
  segment. A claim still in the WAL does not kill: it waits for its
  flush, which the very next tick's fold sees. This mirrors GC's
  supersession barrier (`durable-cut.md` *GC supersession waits for
  its killers*) at the repack layer.
- **Folds never cross a boundary.** With the closing consolidation
  running on the cut tick immediately after the closing flush, every
  killer visible to it is generation-N-resident, so victim and killer
  always publish together at `T2`.

Cross-generation deaths (a window-N+1 write killing a window-N byte)
are deliberately not elided: the byte ships and dies later in S3
through the normal GC path. The mortality curve prices this cost —
it is the tail beyond the knee, and the knee is what the window
harvests.

**Open:** whether today's classifier already refuses WAL-only killers.
`still_at_input` (`repack.rs`) tests the live map, which carries
claims for unflushed writes; if those can mark a pending body dead,
the flush-to-snapshot ordering inside the tick is what makes it safe
today, and the segment-resident rule makes it explicit. To verify at
the `register_entry` choke point during implementation.

## The uploader

A per-volume queue of closed-generation segments, drained oldest ULID
first, each PUT followed by its promote IPC as today
(`upload.rs::drain_pending`). Closed segments are immutable by the
generation rule, so the repack-vs-upload race collapses to the closing
instant: the promote-after-upload step keeps a *still-pending* gate
(a segment consumed between PUT and promote leaves a harmless S3
orphan for reconcile-reap and must not re-register), but in steady
state the uploader and repack work disjoint sets by construction.

Upload confirms advance a per-generation completion count; the cut
predicate is "generation N fully confirmed". Per-volume bandwidth
shaping slots in here as a queue drain rate, orthogonal to
correctness.

## Seals

Every seal remains a synchronous cut boundary, now spanning the whole
backlog: close the open generation, ship everything (both closed
windows), publish. `volume stop`, snapshot, handoff and displacement
latency scale with up to ~2W of survivors. This is the user-visible
cost of the design and the reason the idle-volume early cut matters:
a quiescent volume's open generation is empty and its shipping window
drains dry, so closing early costs nothing and drops both the RPO and
the eventual seal latency to ~zero.

## GC

GC's candidate set, classification, and the Superseded barrier are
untouched: the pass already works over local `index/` + `pending/` +
WAL, and edge visibility already waits for a covering cut. The pass
gate's "complete drain" input becomes "uploader healthy" (no failed
PUTs outstanding), since a mid-window tick with a deferring uploader
is now the normal complete state — the same reframing `deferred ≠
failed` got in #844.

## Testing

The cut consistency oracle (`gc_cycle.rs` tests) gains the generation
dimension: mutations interleave with partial shipping, and the
materialised force-claim reader must always see a whole-generation
prefix. The volume proptest suite gains ops for generation close and
mid-shipping crash, plus invariant checks: content ceilings are
monotone under folds and never cross a boundary; no published frontier
splits a generation; journal frontier equals data frontier; every
acked write is durable within two windows in wall-clock-free
simulation time.
