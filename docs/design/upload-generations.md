# Design: upload generations — data rides the cut

**Status: Implemented** (generation directories, the close-rename cut,
structural deferral for both tiers). Open: per-volume upload bandwidth
shaping, the idle-volume early cut. Builds on
[durable-cut.md](durable-cut.md) (the
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
- **Upload**: a continuous per-volume flow draining the upload
  generation (below), oldest ULID first, at whatever bandwidth allows.
- **Cut** (every `cut_interval`): a predicate and a publish. With the
  upload generation empty, publish HEAD at its frontier, close the
  open generation, and start a fresh one.

## Generation directories

Generations are directories. `pending/` holds exactly two, under fixed
names:

```
pending/open/       the open generation — WAL flushes land here, and
                    every fold (repack, journal consolidation, reclaim
                    outputs) reads and writes only here
pending/upload/     the closed generation — immutable; the uploader
                    drains it, promote removes each file after its
                    upload confirms, and an empty directory is a fully
                    uploaded generation
```

The cut tick, when `pending/upload/` is empty: publish HEAD, remove
`upload/`, rename `open/` → `upload/`, create a fresh `open/`,
fsync `pending/` once. Each step is idempotent or atomic, so a crash
at any point leaves one of three shapes — `open` alone, `open` beside
`upload`, or an empty `upload` whose publish may or may not have
landed — and publish is derived (`confirmed_beyond`), so re-running it
is harmless.

Membership is assigned once, at write time, by which directory a file
lands in, and nothing can move a file between generations: folds are
confined to `open/` by construction, and `upload/` is only ever
read and emptied. The fold-never-crosses rule is therefore not an
invariant to check but a thing the layout cannot express violating.
`ls pending/` shows the entire generation state of a volume — what is
open, what is uploading, and how much of it remains.

The migration from today's flat `pending/` is local-only: the segment
format, S3 objects, and every published artefact are untouched. First
start under the new layout moves any flat pending files into `open/`.

## One upload generation, never a queue

A cut whose upload generation has not emptied does not close: the
open window stretches, cut age grows past `cut_interval`, and the
`[head]` publish line's `age` field (#848) is the health signal.

Letting closed generations queue instead would upload *more* bytes
precisely when bandwidth is scarcest: folds cannot cross generation
boundaries, so content split across queued generations can never
consolidate again, and each queued window ships its own journal slice
and its own not-yet-dead data. The stretched-window rule inverts the
cost — under backpressure the open generation keeps folding, more of
its content dies before ever uploading, and the eventual batch is
smaller. A stall's byte cost is negative. RPO degrades identically in
both schemes (unshipped is unshipped), so the queue would buy no
durability.

Worst-case durability lag in steady state is ~2W: a byte written just
after a close is published two cuts later. That is the loss-window
semantics already accepted for the journal tier, now uniform across
the stream.

## Why membership is not fold identity

An age gate on segment ULIDs starves. Repack mints a fresh ULID for
every fold, so a segment that consolidation keeps absorbing never ages
— observed directly on the rig as the consolidation chain
`X9V → H8N → 0R → EAV`, one fold per tick — while the write-times of
the content it carries grow arbitrarily old. Any eligibility rule
keyed on fold identity lets live claims for old acked writes sit local
forever, and a cut anchored past those write-times would publish a set
missing them.

Directory membership is content age: a file's generation is fixed when
its content enters `pending/`, and folding inside `open/` re-mints
ULIDs without moving anything across the boundary. Starvation is
structurally impossible — every acked byte is durable at most one
stretched-open window plus one upload window after write.

## One frontier for both tiers

The published image must hold journal and data at the same frontier.
An image with journal state at `T1` but data at `T0` replays jbd2
metadata that references data blocks older than the metadata records —
a `data=ordered` violation no real crash can produce, and exactly the
class of un-crash-like image the durable cut exists to prevent.

So the journal defers a full window too: consolidation runs within
`open/`, each generation ships its own ring slice, and S3 holds
per-window journal slices ordered by claimant — the same shape the
committed tier has today at per-tick granularity. Journal PUTs stay at
one per cut; only the content they carry lags a window. This amends
the single-output merge in
[journal-pending-consolidation.md](journal-pending-consolidation.md)
to generation scope.

## Elision stays inside the generation

A rewrite may elide a victim only against a killer that publishes in
the same cut. Two rules make every elision safe:

- **Segment-resident killers only.** Repack classifies a body dead
  only when the superseding claim is held by a segment. **Verified:**
  this is already structural — `prepare_repack` mints `u_flush` and
  flushes the WAL into the open generation *before* snapshotting the
  lbamap, so every claim the classifier sees is segment-resident and
  publishes with the elision; writes racing in after prepare claim
  under a newer WAL the snapshot never contains. The
  flush-before-snapshot ordering is the load-bearing line, pinned by
  `repack_elision_always_ships_the_killer` (volume_reproducers.rs).
- **Folds stay in `open/`.** Victim, killer, and fold output share a
  generation and publish together at its cut.

Cross-generation deaths (an open-generation write killing an upload-generation
byte) are deliberately not elided: the byte ships and dies later in S3
through the normal GC path. The mortality curve prices this cost — it
is the tail beyond the knee, and the knee is what the window harvests.

## ULID order across the boundary

The mint is monotonic by design: a rewrite output sorts above every
write that existed when it was planned, so concurrent writes always
win their claims. The close pass folds `pending/upload/`
(`generation-close-pass.md`) and mints its outputs from the same mint,
so a sealed generation can hold the newest ULIDs in the volume while an
open-generation segment sits below them.

Claimant order still tracks write order, and the classifier is what
carries it. An entry is live only where its own segment is the LBA's
current claimant (`segment_classify::classify_entry`), so a close-pass
output claims an LBA only where the sealed generation still owns it. An
LBA a concurrent write has taken is dropped from the output and stays
with that writer, whose ULID may sit below the output's.

Every write the classifier must see is in the snapshot it reads:
`write_commit` installs the lbamap claim under the WAL's ULID before
returning, and the close prep snapshots under the volume lock. So a
write acknowledged before the prep is visible to the classifier, and one
arriving after mints above the output.

The boundary rests on that claimant gate. Matching an entry on hash and
anchor alone lets a close-pass output claim LBAs a lower-ULID
open-generation segment owns — a claim the apply refuses and a rebuild
grants, which is the divergence #873 closed.

The strict `max(committed) < min(pending)` reading died with journal
deferral (#844 split it per tier); a GC output minted mid-window still
commits (`Added`) above the open generation's pending ULIDs.
Generations scope the invariant once more: within a generation ULID
order is total; across the boundary, membership is the directory and
claimant order alone carries correctness.

## Relation to snapshots

A generation is a cut-cadence frontier with snapshot-floor semantics
that last one window instead of forever, and no published artefact. A
seal is already a synchronous cut boundary, and a snapshot floor
already excludes every prior segment from rewriting (`collect_stats`
skips `seg_ulid <= floor`) — the generation boundary is the same
exclusion made literal: a directory folds cannot reach. It expires
when the generation publishes and its segments become ordinary
committed-tier citizens, with no named manifest, no retention, and
accumulate-into-HEAD rather than truncate-and-re-anchor. A mid-window
user snapshot forcibly closes the open generation and ships the
backlog — the strong frontier subsumes the weak ones.

## The uploader

A per-volume flow draining `pending/upload/`, oldest ULID first,
each PUT followed by its promote IPC as today
(`upload.rs::drain_pending`), with promote removing the shipped file.
The directory is immutable while it ships, so the uploader and the
tick work disjoint sets by construction; a path listed before the seal
races only the seal's own full drain, which the per-volume snapshot
lock already serialises. Upload confirms are the file removals — the
cut predicate is the directory being empty. Per-volume bandwidth
shaping slots in here as a drain rate, orthogonal to correctness.

## Seals

Every seal remains a synchronous cut boundary, now spanning the whole
backlog: ship `upload/`, close and ship `open/`, publish. `volume
stop`, snapshot, handoff and displacement latency scale with up to ~2W
of survivors. This is the user-visible cost of the design and the
reason the idle-volume early cut matters: a quiescent volume's open
generation is empty and its upload generation drains dry, so closing
early costs nothing and drops both the RPO and the eventual seal
latency to ~zero.

## GC

GC's candidate set, classification, and the Superseded barrier are
untouched: the pass already works over local `index/` + `pending/` +
WAL, with pending now read one directory deeper. The pass gate's
"complete drain" input becomes "uploader healthy" (no failed PUTs
outstanding), since a mid-window tick with a part-full upload
directory is now the normal complete state — the same reframing
`deferred ≠ failed` got in #844.

## Testing

The cut consistency oracle (`gc_cycle.rs` tests) gains the generation
dimension: mutations interleave with partial uploading, and the
materialised force-claim reader must always see a whole-generation
prefix. The volume proptest suite gains ops for the close rename and
mid-upload crash, plus invariant checks: `pending/` holds exactly
`open/` and at most `upload/`; every fold's inputs and output share
a directory; no published frontier splits a generation; the journal
frontier equals the data frontier; and every acked write is durable
within two windows in wall-clock-free simulation time.
