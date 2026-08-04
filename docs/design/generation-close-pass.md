# Design: the close pass over a sealed generation

**Status:** Proposed. Builds on upload generations (`upload-generations.md`)
and journal consolidation (`journal-pending-consolidation.md`), both
shipped.

## Problem

`close_generation` is a bare directory rotate:

```rust
pub fn close_generation(&mut self) -> io::Result<Option<u32>> {
    let rotated = segment::rotate_open_generation(&self.base_dir)?;
```

So a cut ships whatever happens to be in `pending/open/` at the instant it
fires. Journal consolidation runs on the tick, from
`run_volume_compactions`, which calls `promote_wal` and then `repack`. That
leaves `pending/open/` holding one consolidation output plus every journal
segment formed by a WAL flush since the last tick, and the cut closes all
of them into `pending/upload/` as separate objects.

Measured on rig pg14 (2026-08-04, v0.1.46, `cut_interval = 120s`,
8-client pgbench at 550 to 750 tps), one closed generation held three
journal segments: a 224-entry consolidation output of 380 KiB, and two
stragglers of 2 entries and 3.4 KiB each.

The cost shows up twice, at the same factor:

- **Requests.** About 3.5 journal objects per cut where the design intends
  one, so roughly 2 extra PUTs per cut, 60 an hour per volume.
- **Object population.** A committed journal segment lives until the jbd2
  head laps back over its last position, so each straggler holds a slot for
  a full ring lap. A 33-minute lap over 120s cuts predicts ~17 live journal
  segments. The volume settled at ~60.

The second is the larger effect. Stragglers set the journal object count
for the whole volume, not just the per-cut request count.

Data segments arrive the same way. The same generation held eleven of
them, sized 2.8, 3.2, 3.9 and 4.9 MiB alongside the 8 to 10 MiB the fold
produces, because a flush after the last tick ships whatever the WAL had.
Every one of those is its own S3 object, and the small ones would fit
alongside a peer inside one part.

## Approach

The cut becomes a prepare/execute/apply cycle, the same shape promote,
repack, GC and reclaim already use, and the rotate happens **first** so the
work runs over a sealed generation.

1. **Prepare (actor, under the volume mutex, cheap).** In one critical
   section, mint the reserved output ULIDs, data first and journal last,
   and then `rotate_open_generation`. Return the input list and the
   reservations as a worker job.
2. **Execute (worker, no lock).** Splice the sealed generation's small
   segments together inside `pending/upload/`, data into the reserved data
   ULIDs and journal into the reserved journal ULID.
3. **Apply (actor, under the mutex, cheap).** Register the outputs, unlink
   the inputs, publish.

The generation then drains as one journal object and a small number of
packed data objects.

## A splice, not a repack

The pass copies body sections and rebases index offsets. It does not
classify liveness, does not resolve entries through `BlockReader`, and does
not decompress or re-encode a single body. An entry crosses into the output
byte-identical, with `stored_offset` shifted by where its input's body
section landed, and the output is signed as a fresh segment.

That is enough because the byte elision has already happened. The fold in
`pending/open/` is what harvests the mortality knee, and by the time a
generation seals, its contents average half a cut interval old. The
measured data-tier curve puts that at a few percent dead, so a full
classification pass over a sealed generation would pay the read path to
find almost nothing. The close pass exists to cut object count, not bytes.

Working on already-compressed bodies also gives the pass something
formation cannot have. `FLUSH_THRESHOLD` is 32 MiB of plaintext, so the
compressed object size it produces is emergent and varies with how
compressible the workload is. A splice over a sealed generation knows every
input's exact compressed size before it writes anything, so it can size its
outputs in both directions against a compressed target, packing the small
and splitting the oversize. The obvious target is the multipart part size,
so that every object it emits uploads as a single PUT.

The target is a soft cap, as `FLUSH_THRESHOLD` is. Splits fall on entry
boundaries, so an entry whose own compressed body exceeds the target
produces an output that exceeds it too.

Two things the splice gives up against a rewrite. Entries that were
superseded within the generation ride along rather than being dropped, and
identical bodies appearing in two inputs stay duplicated. Both are bounded
by one cut's worth of writes, and both are reclaimed later by GC through
the normal path.

## Why the rotate goes first

A sealed generation is immutable. `pending/upload/` takes no new segments,
so a merge over it races nothing and needs no lock for the duration of the
work.

Consolidating before the rotate moves the straggler window rather than
closing it: writes continue while the merge runs, so fresh journal segments
land in `pending/open/` and the rotate ships them uncollapsed. That is the
behaviour being fixed, reintroduced one step later.

It also keeps the volume mutex free of heavy IO, which is the invariant the
whole actor is built around. `VolumeClient::write` and
`write_zeroes` take that mutex directly from the ublk transport on every
guest IO, and with FUA they fsync inside the same critical section. Every
materialise in the system already runs on the worker with the lock
released, and the close pass matches.

## ULID ordering

The reservations are minted in the same critical section as the rotate, so
they land above every segment in the generation being sealed and below
every segment the next generation mints. Three properties follow.

Data outputs are minted before the journal output, so within the sealed
generation the merged journal is the highest ULID. Uploads running
ULID-ascending then still put a segment's data on S3 before the journal
that references it, which is the `data=ordered` requirement from
`journal-pending-consolidation.md`. This is the same ordering
`prepare_repack` establishes, and it is why data consolidation and journal
consolidation belong in one pass rather than two: a pass that lifts data to
fresh ULIDs must lift the journal above it in the same reservation.

Against the next generation, every reservation sorts below everything
`pending/open/` will hold, so a drained generation never commits a segment
that outranks one still pending.

The output count is not known until the pass sizes its inputs, so prepare
over-reserves. The mint is a monotonic counter, so unused reservations cost
nothing and are discarded.

Every output takes a reservation, including the halves of a split. Fresh
ULIDs are what close the path-aliasing race against concurrent readers, the
same reason `execute_repack` and GC mint them, since a reader can hold a
descriptor for a name it already resolved and must never find different
bytes under it.

## Ordering against the open generation and the WAL

A WAL file carries its own ULID, minted in `ensure_wal_open` above every
prior segment and checkpoint ULID, and in-flight claims are staged against
it. That ULID does not name the segment the WAL becomes. `prepare_promote`
mints a fresh `segment_ulid` at flush time and the promote job carries the
WAL's own alongside it as `old_wal_ulid`.

The separation is what makes the ordering hold. A segment landing in
`pending/open/` after the rotate is named by a ULID minted at its flush,
so it outranks any reservation minted in the rotate's critical section, and
the open generation is empty at that instant.

The WAL's own ULID still governs the window between the rotate and the
apply. An in-flight write's claim sits at that ULID, which may be below a
reservation, so the apply installs through the consuming-inputs rule rather
than a strict-newer guard: it takes a sub-range only where the current
claimant is one of the inputs it consumes, and every other claimant keeps
its sub-range because it marks a write the pass did not carry.

What needs care is recency. ULID order decides a claim across segments and
entry order decides it within one (`lbamap.rs`), so both directions of the
splice must preserve the total order they were given:

- **Packing** concatenates inputs in ULID order, so a later input's claim
  lands after an earlier one's in the output, and entry-order-wins
  reproduces exactly what ULID-order-wins decided before.
- **Splitting** partitions entries in index order, so earlier entries take
  the lower reservation, and entry order becomes ULID order.

Preserving the order is what lets the splice skip liveness. A pack that
reordered inputs, or a split that partitioned by size rather than position,
would resolve a doubly-claimed LBA to the wrong entry.

## Timing

A cut is drain, publish, close. The generation just sealed is not drained
until the *next* cut, so the merge has a full cut interval to complete and
the cut's critical path grows by one ULID mint.

The drain of a generation must not begin before that generation's merge has
applied. Both run on the tick loop, so this is sequencing rather than
synchronisation, and it needs a stated answer for a merge still in flight
when the next cut fires. Waiting one cut is the simple form.

## Crash

The reservation lives in memory. A crash between the rotate and the apply
leaves the sealed generation intact in `pending/upload/` with its inputs
unmerged, and by the time the volume restarts the mint has advanced past
segments that the new `pending/open/` already holds. Re-minting then would
place a journal ULID above pending segments, and committing that generation
would put a committed segment above a pending one.

So a generation whose reservation is lost ships unmerged. The merge is a
cost optimisation, so degrading to more objects preserves every correctness
property, and the next cut seals a fresh generation with a fresh
reservation.

The execute phase itself carries the existing repack crash model: inputs
stay in place until the apply, and a retry is idempotent.

## The envelope

What a sealed generation offers is a complete, immutable batch of signed
segments whose bodies are already compressed, reachable without the read
path, with a cheap prepare and apply on either side. That is the whole of
what the pass may assume.

It can:

- **Pack** several inputs into one output, concatenating in ULID order.
- **Split** an input across several outputs, partitioning in index order.
- **Size** its outputs against a compressed target, because every input's
  compressed length is known before a byte is written.
- **Emit pure-tier outputs**, journal entries into the journal reservation
  and data into the data ones, keeping tier purity and data-below-journal.
- **Run off the actor**, holding the volume mutex only to mint and rotate,
  and again to register and unlink.

It cannot:

- **Reorder inputs.** Recency is carried by ULID order across segments and
  entry order within one, so a size-greedy bin-pack of the kind
  `execute_repack` uses would resolve a doubly-claimed LBA to the wrong
  entry. Packing is a linear scan that closes an output when the next input
  would take it past the target.
- **Drop a body on local evidence.** A `DedupRef` or a delta option in
  `pending/open/` or in the WAL resolves backwards into older bodies, this
  generation's among them, so the generation's own index files cannot prove
  a body unreferenced.
- **Split an entry.** Outputs break on entry boundaries, so a single
  compressed body above the target produces an output above the target.
- **Apply with a strict-newer guard.** An in-flight write's claim sits at
  the WAL's own ULID, which can be below a reservation.
- **Emit more outputs than prepare reserved.** The reservation count is
  fixed before the inputs are sized, so over-reserving is what buys the
  freedom to split.
- **Return anything to `pending/open/`.** Every reservation sorts below the
  open generation, and HEAD names whole generations, so a sealed generation
  ships entire or not at all.
- **Survive losing its reservation.** A crash before the apply means the
  generation ships unspliced.
- **Outlast the generation.** The drain and any seal
  (`drain_volume_for_seal`) must find the generation settled, so a splice
  still running when either arrives has to be waited on or abandoned.

The line between the two lists is local information. Everything the pass
can do follows from the generation's own bytes and index files. Everything
it cannot do needs live state, either the lbamap or the extent index, and
consulting those at prepare is precisely what makes a pass a repack rather
than a splice. That is the choice to make deliberately per tenant, not a
limit to design around.

## The pass as a hook

Consolidation is the first tenant, not the purpose. A sealed generation is
the only point in the pipeline where a complete, immutable, not-yet-uploaded
batch exists in one place, which makes it the natural home for any work
that wants to see a whole cut's bytes before they are paid for:

- cross-segment dedup within the cut, which the fold cannot do once the
  bytes are split across generations
- delta selection against sources the cut itself introduced
- dropping entries the cut superseded internally, which the splice carries
- re-encoding at a higher compression level, affordable here because the
  bytes are leaving the machine either way

Each of those is a separate proposal, and each is heavier than a splice.
The structure they share is the prepare/execute/apply cycle above with a
different execute, so the close pass is worth building as a cycle that
takes a job rather than as one hard-coded merge.

## Non-goals

- No change to what a generation means or how HEAD names it.
- No work on the cut's critical path beyond the mint.
- No change to the segment format or the S3 object layout.
