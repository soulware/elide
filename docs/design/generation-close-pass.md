# Design: the close pass over a sealed generation

**Status:** Implemented, sized against `REPACK_TARGET_LIVE` (see *Sizing
outputs*). Builds on upload generations (`upload-generations.md`) and
journal consolidation (`journal-pending-consolidation.md`), both
shipped. Pairs with `open-generation-repack.md`, which covers the pass over
`pending/open/`.

## Problem

`close_generation` is a bare directory rotate:

```rust
pub fn close_generation(&mut self) -> io::Result<Option<u32>> {
    let rotated = segment::rotate_open_generation(&self.base_dir)?;
```

So a cut ships whatever happens to be in `pending/open/` at the instant it
fires. Repack runs on the tick, from `run_volume_compactions`, which calls
`promote_wal` and then `repack`. That leaves `pending/open/` holding the
tick's outputs plus every segment a WAL flush formed since, and the cut
closes all of them into `pending/upload/` as separate objects.

Measured on rig pg14 (2026-08-04, v0.1.46, `cut_interval = 120s`, 8-client
pgbench at 550 to 750 tps), one sealed generation held three journal
segments: a 224-entry consolidation output of 380 KiB, and two stragglers
of 2 entries and 3.4 KiB each.

The cost shows up twice, at the same factor:

- **Requests.** About 3.5 journal objects per cut where the design intends
  one, so roughly 2 extra PUTs per cut, 60 an hour per volume.
- **Object population.** A committed journal segment lives until the jbd2
  head laps back over its last position, so each straggler holds a slot for
  a full ring lap. A 33-minute lap over 120s cuts predicts ~17 live journal
  segments. The volume settled at ~60.

The second is the larger effect. Stragglers set the journal object count
for the whole volume, not just the per-cut request count.

Data segments arrive the same way. The same generation held eleven of them,
sized 2.8, 3.2, 3.9 and 4.9 MiB alongside the 8 to 10 MiB the fold
produces, because a flush after the last tick ships whatever the WAL had.
Every one of those is its own S3 object, and the small ones would fit
alongside a peer inside one part.

## Approach

The cut becomes a prepare/execute/apply cycle, the same shape promote,
repack, GC and reclaim already use, and the rotate happens **first** so the
pass runs over a sealed generation.

1. **Prepare (actor, under the volume mutex, cheap).** In one critical
   section, mint the reserved output ULIDs, data first and journal last,
   and then `rotate_open_generation`. Classify the sealed generation and
   build the job.
2. **Execute (worker, no lock).** Repack `pending/upload/` in place:
   bin-pack its data segments into the reserved data ULIDs, merge its
   journal segments into the reserved journal ULID.
3. **Apply (actor, under the mutex, cheap).** Register the outputs, unlink
   the inputs, publish.

The generation then drains as one journal object and a small number of
packed data objects.

This is `execute_repack` aimed at `pending/upload/` rather than at
`pending/open/`. The bin-pack, the classifier, the journal consolidation
with `allow_journal`, the output signing, the consuming-inputs apply and
the crash model are all reused. What changes is the directory it reads,
that its inputs cannot move underneath it, and how its outputs are sized.

## Why the rotate goes first

A sealed generation is immutable. `pending/upload/` takes no new segments,
so the pass races nothing.

Consolidating before the rotate moves the straggler window rather than
closing it: writes continue while the pass runs, so fresh segments land in
`pending/open/` and the rotate ships them unpacked. That is the behaviour
being fixed, reintroduced one step later.

Immutable inputs are also what separates this pass from the one over
`pending/open/`, which runs against a directory that formation is actively
adding to. Mortality is monotone, so a byte superseded mid-window is still
superseded at the seal and this pass harvests it either way. What a pass
over the open generation bounds is that directory's footprint and segment
count while it is held open, which `open-generation-repack.md` covers. The
close pass runs once, over a fixed set, and its job is the object count and
object size the fold leaves behind.

## Sizing outputs

The bin-pack already measures the units S3 charges for. A candidate's
`live_bytes` sums `stored_length`, the length of the body in the form its
codec names, so `REPACK_TARGET_LIVE` is 32 MiB of *stored* bytes and a
packed output lands near that size on disk and on S3.

What is sized in plaintext is formation. `FLUSH_THRESHOLD` is 32 MiB of
WAL bytes, and the ratio belongs to the workload, so a flush segment
arrives at whatever that compresses to — measured on pg14, 2.8 to 4.9 MiB
alongside the 8 to 10 MiB ones. Those are the objects the close pass packs.

That leaves the target itself as the open question. `REPACK_TARGET_LIVE` is
six times `DEFAULT_PART_SIZE_BYTES` (5 MiB), so a packed output uploads as
several parts. Sizing to the part size instead would make every object a
single PUT, at the cost of more objects per generation, which is the
population the pass exists to hold down. The two pull opposite ways and the
trade wants measuring against Tigris request pricing before it is picked.

## Output ULIDs

Every output takes a freshly minted ULID, which is what closes the
path-aliasing race against concurrent readers, the same reason
`execute_repack` and GC mint them: a reader can hold a descriptor for a
name it already resolved and must never find different bytes under it.

The reservations are minted in the same critical section as the rotate, so
they land above every segment in the generation being sealed and below
every segment the next generation mints. Data outputs are minted before the
journal output, so within the sealed generation the merged journal is the
highest ULID and uploads running ULID-ascending still put a segment's data
on S3 before the journal that references it, which is the `data=ordered`
requirement from `journal-pending-consolidation.md`.

The output count is not known until the pass sizes its inputs, so prepare
over-reserves. The mint is a monotonic counter, so unused reservations cost
nothing and are discarded.

## Ordering against the open generation and the WAL

A WAL file carries its own ULID, minted in `ensure_wal_open` above every
prior segment and checkpoint ULID, and in-flight claims are staged against
it. That ULID does not name the segment the WAL becomes. `prepare_promote`
mints a fresh `segment_ulid` at flush time and the promote job carries the
WAL's own alongside it as `old_wal_ulid`.

The separation is what makes the ordering hold. A segment landing in
`pending/open/` after the rotate is named by a ULID minted at its flush, so
it outranks any reservation minted in the rotate's critical section, and
the open generation is empty at that instant.

The WAL's own ULID still governs the window between the rotate and the
apply. An in-flight write's claim sits at that ULID, which can be below a
reservation, so the apply installs through the consuming-inputs rule rather
than a strict-newer guard: it takes a sub-range only where the current
claimant is one of the inputs it consumes, and every other claimant keeps
its sub-range because it marks a write the pass did not carry. This is what
`execute_repack`'s apply already does.

## Cost

A generation on pg14 holds around 75 MiB across ~15 segments and ~57,000
entries. Materialising that is a decompress and a zstd-3 recompress, near
0.6s of worker CPU against a 120s cut, on a thread that is otherwise idle
between ticks. The generation's bodies are all local, so the pass issues no
S3 GETs to do it.

## Timing

A cut is drain, publish, close. The generation just sealed is not drained
until the *next* cut, so the pass has a full cut interval to complete and
the cut's critical path grows by a mint and a classification.

The drain of a generation must not begin before that generation's pass has
applied, and a seal (`drain_volume_for_seal`) must find it settled for the
same reason. Both run on the tick loop, so this is sequencing rather than
synchronisation, and it needs a stated answer for a pass still running when
either arrives. Waiting is the simple form.

## Crash

The reservations live in memory. A crash between the rotate and the apply
leaves the sealed generation intact in `pending/upload/` with its inputs
unpacked, and by the time the volume restarts the mint has advanced past
segments the new `pending/open/` already holds. Re-minting then would place
a journal ULID above pending segments, and committing that generation would
put a committed segment above a pending one.

So a generation whose reservations are lost ships as it stands. The pass is
a cost optimisation, so degrading to more objects preserves every
correctness property, and the next cut seals a fresh generation with fresh
reservations.

The execute phase itself carries repack's crash model: inputs stay in place
until the apply, and a retry is idempotent.

## The pass as a hook

Consolidation is the first tenant, not the purpose. A sealed generation is
the only point in the pipeline where a complete, immutable, not-yet-uploaded
batch exists in one place, with live state still available to classify it,
which makes it the natural home for work that wants to see a whole cut
before its bytes are paid for:

- cross-segment dedup within the cut, which the fold cannot do once the
  bytes are split across generations
- delta selection against sources the cut itself introduced
- re-encoding at a higher compression level, affordable here because the
  bytes are leaving the machine either way

Each is a separate proposal, and each is heavier than packing. The
structure they share is the prepare/execute/apply cycle above with a
different execute, so the close pass is worth building as a cycle that
takes a job rather than as one hard-coded merge.

## Non-goals

- No change to what a generation means or how HEAD names it.
- No work on the cut's critical path beyond the mint and the classify.
- No change to the segment format or the S3 object layout.
