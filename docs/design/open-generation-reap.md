# Design: the open generation reaps, the close pass packs

**Status:** Proposed. Revises the division of labour set out in
`open-generation-repack.md` and `generation-close-pass.md`, both implemented.
Builds on upload generations (`upload-generations.md`) and journal
consolidation (`journal-pending-consolidation.md`).

## Problem

`open-generation-repack.md` already establishes that mortality is monotone, so
one pass over the sealed generation harvests exactly the dead bytes that N
passes over the window harvest, and that the only remaining job for a pass over
`pending/open/` is bounding that directory while it is held open.

The implementation still runs a full `execute_repack` to do that bounding, and
the cost lands in three places.

**The open window is too short to hold dead bytes.** `pending/open/` is emptied
by every cut, so its contents are at most one `cut_interval` old. Measured byte
mortality has its knee between two and ten minutes. A pass over that window
reads, classifies, recompresses and re-signs bytes that have had seconds to die,
and the data half of it returns close to nothing.

**The close pass repeats the reading.** It runs with `settled_floor: None`, so
every segment in the sealed generation is parsed, Ed25519-verified and fully
classified a second time, including the outputs the open pass has just written.
Re-materialisation is narrower, since a 32 MiB output is already at
`REPACK_TARGET_LIVE` and the bin-pack rarely improves it, but a smaller open-pass
output is rewritten outright within one cut window.

**Admission is decided after the work is paid for.** Phase 1a parses and verifies
every candidate before `admit_within_budget` sees any of them, so a segment the
budget turns away costs a full parse. The settled-density check has the same
inversion. Its purpose is to skip a classification, and reaching it costs the
parse and the signature verify that classification would have shared.

Around that sits machinery whose whole reason for existing is the stalled drain:
`repack_watermark`, `repack_settled_cursor`, `REPACK_SETTLED_SCAN`,
`REPACK_SETTLED_DENSITY`, `REPACK_PRESSURE_BYTES`, `REPACK_PRESSURE_SEGMENTS` and
`RepackTrigger`. A stall path is shaping the steady-state path.

## Decision: packing happens once, at the close

The close pass becomes the only pass that materialises bytes. It is the right
place on every axis. It is the last point before bytes leave the host, so it is
where S3 object count and uploaded bytes are decided; its generation is sealed,
so it races nothing; and it sits off the critical path, since the close runs
after the cut lands and its outputs drain in the following window.

The open generation keeps its bound, supplied by a cheaper operation.

## The open generation reaps

The tick asks the volume to unlink pending segments nothing can reach. No
classification, no body read, no signature verify, no output ULID, no WAL
rotation, no worker job. It parses the index region of the segments it removes,
and of nothing else.

This targets what actually dies inside a ten-second window. Whole-death is the
mortality mode a short window sees: a jbd2 ring rewrite supersedes the LBAs of
the segment before it, and a hot page overwritten twice takes its segment with
it. Partial death is what needs minutes, and that is what the close pass is for.

Three rules govern which segments the reap may take.

- **Reachability.** A segment is reachable while the LBA map holds an extent
  claiming at it, or the extent index holds a location at it whose hash is live
  (claimed, or named as a delta source). The reap takes what is outside both,
  and removes that segment's remaining index entries as it goes, which is what
  keeps dead entries from accumulating in the open window and what stops a
  later write deduping against a body that is gone.
- **The snapshot floor.** A segment at or below `latest_snapshot` is pinned by
  the snapshot whatever the live maps say, exactly as it is for GC.
- **Publish before unlink.** The reap unlinks only after the read snapshot that
  excludes those segments is published, the discipline
  `remove_consumed_inputs` already carries.

### Where the reap runs

On the actor, with the volume mutex held for the state mutation and dropped for
the filesystem work.

Thread choice is close to irrelevant to the guest. Reads are lock-free off the
published snapshot and writes take the volume mutex directly from the ublk
queue thread, so mutex hold time is the whole question and the actor being busy
is not part of it (`architecture.md` *Concurrency and locking*).

The worker is the wrong home for a different reason. It is one thread that
every promote queues behind, so a reap dispatched there delays the promote a
`needs_promote` signal just asked for and lets the WAL run past
`FLUSH_THRESHOLD`. That reaches the write path by a longer route than the one
it avoids.

The reap also has little to move. Where repack has classification, body reads,
recompression and signing, the reap has a census read, an index-region parse
per reaped segment, a set of index removals, a snapshot publish and a batch of
unlinks. So the pass is the same prepare/execute/apply trio as everything else,
with the mutex over the first and third phases:

1. **Prepare (mutex).** Read the census, take the reap set under the cap below.
2. **Execute (no mutex).** Parse the index region of each segment in the set for
   its owned hashes.
3. **Apply (mutex).** Remove those hashes, purge the journal and delta-source
   tiers, publish the snapshot.
4. **Unlink (no mutex).** Remove the files, batched behind one `fsync_dir` as
   `remove_consumed_inputs` already does.

Phase 2 exists because `ExtentIndex::inner` and `deltas` are keyed by hash with
no reverse index, so `remove_input_owned` takes an explicit hash list, the one
repack gets from its classification. The parse skips signature verification.
`remove_owner_at` removes a hash only where the current owner is the segment
being reaped, so a hash a bad parse invents either does not exist or is owned
elsewhere, and either way removes nothing. The gate is the protection, not the
signature.

The `journal` and `delta_sources` tiers are segment-outer, so purging one is a
single outer removal and needs no hash list at all. A pure journal segment
therefore reaps with no parse, which is the tier that dies fastest.

Phase 4 needs no mutex because publish-before-unlink is what makes the names
safe to remove, and after phase 3 nothing references them. The actor is
single-threaded, so no other volume operation runs alongside them either way.

### The per-pass cap

The mutex window is proportional to the entries phase 3 removes, not to the
segments phase 1 selects, so the cap counts entries. **32,768 per pass**, four
times `FLUSH_ENTRY_THRESHOLD`, so a pass reaps at least four full flush
segments' worth and on the ~3,800 entries per segment measured on pg14 around
eight typical ones. Phase 2 parses until the accumulated hash count reaches it.

The number stands on that anchor alone. A close-pass apply holds the mutex
across a whole generation's registrations, ~57,000 entries on the same
measurement, but entry count is not what makes that window long (*The apply
window* below), so it is not a calibration the reap can borrow.

Journal segments do not count against the cap. They cost one outer removal
each, so counting them would price the cheap tier against the expensive one and
throttle exactly the segments the reap exists to take.

A backlog clears in a few passes rather than one. The stall case does not
accumulate, because the reap runs every tick and takes deaths as they happen;
what arrives at once is a restart, where the first pass meets whatever
`pending/open/` holds. The measured post-respawn directory was 38 segments,
which is five passes, twenty-five seconds at a 5s tick.

Journal consolidation moves entirely to the close. The reap is what makes that
safe: superseded ring segments leave as they die, so what survives to the seal
is at most one live ring, which is the population
`JOURNAL_CONSOLIDATION_ULIDS = 1` already assumes.

## Segment liveness is an incremental census

The reap needs one thing, a `Ulid → live reference count` over pending segments.
A reference is an LBA-map extent claiming at that segment, or an extent-index
location at that segment whose hash is live. A count of zero means unreachable.

Both halves are maintained at choke points that already exist, and the pattern is
established. `LbaMap::claim_counts` is already a maintained refcount over hashes,
and `--features volume-invariants` already reconciles the extent index against
`rebuild_owners_unverified` at runtime. The census follows both: maintained
incrementally, reconciled against a rebuild under the same feature gate.

The crux is the second half. A location's contribution turns on whether its hash
is live, so the census reacts to hash-liveness transitions rather than to index
mutations alone. The 1→0 and 0→1 transitions of `claim_counts` are the site,
and each resolves the hash's home segment and moves that segment's count. This
is the part to build carefully, and the part a reconciliation check earns its
place on, because a count that drifts low deletes live bytes.

If that proves heavier than it reads, the fallback is a per-pass sweep. A pass
already builds `claim_referenced_hashes()` at O(lbamap), so recomputing the
census per pass is the same order as what the current pass pays and still
removes every per-segment parse.

## The close budget is elastic

`REPACK_CLOSE_WORK_BYTES` is four output targets of stored data bytes, spent
smallest-first. Smallest-first stays right, because admitting a segment folds
away one object whatever its size. What changes is the size of the budget and
what the pass knows before it spends.

The census makes admission parse-free. Three inputs decide it, all available
without opening a segment: the file size from `stat`, the journal-tier membership
carried across the rotate rather than cleared at it, and the live byte count from
the census. Parse and verify only what admission accepts.

Knowing the live bytes is what lets the budget stretch. A generation that grew
during a stall has been dying the whole time it grew, so it is measurably sparse
at the seal, and that is the case where packing before upload saves the most S3
bytes. A fixed budget ships those bytes unpacked at exactly the moment packing
pays most. The budget therefore scales with the generation's measured dead
fraction, spending more work where more bytes leave.

This is the dial. A larger budget means a longer close and a longer stall
recovery; a smaller one means more S3 bytes and more objects. The census puts a
measured quantity on both sides of it, so it can be tuned against Tigris pricing
rather than guessed.

## The apply window

Every mutex window is a window in which writes wait (`architecture.md`
*Concurrency and locking*). The apply is the longest of them, and what makes it
long is not the entries it registers.

`apply_repack_result` runs `mutate_gated_on_resolvability` once per bucket, and
that gate ends in `unresolvable_lbamap_hashes`, which walks **every** LBA-map
entry doing up to three extent-index lookups each. So the apply is
O(buckets × lbamap), and a close pass over a volume holding a few hundred
thousand extents does millions of lookups with the write path waiting. Two
smaller costs sit beside it under the same mutex: `claim_referenced_hashes()`
copies every live hash key into a fresh set and `named_delta_sources()` walks
every delta source into another, both once per apply and both used only for
membership; and `DeltaBodySource::full_for_segment` opens and reads the output
file per bucket carrying deltas.

Four changes, in leverage order.

**The gate becomes incremental.** It asks a whole-map question, but the
pre-state already answers it and the mutation's footprint is known. An LBA
becomes unresolvable only where the mutation removed or moved the location its
hash resolved through, or where the mutation's lbamap merge introduced the
LBA-to-hash pair. Both sets are bounded by the bucket, so the check is
O(footprint) with the same contract. Delta resolution turns on source hashes
resolving, which would otherwise need a reverse map from source to dependents,
and does not: the stale-liveness check refuses any bucket that drops a hash in
`named_delta_sources` (#897), so a stranded source never reaches the gate.

**The mutex is taken per bucket.** The gate is already per-bucket and the CAS
and consuming-inputs rules are already per-input, so a write landing between
buckets is indistinguishable from one landing before the apply. Publishing once
at the end keeps readers off any partial state, and the inputs stay in place
until after that publish as they do today.

**The two set materialisations become membership probes.**
`LbaMap::is_referenced` already is one, against the maintained refcounts;
`named_delta_sources` wants an `is_named_delta_source` counterpart. That takes
two volume-sized allocations out of every apply.

**`full_for_segment` moves to the worker**, which wrote the file and holds the
entries and `body_section_start` already.

The first and third apply unchanged to GC's fold apply, which reaches the same
gate through the same pair of set materialisations in
`apply_plan_apply_result`. They are tracked there rather than here.

The reap needs none of this. It removes locations for hashes the census says
nothing references, so no LBA can become unresolvable by construction and the
gate has nothing to catch. Its apply is O(removed entries), with the
resolvability check kept as a `volume-invariants` assertion rather than a
production scan.

## A quiet volume cuts early

The cut interval exists to amortise a fixed per-cut cost across the writes in
the window. When no writes are arriving there is nothing left to amortise, so
waiting buys nothing and holds acknowledged writes on local disk. The window
closes when it stops accumulating, which is the reap's signal read the other
way round.

What sits local is `wal/` and `pending/open/`. `run_drain` runs on every tick
over `pending/upload/`, so a sealed generation uploads within a tick whatever
the cut does; `close_generation` is gated on `cut_landed`, so the open
generation waits for a cut to unlock its rotate. The rule:

**While nothing new has arrived and unpublished local content exists, cut on
the tick.** Unpublished local content is a non-empty `wal/`, `open/` or
`upload/`.

One cut does not clear the pipeline. A byte reaches HEAD through flush, cut,
close, drain, cut, so the rule fires repeatedly until the three directories are
empty. It self-terminates for free, because `publish_head_delta` already
returns without a PUT when nothing changed and no reap is due, so an idle
volume with an empty pipeline costs nothing per tick.

A quiet cut resets `last_cut`, so the clock-driven cut lands a full interval
after it rather than immediately behind it.

### The threshold

Quiescence is a bet that writes will not resume. Waiting pays only if they do,
and it pays twice, by amortising the cut and by letting later writes kill bytes
before they ship. Neither is available without traffic, so on a volume that
stays quiet the wait harvests nothing.

The bet is wrong on a bursty workload, where a gap long enough to trip the rule
shortens the window and a shorter window folds less and ships more bytes. So
the trigger is elapsed quiet time rather than a single quiet tick, configured
as `[gc] quiet_cut_after` in seconds, default 20s. That is four ticks at the
5s `drain_interval` default, short enough to clear the pipeline about fifteen
seconds after the last write and far short of the two-to-ten-minute mortality
knee, so a volume under load never reaches it.

Configuring the dial in seconds rather than ticks keeps it meaningful when the
drain interval moves, and makes it read as what it is, the length of silence
that ends a window.

### Sampling

The signal is local to the host. `wal/` holds at most one file and the
coordinator already stats `pending/upload/` for `upload_generation_drained`, so
a per-tick sample of the WAL's size and `pending/open/`'s count and bytes gives
quiescence with no IPC. A write skipped as a no-op never reaches the WAL, so it
correctly reads as no activity.

The sample belongs at the top of the tick, feeding `cut_clock_due`.
`run_volume_compactions` takes that value and runs before the drain and the
publish, so a quiescence cut sampled there carries the WAL flush with it.
Sampled later it would produce a cut without the flush, leaving the residue the
rule exists to move.

## WAL rotation

Rotation has four triggers today. `FLUSH_THRESHOLD` at 32 MiB of WAL bytes,
`flush_due` on the tick (which fires on the cut and on the GC supersession
barrier), `prepare_reclaim`, and `prepare_repack`.

The reap does not rotate, which removes the fourth. Reclaim's stays, and is
load-bearing: its outputs supersede the WAL content they consume, so the
`u_flush < u_reclaim` ordering is what keeps a rebuild from letting the flushed
segment shadow the reclaim output.

That leaves three triggers, each answering a different question. Size bounds the
WAL file and the recovery replay. The cut bounds how long an acknowledged write
stays outside S3, and is therefore already the durability cadence. Reclaim's is
an ordering requirement, not a schedule.

No fourth, time-based cadence is proposed. A flush interval could only bind by
firing more often than the cut, since a cut flushes first; it would be a second
time knob sitting under an existing one, and what it would buy is a smaller WAL
under write rates low enough that `FLUSH_THRESHOLD` never trips, where a small
WAL is not a cost. Stating the three rules positively is the change: rotation
happens on size, on the cut, and on reclaim's ordering requirement.

A quiet volume's WAL moves on the same three. `quiet_cut_after` is a cut
trigger, and a cut flushes first, so the residue a low write rate leaves below
`FLUSH_THRESHOLD` rotates with the quiescence cut that carries it.

Fewer rotations also mean fuller WAL segments, so a flush lands nearer
`FLUSH_THRESHOLD` and the close pass meets fewer, larger inputs.

## What the stall costs

With no packing in the open window, a long stall accumulates partially dead
segments the reap cannot take. They are cheap to hold. A read reaches a pending
segment through its claimant, and the cost of many is descriptor-cache pressure
against the 512-slot capacity (`project read_decay`), not per-read search.

What the stall costs is paid at the first close after the drain recovers, which
meets a very large generation and spends an elastic budget against it. That is
the trade named above, and it is the one to revisit first if a stall proves
expensive in practice.

## What this removes

`RepackTrigger`, `repack_watermark`, `repack_settled_cursor`,
`accumulation_since`, `select_candidates`, `is_settled`, `REPACK_SETTLED_SCAN`,
`REPACK_SETTLED_DENSITY`, `REPACK_PRESSURE_BYTES`, `REPACK_PRESSURE_SEGMENTS`,
and with them the `settled_floor` and `work_budget` options inside `RepackJob`,
which becomes a job with one shape. `execute_repack` keeps the classifier,
bin-pack, journal consolidation, output signing, consuming-inputs apply and
crash model, and runs from one caller.

## Open questions

- How the elastic budget is shaped. Dead fraction against a floor and a ceiling
  is the obvious form; what the ceiling is wants measuring against how long a
  close may sit on the cut's critical path.
- Whether the proptest simulation model needs a reap operation of its own or
  reads it as a variant of the existing repack op.
- What `quiet_cut_after` should be on the soak rig.
- The ordering of the four apply-window changes. They come from reading the
  code, and nothing has profiled an apply, so which of them dominates is a
  guess until something does. 20s is reasoned from the
  mortality knee rather than measured, and the workload that would settle it is
  a bursty one, which the current pgbench soaks are not.

## Non-goals

- No change to the tick cadence, which continues to drive drain, GC and the
  cut. `quiet_cut_after` adds a trigger the tick evaluates, not a second loop.
- No change to what a generation means or how HEAD names it.
- No change to the segment format or the S3 object layout.
