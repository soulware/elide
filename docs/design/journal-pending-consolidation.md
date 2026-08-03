# Design: consolidating journal segments in pending/

**Status:** Implemented at the single-output default (the split path across
several journal ULIDs is not built), with journal upload deferred to the
cut cadence (§ *Journal upload rides the cut*). Builds on the disjoint
journal tier (`gc-journal-segregation.md`, #774/#776), claimant-aware
journal reap (#778), and durable cuts (`durable-cut.md`), all shipped.

## Problem

A journal segment is one drain tick's worth of jbd2-window writes. They are
tiny (a fixture measured 108 committed journal segments averaging ~14 KiB of
body, ~27 blocks each) and numerous, and each one is a separate object on S3:
the upload path writes one object per segment, keyed
`by_id/<vol>/segments/<date>/<ulid>` (`elide-coordinator/src/upload.rs`). So a
volume under jbd2 churn spends most of its PUTs on journal segments.

The bodies are already segregated at formation, so `pending/` holds pure
journal segments and pure stable segments under distinct ULIDs. Repack today
leaves journal alone: `execute_repack` skips any pending segment that carries a
journal entry while it still holds live content (`elide-core/src/actor.rs`,
`is_journal_segment && live_entry_count > 0`), so a fully-dead one still reaps
as an all-Drop bucket but a live one is never merged.

## Approach

Merge the pure-journal segments in `pending/` into one pure-journal segment
before promote (configurable, see below), so a tick's N tiny PUTs become one.
This replaces the skip branch in `execute_repack` with a journal-consolidation
pass. It is a local rewrite over `pending/`; every segment's live content
still uploads, merged first, with journal upload riding the cut cadence
(§ *Journal upload rides the cut*).

Each output carries only the live journal entries of its inputs (dead ones drop
as free compaction), and collapses same-hash entries to one shared body. The
output keeps the journal flag and stays journal-tier, so it reaps whole exactly
as its inputs would have.

The merge reuses the existing rewrite materialiser rather than a bespoke journal
writer: the classifier already routes a superseded journal LBA to `Drop` and a
partially-reclaimed multi-block journal write to run-sliced `Keep`s, and the
materialiser already assembles those into an output body. The materialiser's
guard against journal-tier input entries (a journal entry reaching a durable
output is a tier leak) is relaxed only for this pass, behind an `allow_journal`
flag; the pass re-tags every output entry journal before the write, so the guard
still holds for every other rewriter and the merge stays a journal→journal
rewrite. Because the output entries carry the journal flag, the apply path
registers them into the disjoint `(segment, hash)` journal map and re-points each
LBA's claimant with no journal-specific code — the same bucket apply the data
rewrites use.

## How many output segments

One journal output per tick, by default: merge the live journal entries of every
pending journal segment into a single new pure-journal segment, with no size cap.

Consolidation carries only live entries, and that bounds the output. A journal
entry is dead once a newer segment claims its LBA (the claimant-aware rule,
#778), so when `pending/` has fallen behind and holds several ring laps, every
superseded older-lap write is dropped in the merge. What survives is the current
content of each window position, at most one ring's worth (~16384 blocks, a few
MiB compressed) however deep the backlog. So a backlog consolidation is a
compaction, not a concatenation: many laps of stored journal collapse into one
live-ring segment and one PUT. The output can never span more than one lap or
hold a position twice, which is why it needs no size cap and no wrap handling.
Across ticks the volume still accrues one journal segment per tick, each a ring
slice that reaps whole once the log laps past it.

`JOURNAL_CONSOLIDATION_ULIDS` (a repack const, `1`) fixes how many output ULIDs
`prepare_repack` reserves for the merge, minted after every data output ULID so
each sorts above the data (see the invariant below). Over-reserving is free —
unused reserved ULIDs are discarded, the mint having already advanced past them.
**Under-reserving is not free**: a pass that repacks data must lift *all* pending
journal above its data outputs, so the reservation must be enough to hold the
whole live journal (one output always is, since the live set is at most one ring).
Raising it above one splits the live ring across that many segments in ULID (ring)
order, which only buys slightly finer reap granularity; because the surviving set
is already one ring, there is no wrap to break across, and all of it still lands
above the data. The split path is not built; the count is a const until it lands,
at which point it becomes a config knob.

## Invariant: data stays below its journal through repack

For an epoch that touched the window, formation mints the data segment below its
journal segment, because ext4 `data=ordered` writes the file data to home before
committing the metadata to the jbd2 journal. That ULID order is load-bearing:
uploads run ULID-ascending, so `data_ulid < journal_ulid` is what makes "a journal
segment on S3 implies its data is on S3 too" hold. The unsafe state is the inverse
— a journal (metadata) present without the home data it references.

The existing data repack already moves pending data to fresh higher ULIDs, which
on its own would push data *above* its journal and invert the order (latent today
only because snapshot DR uses explicit signed sets and `claim --force` is not yet
journal-anchored). Consolidation is what keeps the order intact, and a pending data
segment's journal is always also pending — uploads are ULID-ascending and stop on
the first failure, so journal-committed implies data-committed, hence data-pending
implies journal-pending. So the journal to move up is always right there.

The pass preserves the order by construction, without needing atomicity across the
two rewrites:

- `prepare_repack` mints the data output ULIDs, then the journal output ULID(s)
  **last** (both below `u_flush`), so every journal output sorts above every data
  output (and above everything committed and pending).
- `execute_repack` writes the **journal consolidation first**, then the data
  buckets.

At every crash point the data is either at its original low ULID or at a data
output below `J'`, and the journal is either at its original ULID (already above
that data) or at `J'` (the global max) — so data never sits above its journal.
The highest-ULID journal also uploads last, keeping data-before-journal on S3.

This rests on consolidation covering **all** pending journal (≤ ceiling), not a
subset. A pass that repacks data lifts every data segment to a fresh high ULID, so
any journal left behind at its original low ULID would then sit *below* that data
— the inverted, unsafe state, for exactly the epochs whose journal was skipped.
The default satisfies this for free: the live journal is at most one ring, so a
single output (no size cap) always holds it and nothing is left behind. It becomes
a real constraint only if a future size cap or partial/split path could leave
journal unconsolidated — such a path must either lift all journal (into several
outputs, all above the data) or suppress data repack for that pass. Stated as an
invariant: **a pass that repacks data must move all pending journal above its data
outputs.**

## The journal-map rekey and its cost

The disjoint journal tier keys its extent map by `(segment_ulid, hash)`
(`elide-core/src/extentindex.rs`), unlike the stable map which keys by the pure
hash. The segment in the key is what stops journal content deduping across
segments (the stranding cause). It also means consolidation changes the key of
every entry it moves, and re-points every affected LBA's claimant in the lbamap
(the read path resolves a journal LBA through `lookup_journal(claimant_ulid,
hash)`, so the claimant is load-bearing).

The flat `HashMap<(Ulid, Hash), Location>` makes every segment-scoped operation
O(total map size), and consolidation would run them constantly:

- `purge_journal_segment` (`retain` over the whole map) runs on every reap.
- `promote_journal_segment_to_cache` (`keys().filter()` over the whole map) runs
  on every drain tick that formed journal.
- `rekey_journal` is a remove+insert per entry, so a K-input merge is O(entries).

**Proposed data structure:** a two-level map
`HashMap<Ulid, JournalSegment>` where `JournalSegment` holds the segment's
`body_section_start` once and a `HashMap<Hash, Location>` of its entries. This
makes the hot paths cheap:

- purge a reaped segment is one `remove` at the outer level, O(1).
- promote-to-cache mutates one submap, O(entries in that segment).
- renaming a segment (restore under a new identity, or a whole-segment rekey)
  moves one submap to a new key, O(1) plus a segment-id touch.
- consolidation builds the output submap from its inputs' submaps, O(merged
  entries), which is inherent to writing the merged body; it then drops the
  input submaps wholesale rather than deleting entries one key at a time.

Both levels stay `imbl` persistent maps, so snapshot clones keep sharing
structure and only the touched submap's path is copied on write. Hoisting
`body_section_start` to the segment level also removes it from every entry,
where it is redundant today.

This map lives only in memory and is rebuilt from the on-disk segments and their
per-entry journal flags, so changing its shape is not an on-disk format change
and needs no migration.

## Journal upload rides the cut

Deferral is the generation layout
(`docs/design/upload-generations.md`): journal segments land in
`pending/open/` and the consolidation pass keeps collapsing them there
— the steady state is the window's ring merging with each new tick's
journal — and a cut closes the open generation into `pending/upload/`,
whose drain uploads it whole before the next cut publishes. Journal
costs one PUT per cut instead of one per tick, and every published cut
is complete by construction: HEAD only ever names whole generations,
journal and data at one frontier. The volume's recovery point is the
last cut for every LBA, so the cut interval is the volume's RPO and
"journal upload cadence" is the same number.

A drained generation uploads ULID-ascending, so journal commits
ascending among themselves: a committed journal ULID is always below
every pending journal ULID. That ordering is what keeps a rebuild's
claimant comparison resolving every ring position to its newest writer
while the open generation holds the live ring.

Seals drain fully — snapshot, stop, and handoff each close the window
synchronously (`drain_volume_for_seal`), so the snapshot floor never
lands above a pending journal segment and a signed manifest always
carries the live ring.

## Correctness

- **Reap-whole holds.** The output is a pure journal segment and reaps whole
  under the claimant-aware liveness rule (#778) once every LBA it holds is
  reclaimed by a newer segment.
- **Same-hash across inputs.** jbd2 content is repetitive, so two inputs can
  hold the same hash under different keys. The merge keeps one body; both LBAs
  that resolve to it read identical bytes, and the redundant copy reaps with the
  segment. This is the within-segment sharing the tier already allows.
- **Claimant lockstep.** Each merged LBA's claimant moves from its input to the
  output in the same step as the map rekey, so a read never resolves a claimant
  that the journal map no longer holds.
- **Crash safety.** Consolidation is a rewrite in `pending/` before promote. A
  crash before it completes leaves the inputs in place, and the pass retries
  idempotently, matching the existing repack crash model.
- **Rebuild.** The output is a real signed segment with the journal flag, so a
  rebuild registers it through the normal journal path and reproduces the
  consolidated state.
- **Output ULID.** The merged segment consumes one of the journal output ULIDs
  `prepare_repack` reserves (the volume's monotonic `UlidMint::next`), exactly as
  every data repack output consumes a reserved bucket ULID. It is above all
  committed and pending segments by construction, so it neither collides with a
  live sibling nor reorders against the inputs it replaces. There is no
  `max(inputs).increment()` step.

## Non-goals

- No repack once uploaded. Reap-whole already reclaims committed journal for
  free as the ring wraps, so a post-upload rewrite would pay GET+PUT+DELETE to
  reorganise content that is about to be deleted. It would also re-key committed
  journal to fresh higher ULIDs and so reorder it against data already on S3,
  which would demand machinery to preserve the data-before-journal ordering
  through S3-visible rewrites (the ordering the `claim --force` recovery anchor
  leans on). Touching journal only in `pending/`, before its first upload, avoids
  all of that: the ordering is a property of first upload alone, first upload is
  monotonic by the mint, and a committed journal segment is then immutable until
  it reaps whole.
- No change to stable packing.
- No jbd2 transaction parsing; the ring order comes from segment ULIDs and
  in-window LBAs, not from journal internals.

## Sequencing

The two-level journal map lands as the first commit, ahead of consolidation. It
stands on its own by turning `purge_journal_segment` and
`promote_journal_segment_to_cache` from O(total map size) into O(1) / O(segment),
so it is a reviewable unit even before the consolidation pass that depends on it.
Both commits go in one PR.

