# Design: maintaining journal segregation across GC

**Status:** Proposed.

## The invariant

Journal-window entries and stable-LBA entries live in separate segments.

Formation establishes it. A promote whose epoch touched journal LBAs writes a
pair, the stable share under the first ULID and the journal share under a
second, higher one
([`delta-compression.md`](delta-compression.md) § *Segment segregation*).
jbd2 is a circular log, so a journal segment's claims die together and the
whole file is reaped rather than compacted.

## Where it is lost

The invariant is established once and never maintained. GC dissolves it on the
first pass that touches a journal segment.

`select_buckets` has no journal concept. It partitions candidates into
tombstones, small, and sparse, then packs FFD by materialised bytes. Two of its
properties act directly against segregation:

```rust
let is_small = s.live_lba_bytes <= SWEEP_SMALL_THRESHOLD;
if is_small || is_sparse { candidates.push(s); }
```

Journal segments are small by construction, so they are always candidates
regardless of density. FFD sorts descending by materialised bytes, so they sort
last and become the filler that tops up buckets opened by large data segments.
The small-segment sweep is precisely a remixing path.

Nothing else re-establishes the split. `segment.rs` carries no journal flag,
and the coordinator reads the window only to rebuild the extent index.

## Measurement

A scan of every LBA-bearing entry in all 62 segments of the postgres soak
volume against its window `[1081344, 1097728)`, 2026-07-22:

- **No pure-journal segment existed**, while formation was minting them
  continuously at 2 to 22 entries every few seconds.
- **Every segment held both**, including ones minted after that boot's
  activation marker, at entry counts that identify them as bucket outputs:

```
MIXED  01KY4Y6F5R9B8W0T5EWFRCHQQE  in=100  out=7989
MIXED  01KY4Y4RGT7FZTX7MFP9WTWZTJ  in=134  out=7452
MIXED  01KY4Y7DZ2FP450X2CJAMH71KF  in=16   out=8086
MIXED  01KY4Y1FZ1XAZJKSTCD8ZZVM6N  in=776  out=5650
```

Journal content lands at roughly 2 to 5 percent of each output. Small, and the
worst possible share: it is guaranteed to die within a wrap, spread across
every segment GC produces. Each output therefore starts life unable to be fully
live, with density bleeding downward from birth, which returns it to candidacy
sooner. Every pass re-mixes fresh journal content into the survivors.

## Design

One selection pass over two disjoint candidate pools.

`collect_stats` already walks every entry of every candidate and already holds
the window, so it labels each segment as journal or stable in the same pass at
no extra I/O. `select_buckets` then runs per pool. A bucket's inputs are
therefore all-journal or all-stable, and its output is pure by construction.

### The journal pool inverts the trigger

The pools share the selection machinery and differ in what triggers it. The
journal region is a fixed extent, cyclically overwritten, whose content is
guaranteed to die within a wrap, and two of the stable pool's heuristics are
wrong there.

Density asks whether it is worth rewriting live bytes to reclaim dead ones.
For journal content the answer is almost always no, because the dead-segment
path reclaims it for free once the wrap comes round.

The unconditional small-segment sweep exists to stop small-file proliferation.
Journal segments are small by design and short-lived, so that rule guarantees
GC keeps picking them up and rewriting data that was about to disappear.

So the journal pool packs on **segment count** and never on density. Segments
are left to die and be reaped whole, which is the cheapest outcome and the one
segregation exists to enable. The count trigger stays as relief for file-count
pressure if journal segments ever accumulate, which happens when a filesystem
goes quiet with a partially-written region lingering.

The stable pool keeps today's heuristics unchanged.

### Splitting the materialised output

Pure pools mean pure outputs, so the split is not what maintains the invariant
in the steady state. It does two other jobs.

It is the **migration path**. Segments mixed before this design existed, both
the pre-awareness backlog and everything GC has mixed to date, go in the stable
pool and shed their journal content on first rewrite. After that every input is
pure and the split stops emitting anything.

It is also the **structural guarantee**. Keeping it permanently costs nothing
when no entry falls in the window, and it makes "no segment is ever mixed" a
property of the code that writes segments rather than of pool discipline being
correct at every call site.

`Materialised::partition_journal` implements it. Destination is a pure function
of the entry's LBA, as journal classification is everywhere else:
`materialise_plan` produces `Vec<PendingEntry>`, each carrying its own
`start_lba` and its own body. Canonicals stay with the stable share, since they
make no LBA claim and a journal DedupRef resolving against one must point
backward to a lower ULID.

Splitting there rather than in the plan builder puts it at the seam every
rewriter shares. `materialise_plan` serves coordinator GC, redact,
sweep_pending, repack and delta_repack, so no plan builder can forget to
classify, and repack gains the same guarantee — it merges pending segments and
can mix them exactly as GC does.

Only the delta body needs care. `DeltaOption.delta_offset` indexes the
segment's delta section, so each share rebuilds its own delta body and re-bases
the offsets it carries. Journal entries are never Delta at formation (the tier
skips the journal partition structurally), so this is the pre-awareness and
defensive case rather than the common one.

### The plan format

`RewritePlan` carries one `new_ulid` and a `Vec<PlanOutput>`, where each
`PlanOutput` is a per-record instruction naming the input it reads from. The
records are the output segment's contents, not a list of output segments, so a
plan produces exactly one segment today.

Emitting a pair therefore extends the plan with a second output ULID, and needs
no per-record destination because destination is derived at materialise time.
The coordinator provisions both ULIDs per bucket from `gc_checkpoint`, since it
uploads `gc/<ulid>` and calls `promote_segment` per output and so must know
both names in advance. An unused second ULID only advances the volume's mint.

Two plans over the same inputs does not work. `plan.inputs()` feeds the
divergence and resolvability checks, and applying a plan consumes its inputs by
deleting `index/<input>.idx`, so a second plan over the same inputs would find
them gone. Inputs being consumed exactly once is load-bearing, not incidental.

The format change is cheap. A plan is emitted per tick, applied, and deleted by
`finalize_gc_handoff`, so nothing persisted needs migrating, and the
serialisation already carries a version tag.

### Reporting

A plan stops fully describing what gets written, because the split happens
after the coordinator has emitted it. Plan-emission logging and `GcStats` say
what was actually produced rather than assuming one output per bucket, and
`GcPlanApplyResult` reports which outputs exist so the coordinator uploads and
promotes only those.

## Open

The steady-state journal segment count is unmeasured, and it decides whether
the count trigger needs a considered threshold or is a safety valve that never
fires. The soak volume showed 7 journal-shaped segments against 55 stable, with
individual ones vanishing within about two minutes, which suggests reap-only
suffices. That is one workload at one moment, and postgres with an fsync per
commit is near the worst case for journal traffic, so it bounds the answer
rather than giving it. Watching the journal pool's count across a soak settles
it.

## Alternatives

**Exclude journal segments from GC entirely.** Never rewrite the
shortest-lived data on the device and let it tombstone. This is the journal
pool's behaviour minus the count trigger, so it is the same design without
relief for file-count pressure.

**Partition the output only.** Leaves journal segments as unconditional
candidates in one pool, so each pass pulls a journal segment into a data
bucket and splits it back out, rewriting content that was about to die. The
split fires forever instead of converging.

## Verification

- A bucket whose inputs are all stable emits one segment.
- A mixed pre-awareness segment passed through GC comes out as a pair, and the
  journal segment's ULID sorts above the primary's.
- Journal candidates never appear in a stable bucket's inputs, and the stable
  pool's bucket selection is unchanged for a volume with no journal window.
- The journal pool packs only once its count trigger is reached, and a
  fully-dead journal segment is reaped without being packed at all.
- Re-running the entry scan on the soak volume finds no mixed segment above the
  first post-change GC output.
- `gc_proptest` and the crash-recovery oracles cover whether the split loses or
  duplicates any entry.

## Related

- [`delta-compression.md`](delta-compression.md) § *Journal-region awareness*
  for the window, the ownership rule, and formation's segregation.
- [`gc-ulid-ordering.md`](gc-ulid-ordering.md) for the output-ULID rules the
  pair mints under.
- [`gc-bucket-unification.md`](gc-bucket-unification.md) for the bin-pack each
  pool runs.
