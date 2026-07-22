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

Journal content lands at roughly 2 to 5 percent of each output, and every pass
re-mixes fresh journal content into the survivors.

The cost is not the density those blocks consume. A share that small decays a
segment by 2 to 5 percent and stops, nowhere near the sparse threshold, and
what actually makes those outputs candidates is `is_small`. The cost is that
mixing converts free reclamation into paid reclamation. A pure journal segment
dies whole and is deleted with no rewrite. A mixed one never dies, because
long-lived data sits alongside the journal blocks, so its journal garbage is
reclaimable only by a rewrite that copies all the surviving data too.

That garbage arrives at the journal write rate. The window is 16384 blocks, so
every wrap turns 64 MiB into garbage, and journal-shaped segments were
disappearing in about two minutes. Treating that as the wrap interval puts the
figure in the tens of GB per day, all of it reclaimable only through segment
rewrites, which is write amplification scaling with the dominant write stream
on an fsync-per-commit workload. The daily number is an extrapolation from one
observed segment lifetime, not a measurement.

## Design

One selection pass over two disjoint candidate pools.

`collect_stats` already walks every entry of every candidate and already holds
the window, so it labels each segment as journal or stable in the same pass at
no extra I/O. `select_buckets` then runs per pool. A bucket's inputs are
therefore all-journal or all-stable, and its output is pure by construction.

### The journal pool packs nothing

The pools share the selection machinery and differ in what admits a candidate
to it. Both of the stable pool's triggers are wrong for a fixed extent that is
cyclically overwritten.

Density asks whether it is worth rewriting live bytes to reclaim dead ones.
For journal content the answer is no, because the dead-segment path reclaims it
for free once the wrap comes round.

The unconditional small-segment sweep exists to stop small-file proliferation.
Journal segments are small by design and short-lived, so that rule guarantees
GC keeps picking them up and rewriting data that was about to disappear.

So the journal pool has no trigger at all. Segments are left to die and be
reaped whole, which is the cheapest outcome and the one segregation exists to
enable.

Merging them would also work against the mechanism that makes reaping cheap. A
journal segment dies whole because its blocks were written together in time and
are overwritten together in time. A merged segment can only die once the
youngest member's blocks have all been overwritten, so it dies later and spends
longer partially dead. If a trigger is ever wanted, it should pack ULID-adjacent
runs rather than the bin-pack's descending-by-size order, so the members still
die together.

The stable pool keeps today's heuristics unchanged.

### The existing backlog ages out

Every segment mixed before this design, both the pre-awareness backlog and
everything GC has mixed to date, stays mixed and is left alone. Its journal
entries die as the log wraps over their LBAs, and the segment is a pure stable
segment from then on. That happens at the wrap interval, minutes on the soak
volume, without a rewrite.

Rewriting them to shed the journal content would have meant a second output
ULID per bucket, a plan format that names two outputs, and an apply result that
reports which were written. All of it to accelerate something that resolves on
its own, and all of it permanent, since a plan cannot know in advance whether a
bucket will split.

The residue is a segment whose journal LBA is never rewritten, which is the
same lingering case the journal pool has. It holds one impure segment rather
than one lingering segment.

### Nothing re-mixes

The invariant holds without a split because no writer merges journal content
into a stable segment.

Formation partitions the epoch (`partition_journal_pending`, at both the
promote take and the WAL-recovery path). GC pools keep journal segments out of
stable buckets. Repack mints one output ULID per input segment
(`prepare_repack`), so it rewrites in place and never merges two.

### Reaping is unchanged

A journal segment that has fully died has no live entries, so it is not
journal-labelled at all. It is a tombstone, it goes in the stable pool, and it
folds into a bucket and is reaped exactly as before. That is the entire
lifecycle for journal segments, and it is why the pool packing nothing does not
strand them.

## Open

The steady-state journal segment count is unmeasured, and it decides whether
the pool ever needs a compaction trigger. The soak volume showed 7
journal-shaped segments against 55 stable, with individual ones vanishing
within about two minutes, but that number is from the mixed world: those
segments hold a fraction of the window, and the rest of it lives inside the 62
mixed segments. Once segregation holds, those LBAs migrate to journal segments
and the population is set by how many blocks a formation epoch covers, which
was 2 to 22.

The per-pass census reports the pool's size, the blocks it holds against the
window, the age of its oldest member, and the count of stable segments still
mixed. A settled population with a bounded oldest age says reap-only suffices.
A climbing oldest age says segments are stranded, and a count that grows
without one says file-count pressure is real.

## Alternatives

**A count trigger on the journal pool.** Pack journal segments once enough of
them accumulate, as relief for file-count pressure. The threshold has no
measurement behind it, so it would ship as a number picked against the mixed
world, and it fires on a signal that cannot distinguish a busy journal from a
stalled one. The census exists to answer this before the trigger is written.

**Partition the output.** Split a rewrite's materialised entries into a stable
share and a journal share, so a mixed input sheds its journal content on first
rewrite. It costs a second output ULID per bucket permanently, since a plan
cannot know in advance whether a bucket will split, and it buys migration of a
backlog that ages out on its own.

**Partition the output only, without pools.** Leaves journal segments as
unconditional candidates, so each pass pulls one into a data bucket and splits
it back out, rewriting content that was about to die. The split fires forever
instead of converging.

## Verification

- Journal candidates never appear in any bucket's inputs, and the stable pool's
  bucket selection is unchanged for a volume with no journal window.
- A fully-dead journal segment is reaped without being packed.
- A GC output on a volume with a journal window contains no live in-window
  entry that was not already in one of its inputs.
- Re-running the entry scan on the soak volume finds the mixed count falling
  and no new mixed segment above the first post-change GC output.

## Related

- [`delta-compression.md`](delta-compression.md) § *Journal-region awareness*
  for the window, the ownership rule, and formation's segregation.
- [`gc-bucket-unification.md`](gc-bucket-unification.md) for the bin-pack the
  stable pool runs.
