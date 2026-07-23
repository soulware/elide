# Design: maintaining journal segregation across GC

**Status:** Pool separation implemented. The as-is rule below is proposed, after
a fresh-volume soak measured pool separation alone stranding journal content.

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

### Pool separation is not sufficient

Keeping journal segments out of stable buckets stops one loss path. A second
survives it, because liveness is by content hash and jbd2 content is
repetitive.

`collect_stats` reads liveness from `lbamap.lba_referenced_hashes()`. When the
log wraps over a journal LBA the entry that held it is LBA-dead, but its content
hash is still referenced by another current journal LBA, so `classify_entry`
returns `DemoteToCanonical` and keeps the body for dedup resolution. A canonical
has `start_lba` 0, and `owns_entry` is false for it, so the segment is no longer
all-journal. The classifier moves it to the stable pool, where a small segment
is an unconditional sweep candidate, and the next pass welds the journal-content
canonical into a data bucket. A `Delta` follows the same path through
`CanonicalDelta`.

A journal segment therefore does not age into a pure stable segment. It ages
into a stable segment that still carries its journal content, which is then
rewritten into ever-larger data segments. The reap-whole path never runs,
because demotion keeps the segment alive. That the backlog ages out and that no
writer re-mixes both assumed a journal entry dies when the log wraps over its
LBA, which hash liveness prevents.

Measured on a fresh volume under a fifteen-minute pgbench run, 2026-07-23,
v0.1.28: no journal segment reached the tombstone state, `mixed_blocks` grew
from 1114 to 3867 and did not fall when writes stopped, and the journal pool
held only shares that had not yet had an entry demoted.

### Journal content is stored as-is

The journal is a circular buffer whose content is overwritten every wrap. Dedup
and delta keep content alive for as long as a reference exists, which is the
opposite of what a circular buffer wants. Demotion is that opposition surfacing.

Journal and durable content are disjoint tiers. They never share a segment, and
they never reference each other's bodies.

A journal-window entry is always `Data` or `Inline`. Formation writes journal
blocks verbatim, skipping dedup classification and delta formation, so a journal
segment holds only own-body entries. Nothing outside a journal segment
references journal content, because a journal-window body is never offered as a
dedup or delta source. An overwritten journal LBA then classifies dead, not
canonical, because nothing points at it, and the segment reaps whole once its
last entry dies. Repetitive journal blocks that share a hash each keep their own
body, so dropping a dead one loses nothing a live one needs.

Both directions matter. A journal write that deduped against a durable body
would tie the two tiers' lifetimes together, and a durable body kept alive only
by an ephemeral journal reference would outlive its own use. Forbidding journal
content as either source or target keeps the tiers independent and makes durable
content never depend on the journal.

The cost is that identical journal blocks, and a journal block that matches a
durable page, are stored more than once. The window is 16384 transient blocks,
so the saving foregone is small and short-lived, against reap-whole reclamation
of the dominant write stream.

### Reaping

A journal segment dies once every one of its LBAs has been overwritten and no
entry remains live. Under the as-is rule its entries are never kept for dedup,
so death by LBA is death: the segment has no live entries, becomes a tombstone,
and is reaped whole with no rewrite. This is the outcome pool separation aims at
and that demotion prevented.

## Open

The steady state under pool separation alone is measured, and journal content
strands. The fresh-volume run showed the climbing-oldest-age and growing-count
shape and did not settle, because demotion keeps journal segments alive. The
as-is rule is what lets them die.

The steady-state population under the as-is rule is not yet measured. It is set
by how many blocks a formation epoch covers, which was 2 to 22, against the wrap
interval that reaps them. The per-pass census reports the pool's size, the
blocks it holds against the window, the age of its oldest member, and the count
of stable segments still mixed. A settled population with a bounded oldest age
says reap-only suffices; a climbing oldest age, or a count that grows without
one, says a compaction trigger is wanted.

**Preserve the journal label through demotion.** Keep a demoted journal entry
in the journal pool rather than letting the canonical flip it to stable, so GC
never welds it into data. It stops the welding but not the stranding, because
the canonical is still live and the segment still never reaps whole. It treats
the symptom and leaves the write amplification the as-is rule removes.

**A count trigger on the journal pool.** Pack journal segments once enough of
them accumulate, as relief for file-count pressure. Under the as-is rule the
population is bounded by the formation rate against the wrap interval, so a
trigger is a fallback for a journal that does not wrap, not the mechanism. If it
is ever written it should pack ULID-adjacent runs, whose members die together,
rather than the bin-pack's descending-by-size order.

**Partition the output.** Split a rewrite's materialised entries into a stable
share and a journal share, so a mixed input sheds its journal content on first
rewrite. Under the as-is rule no stable output holds journal content to shed, so
it is unnecessary, and it costs a second output ULID per bucket permanently
since a plan cannot know in advance whether a bucket will split.

## Verification

- A journal segment holds only `Data` and `Inline` entries. No `DedupRef`,
  `Delta`, or canonical form appears in one.
- No entry outside a journal segment references a journal-window body, and no
  journal entry references a body outside its own segment. Assertable at rebuild
  and in the proptest oracle, which the demotion regression would have tripped.
- Journal candidates never appear in any bucket's inputs, and the stable pool's
  bucket selection is unchanged for a volume with no journal window.
- A journal segment whose LBAs are all overwritten reaches the tombstone state
  and is reaped whole, with no rewrite.
- On the fresh-volume soak, `mixed_blocks` falls to the pre-activation residue
  and `tombstones` accrue as the log wraps, rather than stranding.

## Related

- [`delta-compression.md`](delta-compression.md) § *Journal-region awareness*
  for the window, the ownership rule, and formation's segregation.
- [`gc-bucket-unification.md`](gc-bucket-unification.md) for the bin-pack the
  stable pool runs.
