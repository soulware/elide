# Design: epoch applies

**Status:** steps 1 to 4 shipped (#984, #985, #987, #988, #989, 2026-09-01),
with the prep follow-ons #990 and #991 (2026-09-02). Step 5 is open. The
measurements come from the `write_contention` simulator (2026-08-31, parked on
the `wip-measurement-probes` branch) and the rig's per-site lock statistics
(2026-09-01 and 2026-09-02). Builds on claimant tracking
(`lbamap-claimant-tracking.md`), the plan-apply gate (`gc-plan-handoff.md`) and
the reap (`open-generation-reap.md`).

## Problem

Guest writes and structural applies share one volume mutex. A write holds it
for 0.100ms on average. An apply holds it for the time it takes to mutate the
two maps in place, and that hold is the stall the guest sees.

The rig's lock lines for the rc24 loaded windows (308 windows, 2026-08-29 to
08-30, `writes n≥1000`) rank the holds by their per-window maximum:

| site | max hold | total hold |
|---|---|---|
| gc-plan-apply | 460ms | 41.3s |
| repack-apply | 282ms | 23.2s |
| promote-apply | 108ms | 18.4s |
| promote-segment-apply | 78ms | 11.8s |
| publish | 24ms | 7.5s |
| promote-prep | 21ms | 3.8s |

In the same windows 15.3% of guest writes blocked on the mutex. The per-window
maximum write wait had a median near 65ms and a worst case of 470ms. The goal
is a guest write stall under 1ms.

The apply holds are long because every apply mutates the shared `LbaMap` and
`ExtentIndex` through `Arc::make_mut` while it holds the lock. The maps are
persistent trees, so each mutation path-copies a root-to-leaf path over a map
of hundreds of thousands of entries. A probe measured 8192 inserts into a
250k-entry pair of maps at 25ms. A close pass applies ten or more buckets of
~10k entries each.

The trims shipped in August and on 2026-09-01 (#960 to #963, #973 to #982)
moved read-only walks, disk I/O and the old snapshot's free off the lock. The
mutation itself stays, and it sets the floor.

## The scheme

The volume keeps its mutex. Under it the maps become three layers
(`MapLayers`, `elide-core/src/map_layers.rs`):

- **base**, the two large maps, which only an apply replaces,
- **frozen**, a list of immutable layers, one per promote in flight, each
  tagged with the WAL ULID of the epoch it holds,
- **delta**, the two small maps that hold the open WAL's writes.

A write inserts into `delta`. An apply runs in three steps:

1. **Freeze**, under the lock, O(1). A promote moves `delta` into a new frozen
   layer and rotates the WAL. Every other apply clones the `base` handle.
2. **Fold**, off the lock, O(batch × log n). The apply runs today's transform
   functions against its clone of `base`, and produces a new base.
3. **Swap**, under the lock, O(1) plus a check bounded by `delta`. The apply
   installs the new base and pops its frozen layer.

Reads resolve `delta`, then each frozen layer from newest to oldest, then
`base`.

The WAL rotation is the epoch boundary. `delta` holds exactly the open WAL's
writes, so the frozen layer a promote takes is that promote's own entry set.
The `pending` vector is the worker's input, because segment formation needs
WAL order and body offsets that the maps do not carry. The prep hands the
worker the raw `pending` writes, the journal ranges, a journal segment ULID
minted under the lock, and an O(1) clone of the layers. The worker
materialises the clone once and stages against it, so a retry after a failure
stages again from the same immutable layer.

## Writes

The write path keeps its shape. Under the mutex it appends to the WAL, inserts
the claim into `delta.lbamap` with the WAL ULID as claimant, inserts the WAL
location into `delta.extent_index` (or the journal tier), and publishes. The
dedup lookup in `write_commit` consults every layer, newest first.

`delta` holds at most one WAL epoch of writes, so the path copy a write pays is
over a map of thousands of entries rather than hundreds of thousands. The
simulator measured the large-map path copy at about 30% of the write's cost at
one thread, with readers present or absent.

## Reads

`ReadSnapshot` carries `base`, the frozen list, `delta` and the two generation
counters. A publish clones the layer handles, O(1) each.

A point lookup (`lookup_extent`, `lookup_journal`, `lookup_delta`) queries the
layers in order and returns the first hit. `has_full_match` answers from the
topmost layer that covers any part of the range. Each miss costs one more tree
descent, measured at about 250ns per layer on a populated delta
(`second_lookup_cost` probe). A walk of a whole map (liveness, the gate's
residual walk, the invariants) reads `materialised()`, the layers folded into
a clone of `base`, which costs two handle clones when the layers are empty.

A range query (`extents_in_range`) is an overlay. It queries `delta` for the
range, fills each gap from the newest frozen layer, then the next, then `base`.
A newer layer's extent masks the sub-range it covers in every older layer.

The extent index has one location per hash per tier, and the write path never
inserts a hash that resolves in a lower layer, so the first hit is the canonical
location.

## Applies

Every apply site keeps its transform functions. What changes is the map they
run against and the moment they run.

| site | transform today | epoch shape |
|---|---|---|
| promote-prep | take `pending`, stage, mint | freeze: `delta` → frozen layer, rotate WAL, mint |
| promote-apply | CAS WAL locations to segment locations, bump claimants | fold the frozen layer into a clone of `base` with the segment's locations and ULID; swap, pop the layer |
| promote-segment-apply | flip pending locations to cache, rekey journal | clone `base`, flip, swap |
| gc-plan-apply | `register_entry_consuming_inputs`, `remove_owner_at`, `purge_journal_segment`, gate | fold the frozen layers below the plan's ULID into a clone of `base`, transform, gate on the clone under the upper layers, swap with the removal check, retire those layers |
| repack-apply (per bucket) | same shape as gc-plan-apply | clone `base`, transform, gate on the clone under the upper layers, swap with the removal check |
| reap-apply | `remove_input_owned`, purges | clone `base`, transform, swap with the removal check |
| reclaim-apply | `register_entry_if_newer`, register output | fold the frozen layers below the output's ULID into a clone of `base`, transform, swap, retire those layers |
| gc-handoff-finalize, own-segments, publish | no map mutation | unchanged |

A refused gate discards the clone.

The GC plan folds below its ULID for the reason the reclaim does. The plan's
ULID is minted at a GC checkpoint, so every WAL opened after it sorts above,
and a frozen layer below it is a promote the actor stashed after a failure.
That layer's claims sit below the plan, and the rebuild admits by highest
ULID, so a plan that carries an LBA the layer claims would win on disk and
lose in memory. The absorb put those claims in `base`, where
`register_entry_consuming_inputs` refused the range and the superseded-carry
check refused the plan. The replay of the layer into the fold's clone keeps
that refusal (`a_gc_plan_fold_replays_a_stashed_layer_below_its_ulid`). The
repack and the reap have no ULID-order check, so their fold over `base` alone
gives the materialised map the absorb gave.

The liveness probes (`still_at_input`, `is_referenced`,
`is_named_delta_source`, the gate's `claim_refcount`) read the layers
materialised into one map, which is the map the rebuild gives. A layered sum
over-counts a `base` claim that an upper layer masks. The fold materialises
off the lock, so the exact answer costs the guest write nothing.

Only frozen layers ever hold WAL locations, and `delta` holds only the open
WAL's. The drain flip re-points locations the drained segment owns, and those
entered `base` at the promote's fold, so the flip touches `base` alone
(`fold_base`, `swap_base`).

The reclaim admits by ULID order. `prepare_reclaim` closes the WAL before it
mints the output's ULID, so every frozen layer at the prep sorts below the
output and every write after the prep sorts above it. A frozen layer below the
output can exist at the fold, when the actor stashed a failed promote for a
retry, and a fold over `base` alone would leave that layer to mask the output
in memory while the rebuild picks the output. The reclaim's fold replays the
frozen layers below its ULID into the clone and its swap retires them
(`fold_below`, `swap_below`). The layers above mask the output, which is the
rebuild's order. The fold reads each run's landed blocks through the layers
above the output (`above`), so a write that arrived after the prep refuses the
blocks it covers, and a pass with no landed run deletes its output.

A promote whose layer an earlier fold retired folds and swaps as before: its
replay finds the layer gone and its CAS flips find the WAL locations in `base`.

## The fold rules mirror the rebuild

A fold admits entries with the functions the disk rebuild uses for the same
segment. This is the correctness statement of the whole design, and the
`volume-invariants` build checks it: after every swap,
`assert_lbamap_consistent` compares the layered state, materialised, with a
rebuild from disk.

**Promote fold.** The frozen layer's claims are later than every claim in
`base` on the same LBA range. `base` receives content only through applies,
and an apply's output carries content that existed before its inputs were
consumed, so it predates any write that arrived after the freeze. The fold
therefore registers the frozen layer's claims over `base` on their ranges, and
registers the segment's body locations with the lowest-ULID canonical rule the
extent index already applies. The rebuild produces the same result through
consuming-inputs admission, since a repack or GC output never names the WAL
among its inputs.

**Other folds.** The transform functions are the rebuild's, so their admission
is the rebuild's admission by construction. `register_entry_consuming_inputs`
takes a range only from a consumed input, and a WAL is never an input, so it
respects every frozen layer over `base` alone. `register_entry_if_newer` takes
a range from a lower claimant, so it respects a frozen layer only over a fold
that took every layer below its ULID (`fold_below`).

## Removals race the layers

A base-only transform cannot see the claims in `delta` and the frozen layers.
Today the mutex serialises writes and applies, and the stale-liveness check
reads the one live map. Under the scheme a GC fold, a repack bucket or a reap
can judge a hash dead against `base` while a write in `delta` has claimed it,
through the dedup lookup that resolved the hash in `base`. The swap would then
strand that claim.

Two checks close the window:

1. The fold reads liveness over the materialised layers at its start, so a
   claim already in `delta` or a frozen layer refuses the removal there.
2. The swap, under the lock, checks the hashes the fold removed against the
   claims in `delta` (`MapLayers::delta_claims_any`). Only `delta` changes
   between a fold and its swap: freezes and every other mutation of `base`
   run on the actor thread, which is the thread that folds. The walk is over
   `delta`'s claim keys, which are few against a fold's removals. A hit
   refuses the unit, one plan, one bucket or one reap pass; the apply
   discards its clone, and the next pass runs against a base that includes
   the claim.

The GC plan's commit rename runs after the check and before the swap. A
rename failure leaves the maps as they were, and a crash between the two
ends the process with the output committed for the rebuild.

The promote fold has no removal, and its input layer is immutable, so its CAS
preconditions (`pre_promote_offsets`) hold by construction.

## Frozen depth

Each promote in flight owns one frozen layer. The WAL-threshold promote and the
GC checkpoint promote can overlap, so the list can hold two, and a promote the
actor stashed after a failure keeps its layer across retries. A layer retires
at its promote's swap, or at the swap of a `fold_below` that replayed it. A
read pays one descent per layer, so the depth is a cost the lock line reports.
`promotes_in_flight` bounds it today; the design keeps that bound.

## Off-lock consumers of the maps

`sweep_unreachable`, `scan_reclaim_candidates`, the gate's residual walk and
the invariants asserts iterate a whole map. They take a snapshot and call
`materialised()`, which folds the layers into a clone of `base` off the lock,
in O(layer × log n). The coordinator's GC reads the maps from disk and is not
affected.

A release no-op assertion is free only when its receiver is. The invariants
umbrella reads `base()` for the delta-source counts, which live there; a
`materialised()` receiver pays the fold in every build (rc27 saw it as
`repack-unlink` at 5.1ms).

## What the mutex still covers

- a write: WAL append, two inserts into `delta`, publish,
- a freeze: two moves and a WAL rotation,
- a swap: two handle assignments and the removal check,
- a prep: the `pending` take and the ULID mints.

Each is O(1) or O(delta). The residual stall is writer-against-writer queueing
at high thread counts. The simulator measured arm D at a write stall p99 of
28µs, 344µs, 950µs, 2.2ms and 5.0ms at 1, 2, 4, 8 and 16 writer threads, with
throughput 1.23 to 1.32 times the current design. The apply hold no longer
appears in the stall distribution: the stall p99 equals the write path's own
p99.9. Removal of the queueing term needs the CAS delta of arm B, which is out
of scope here.

## Implementation order

1. The layered `ReadSnapshot`, the overlay range query, `materialised()`, and
   writes into `delta` (#984, #985). The applies absorb the layers into `base`
   and mutate it in place under the lock. Rig (rc27): write hold 0.0926 to
   0.0428 ms per write.
2. The promote as freeze, fold, swap (#987). Rig (rc28): `promote-prep` max
   72.2 to 0.7ms, `promote-apply` max 55.8 to 0.3ms, blocked writes in the
   10-100ms band 2554 to 1805 per million, the series low.
3. The drain flip and the reclaim as fold and swap (#988). Rig (rc29):
   `promote-segment-apply` max 78.2 to 0.3ms; the 10-100ms band 1805 to
   1394 per million; `gc-plan-apply` and `repack-apply` are 86% of the
   lock hold that remains.
4. GC plan apply, repack buckets and the reap, with the swap removal check
   (#989). Rig (rc30): `gc-plan-apply` max 64.3 to 0.5ms, `repack-apply`
   max 48.0 to 0.3ms; the 10-100ms band 1394 to 175 per million. The preps
   then hand the worker the base index (#990, `gc-plan-prep` max 25.1 to
   0.0ms) and the map layers (#991, `close-prep` max 11.3 to 1.2ms). Every
   worker site holds under 3ms at the median; the worst write wait equals a
   guest write's own hold.
5. The fold-equals-rebuild assertion after every swap in the
   `volume-invariants` build, and a proptest that interleaves writes with
   folds.

Each step is measured on the rig's `[lock …]` lines before the next starts.

## Open questions

- The depth policy when a third promote would freeze while two layers are in
  flight: wait, or stack.
- `pending` and `delta` describe the same writes. Whether the worker can form
  the segment from the frozen layer plus the WAL file, and `pending` goes,
  decides how much state the freeze moves.
