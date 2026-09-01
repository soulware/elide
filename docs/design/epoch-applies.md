# Design: epoch applies

**Status:** design only. The measurements come from the `write_contention`
simulator (2026-08-31, parked on the `wip-measurement-probes` branch) and the
rig's per-site lock statistics (2026-09-01). Builds on claimant tracking
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

The volume keeps its mutex. Under it the maps become three layers and an
epoch counter:

- **base**, the two large maps, which only an apply replaces,
- **frozen**, a list of immutable layers, one per promote in flight,
- **delta**, the two small maps that hold the open WAL's writes,
- **epoch**, which the WAL rotation increments.

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
The `pending` vector stays as the worker's input, because segment formation
needs WAL order and body offsets that the maps do not carry.

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

A point lookup (`lookup`, `lookup_with_claimant`, `claim_refcount`,
`extent_index.lookup`) queries the layers in order and returns the first hit.
Each miss costs one more tree descent, measured at about 250ns per layer on a
populated delta (`second_lookup_cost` probe).

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
| gc-plan-apply | `register_entry_consuming_inputs`, `remove_owner_at`, `purge_journal_segment`, gate | clone `base`, transform, gate on the clone, swap with the removal check |
| repack-apply (per bucket) | same shape as gc-plan-apply | same shape as gc-plan-apply |
| reap-apply | `remove_input_owned`, purges | clone `base`, transform, swap with the removal check |
| reclaim-apply | `register_entry_if_newer`, register output | clone `base`, transform, swap |
| gc-handoff-finalize, own-segments, publish | no map mutation | unchanged |

A refused gate discards the clone. Today it restores two `Arc`s; the outcome
is the same.

Only frozen layers ever hold WAL locations, and `delta` holds only the open
WAL's. The drain flip and the reclaim therefore touch `base` alone.

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

**Other folds.** The transform functions are unchanged, so their admission is
the rebuild's admission by construction. `register_entry_consuming_inputs`
takes a range only from a consumed input, and `register_entry_if_newer` takes
it only from a lower claimant.

## Removals race the layers

A base-only transform cannot see the claims in `delta` and the frozen layers.
Today the mutex serialises writes and applies, and the stale-liveness check
reads the one live map. Under the scheme a GC fold, a repack bucket or a reap
can judge a hash dead against `base` while a write in `delta` has claimed it,
through the dedup lookup that resolved the hash in `base`. The swap would then
strand that claim.

Two checks close the window:

1. The fold reads liveness across every layer at its start. `claim_refcount`
   and `is_named_delta_source` sum over `base`, the frozen layers and `delta`.
2. The swap, under the lock, checks each hash the fold removed against the
   `delta` entries written since the fold started. `delta` is small and the
   check is one lookup per removed hash. A hit refuses the swap, the apply
   discards its clone, and the next pass runs against a base that includes the
   claim. This is the refusal shape `mutate_gated_on_resolvability` already
   has.

The promote fold has no removal, and its input layer is immutable, so its CAS
preconditions (`pre_promote_offsets`) hold by construction.

## Frozen depth

Each promote in flight owns one frozen layer. The WAL-threshold promote and the
GC checkpoint promote can overlap, so the list can hold two. A read pays one
descent per layer, so the depth is a cost the lock line reports.
`promotes_in_flight` bounds it today; the design keeps that bound.

## Off-lock consumers of the maps

`sweep_unreachable`, `scan_reclaim_candidates`, the gate's residual walk and
the invariants asserts iterate a whole map. They take a snapshot and call
`materialise()`, which folds the layers into a clone of `base` off the lock, in
O(layer × log n). The coordinator's GC reads the maps from disk and is not
affected.

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

1. The layered `ReadSnapshot`, the overlay range query, `materialise()`, and
   writes into `delta`. Applies keep their in-place mutation on a materialised
   base under the lock. This step changes no hold and validates the read path.
2. The promote as freeze, fold, swap. This removes `promote-apply` and
   `promote-prep` from the hold ranking.
3. The base-only applies: the drain flip and the reclaim.
4. GC plan apply, repack buckets and the reap, with the swap removal check.
5. The fold-equals-rebuild assertion after every swap in the
   `volume-invariants` build, and a proptest that interleaves writes with
   folds.

Each step is measured on the rig's `[lock …]` lines before the next starts.

## Open questions

- The promote fold's "layer wins on its ranges" rule rests on the claim that
  `base` never receives content newer than a frozen write on the same range.
  A proptest that interleaves writes, promotes and repack outputs with ULIDs
  minted after the WAL's is the check to write before step 2.
- The journal tier is keyed by `(claimant, hash)`. A journal write inserts
  under the WAL ULID in `delta`, and the promote fold rekeys it to the segment.
  Whether `lookup_journal` needs the layer walk, or the claimant alone selects
  the layer, decides the read cost for journal LBAs.
- The depth policy when a third promote would freeze while two layers are in
  flight: wait, or stack.
- `pending` and `delta` describe the same writes. Whether the worker can form
  the segment from the frozen layer plus the WAL file, and `pending` goes,
  decides how much state the freeze moves.
