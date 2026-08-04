# Design: repack on the open generation

**Status:** Proposed. Pairs with `generation-close-pass.md`, which covers the
sealed generation. Builds on upload generations (`upload-generations.md`) and
halt-on-failure drain (`durable-cut.md`), both shipped.

## Problem

Repack runs from `run_volume_compactions` on every tick, and
`prepare_repack` starts a pass whenever `pending/open/` holds anything:

```rust
let flushed = control::promote_wal(&self.fork_dir).await;
if let Some(s) = control::repack(&self.fork_dir).await
```

The tick is `[supervisor] drain_interval`, 5s by default. A cut at 120s
therefore materialises the open generation about 24 times before any of it
ships, once per tick, each pass rewriting every surviving byte the previous
pass just wrote.

Measured on rig pg15 (2026-08-04, v0.1.46, perf-2x, scale 50 / 8 clients,
180s benches, config varied across machine restarts):

| tick | gc | tps | worker | worker ms/txn | actor ms/txn |
|---|---|---|---|---|---|
| 5s | 10s | 617.7 | 0.52 core | 0.85 | 0.29 |
| 60s | (60s) | 842.2 | 0.39 core | 0.46 | 0.07 |
| 5s | 600s | 530.6 | 0.60 core | 1.12 | 0.24 |
| 60s | (60s) | 922.2 | 0.31 core | 0.34 | 0.07 |

Throughput ran 618, 842, 531, 922 against a volume that only aged, so the
effect belongs to the cadence. The 60s tick averages **+43%** guest
throughput at 2.5x less worker CPU per transaction. The 16 ublk queue
threads are the control: their per-transaction cost holds at ~0.2ms across
every variant, as work proportional to guest IO does.

The third row is the one that settles where the cost lives. It leaves the
tick at 5s and takes GC compaction out, and it is the *worst* of the four:
without folding, the committed population stays sparse and every pass
downstream of it carries more. GC compaction pays for itself.

These four benches predate #861, #862 and #863, which move the GC handoff
scan, the guest FLUSH fsync and the repack segment build off the volume
lock. Those reach the actor column. The worker column is the cost of doing
the work at all, which is what the cadence governs.

## What a pass over the open generation is for

Mortality is monotone. A byte superseded at t=30s is still superseded when
the generation seals, so one pass over the sealed generation harvests
exactly the dead bytes that N passes over the window harvest. Repacking
during the window changes when dead bytes stop occupying local disk, and
nothing else about what eventually ships.

That leaves one job: **bounding the open generation while it is held open.**

A cut requires the previous generation to have drained:

```rust
let cut_due = self.cut_due() && Self::upload_generation_drained(&self.fork_dir);
```

So when S3 is unavailable the drain halts on its first failure,
`pending/upload/` stays occupied, the cut is withheld, and `pending/open/`
takes every WAL flush for as long as the outage lasts without rotating. The
open generation is the one directory in the pipeline that grows without a
bound of its own, and a pass over it is what supplies the bound: dead bytes
leave, and a bin-packed output replaces a run of flush segments, which also
holds down the segment count the read path probes.

## The trigger is pressure

The pass fires on what has accumulated in `pending/open/` since the last
one, measured as bytes and segment count from the directory listing, rather
than on the clock.

Pressure describes the situation directly. An outage produces backlog, and
backlog is what the trigger reads, so the pass fires harder exactly when the
directory is growing and stays silent when it is not. A period gets both
halves wrong at once: it fires on a window with nothing in it, and it fires
no faster when a stalled drain is filling one. It also guarantees the case
where a cut arrives moments after a periodic pass and materialises the same
bytes twice inside a few seconds.

**The gate belongs in `prepare_repack`.** Repack reaches the volume only as
`VolumeRequest::Repack`, sent by the coordinator's tick, and
`prepare_repack` already answers `Ok(None)` when there is nothing to do. A
threshold there keeps the tick asking at its own cadence and makes the
answer usually no, so the cadence becomes an upper bound on how often the
question is posed rather than a schedule of work. The volume is also the
side that knows its own state, which is where the decision reads naturally.

Two thresholds, both cheap to evaluate from a `read_dir`:

- **Accumulated bytes**, the footprint the bound exists to hold. Sized
  against `REPACK_TARGET_LIVE`, since a pass whose inputs sum to less than
  one output target has no packing to do.
- **Segment count**, which the read path pays for separately through the
  descriptor cache (`project read_decay`: miss rate is a function of
  capacity against live segment count).

Either crossing starts a pass.

## Division of labour

Three rewriters run over a volume's bytes, and after this change each has
one job:

- **The open generation pass** bounds footprint and segment count while a
  generation is held open. Pressure-triggered.
- **The close pass** (`generation-close-pass.md`) sets the shape of the
  objects that reach S3, sized in compressed bytes against the multipart
  part size. Once per cut, over immutable inputs.
- **GC** keeps the committed population dense, which the third measured row
  shows is load-bearing for both of the above.

In a healthy volume, uploads keep up, no backlog accumulates, the open pass
never fires, and the close pass materialises the generation exactly once
between a byte being written and that byte reaching S3.

## Reclaim

Reclaim sits upstream of both passes. It rewrites bloated LBA sub-ranges of
committed content, and `prepare_reclaim` mints its output into
`segment::pending_open_dir`, so it produces into the open generation exactly
as formation does. Both passes then consume what it wrote.

The close pass is what gives reclaim's output a sensible shape. A reclaim
run emits one small segment, historically around 650 KiB of live bytes
landing near 50 KiB compressed, and today each becomes its own S3 object
that GC later folds into a larger one, so the same live bytes are written
and uploaded twice. Packing reclaim output at the seal ships it inside a
part-sized object the first time.

Reclaim also shares the per-tick shape this document takes off repack. It
runs third in `run_volume_compactions`, after `promote_wal` and `repack`,
under a `cap` of one candidate per tick which bounds per-tick latency the
way a period bounds repack. On the measured pgbench workload every pass in
the bench window came back `runs_rewritten=0 discarded=1`, at 118 ms to
1.07 s per pass against a 5s tick. The scanner finds a candidate, prep
snapshots and mints, the worker walks the bloat gate, and the candidate is
discarded.

`prepare_reclaim` opens with `flush_wal()`, which reaches
`flush_wal_to_pending()` and builds the segment inline on the actor thread.
The flush carries the `u_flush < u_reclaim` ordering invariant, since
reclaim's new LBA mappings supersede the pre-reclaim WAL entries they
consume and a rebuild otherwise lets the flushed segment shadow the reclaim
output. #863 gave `prepare_repack` the shape that keeps this ordering while
moving the segment build off the lock, dispatching the flush as a
`PromoteJob` the worker executes, and the same shape applies here (#865).

### Per-run admission comes first

Moving reclaim toward the trigger this document proposes depends on #866.
`apply_reclaim_result` gates on `Arc::ptr_eq` over the whole lbamap and then
registers unconditionally, so a write anywhere on the volume discards the
entire result, including runs the reclaim never touched. Every other apply
path in the system already admits per item, `apply_repack_result` through
CAS on `current loc.segment_id == input_ulid` and `insert_consuming_inputs`.

A whole-map token is what makes reclaim hostile to batching. Larger, less
frequent passes hold a longer window between prep and apply, which raises
the chance that one unrelated write throws away a bigger result, so the
trigger change makes the existing gate worse rather than leaving it neutral.
Per-run admission turns that into partial success, where the runs a
concurrent write invalidated are refused individually and the rest land, and
a longer window costs proportionally rather than wholesale.

The same gate is what orders #865 behind #866. Dispatching the prep flush to
the worker puts `apply_promote` and its `Arc::make_mut(&mut self.lbamap)`
between the reclaim's prep snapshot and its apply, where the current inline
flush runs before the snapshot is taken.

## What the two passes share, and where they part

Both are `execute_repack`: the same classifier, bin-pack, journal
consolidation under `allow_journal`, output signing, consuming-inputs apply
and crash model. `RepackJob` already carries its target as `pending_dir`,
and `seg_paths` pins the candidate list at prep, which is what the sealed
generation needs and gets for free.

Three things differ, and they sit in prep rather than in the pass:

1. **The WAL flush.** `prepare_repack` closes the running WAL into a fresh
   segment and includes it, because the WAL holds the open generation's
   newest content. Those bytes belong to the generation *after* the sealed
   one, so the close pass runs with `flush: None` — a shape
   `RepackPrep { flush: Option<PromoteJob>, job }` already admits.
2. **When output ULIDs are minted.** The open pass mints at prep,
   just-in-time, needing only `max(pending) < running_WAL`. The close pass
   mints inside the rotate's critical section and holds the reservations, so
   they sort above the sealed generation and below everything the next
   generation mints.
3. **How outputs are sized.** The open pass budgets plaintext against
   `REPACK_TARGET_LIVE`. The close pass accumulates compressed length
   against the part size.

## Cost

A pass costs one materialisation of the live bytes it covers. Under the
pressure trigger the number of passes over a generation's lifetime is
governed by how far the drain falls behind rather than by how long the
generation stays open, so a healthy volume pays once at the close and a
stalled one pays per backlog threshold crossed.

## Non-goals

- No change to the tick cadence itself, which continues to drive
  `promote_wal`, drain, GC and the cut.
- No change to what a generation means or how HEAD names it.
- No change to the segment format or the S3 object layout.
