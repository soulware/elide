# Design: the fork branch invariant

**Status:** Implemented.

## The invariant

A fork's branch ULID names a snapshot of the source.

Provenance records the branch as the literal path `<source-ulid>/snapshots/<branch-ulid>`,
and `fork_volume` derives it from `latest_snapshot`. The branch point is a
snapshot by definition, not by convention.

## What the invariant carries

Cross-fork safety, in three links.

A child resolves only source segments at or below its branch ULID.
`segment_ref_from_path` applies the cutoff (`segment.rs`, `if stem > cutoff
{ return None }`) inside `discover_fork_segments`, which is what both the
`LbaMap` rebuild (`lbamap.rs`) and the `ExtentIndex` rebuild
(`extentindex.rs`) use to load an ancestor layer.

A volume's rewrite floor is the maximum over its own `snapshots/*.manifest`
files, and `collect_stats` skips `seg_ulid <= floor`. The same floor gates
`prepare_repack` and reclaim.

The branch ULID is one of those snapshots, so the floor sits at or above it,
and every segment a child can reach is frozen.

The rewriters therefore never reason about children. `rebuild_chain` walks
ancestors only, so a child's DedupRef into a source is invisible when GC runs
on that source, and it does not matter because nothing a child reaches is ever
a candidate. This holds for `Data` entries and canonicals alike.

Remote children hold it for the same reason. A fork on another host branches at
a snapshot the source published, and every published snapshot is one the source
created locally, so the branch ULID is at or below the source's local floor.

The invariant applies to both cutoff-bounded edge kinds. A child's
`extent_index` entries are `<source-ulid>/<snapshot-ulid>` pairs, loaded as
bounded ancestor layers by `walk_extent_ancestors`, and they name snapshots on
the same terms.

## Enforcement

`resolve_snapshot` validates the pinned source forms — `ForkSource::Pinned` and
`ForkSource::PinnedName` — against the source's own snapshots before the fork is
minted, and rejects a `snap_ulid` that names none.

The check is answerable exactly where it is needed, because the two source
classes differ in both respects at once.

A supervised writable volume created every snapshot it has, so they are all
local, and the check needs nothing prefetch has not already done. It is also
the only class a rewriter touches: an unbacked pin against a running writable
volume names a branch above that volume's floor, and the volume then collects
segments the child still resolves.

A readonly skeleton is exempt. It has no daemon, so `gc_checkpoint` never
answers and no rewriter reaches it, and its branch manifest is legitimately
absent at mint time — `pull_chain` reads `meta/<ulid>.{provenance,pub}` only,
and snapshot manifests arrive in `surface_prefetch`, which runs after
`mint_fork`. `fork_volume_at` requires no local marker for the same reason.

This is the same distinction that decides whether a volume is rewritten at all,
so the validation reads off an existing artefact class rather than introducing
an axis.

The `snap_ulid` is parsed with `Ulid::from_string` at the CLI boundary and
looked up through `signing::snapshot_manifest_filename`, so a stop-snapshot
suffix cannot satisfy it. Stop snapshots do not raise the floor either, since
`latest_snapshot` parses the stem as a ULID and `<ulid>-stop` fails.

The floor keeps its definition, the three rewriter sites call `latest_snapshot`,
and no new on-disk state appears.

## Snapshot release

The invariant is established at fork time and a later release can break it. A
released snapshot lowers the floor, and a child that branched at it is exposed
again.

Nothing releases snapshots today. No code path deletes a `<ulid>.manifest`.

A release verb refuses a snapshot that a local fork branched at. The lineage
forest already carries `ParentEdge { ulid, snapshot }` for every local child
and already walks every local provenance each liveness tick, so the answer is a
forest query rather than new state. `extent_index` edges pin on the same terms
and belong in the same query.

## Verification

`elide-coordinator/src/fork.rs`:

- A pinned fork against a local writable source at a ULID that names no
  snapshot is rejected, and the rejection names the source and the ULID.
- A pinned fork at a real snapshot of a writable source succeeds.
- A pinned fork against a readonly skeleton succeeds with no local manifest,
  which pins the prefetch ordering the exemption exists for.
- A stop-snapshot ULID does not satisfy the check.

`elide-coordinator/tests/gc_test.rs`:

- `gc_leaves_a_forks_reachable_range_alone` — a source sweeps after a child
  branched at its snapshot, and the branch-time segment stays out of the pass,
  keeps its `.idx` and its cache body, and still serves the child's read.

The `fork_proptest` and `gc_proptest` oracles cover whether a rewrite removes
bytes a fork still resolves.

## Related

- [`ancestor-liveness.md`](ancestor-liveness.md) for the lineage forest and the
  anchor and skeleton classes this reads off.
