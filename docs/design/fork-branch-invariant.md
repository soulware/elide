# Design: the fork branch invariant

**Status:** Proposed.

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

## Where it is not enforced

`ForkSource::Pinned` and `ForkSource::PinnedName` carry a caller-supplied
`snap_ulid` through `resolve_snapshot` into `fork_volume_at` with no existence
check at any hop.

`fork_volume_at` declines to require a local marker, and prefetch ordering is
why. `pull_chain` pulls skeletons, reading `meta/<ulid>.{provenance,pub}` only;
snapshot manifests arrive in `surface_prefetch`, which runs after `mint_fork`.
A pulled source's branch manifest is not on disk when the fork is minted.

What holds today is the shape of the other two source forms. A writable source
takes a fresh implicit snapshot at fork time, so its branch ULID is its floor.
A readonly source is never rewritten, because GC runs only on a supervised
`fork_dir` behind a live-daemon `gc_checkpoint` call. Neither is a check.

Nothing stops a pinned fork against a running writable volume at a ULID above
that volume's floor. The volume then collects segments the child still
resolves, and the child reads wrong bytes.

## Design

`resolve_snapshot` validates the pinned forms against the source's snapshots
before the fork is minted, and rejects a `snap_ulid` that names none.

The check is answerable exactly where it is needed, because the two source
classes differ in both respects at once.

A supervised writable volume created every snapshot it has, so they are all
local, and the check needs nothing prefetch has not already done. It is also
the only class a rewriter touches.

A readonly skeleton has no daemon, so `gc_checkpoint` never answers and no
rewriter reaches it. Its branch manifest may legitimately be absent at mint
time, and nothing depends on its floor.

This is the same distinction that already decides whether a volume is
rewritten at all, so the validation reads off an existing artefact class
rather than introducing an axis.

The `snap_ulid` is parsed with `Ulid::from_string` and looked up through
`signing::snapshot_manifest_filename`, so a stop-snapshot suffix cannot satisfy
it. Stop snapshots do not raise the floor either, since `latest_snapshot`
parses the stem as a ULID and `<ulid>-stop` fails.

Nothing else changes. The floor keeps its definition, the three rewriter sites
keep calling `latest_snapshot`, and no new on-disk state appears.

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

- A pinned fork against a local writable source at a ULID that names no
  snapshot is rejected, and the rejection names the source and the ULID.
- A pinned fork at a real snapshot of a writable source succeeds.
- A pinned fork against a readonly skeleton succeeds with no local manifest,
  which pins the prefetch ordering the exemption exists for.
- A stop-snapshot ULID does not satisfy the check.
- A GC test asserting a source leaves its child's reachable range alone, so the
  floor property is stated somewhere other than this document.
- The existing `fork_proptest` and `gc_proptest` oracles cover whether a
  rewrite removes bytes a fork still resolves.

## Related

- [`ancestor-liveness.md`](ancestor-liveness.md) for the lineage forest and the
  anchor and skeleton classes this reads off.
