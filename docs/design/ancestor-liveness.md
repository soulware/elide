# Local ancestor liveness

Status: proposed.

A `by_id/<ulid>/` directory is shared state: it can be a named volume's
home *and* an ancestor layer that other local volumes' read paths walk
through. `volume remove` decides from the target's own lifecycle state
alone (stopped, released, readonly), so it can delete a directory that a
sibling volume's fork chain still requires — after which that sibling's
daemon cannot open and crash-loops under supervision.

This doc proposes making local ancestor presence a *liveness* property
with a single reachability definition, enforced in both directions:

- **remove** unbinds the name and demotes the directory to the readonly
  ancestor-skeleton shape instead of deleting it;
- a **sweep** deletes skeletons no local volume's lineage reaches;
- a **heal** pass re-pulls ancestors a lineage reaches but which are
  missing or incomplete on disk.

Sweep and heal are the same computation with opposite signs, so local
`by_id/` state becomes convergent: reachable ⇒ present, unreachable ⇒
eventually deleted.

## Incident (coord-1, 2026-07-03)

All on one coordinator, which the volume never left:

| time (UTC) | event |
|---|---|
| 07-02 16:44 | `vol2` (fork `01KWHK77…0FN0`) stopped; stop-snapshot `…J3C5` committed |
| 07-02 16:45:14 | released at handoff snapshot `…J3C5` |
| 07-02 16:45:21 | new claim binds `vol2` → fork `01KWHVGW…A426`; fence rehomes the old fork as **`vol2-2595e8`** |
| 07-02 16:47 | force-claim mints `01KWHVM5…M6S0` from `…A426`; the claim set follows the frontier, so its signed provenance parent is `01KWHK77…0FN0/…J3C5`; one head-delta segment re-owned |
| 07-02 16:47:08 | `…M6S0` opens fine — `fork_layers=3`, parent dir present |
| 07-03 06:50:06 | operator removes `vol2-2595e8` → `remove_dir_all(by_id/01KWHK77…0FN0)` |
| 07-03 06:50:14 | `volume start vol2` → `verify_ancestor_manifests` fails (`ancestor 01KWHK77…0FN0 not found locally`); supervisor crash-loops with backoff |

No data was lost — remove is a local-instance verb and the bucket still
holds `by_id/01KWHK77…0FN0/` in full. Only the local read form was
destroyed while still referenced.

## The layering mismatch

The operator surface is **names**; the dependency graph is
**directories**. Rehome (`displaced-fork-rehome.md`) renames the old
incarnation out of the way, and the suffix name reads as "legacy copy,
safe to delete" — that is what the rename is *for*. But
`verify_ancestor_manifests` and the read path never see names: they
walk `by_id/<ulid>` chains. `remove` takes a name and acts on the
directory, fusing two operations — unbinding a disposable identity and
deleting possibly-shared bytes — into one verb. In filesystem terms it
does `unlink` + `rm -rf` with no link count.

Rehome is only the most seductive route to the broken state. The
precondition is co-residency of a dependent and a removable
ancestor-instance, reachable four ways:

1. **Same-coord re-claim** (the incident): release → claim →
   force-claim on one coordinator leaves the old incarnation local, and
   frontier-following claims (`a65112f`) point the new fork's parent
   straight at it.
2. **Rehome-back after travel**: the claim hydrate on return finds the
   ancestor already local (the rehomed instance) and skips the pull, so
   a named, removable volume silently becomes an ancestor layer.
3. **Removing a pulled ancestor skeleton**: `pull_volume_skeleton`
   marks the dir `volume.readonly` → `ReadonlyImported`, which
   `remove_volume` accepts on the assumption "removing it just drops
   the bytes" (`elide-coordinator/src/inbound/mod.rs`). Identical crash
   on any coordinator that claimed a fork.
4. **Removing an imported readonly base** that local forks were forked
   from.

And the chain is walked to the root, so every co-resident hop is
load-bearing — on the incident machine the grandparent `…006X` is
equally removable and equally fatal.

## What open requires — and what is already lazy

Per ancestor, the read form the daemon needs *at open* is:

- `volume.provenance` — verified under the pubkey the child committed
  to, to walk the next hop;
- `snapshots/<snap>.manifest` — the pinned segment set;
- `index/<seg>.idx` for every manifest segment — the LBA-map rebuild
  reads all sections up front to know where every block lives.

Segment **bodies** are already lazy: `BlockReader` demand-fetches them
into `cache/` with per-ancestor `volume-ro` credentials vended at read
time. So "fetch ancestors lazily" cannot mean per-read laziness — the
LBA rebuild consumes whole index sections at open — but it *can* mean
materialising the metadata read form on demand, per ancestor directory,
before open. The machinery exists: `prefetch_indexes`
(`elide-coordinator/src/prefetch.rs`) walks the lineage chain, calls
`pull_volume_skeleton` for ancestors not present locally, and fetches
their index sections and snapshot artifacts, minting `volume-ro` per
ancestor prefix.

What's missing is the trigger. The startup task runs `prefetch_indexes`
only when the fork itself has no local segments — the "freshly pulled
skeleton" heuristic (`elide-coordinator/src/tasks.rs`). A fork whose own
`index/` is populated but whose *ancestor* is missing (the incident)
never prefetches; the supervisor spawns the daemon straight into the
open failure.

Keeping the fetch in the coordinator (not the daemon) stays the right
split: ancestor directories are shared across volumes, so the
coordinator is their single writer; the daemon's open remains a
deterministic local verify with no network dependency, per the
hydrate-then-verify shape the claim path already has.

## Design

### Liveness

Partition `by_id/` directories:

- **Anchors** — directories the operator or a job explicitly owns: any
  dir holding `volume.key`, a `by_name` binding, or an in-flight
  marker (`volume.claiming`, `volume.importing`). Never swept; removed
  only by verb.
- **Skeletons** — `volume.readonly`-marked dirs with none of the
  above: pulled ancestors and demoted removals.

A skeleton is **live** iff some anchor's `lineage_ulids`
(`elide-core/src/volume/ancestry.rs`: fork-parent chain + extent-index
sources + recovery sources) contains its ULID. There is no reverse
index; liveness is a scan over anchors walking each lineage — fine at
coordinator scale.

"Anchor" deliberately makes no topological claim. In the lineage tree
the anchors are usually the tips and the skeletons the interior and
root nodes — but not always: an anchored volume that was itself forked
from sits interior. Ownership and tree position are orthogonal axes,
and "root" stays reserved for lineage topology
(`ProvenanceLineage::Root`, the parentless head of a fork tree).

The anchor-set definition resolves the imported-base trap: an imported
base with no forks yet is an anchor via its name binding, so it is
never swept as garbage; removing its name demotes it into the skeleton
pool, where it survives exactly as long as forks reference it.

### Remove: unbind + demote

`remove_volume` keeps its current preconditions (halted, flushed unless
`--force`, ownership released first). It then always unbinds the name
and settles S3 ownership as today, but instead of `remove_dir_all`:

- drop `volume.key`, `wal/`, `pending/`, `gc/`, `volume.lock`,
  `volume.toml`, `control.sock`;
- keep `index/`, `snapshots/`, `volume.pub`, `volume.provenance`, and
  `cache/` (already-fetched bodies keep serving dependents);
- write `volume.readonly`.

The result is byte-shape-identical to what `pull_volume_skeleton` +
prefetch would produce, so "removed here" and "claimed onto a fresh
coord" converge to the same on-disk state. The signing-key shadow at
`keys/<ulid>.key` survives, as today, so a released name stays
reclaimable.

Remove never refuses for dependency reasons and needs no dependency
check of its own — an unreferenced skeleton is the sweep's problem, not
the verb's. The reply should still say what happened
(`kept as read-only ancestor; N volume(s) reference it` /
`removed`), so an operator reclaiming disk space is not surprised.

### Sweep and heal

One pass, folded into the coordinator's existing tick loop, computes
the reachable set once and acts in both directions:

- **sweep**: delete skeletons outside the reachable set;
- **heal**: for each anchor, if any lineage hop is missing its dir or its
  read form is incomplete (missing `.idx` for a manifest segment,
  missing manifest), run the existing `prefetch_indexes` chain walk to
  re-materialise it — the same code the claim path uses, with a new
  trigger: *lineage incompleteness* instead of *fork looks freshly
  pulled*.

Heal turns the incident's terminal crash-loop into a self-repairing
blip: the supervisor's open fails, the next tick re-pulls the parent
skeleton and sections from the bucket, the next spawn succeeds. It also
covers any other cause of a missing ancestor (partial pull, operator
surgery, disk restore).

### Operator surface: `volume tree`

The same lineage forest, rendered. Local-only by construction: it walks
`by_id/` provenance on disk, no bucket reads.

```
01KWHFHKKY…006X                       skeleton
└─ 01KWHK77…0FN0                      skeleton   2 dependents
   ├─ vol2         01KWHVM5…M6S0      rw  running
   └─ vol2-2595e8  01KWKE2W…NVQY      rw  stopped
```

- Primary edges are fork parents, labelled with the snapshot pin.
  Extent-index and recovery-source references are cross-edges (the
  structure is a DAG), so they annotate the row (`+2 extent sources`)
  rather than draw.
- Anchors and skeletons render distinctly: a leaf skeleton is visibly
  sweepable, an interior one visibly load-bearing — the dependency
  structure `remove` acts on, shown before the verb runs rather than
  enforced by a refusal ("eligibility shown, not filtered").
- A reachable-but-missing ancestor renders as a broken node
  (`… MISSING`) — a heal candidate.

Liveness, heal, and tree are three consumers of the one
lineage-forest computation, so the tree is also the low-risk first
consumer: it can land and be eyeballed before the same computation is
wired to deletion.

### Races

The sweep must not eat a skeleton pulled for a claim that has not yet
finalized: mid-claim, the new fork's provenance may not be readable, so
nothing on disk references the just-pulled ancestors. `volume.claiming`
and `volume.importing` dirs are anchors, but their lineages may be
unreadable; options, to be settled at implementation time:

- skip the sweep entirely while any claiming/importing marker exists
  (simplest; claims are seconds long);
- exempt skeletons younger than a grace window;
- have the claim job register pulled ULIDs in its in-flight state.

## Field recovery and the stale hint

Until heal exists, a volume in this state is close to wedged, because
every data-preserving verb needs the daemon the missing ancestor
prevents from starting (observed on the incident machine, 2026-07-03):

- `volume list` shows the crash-looping volume as `stopped` (disk
  -derived, no live pid) while `remove` refuses it as "running" — the
  shape is `Stopped`, not `StoppedManual`, since the supervisor would
  still respawn it;
- `volume stop` fails (drain needs the daemon) → `stop --force`;
- `volume snapshot` would fail the same way, so the volume's durable
  state past its last snapshot can never be covered;
- plain `remove` then refuses (`NeedsDrain`), and `remove --force`
  releases at the recorded handoff **or synthesises an empty one**
  (`release_owned_for_remove`,
  `elide-coordinator/src/inbound/lifecycle.rs`) — for a
  freshly-claimed record with no recorded handoff that discards the
  volume's entire claim set.

The one data-preserving exit exists only when the deleted ancestor was
a *named* released volume: claim it back. `volume claim vol2-2595e8`
mints a fresh fork of `…0FN0` and its prefetch re-pulls the `…0FN0`
skeleton into `by_id/` as a side effect — after which the dependent
volume starts normally and the reclaimed fork can be stopped and
removed again. A deleted *unnamed* skeleton (route 3) has no name to
claim, and the only exits are hand-materialising the read form from the
bucket or `remove --force` discard. Heal closes exactly this hole.

Independently: the open-failure hint
(`elide-core/src/volume/ancestry.rs:107`) says to run
`elide volume remote pull`, a verb deleted with the breadcrumb
subsystem (#650). It should name the actual recovery
(remove + re-claim, or nothing once heal lands).

## Open questions

- Sweep cadence, and whether `remove` runs a synchronous sweep so
  removing the *last* referent frees disk immediately.
- Exact wording of the remove reply for the demoted case.
- Whether `heal` should also verify skeleton *completeness* against the
  manifest on every tick or only on open-failure signal from the
  supervisor (cost: one chain walk per anchor per tick).
