# LIST-elimination plan

Remove every `s3:ListBucket` use from the coordinator runtime. Each
prefix LIST becomes a deterministic GET; then the `ListBucket`
statement is deleted from `coord-writer`'s role template and from
`design-mint.md` (resolves open question #12). The decision stands
independent of whether Tigris can prefix-scope `ListBucket` — that is
parked (`design-mint.md` #12); this work is the backend-portable answer
and a long-wanted perf win regardless.

Authority: `design-mint.md` § *`coord-writer`* / open question #12.
Related: `design-volume-event-log.md` (event HEAD pointer),
`design-peer-segment-fetch.md`.

## The LIST surface (from a full sweep of `elide-coordinator/src`)

| Prefix LISTed | Call sites | What it derives | Role today |
|---|---|---|---|
| `by_id/<vol>/snapshots/` | `fetch.rs:325`, `fork.rs:561`, `prefetch.rs:949`, `start_remote.rs:147` | max snapshot ULID + its dated `.manifest` key | `coord-data` |
| `by_id/<vol>/snapshots/` | `inbound/lifecycle.rs:777`, `inbound/lifecycle.rs:1502` | the *set* of snapshots, for cleanup/delete | `coord-data`/`writer` |
| `by_id/<vol>/segments/` | `prefetch.rs:442`, `fork.rs:670`, `recovery.rs:165` | the live segment-ULID set for the volume | `coord-data` |
| `by_id/<vol>/retention/` | `prefetch.rs:643` (`list_supersessions`), `reaper.rs:80` | GC supersession markers (input→output) | `coord-data` |
| `events/<name>/` | `peer_discovery.rs:171`, `volume_event_store.rs:155/253` | the event-record set / head for a name | `coord-writer` |

`config.rs:289` (`probe`, bare `by_id/`) is the *non*-mint passthrough
reachability check — not on the mint path, out of scope.

Keys are date-partitioned (`…/snapshots/YYYYMMDD/<ulid>.manifest`,
`…/segments/YYYYMMDD/<ulid>`), so today's LIST is a recursive prefix
scan; the substitutes below do not need the date partition.

## Substitution design

Two classes:

The substitutes form three layers, not two. The spine is the
**per-name event log** — already append-only, already self-linking,
already getting a `HEAD` pointer. Snapshot enumeration is a
*projection of that spine*, not a parallel structure (the rejected
alternative — chaining snapshot manifests — fails because snapshots
are deleted mid-sequence, e.g. `-stop` snapshots; the event log
represents deletion as another appended event, not a structural
mutation, which is exactly why the projection survives deletion where
a manifest chain would not). Only the genuinely high-cardinality
per-write sets (`segments`, `retention`) need a separate maintained
index.

### Layer A — the event-log spine

- **`events/<name>/HEAD`** — pointer to the newest event; readers walk
  the back-linked chain from it (across `RenamedFrom.inherits_log_from`
  for renamed names). Replaces the `events/<name>/` LISTs
  (`peer_discovery.rs:171`, `volume_event_store.rs:155/253`). Key
  shape coordinated with `design-volume-event-log.md`, not reinvented.
  Runs under `coord-writer`.
- **Snapshot lifecycle becomes events.** Add `SnapshotPublished {
  snap_ulid, kind }` and `SnapshotDeleted { snap_ulid }` to
  `EventKind`. The *handoff/fork* snapshots are **already** in the log
  — `Released`/`ForceReleased` carry `handoff_snapshot`, `ForkedFrom`
  carries `source_snap_ulid`; the projection folds those too, so a
  release/claim handoff needs no new event. The set of a volume's
  snapshots, and the latest of each `kind`, is the fold of
  `SnapshotPublished` − `SnapshotDeleted` (+ the handoff/fork
  references) over the chain. Replaces the snapshot-set LISTs
  (`lifecycle.rs:777`, `lifecycle.rs:1502`, and
  `latest_release_handoff_snapshot` behind `lifecycle.rs:560/707` —
  the latter is *pure redundancy today*: it LISTs to recompute a ULID
  the `Released` event already records).

  Consequence: routine snapshot publish (`upload.rs:876`, per-volume,
  `coord-data`) must also append to the per-name event log
  (`coord-writer`). This crosses the data/control role boundary, but
  snapshot publish is an infrequent coordinator-mediated control
  action (not per-write), and the coordinator holds both roles — it
  composes both handles at that one touch-point, the mixed-prefix
  pattern `design-mint.md` § *Coordinator store architecture* already
  prescribes.

### Layer B — latest-pointer caches (O(1) hot path)

The spine fold is O(events since the datum). For the hot reads that
only want "the latest" — claim/hydrate/fork resolution — a derived
pointer avoids the walk:

- **`by_id/<vol>/snapshots/LATEST`** — latest snapshot **per kind**
  (`snapshot_take_new` semantics: stable vs `-stop`), written
  conditional-PUT at publish. Migrates `fetch.rs:325`, `fork.rs:561`,
  `prefetch.rs:949`, `start_remote.rs:147`, `lifecycle.rs:777`.

This pointer is a **cache of the Layer-A fold, never an independent
truth**: it is reconstructable by replaying the event log, and that
equivalence is the reconcile invariant (below). A lost/stale pointer
is a performance regression, not a correctness one.

### Layer C — maintained index (`segments`, `retention` only)

The genuinely high-cardinality per-write sets — accreted by the WAL
drain and GC, pruned by the reaper — are too large to fold from the
event chain on every read, so they keep a dedicated per-volume index
object:

- **segment index** — appended by the drain (`upload.rs`) as each
  segment is uploaded and by GC as it writes outputs; the reaper
  tombstones entries it deletes. Replaces `prefetch.rs:442`,
  `fork.rs:670`, `recovery.rs:165`.
- **retention index** — appended by GC with each supersession marker.
  Replaces `prefetch.rs:643`, `reaper.rs:80`.

These two may collapse into one per-volume append-only "manifest
delta log" — an implementation choice deferred to its phase, but
constrained by the next section. Snapshots are deliberately **not**
here: they are Layer A.

### Worked example — a release/claim cycle

Coordinator **A** owns `myvol`; **B** later claims it. Every step is a
GET or a known-key PUT/DELETE — no LIST.

1. **Steady state (A).** A seals snapshot `S2`: writes
   `by_id/<vol>/snapshots/<date>/S2.manifest`, appends
   `SnapshotPublished{S2,Stable}` to `events/myvol/`, advances
   `events/myvol/HEAD`, bumps `snapshots/LATEST` → `(S2,Stable)`.
2. **Release (A).** A seals the handoff/stop snapshot `Sh`, writes its
   manifest, CASes `names/myvol` Live→Released, appends
   `Released{handoff_snapshot: Sh}` and advances `HEAD` (this event
   already exists today). Optionally bumps `LATEST` → `(Sh,Stop)`.
3. **Claim (B).** B CASes `names/myvol` Released→Claimed. To learn
   what to fork from it reads `snapshots/LATEST` (O(1)) and/or walks
   `events/myvol/` from `HEAD` back to the newest `Released` →
   `handoff = Sh` directly (today this is the redundant
   `latest_release_handoff_snapshot` LIST). B appends `Claimed`,
   advances `HEAD`.
4. **Hydrate (B).** From `Sh.manifest` (a GET) B gets the segment
   ULID set — the manifest already enumerates segments, so no LIST;
   any segment not local is range-GET by deterministic key.
5. **Stop-snapshot cleanup (B).** Today `lifecycle.rs:1502` LISTs the
   snapshot prefix to find and delete leftover `-stop` objects. Under
   this design B already knows `Sh` from step 3's event walk: it
   `DELETE`s `Sh` by known key and appends `SnapshotDeleted{Sh}`, so
   the projection stays exact. No LIST.

The invariant the example illustrates: **the event log is the
per-name authoritative spine; a snapshot's existence and removal are
appended events; "the snapshot set" and "the handoff" are folds over
the chain from `HEAD`; `snapshots/LATEST` is an O(1) cache of one
fold, never independent truth.**

### Reconcile/repair without LIST

LIST is today's implicit source of truth ("what is actually in the
bucket"). Removing it removes that self-heal, so the plan must replace
it, not merely delete it:

- **Layer A/B reconcile by event replay, not LIST.** The snapshot
  projection and the `LATEST` cache are derived from the event chain;
  their authoritative rebuild is *replaying `events/<name>/`*, which
  is itself LIST-free (the chain walks from `HEAD`; `HEAD` durability
  is `design-volume-event-log.md`'s concern, not redesigned here). A
  stale/lost `LATEST` is recomputed by replay — a perf event, not a
  correctness one.
- **Layer C index is authoritative for the runtime**; readers trust
  it. Divergence is bounded and one-directional by construction if the
  index entry is written *after* the object PUT and *before* the
  operation reports success: a crash can leave an object with no index
  entry (a reclaimable space leak — never a correctness loss, since an
  un-indexed segment is simply not consumed), never an index entry
  with no object on a path that matters (readers already tolerate a
  `404` on segment fetch — `list_supersessions` explicitly does).
- The **rebuild defines correctness** (cf. the project invariant for
  derived state with rebuild + incremental paths): for Layer A/B the
  rebuild is the event replay above; for the Layer C index it is a
  one-time elevated LIST. Either way the incremental
  drain/GC/reaper/publish updates must structurally match what the
  rebuild would produce — asserted in the proptest model (below), not
  by convention.
- Orphan reclamation (un-indexed objects) is an **explicit operator
  maintenance pass** that may use a privileged LIST under a separate
  elevated credential — deliberately *not* the coordinator runtime or
  the exposed surface. Runtime stays LIST-free; this keeps the "no
  optional correctness path in runtime" principle intact (repair is
  explicit and privileged, not a silent fallback).

## Phasing

Each phase is independently shippable and leaves the tree green; no
phase introduces a dual LIST+index runtime fallback (that would defeat
the purpose and is itself an optional-correctness path).

Ordered so each phase builds on the prior: the event-log spine first,
since snapshots project onto it.

- **P1 — event-log spine: `events/<name>/HEAD` + chain walk.** Migrate
  `peer_discovery` and `volume_event_store` off the `events/` LIST;
  align the pointer/key shape with `design-volume-event-log.md`. This
  is the substrate the next phase folds over.
- **P2 — snapshots as an event projection.** Add `SnapshotPublished` /
  `SnapshotDeleted` to `EventKind`; emit on publish/delete (compose
  the `coord-writer` event-log handle at the `coord-data` publish
  touch-point). Add the `snapshots/LATEST` per-kind pointer as the
  O(1) cache. Migrate the latest-snapshot consumers (`fetch.rs:325`,
  `fork.rs:561`, `prefetch.rs:949`, `start_remote.rs:147`,
  `lifecycle.rs:777`) to the pointer, and the set/handoff/cleanup
  consumers (`lifecycle.rs:560/707/1502`) to the chain fold. Removes
  every snapshot LIST.
- **P3 — segment index.** Drain + GC maintenance, crash-ordering as
  above; migrate `prefetch`/`recovery`/`fork-verify`; define + test
  the reconcile invariant.
- **P4 — retention index** (or fold into P3's delta log); migrate
  `prefetch` supersession and `reaper`.
- **P5 — drop the grant.** Delete `s3:ListBucket` from
  `mint/examples/elide_roles/coord-writer.json`, the §*`coord-writer`*
  policy, and the role-inventory table in `design-mint.md`; add a CI
  grep guard that no `.list(` reaches a mint-backed store. End state:
  no role carries `ListBucket`.

## Back-compat

Clean break (project default). Indexes/pointers are derived state,
regenerated once by an elevated offline migration (or by republishing
a snapshot). No on-disk format negotiation, no runtime dual path.

## Validation

- Per phase: targeted unit/integration tests.
- The proptest simulation already drives drain/GC/reaper; extend it so
  the index — not a LIST — is the queried set, and assert the
  index ≡ object-set invariant after every op, including crash
  injection between object PUT and index append (proptest-guardian
  scope).
- End-to-end on the Tigris VM with `coord-data` carrying no
  `ListBucket` and `coord-writer`'s `ListBucket` removed.

## Out of scope / revisit later

- Whether Tigris honours prefix-scoped `ListBucket` (`design-mint.md`
  #12). If it does, this work still stands (perf + portability); it
  only relaxes the security urgency.
- `volume list --remote` and any operator-facing bucket enumeration —
  these legitimately enumerate and run under an explicit elevated
  credential, not the coordinator runtime; they are not in this
  removal.
- The interim credential posture before P5 lands (the per-volume LIST
  paths fail on Tigris under `coord-data` until then) — a separate
  decision, tracked with the mint cutover, not here.
