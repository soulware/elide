# Design: permanent deletion of a volume's bucket state

**Status:** Proposed (2026-08-07). No implementation.

## Problem

A volume's bucket state outlives every operator verb that exists.
`evict` unlinks local `cache/` artefacts and issues no S3 call at all
(`elide-coordinator/src/tasks.rs:39-104`). `release` flips
`names/<name>` to `Released` with a handoff snapshot so another
coordinator may claim it. `remove` tears down the local fork and, when
the name is still owned, performs that same release flip first
(`elide-coordinator/src/inbound/mod.rs:1272-1284`), so the name stays
claimable and every byte under `by_id/<vol_ulid>/` stays where it is.
`docs/architecture.md:745` states the position directly: bucket-level
deletion is out of scope.

The consequence is that storage for a volume the operator is finished
with is billed forever, and the only way to reclaim it is out-of-band
bucket surgery with admin credentials, performed against a key layout
the operator has to reconstruct by hand.

The four S3 deletes that do exist are all narrow. The retention reaper
deletes segments carrying an expired `Superseded` edge
(`elide-coordinator/src/gc_cycle.rs:1129`), stop-manifest cleanup
deletes promoted `-stop.manifest` keys
(`elide-coordinator/src/volume_data.rs:401-404`), and import and fork
roll back `names/<name>` on failure
(`elide-coordinator/src/name_store.rs:179-192`).

## Surface

`elide volume remove --purge <name>`, gated behind an interactive
confirmation.

Purge is reachable only through `remove`, because a volume whose bucket
state is gone has no meaning as a local instance. The two are one
operation with one outcome, and splitting them into separate verbs
would create a window in which a local fork points at a deleted prefix.

The confirmation is a `y/N` prompt in the CLI, defaulting to no. It
prints the name, the volume ULID, and the object count and byte total
from a preflight `Request::PurgePreview` round trip, so the operator
confirms against a measured quantity rather than a name they may have
mistyped. `--yes` supplies the answer for scripted callers, which
`docs/quickstart-local.md:111` and the integration tests need. A purge
with no `--yes` and no TTY refuses.

This establishes the prompt pattern for the CLI. Destructive operations
today gate on `--force` flags alone (`src/main.rs:375-377`, `:387-389`,
`:409-411`) and no interactive confirmation exists anywhere in the
tree, so the prompt arrives with its first caller.

## Purge is not remove plus deletes

Three properties of `remove` invert under `--purge`.

**The name record is deleted rather than released.** The release flip
publishes a `handoff_snapshot` naming the state a future claimant forks
from, and the invariant is that the snapshot lives under the record's
`vol_ulid` (`elide-coordinator/src/inbound/lifecycle.rs:732-758`).
Advertising a handoff into a prefix that is about to be deleted
produces a claimable name over absent bytes. Purge therefore skips
`release_owned_for_remove` entirely and takes the record to a terminal
state instead.

**A referenced volume is refused rather than demoted.** Forks copy
nothing. `fork_volume_at` creates a WAL, a keypair, and a signed
provenance record (`elide-core/src/volume/fork.rs:44-108`), and the
child's reads resolve the ancestor's own prefix: `find_owner` walks the
search dirs and returns the owning directory's ULID
(`elide-core/src/block_reader.rs:655-675`), which becomes the
`by_id/<owner_vol_id>/segments/<date>/<seg>` key in the fetcher
(`elide-fetch/src/lib.rs:1384-1391`). The sharing is transitive to the
lineage root (`elide-core/src/volume/ancestry.rs:156-170`). So where
`remove` demotes a lineage-referenced directory to a skeleton
(`docs/design/ancestor-liveness.md`), purge refuses, because the bytes
are load-bearing for the entire descendant closure and no local
demotion protects them.

**The signing key shadow is deleted.** `remove` keeps
`<data_dir>/keys/<vol_ulid>.key` (`elide-coordinator/src/key_shadow.rs:12`)
so a removed volume can be re-claimed. Purge removes it with the rest.

## Name record lifecycle

Purge adds a `NameState::Purging` variant, mirroring `Importing`
(`elide-core/src/name_record.rs:123-131`). `check_transition` refuses
every verb for it, which makes the name unclaimable and makes the
record single-writer by construction. That single-writer property is
what lets the final delete be unconditional, on the reasoning already
recorded for `clear_importing`
(`elide-coordinator/src/inbound/lifecycle.rs:626-631`).

The ordering is:

1. CAS `names/<name>` to `Purging`.
2. Delete every object under `by_id/<vol_ulid>/`.
3. Delete `meta/<vol_ulid>.pub` and `meta/<vol_ulid>.provenance`.
4. Append a `Purged` event to `events/<name>/`.
5. Delete `names/<name>`.
6. Tear down local state: the fork directory, the `by_name/<name>`
   symlink, and the key shadow.

Step 1 first is what makes the sequence crash-safe. A crash at any
later point leaves a `Purging` record, which is a tombstone no verb
accepts and which carries the `vol_ulid` needed to resume from step 2.
A boot-time sweep resumes those records, alongside the existing
`clear_stale_import_records` (`elide-coordinator/src/import.rs:664-703`).

## What survives

`events/<name>/*` survives, and step 4 appends a terminal `Purged`
record to it. The event journal is append-only at three layers: the
`EventJournal` trait has no `delete` method
(`elide-coordinator/src/stores.rs:148-151`), the IAM templates grant no
role delete on `events/*` (`deploy/mint/role-templates/coord-rw.json:14-17`),
and `docs/design/mint.md:185-188` records the invariant. Keeping the
journal preserves that invariant with no IAM change, and the journal
then reads as a complete account of the volume including its death.

The journal is keyed by name rather than by ULID, so a later claim of
the same name inherits the prior name's history. The `Purged` event is
the boundary marker that makes the inherited history legible, in the
same role as the two-event rename boundary in
`docs/design/volume-event-log.md`.

## Credential

Purge runs on a new `volume-purge` mint role, a sixth template
alongside the five in `deploy/mint/role-templates/`. It grants
`s3:ListBucket` and `s3:DeleteObject` on `by_id/{{caveat.volume}}/*`,
and `s3:DeleteObject` on `meta/{{caveat.volume}}.*`. Both are
expressible as trailing wildcards, which is what Tigris supports.

A separate role keeps the destroy authority off every running volume.
`volume-rw` already carries delete on `by_id/<vol>/*`
(`deploy/mint/role-templates/volume-rw.json:6-8`) and could absorb the
rest, but then a live volume permanently holds the authority to
enumerate and destroy its own prefix, and minting a purge credential
stops being its own audit event. `meta/*` is currently undeletable by
every role, with `coord-rw` holding put-only
(`deploy/mint/role-templates/coord-rw.json:32-35`); scoping the new
grant to `meta/<vol>.*` keeps that property for every volume other than
the purge target.

`names/<name>` deletion rides the existing `coord-rw` grant
(`deploy/mint/role-templates/coord-rw.json:5-8`).

## Enumeration

Purge enumerates `by_id/<vol_ulid>/` by LIST.

`RoleStore::list` and `list_with_delimiter` return `NotSupported`
unconditionally today (`elide-coordinator/src/mint_stores.rs:210-235`),
because no role carries `s3:ListBucket`; the reasoning is in
`docs/plans/list-elimination-plan.md` and the steady-state enumeration
paths were rebuilt around signed manifests and `by_id/<vol>/HEAD`
instead (`docs/design/segment-index.md`).

Enumerating a purge from those manifests would leave orphans behind:
failed multipart uploads, segments written by a previous owner that the
current index never learned, and any object outside the reachable
manifest chain. An operation whose entire purpose is to stop paying for
bytes cannot leave bytes behind, so purge takes the LIST. The
list-elimination policy prices steady-state per-tick enumeration, and a
once-per-volume destroy is outside what that policy is protecting.

`RoleStore` does not override `delete_stream`, so a bulk delete would
fall through to the trait's sequential default. Overriding it to reach
S3's `DeleteObjects` bounds a large volume's purge to a round trip per
thousand keys.

## Open question: descendants on another coordinator

Purge can see local lineage and refuse against it, by the same forest
`remove` already builds
(`elide-coordinator/src/lineage_forest.rs:94`). It cannot see a fork
taken on another host, because detecting one means enumerating
`names/`, and no coordinator credential carries list over that prefix.

The failure mode of purging under an unseen descendant is bounded but
real. The descendant's next `pull_volume_skeleton` fails hard when
`meta/<vol>.pub` or `meta/<vol>.provenance` is absent
(`elide-coordinator/src/pull.rs:86-97`), so a host that has not yet
hydrated the ancestor breaks loudly rather than silently. A host that
already holds the ancestor's local read form keeps serving metadata and
fails only on a cache miss that reaches for a deleted segment body.

Three candidate dispositions, undecided:

- Refuse on local lineage alone and accept the remote failure as loud.
- Require `--force` in addition to the confirmation for every purge,
  treating an unseen fork as always possible.
- Grant the purge role list over `names/`, GET each record, and refuse
  when any `parent` field names this `vol_ulid`. This catches direct
  remote children and not deeper chains, and widens a per-volume
  credential to the whole name space.

A fourth direction worth weighing is making descendants discoverable at
all, which is a gap `docs/design/ancestor-liveness.md` leaves open on
the bucket side. The child's `meta/<child>.provenance` names its
parent, and the forking coordinator holds `volume-rw` on the child
alone, so it has no way to record the edge in the parent's prefix.
