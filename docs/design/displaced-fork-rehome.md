# Displaced-fork rehome

**Status:** Proposed (2026-07-01). Companion to
[`force-release-fencing.md`](force-release-fencing.md) (the claimant-side
safety fence) and [`volume-event-log.md`](volume-event-log.md) (whose rename
boundary this deliberately does *not* reuse). Covers the **previous owner's
local disposition**: what coordinator A does with its own live fork V1 once a
peer B has force-claimed `names/<name>` out from under it — the piece
`force-release-fencing.md` scopes out as "teardown, hygiene" and defers as
"cleanup of garbage under V1."

## Problem

`force-release-fencing.md` establishes that a force-claim is *safe* for the
claimant regardless of A's liveness: A's `volume-rw` discharges carry the
liveness predicate `names/<name> → V1`, so B's forced CAS makes A's credential
renewals fail and A loses the *capability* to mutate V1's prefix within the
liveness-staleness bound (~5 min). B's basis and head-delta are protected by
the credential layer, not by A's cooperation.

That leaves A's **own** side unspecified, and today it is handled badly:

- **The guest keeps writing into a dying fork.** A's ublk device stays up
  serving RW. The credential fence stops A's *S3 drains* (they begin failing
  as creds lapse) but does nothing to the *local* write path — the guest's
  writes still land in V1's WAL, which can no longer drain. The guest believes
  its writes are durable; they are accumulating in a WAL with nowhere to go.
- **Detection is gated and inert.** The only ownership check A runs is folded
  into the reap step (`gc_cycle.rs`), which early-exits when there is no
  drain/GC scratch — so an idle-but-serving displaced fork is never checked —
  and when it does fire it only logs and skips reap. A keeps serving until an
  operator manually stops it.
- **`volume list` can't show it.** State is derived purely from local markers
  (`VolumeLifecycle::from_dir`); a displaced fork reads as plain `stopped`,
  indistinguishable from a healthy one.
- **Force-claiming over a stale local fork silently drops it.** When A itself
  later runs `claim --force` for the same name (a common recovery move),
  `force_claim.rs` swaps the `by_name` symlink to the new fork and leaves the
  old fork orphaned on disk with no warning and no WAL inspection.
- **Orphaned forks accumulate.** Nothing reclaims a superseded local fork; its
  WAL / pending / index / cache / keys sit on disk indefinitely.

## Proposed: fence-to-stopped, then rehome

On detecting displacement, an alive A does two things — **fence** its local
device to a stop, and **rehome** its fork under a new name — so the diverged
volume survives as a first-class, inspectable object rather than silent
garbage.

### Detection

Promote the reap-step ownership check into an unconditional per-tick poll:
each tick A reads `names/<name>` and compares `record.vol_ulid` against the
fork it is serving, *before* the drain/GC early-exit, so idle running forks
are checked too. This is the same read that already exists; the change is
running it unconditionally and acting on the result.

The poll rides the existing per-running-volume tick (`gc_interval`, ~10 s),
which bounds the window between B's CAS and A's fence — far tighter than the
~5-min credential-fence bound that provides the actual safety, so the interval
is a promptness knob, not a correctness one. A *stopped* displaced fork has no
tick and needs none: it is rehomed at its next `start`, where `mark_live`
already detects the ownership conflict (today it only errors).

### Fence

On mismatch, A stops the ublk device. The guest gets an honest `EIO` and can
fail over, instead of writing into a WAL that can never drain. This is A's
`force-release-fencing.md` "name-record poll → halt" made load-bearing *for
the guest*; it stays non-load-bearing for B's safety, which the credential
fence already covers.

The stop is a teardown, not a park: A `del_dev`s V1's kernel device and
removes the `[ublk]` transport from its config. The rehomed fork therefore
starts transport-less until an explicit `volume update --ublk` re-exposes it
over a freshly-allocated device.

### Rehome

A no longer owns `names/<name>`, so it cannot rename it. Instead A rehomes its
*fork* under a name it creates:

1. Conditional-create (`If-None-Match: *`) `names/<name>-displaced-<V1>` with
   `vol_ulid = V1`, `coordinator_id = A`, `state = stopped`. A writes this
   with its still-live *coordinator-level* creds; only its *volume-level*
   creds for V1 lapsed.
2. Rebind the local `by_name` symlink from `<name>` to
   `<name>-displaced-<V1>`.
3. Emit a `displaced` event into `events/<name>-displaced-<V1>/` recording the
   source name, the displacing coordinator B, and B's fork V2.

The result is a normal `stopped` volume. Because the fork is *renamed on
disk*, `volume list` shows `<name>-displaced-<V1>` with no new state variant —
the name itself carries the signal, so surfacing costs nothing.

**Suffix = the fork's own ULID**, not a wall-clock timestamp: an A that
restarts mid-displacement re-derives the identical name and the
`If-None-Match` create is idempotent, rather than minting a second
`-displaced-<t2>` name.

### Why not the rename two-event boundary

`volume-event-log.md`'s rename ties two name logs with `renamed_to` /
`renamed_from` and tombstones the old pointer as a forward link. That shape is
wrong here because the rebinding is **asymmetric**: `<name>` is not being
vacated — it is *alive under B*. A `renamed_to` on `events/<name>/` would
falsely tombstone a live name and forward it to the diverged fork. Rehome is
fork-rehoming, not name-renaming: a single `displaced` event on the *new*
name's log, mirroring `created` / `forked_from` provenance, with no write to
`<name>`'s log or pointer (both owned by B). It pairs with the `force_claimed`
event B emits on `<name>`'s log — carrying `displaced_coordinator_id` and
source `vol_ulid` — to give both-sided provenance.

### Three triggers, one primitive

Rehome is the single disposition for *"my local fork is no longer this name's
owner,"* and it fires wherever that condition is first noticed:

1. **The running poll** (above) — the common case; fences the guest and
   rehomes in one step.
2. **The start-refusal** — a stopped stale fork, or a coordinator that just
   restarted and polls cold: `mark_live`'s existing `OwnershipConflict`
   becomes a rehome instead of a bare error.
3. **`force_claim` finalize** — when A itself force-claims the same name, its
   about-to-be-replaced local fork is rehomed *before* the `by_name` swap,
   replacing the silent symlink drop at `force_claim.rs`.

A prompt poll usually rehomes a displaced *running* fork before a later
self-force-claim would meet it, so (3) is mostly a residual for the
stopped/cold cases — but routing all three through one `rehome(fork)` makes
*preserve, never silently orphan* an invariant independent of how the
name-loss was noticed.

## Undrained writes survive rehome

`force-release-fencing.md` states A's "accepted-but-undrained writes are
lost." That is the contract under *halt-and-discard*. Rehome changes it: V1's
local WAL / pending is preserved under the new name. Starting
`<name>-displaced-<V1>` is a normal claim/start — it re-attests volume creds
under the *new* name (A holds V1's `volume.key`; the new name is live → V1),
and the ordinary drain then flushes the preserved WAL to `by_id/<V1>/` under
fresh creds. Rehome is therefore the only disposition that can recover a
displaced fork's undrained tail. The flush happens only as a side effect of
that deliberate `start`: the rehome itself never drains (A's V1 creds are dead
until re-attest), and a local `volume remove` never starts, so it never
pays the flush.

This does not weaken B. A's V1 writes, drained or not, are a *divergent
branch* — never folded into V2, because the head-delta cut in
`force-release-fencing.md` already excludes anything past B's one-shot HEAD
read. Rehome gives that branch a home instead of a grave.

## Disposition: preserve, or remove locally

Rehome is a *local* lifecycle disposition; it does not touch bucket storage.
A rehomed fork's choices are the same as any volume's:

- **Preserve (default): rehome.** The diverged fork becomes
  `<name>-displaced-<V1>`, a first-class `stopped` volume — visible and
  startable like any stopped volume, though it carries no ublk transport
  until `volume update --ublk` re-enables it.
- **Remove locally: `volume remove`.** A rehomed fork *is* a normal volume, so
  it is removed from the host by the ordinary local-removal path, identical to
  any other volume — there is no displaced-special verb.

Either choice replaces today's silent-discard (`mark_reclaimed_local`) and
silent-abandon (the `force_claim.rs` symlink swap): the fork is kept as a
named volume or removed by the ordinary path, never orphaned.

Bucket-level storage is out of scope: Elide deletes no volume's S3 prefix —
displaced or not — so V1's segments persist under their prefix exactly as
every volume's do.

## Dead or partitioned A

Rehome requires a live A to run it. When A is genuinely gone, nothing rehomes:
V1 stays orphaned under its prefix for the retire/GC path, exactly as
`force-release-fencing.md` assumes, and `<name>` is B's cleanly. Best-effort
is the ceiling for a partitioned host — the credential fence still makes B
safe; the rehome is the bonus A provides *when it can*.

## Decisions

Settled 2026-07-01:

- **Detection rides the existing tick.** The ownership poll reuses the
  per-running-volume `gc_interval` (~10 s) — a promptness bound, not a
  correctness one (the credential fence is the safety). No dedicated interval;
  stopped forks rehome at start-refusal.
- **The `displaced` event carries `source_name` + `displaced_by` (B) +
  `source_fork` (V2), and does *not* inherit `<name>`'s log.**
  Log-inheritance would bleed `<name>`'s post-divergence timeline (which
  continues under B) into the rehomed fork's backward walk; the cross-link is
  a point reference to the divergence, already mirrored by B's `force_claimed`
  event, and the pre-divergence lineage comes from V1's fork chain.
- **No special first-start handling.** `start` = use it (drains normally); the
  rehome never drains and `delete` never starts, so the preserved WAL flushes
  only on a deliberate start.
- **One `rehome(fork)` primitive, three triggers** (poll, start-refusal,
  `force_claim` finalize) — preserve-never-orphan as an invariant.
- **Removal is the ordinary local `volume remove`, identical to any volume.**
  No displaced-special verb; bucket-level deletion is unsupported for *any*
  volume and out of scope, so the S3 prefix persists like every volume's.
