# Remote coord IPC: operator ops against a non-local coord

**Status:** Exploration. No implementation. Depends on the central
auth service in [`auth-service.md`](auth-service.md)
landing first.

This doc captures the routing decision for running operator IPC verbs
(e.g. `volume snapshot`, `volume create`) against a coord on another
host. It builds on:

- [`auth-model.md`](auth-model.md) — operator
  authorisation gates every mutating IPC verb via the
  mint-issued primary + auth-issued discharge chain.
- [`auth-service.md`](auth-service.md) —
  **coord as clearer**, and coord **attenuates the primary per
  forward**. The operator session lives at the coord; the CLI is not
  a party to the macaroon chain.
- [`peer-segment-fetch.md`](peer-segment-fetch.md) —
  the existing coord-to-coord channel, used today as a read-only
  cache tier for `.idx`/`.body`/skeleton artefacts.

## Problem

`elide volume snapshot V` and similar operator verbs run against the
local coord over PID-trusted UDS. A volume is bound to a host (its
ublk device, WAL, and local index/cache live there), so the natural
question is: how do you run such a verb against a volume whose home
host is *not* this machine?

Two routings are possible.

## Routing options

**A — `cli ↔ remote coord` (direct):** the CLI opens a network
connection to the remote coord and presents an operator capability
itself.

**B — `cli ↔ local coord ↔ remote coord` (forward):** the CLI talks
to its local coord over UDS as it does today; the local coord
resolves the volume's home host, attenuates its operator session for
this specific op, and forwards over the existing peer channel. The
remote coord clears and executes.

## Decision: B

The forward-via-local-coord shape falls out of decisions already made
in the auth design:

- **CLI is unauthenticated by design.** Local IPC is UDS +
  PID-trusted; the CLI holds no macaroons, no S3 creds, no session.
  Routing A would reintroduce CLI-held credentials, reversing
  `cli_creds_unauthenticated`.
- **Coord is the operator's agent.** `docs/design/auth-service.md` places
  the operator session at the coord and makes coord the clearer.
  Forwarding is already a coord responsibility — the existing
  per-forward attenuation to mint is structurally the same shape as
  per-forward attenuation to a peer coord.
- **One transport, one auth model.** The coord↔coord channel already
  exists for `peer_fetch`. Reusing it for control ops keeps a single
  authenticated channel between coords rather than introducing a
  second CLI-facing remote surface on every coord.

## Shape

1. CLI invokes `volume snapshot V` against its local coord over UDS
   (today's path).
2. Local coord resolves V's home host. The volume's `names/<name>`
   record or `by_id/<vol_id>` skeleton names the owning coord; the
   local coord may itself be the owner, in which case this collapses
   to the existing local path.
3. If remote: local coord attenuates its operator session down to
   `(op=snapshot, vol=V, target=<coord>)` plus a short `exp`,
   the same construction used for per-forward attenuation to mint.
4. Local coord forwards `(attenuated bundle, op, args)` over the
   peer channel to the remote coord.
5. Remote coord clears the bundle (caveats evaluated against its own
   live IPC context: this volume, this op, this host), verifies
   cryptographically via mint as it would for a local CLI call, and
   executes the op locally.
6. Result returns over the peer channel to the local coord and back
   to the CLI.

From the remote coord's perspective the op executes locally exactly
as it would for a local CLI caller; the only difference is the
provenance of the capability. No multi-host state machine is
introduced — this preserves the framing in `docs/design/peer-segment-fetch.md`
that cross-host coordination rendezvous through S3.

## Assumption: caller has a local coord

A coord is required on the host running the CLI. This drops a
constraint that would otherwise need a second auth path (CLI-held
credentials), a client-only coord variant, or a separate remote
tool. If the coordless-laptop case becomes interesting later, the
answer is an ephemeral local coord process rather than reintroducing
routing A.

## Open

- **Home-host resolution.** Which artefact authoritatively names a
  volume's owning coord, and how stale can that pointer be before a
  forward needs to fail closed? `names/<name>` and `by_id/<vol_id>`
  both carry candidate signals; the choice interacts with
  `docs/design/portable-live-volume.md` and the handoff protocol.
- **Per-forward attenuation scope.** Whether the attenuated bundle
  needs to bind the target coord's ULID (analogous to the mint-bound
  per-forward attenuation), and how a misrouted forward should fail.
- **Which verbs are remote-eligible.** Read-only inspection verbs are
  the obvious first slice; mutating verbs that touch the local ublk
  device on the calling host are inherently local-only.
