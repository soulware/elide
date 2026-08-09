# Peer durability tier and off-host background work

**Status:** Exploration (2026-08-09). Discussion notes, no decision.

## Problem

Time-to-durable is bounded below by cut cadence plus S3 PUT time. A write
is durable against host loss only once a cut covering it has published, so
cut cadence is the RPO ([durable-cut.md](durable-cut.md)). The question
explored here is whether landing bytes on a second host should count as
durable, with that host then responsible for getting them to S3.

The idea splits into two legs that can be evaluated independently.

## Leg 1: peer as the durability tier

The strong form streams WAL entries to a peer continuously and acks
durability on the peer's fsync. That decouples RPO from cut cadence
entirely and replaces an S3 PUT with one intra-region RTT plus an NVMe
flush. The weak form (upload finished segments to the peer instead of
Tigris) leaves cut cadence as the dominant RPO term and is worth little.
This is synchronous WAL shipping in the database sense.

### Where the reference stands

The LSVD paper acks writes after local SSD persist (§3.2) and accepts loss
of the un-uploaded tail on machine failure (§3.4). Its replication (§4.8)
lazily copies completed objects between object stores for DR. lab47/lsvd
matches (`close_segment.go` uploads in the background after ack). A peer
durability tier is beyond the reference, on the pattern of synchronous
replication in databases.

### Receiver shape

Two candidate shapes for the peer.

**Generic object store on the peer (MinIO or similar).** Gives an S3 API
so existing `ObjectStore` code works, but introduces a second
eventually-consistent object namespace underneath the per-volume `HEAD`
whole-object R-M-W, which wants exactly one authoritative store and one
writer ([segment-index.md](segment-index.md)). Something still has to
relay bytes to Tigris, and the receiver knows nothing of segments, cuts,
or claims, so the elide-aware follow-ons below stay out of reach.

**Cutdown coord (elide-aware receiver).** Fits existing machinery:

- The peer-fetch channel
  ([peer-segment-fetch.md](peer-segment-fetch.md)) already moves segment
  bytes between hosts under macaroon-style tokens; replication is the
  same channel in a push direction.
- The attestation coordinator established the precedent of a coord
  instance running a subset role
  ([mint-volume-attestation.md](mint-volume-attestation.md)).
- Per-volume attested credentials already scope a coord to
  `by_id/<vol>/` prefixes, so the peer can hold upload authority for
  exactly the volumes it protects.
- Single-writer HEAD is preserved by having the peer upload only
  immutable segment bodies, with the primary publishing the index once
  the peer confirms. This slots into the upload-generation accounting
  ([upload-generations.md](upload-generations.md)).

### The design crux: peer-down semantics

When the peer is unreachable, the options are:

1. **Block writes.** Availability now couples two machines.
2. **Ack local-only and widen RPO.** The durability claim silently stops
   holding.
3. **Fall back to direct-to-Tigris upload.** A second execution path for
   a correctness property, which the project's design principles price as
   a real cost.

This decision *is* the design. It should be settled before any protocol
work.

### Measure before designing

Tigris runs on Fly infra, so PUT latency from a Fly host is far from
AWS-S3-shaped. The gap between "peer RTT + fsync" and "small PUT to
Tigris" is a cheaply measurable number. If it is small, the streaming leg
(decoupling RPO from cut cadence) dominates regardless of who receives
the bytes, and could even target Tigris directly.

## Leg 2: off-host repack/GC

Partly viable, and independent of leg 1. Everything below the durable cut
floor is published, immutable state reachable through S3, so a
non-volume host with scoped credentials could do sweep/repack rewrite
work (fetch inputs, delta/zstd recompress, write outputs, publish a plan)
against published state, scoped strictly below the floor so open
generations and un-cut WAL are never in play.

What cannot move: applying the plan into the live extent index. That runs
where the live LBA map lives, and it is the measured source of
guest-latency excursions (the merge phase of gc-plan-apply,
[open-generation-reap.md](open-generation-reap.md)). Offload removes GC's
CPU from the shared host (GC is ~97% of coord CPU) but leaves the apply
cost in place.

A peer that already holds recent segments does this work with warm cache
locality, but the enabling requirement is only published-state access, so
remote repack can be prototyped without any replication protocol.

## What the peer tier additionally buys

A peer that holds a volume's recent segments is a warm standby. Combined
with force-claim fencing and peer fetch, failover becomes claim + serve
from peer cache while hydrating from S3. This is arguably the biggest
prize, and one the generic-object-store shape cannot deliver.

## Next probes

- Measure small-object PUT latency to Tigris from a Fly host against
  peer RTT + NVMe fsync on the same pair.
- Put a number on the value of sub-cut-cadence RPO for real workloads.
- Prototype remote repack against published state below the cut floor,
  as its own experiment.
