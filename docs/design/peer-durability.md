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

A peer that already holds recent segments does this work with warm cache
locality, but the enabling requirement is only published-state access, so
remote repack can be prototyped without any replication protocol.

### What the CPU accounting says

Moving only today's GC/repack work buys little on the primary. The GC-off
ABBA (v0.1.51, fixed-rate pgbench) put GC at 97% of coordinator CPU
(0.111 to 0.003 ms/txn) but ~8% of volume-server CPU (1.077 to 0.985),
and the coordinator is the small process (0.11 ms/txn against the
volume's ~1.0). The volume's CPU lives in the promote path: the
v0.1.58-rc1 flamegraph reads zstd at 55% of visible self time and
`delta_compute` at 34% inclusive, write-time work that runs wherever the
writes land. Offload of the current GC therefore removes nearly all of a
small process and ~8% of the big one.

What cannot move: applying the plan into the live extent index. That runs
where the live LBA map lives, and it is the measured source of
guest-latency excursions (the merge phase of gc-plan-apply,
[open-generation-reap.md](open-generation-reap.md), 71% of a hold that
runs ~11.2 µs/entry). Offload leaves the excursions in place.

One second-order win is real: the primary is a 2-cpu box, and the 3x
spread in apply hold at fixed entry count is suspected CPU contention
between the GC worker and the apply. An off-host worker removes that
contention.

### The recompression form

The split earns its keep when the off-host leg carries the compression
work, on the pattern of
[close-pass-recompression.md](close-pass-recompression.md). The runtime
delta ABA (v0.1.58-rc2) measured delta off cutting volume CPU 29%
(0.976 to 0.695 ms/txn) and mean guest latency 10x (392 to 29 ms), for
~2% of stored bytes. Delta's cost is where it runs, at write time on the
primary. In the stronger form the primary writes cheap segments (delta
off, plain body codec) and the peer performs delta conversion and heavy
recompression below the cut floor as repack-shaped rewrite work. The CPU
and latency win is bankable on the primary by the switch alone; the peer
recovers the storage yield asynchronously instead of it being forfeited.

### Apply pressure needs a budget

Every rewrite the peer produces comes home as a plan apply under the
volume mutex on the primary. Today the rewrite work and the apply share
a host, so rewrite cost throttles apply pressure naturally. Off-host
compute removes that throttle: a peer with idle CPU can generate plans
faster than the primary can absorb their holds, feeding the excursion
problem from a new direction. An off-host leg needs an explicit
apply-pressure budget on the primary's side.

### What the primary's data dir becomes

The split leaves the directory taxonomy unchanged and shifts what the
directories are doing.

- `wal/`, `pending/open/`, `index/` are the unpublished spine above the
  cut floor, which the peer never touches by construction. The plan
  apply stays local and appends to `index/` as today.
- `pending/upload/` depends on the leg. Leg 2 alone leaves publishing
  with the primary, so closed generations drain to S3 as today. Under
  leg 1's strong form the upload responsibility moves to the peer and
  `upload/` shrinks to a confirmed-awaiting-index-publish queue; what
  remains of it is the buffer the primary falls back on when the peer
  is down, another face of the peer-down crux.
- `cache/` works harder. Peer rewrites produce segments the primary
  never wrote: the apply retargets the index at them, GC retires the
  inputs, and the primary's next read of that data is a demand fetch.
  Each off-host pass converts warm local bytes into cold remote ones,
  and the volume trends toward the pulled-ancestor shape for its cold
  tail, with only the recent spine native. The peer-fetch channel
  offers the mitigation (peer pushes or primary prefetches outputs
  before the apply lands).
- `dmat/` growth becomes peer-driven. If the peer does delta
  conversion, the primary still pays the read side: materialised
  sources in `dmat/` (measured ~10x blob size) and decompression per
  delta read. A read-side budget belongs with the close pass, alongside
  the apply-pressure budget above.

Nothing on disk leaves the primary. GC's local janitor work (unlinking
retired inputs at apply time) stays, since only compute moves to the
peer, and custody of every directory stays put.

### To explore: aggressive evict, cache/ as working set

The natural follow-on is an eviction policy that keeps `cache/` to the
volume's hot working set, with the fully hydrated volume living in
S3 (and on the peer for recent data) rather than on the primary. This
converges on the LSVD reference's native model, where local SSD is
strictly a cache over the object store; the fully-hydrated-locally
stance is elide's departure from the paper. It also reframes the
`cache/` point above: with a hot-only policy, repack outputs arriving
cold is the steady state rather than a regression.

The mechanism already permits it. Every `cache/` body is redundant with
S3 by construction, `.present` tracks partial hydration so a miss
fetches ranges rather than whole bodies, and signatures authenticate
demand-fetched bytes. What is missing is policy (evict is a manual
command today) and the data to set it:

- **Miss latency and miss rate.** A local hit is ~100 µs of NVMe; a
  peer fetch is an intra-region RTT plus the peer's NVMe; a Tigris GET
  is tens of ms. A working set that outgrows `cache/` puts guest reads
  on the slow path, so the policy wants miss telemetry that does not
  exist yet.
- **The cold-start read burst.** The unexplained 21.5 GB read after
  overnight idle (against 1.4 GB warm) is a local-disk oddity today and
  a guest-visible fetch storm under aggressive evict. Its mechanism
  should be understood before the cache shrinks.
- **Delta-aware eviction.** A miss on a Delta entry pulls its source
  chain and rematerialises into `dmat/`, so one guest read can fan out
  into several fetches plus decompression. Either sources of hot
  dependents count as hot, or the close pass keeps hot ranges
  non-delta.
- **Granularity.** `.present` supports extent-level heat tracking,
  which matters because repack mixes long-lived bytes into shared
  segments. Journal segments are the easy first tier: write-hot,
  read-cold, dead at wrap.

The prize is a bounded, small disk budget on the primary, and a live
volume reduced to claim + WAL + hot cache, which is the shape that
makes portable-live-volume relocation
([portable-live-volume.md](portable-live-volume.md)) and the
warm-standby failover below cheap.

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
  as its own experiment. The recompression form is the one worth
  prototyping: primary writes with delta off, remote pass converts.
- Measure the warm-to-cold read penalty an off-host repack pass imposes
  on the primary, before and after a peer-fetch prefetch of the outputs.
- Instrument cache miss rate and miss latency on the primary, the
  prerequisite for any evict policy, and explain the cold-start read
  burst.
