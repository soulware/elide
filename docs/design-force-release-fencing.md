# Forced-claim fencing

**Status:** Proposed (2026-04-29; reworked 2026-06-09 to the
`claim --force` shape — see
[`design-mint-volume-attestation.md`](design-mint-volume-attestation.md)
§ *Recovery is a claim*). Companion to
[`design-portable-live-volume.md`](design-portable-live-volume.md).
The claimant side of forced recovery is specified there and in the
attestation doc; this doc covers the **previous owner** side: what
must happen on coordinator A's host when A is alive and a peer has
force-claimed A's volume out from under it.

## Problem

`volume claim --force` exists for the case "the previous owner is
unreachable and not coming back." Coordinator B force-CASes
`names/<name>` from A's stale `Live`/`Stopped` record to a fresh fork
V2, bases V2 on the record's `latest_snapshot` S — A's last published
user snapshot — and **re-owns the post-S tail** (the segments A
drained after S, resolved from V1's HEAD) as V2's own first segments
under V2's prefix.

The verb's safety contract — "the dead owner's writes that never
reached S3 are lost; nothing else" — assumes A is in fact dead. If A
is **alive** when `--force` runs (a partition that resolves, or a
mistakenly-issued `--force`), A keeps mutating `by_id/<V1>/...` until
fenced. The dangerous mutations are not new writes (those become
orphans, harmless), but A's GC superseding and reaping segments B
still needs: the basis set (forever) and the tail (during the
re-own copy).

## What the claim-first shape gives for free

**The basis pin needs no mechanism at all.** V2 and its descendants
reference V1 ULIDs only at or below S — the set named by S's manifest
and the chain beneath it. S is A's *own published snapshot*: its
manifest is already in A's local `snapshots/`, so A's GC floor
(`latest_snapshot(fork_dir)`) already freezes everything at or below
it. The floor only ever advances, so the frozen set only grows —
including under a zombie A that keeps publishing. There is nothing to
pull, no reaper check to add, no new floor input: the basis is pinned
by the same rule that protects every published snapshot from its own
owner.

**The fence is the credential layer, not self-policing.** Every S3
write A issues for V1 rides `rw-self` discharges whose liveness
predicate is `names/<name> → V1`
([`design-mint-volume-attestation.md`](design-mint-volume-attestation.md)
§ *One liveness check unifies RW-self and RO-ancestor*). B's forced
CAS makes that predicate false; A's discharge renewals fail from the
CAS onward and A's outstanding credentials lapse within the
liveness-staleness bound (the Tigris keypair lifetime, ~5 min). A
zombie A loses the *capability* to mutate V1's prefix whether or not
it ever observes the flip. This ties enablement together: the fence
exists once `rw-self` enforcement is on, so `claim --force` sequences
with attestation enablement.

**A's name-record poll remains, for teardown rather than safety.** On
observing `coordinator_id != self`, A halts the daemon and marks the
fork reclaimed locally. This converts silent post-claim writes into
prompt local errors; it is hygiene, not load-bearing.

## The tail race

The only transient exposure: B copies tail segments — above A's
floor, exactly the segments A's GC preferentially compacts — while A
may still hold live credentials inside the fence window.

- **A supersedes a tail segment mid-copy.** The live bytes are
  preserved in the GC output; HEAD's `superseded` entries record the
  mapping. B re-resolves V1's HEAD and copies the output instead.
- **A physically reaps an input** only after the retention window
  elapses (HEAD `Superseded` entries are the timing carrier), which
  adds slack on top of re-resolution.
- **Convergence rule:** B iterates resolve-HEAD → copy-missing until
  a re-read shows no change and every named segment exists under
  V2's prefix. Termination is guaranteed: A's HEAD writes stop when
  its credentials lapse, after which one further iteration
  stabilises.

B writes nothing under V1's prefix at any point — reads ride
`ro-ancestor` against V2's declared parent, writes ride `rw-self`
into V2.

## Failure-mode walkthroughs

**A is partitioned from S3, B runs `claim --force`, A reconnects
later.**

During partition: A's drain fails, segments accumulate locally. Zero
mutations to V1's prefix. A reconnects: its discharge renewal fails
against the rebound record — A has no S3 write capability at all.
Its next poll observes the flip and tears down locally. B's basis
was never exposed (it sits under A's own floor regardless), and the
tail copy ran against a frozen HEAD.

**A is healthy and `--force` is mistakenly issued.**

The exposure window is bounded by the credential fence (≤ the
liveness-staleness bound) intersected with B's copy. Within it, A's
GC may supersede or reap tail segments; B's copy retries through
HEAD re-resolution and is further protected by the retention window
on physical deletes. After the window, A is hard-fenced. A's
accepted-but-undrained writes are lost — the verb's stated contract,
unchanged. The basis set is never at risk: it is below A's floor.

**Operator-initiated graceful retire (no claimant in mind yet).**

A normal `release`: A snapshots, halts, flips the name to `Released`
with a volume-signed handoff. No forced CAS, no tail to re-own, no
fence needed. A later claimant runs a normal `claim` from
`handoff_snapshot`. The forced path is only for records whose owner
cannot run that protocol.

## What's not addressed by this mechanism

- **Tightening `--force`'s precondition.** Refusing `claim --force`
  when A's heartbeat is recent reduces stray triggers but is
  independent of the fence. Belongs in
  [`design-portable-live-volume.md`](design-portable-live-volume.md).
- **Cleanup of garbage under V1.** The tail originals (now duplicated
  into V2), anything A wrote post-displacement, and V1's HEAD itself
  accumulate under V1's prefix until a "retire-`vol_ulid`" path runs
  once no living fork references V1. Out of scope for this doc.

## Open questions

- **Fence-window constant.** The bound is the `rw-self`
  re-attestation cadence / Tigris keypair lifetime (attestation doc
  § *Liveness*). Whether B should wait it out before its *final*
  HEAD resolve, or rely purely on iterate-to-stable (assumed above),
  is an implementation choice.
- **Sign `names/<name>` records.** Defence in depth against
  non-coordinator bucket writers. Not load-bearing for the fence.
