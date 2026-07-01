# Volume-ownership attestation for mint tokens

**Status: Exploration.** Captures the design discussion so far; the
points raised have been resolved into *Decided*. Builds on `docs/design/mint.md`
(token issuance, `req`/`caveat` namespaces, third-party caveats) and
`docs/design/portable-live-volume.md` (per-volume signing keys, signed
provenance, the `names/<name>` claim).

## The gap this closes

Before this work a role's per-volume scoping field rode the PoP-signed
request **body** as `req.volume`, classed as *honest-but-unverified*.
For `volume-rw` the policy ARN was
`by_id/{{req.volume}}/*` with `req.volume` self-asserted: a compromised
or malicious coordinator could request RW credentials scoped to **any**
volume's prefix. Per-volume read credentials self-asserted the same way.
The only thing standing between coordinators on that path was
per-segment signing catching bad *data* on read — integrity, not access
control.

The goal is to make the per-volume scoping value **attested** rather than
self-asserted — it moves out of the self-asserted body and into a new
MAC-verified template namespace, `caveat.volume` (§ *Every template
value is MAC-verified or mint-computed*) — without teaching mint anything
about volumes. The self-asserted `req.*` namespace is removed entirely.

## The mechanism: a third-party caveat discharged by the attestation coordinator

mint embeds a third-party caveat (TPC) in the credential: "valid only if
discharged by the *attestation coordinator*, attesting the volume named
in the discharge." The attestation coordinator (referred to below as
**coord B**) is the discharge authority; the requesting coordinator
(**coord A**) fetches a discharge and presents it alongside its primary.

This is the canonical macaroon composition — symmetric TPC + discharge,
the same shape as the operator-authorisation chain in
`docs/design/auth-service.md`. mint shares one symmetric discharge key with
coord B (config item #2 in `docs/design/mint.md` § *Mint configuration*),
embeds a static TPC, verifies the discharge against that key, clears it,
and reads `caveat.volume` from the discharge's caveat.

### TPC structure and timing — reuses `mint/src/tpc.rs`

The TPC is the existing `Caveat::ThirdParty { location, vid, cid }`
(`mint/src/caveat.rs`), built by the existing `tpc.rs` primitives — only
the shared key and the message change. A hidden value `r` (the caveat /
discharge root key) anchors it:

- **`r` — fresh random, drawn per TPC at attachment.** It exists
  nowhere outside the caveat (mint keeps no per-client state — `r`
  travels only inside `vid`/`cid`), so a discharge is MAC-valid
  against exactly the caveat it was minted for.
- **`vid = AEAD(Tₙ₋₁, r)`** — `r` sealed under the chain tag at
  the TPC's position; the *verifier* (mint) recovers `r` by walking the
  chain and decrypting. The `AEAD` seal is the one defined in
  [`auth-service.md`](auth-service.md) § *Keys*.
- **`cid = AEAD(K_M-B, r ‖ message)`** — `r` plus the message,
  sealed under the key shared with coord B; the *authority* (coord B)
  recovers `r` + message by decrypting. For volume attestation the
  message is `lp(client_id) ‖ lp(org_id) ‖ mode`,
  `mode ∈ {volume-rw, volume-ro}` — extending the auth TPC's
  `lp(client_id) ‖ lp(org_id)` with `mode`. `org_id` is retained for
  parity with the auth TPC, so coord B can org-attribute the discharge
  even though volume entitlement is anchored by the possession proof, not
  the tenant claim. `mode` is the load-bearing addition: coord B cannot
  MAC the primary, so the role it discharges for must be sealed by mint
  here rather than asserted by coord A. `mode` carries the **role name** —
  mint seals it into the CID directly (there is no separate mode config;
  mint collapsed mode into the role name), and coord B reads it to pick
  its predicate (`volume-rw` ⟹ `target == owned`, `volume-ro` ⟹ an
  ancestor of `owned`). **The volume is deliberately absent**, keeping
  mint volume-agnostic; it is named only in the live discharge request
  and stamped into the discharge's `caveat.volume`.

`r` is recoverable by mint (via `vid`) and coord B (via `cid`), but **not
by the holder** — coord A has neither `K_M-B` nor the intermediate chain
tag, so it is a pure courier that can neither read nor forge `cid`/`vid`
nor mint a discharge.

The TPC is appended **at credential issuance** via `tpc::build_caveat`
→ `Macaroon::attenuate`, reading the credential's `tail` as `Tₙ₋₁`. It is
**static for the credential's life**; the holder only appends a narrowing
`exp`. A discharge is minted by coord B under `r` with the discharge
keyref, carrying attested `caveat.volume = target` + `exp`,
and binds to this primary because the same `r` is encrypted in this
chain's `vid` (and to coord A, since that primary is `cnf`-bound). At
verify, mint anchors the bundle on the primary's keyring keyref under
`K_M` and verifies the discharge under the `r` recovered from the `vid`.

A discharge is thus a self-contained bounded macaroon, not a bearer
token — **safe to cache**. coord A re-presents one across every
`assume-role` within its `exp`, including the repeated calls that refresh
an expired Tigris keypair; mint re-verifies the MAC and re-clears `exp`
per request (verify ≠ clear). coord B is consulted only to **mint** a
discharge — on first-touch for a target and again on expiry — never on
every keypair refresh. How long that `exp` is, and so how often coord B
re-attests, is set per mode in *One liveness check*.

### Why a coordinator, not mint itself

mint must stay volume-agnostic. The verification logic — `volume.pub`
locations, lineage walks, claim-record liveness — is volume-domain code
that belongs in the coordinator. Folding it into mint would be cheaper
(no second process, no discharge round-trip) but would puncture the
"mint knows nothing about volumes" invariant.

When coord B is co-located *and* co-operated with mint, the TPC is not
buying a real trust boundary (same host, same operator, same blast
radius). What it buys is:

- **a code seam** — mint never links volume-domain logic; its
  volume-agnostic invariant survives intact; and
- **a future-movable authority** — the attestation coordinator can later
  be split off, replicated, or replaced without touching mint's wire
  contract.

The round-trip is paid for *architectural cleanliness*, not isolation,
as long as the two sit together.

## The enabling fact: ownership and lineage are provable from public signed state

A naive reading worries that a TPC fixes its third party at embed time,
while volume ownership varies per volume — so mint would have to learn
the topology to name the right discharger. That worry dissolves because
**coord B needs no privileged knowledge**:

- **Ownership** is provable against `meta/<vol>.pub` — the Ed25519 public
  key uploaded to S3 under the flat `meta/` prefix (segment bodies, by
  contrast, live under `by_id/<vol>/`). The private `volume.key` never
  leaves the owning coordinator. Possession of the key *is* ownership.
- **Lineage** is provable from `meta/<vol>.provenance`, signed by each
  volume's own key, naming `parent:` (fork chain) and `extent_index:`
  (dedup sources).
- **Liveness** is provable from the `names/<name>` claim record — the
  single shared mutable surface, signed in the event log — which
  resolves a name to the current episode's `by_id` ULID. Liveness of
  the *binding*, not of a daemon: see *One liveness check*.

All three are world-readable and signed. So coord B is a **pure function
over public signed state plus a possession proof**: it holds no secret,
can vouch for *any* volume, and can therefore be a **single fixed
authority** named statically in the TPC. The per-volume-owner-resolution
problem never arises, and mint stays volume-agnostic.

## Flow: single volume (RW)

1. coord A holds `volume.key` for the live volume vol_Y it owns.
2. mint issues a `volume-rw` primary carrying a static TPC to coord B.
3. coord A → coord B `POST /v1/discharge`: `req:{volume: vol_Y}` plus a
   `volume.key` signature bound to this credential's TPC (over
   `blake3(cid)`; see *Possession-proof binding*), so it is not
   replayable against another credential.
4. coord B fetches `meta/vol_Y.pub`, verifies the possession
   proof, confirms liveness (`names/<name> → vol_Y`), and discharges,
   stamping attested `caveat.volume = vol_Y`.
5. coord A presents primary + discharge to `assume-role`. mint verifies
   both chains, clears the TPC, and renders `by_id/{{caveat.volume}}/*`
   from the **attested** volume.

The duties split cleanly: **coord B attests the *volume* (possession);
mint binds the *principal* (via `cnf`/PoP).** Neither learns the other's
job.

## Generalised predicate: the ancestor chain

A reader needs `volume-ro` for **each** volume in vol_Y's read set —
`walk_ancestors(vol_Y) ∪ walk_extent_ancestors(vol_Y)` (fork chain feeds
the LBA map; `extent_index` sources feed dedup; both must be readable).
Per-ancestor credentials are already the accepted shape (Tigris has no
mid-resource wildcard).

coord A anchors **once** at the anchor volume and derives the whole set
from the signed lineage. coord B evaluates:

- **self (RW):** possession(vol_Y) ∧ liveness(vol_Y)
  → attest `caveat.volume = vol_Y`
- **ancestor (RO), per vol_X:** possession(vol_Y) ∧ liveness(vol_Y) ∧
  `vol_X ∈ ancestors(vol_Y)` (signed-provenance walk, bounded by
  `MAX_EXTENT_INDEX_SOURCES`) → attest `caveat.volume = vol_X`

The possession proof anchors entitlement; the lineage walk authorises
each specific RO target. The entire authorization graph reduces to *one
possession proof of one live-binding volume key plus the public signed
lineage*.

### The read set is exactly fork ∪ extent_index — complete by construction

`ancestors(owned)` in the predicate is `walk_ancestors(owned) ∪
walk_extent_ancestors(owned)`: the fork chain (inherited LBA-map blocks)
plus the extent-index sources (blocks the volume `DedupRef`'d at write
time, whose canonical bodies can live in another volume's `by_id/`
prefix). This union is not a heuristic — it is provably the *complete*
set of prefixes a reader can touch. Write-time dedup emits a `DedupRef`
only when the block's hash already resolves in the in-memory extent
index, and that index is rebuilt at open *solely* from `walk_ancestors ∪
walk_extent_ancestors` (`elide-core/src/volume/open_state.rs`); every
`new_dedup_ref` call site is gated on `extent_index.lookup(hash)`. There
is no out-of-band dedup against volumes outside the recorded lineage, so
a read can never resolve to a prefix outside this union. coord A
therefore never legitimately needs a prefix coord B would refuse, and
coord B never vouches for one a read could not reach. The one read
outside this union is the forced-claim re-own of a never-snapshotted dead
volume — a transient recovery copy, not a steady-state read — authorised
by the `recovery_sources` grant (§ *The no-basis re-own and
`recovery_sources`*).

> **Delta to `architecture.md`** (apply with this work): tighten the
> cross-volume-dedup prose (§ *Cross-volume dedup*, ~line 938). Dedup
> matches only the in-memory extent index — i.e. `fork ∪ extent_index`;
> the "all volumes under a common root" pool is the *import-time*
> candidate set for `--extents-from`, and anything actually deduped
> against is recorded in `extent_index`. State it so no out-of-band
> write-time dedup path is implied.

### Credential model: role == keypair, acquired lazily per ancestor

`assume-role` returns a **single keypair** — a role is a keypair, per
Tigris. `volume-ro` keeps the merged per-ancestor shape
(`docs/design/mint.md` § *Per-volume read credentials*): one single-prefix
keypair per ancestor, **acquired lazily on first demand-fetch from that
owner**, not a single keypair whose policy spans the chain. This is not
an artefact of "no list caveats" — it mirrors the read path, which is
lazy and per-owner (`SegmentFetcher` takes `owner_vol_id`; `RemoteFetcher`
caches per owner, each entry acquired on first fetch). Elide reads are
sparse — a boot touches ~6% of an image — so provisioning the whole chain
eagerly grants access to ancestor prefixes that are never read, and
coarsens least-privilege (a leaked cred would span a lineage, not one
prefix).

Attestation layers onto this without disturbing it. Today the *requesting
coordinator* already authorises `target ∈ {requester} ∪ lineage(requester)`
at its IPC boundary, re-deriving lineage locally, and mint trusts the
body assertion. The attestation design **moves that same check to coord
B** so mint can verify it rather than trust the requester — each lazy
first-touch acquisition simply gains a discharge step; the keypair stays
single-prefix and the read path is unchanged.

A single keypair whose policy spans the chain (one keypair, N
statements, assembled in mint code from N scalar renders — never template
iteration) only wins for *dense* full-chain reads (`materialize`, GC
repack, offline filemap). It is **orthogonal** to attestation — an
eager-vs-lazy tradeoff in its own right — and is not adopted here (see
*Decided*: `volume-ro` stays lazy per-ancestor).

### One liveness check unifies RW-self and RO-ancestor

Possession of `volume.key` proves "operator of episode vol_Y"; the
`names/<name>` check upgrades that to "operator of the name's *current*
episode". **Liveness is a property of the binding — not the record's
`Live` state, and not a running daemon.** The predicate is:

```
record.vol_ulid == owned  ∧  record.state ≠ Released
```

What it fences is a *displaced or relinquished* episode — the two ways
an episode whose key coord A still holds stops being current. A forced
claim rebinds `vol_ulid` to the new fork, so a displaced anchor fails
the first conjunct; a release flips the state to `Released` (the record
retains the old `vol_ulid` only for handoff), so a relinquished anchor
fails the second. Every *bound* state is a live binding:

- **`Live`** — the daemon is running.
- **`Stopped`** — claim creates records in `Stopped`, and hydrate,
  claim's post-CAS chain reads, and stopped-volume verbs (filemap
  generation) all anchor before any daemon runs. The fence is about who
  holds the name, not whether a process is up.
- **`Importing`** — an import in flight: the record binds the new
  vol_ulid from import start, and the importer's on-disk key anchors
  the drain's `volume-rw` discharges for the whole construction window
  (see *Import runs under an `Importing` record*).
- **`Readonly`** — a readonly import is terminally bound: no lifecycle
  verb accepts a `Readonly` record, so no displacement scenario exists.
  In practice a `Readonly` record never anchors anything — the flip
  that publishes it destroys the volume key (see *Import runs under an
  `Importing` record*), so possession is unprovable. The predicate
  accepts it anyway because excluding it would buy nothing: the
  possession check already refuses, and `state ≠ Released` keeps the
  predicate a single structural test.

Liveness is one predicate, checked once at the anchor, covering
RW-on-self and RO-on-ancestors alike — and it means coord A's
coordinator identity needs no separate proof to coord B: key possession
+ a live `names/<name>` binding *is* the ownership statement. mint
still binds the principal via `cnf`.

Because a discharge can be cached (see *TPC structure*), its `exp` is the
**liveness-staleness bound** — the window in which a cached discharge
keeps vouching after the binding has changed. The two modes sit
at opposite ends:

- **RW-self** is liveness-sensitive: a forced claim or handoff revokes
  ownership, so a stale RW discharge would keep minting writer keypairs
  for a deposed owner. `discharge_ttl` here should be short — on the order
  of the Tigris keypair lifetime (**start at ~5 min**) — so re-attestation
  rides roughly the same cadence as keypair refresh and the staleness
  window stays small.
- **RO-ancestor** is immune: ancestors are frozen, their bindings never
  change, so the discharge cannot go stale. `discharge_ttl` can be long — bounded
  only by the primary's own `exp` (**start at ~1 h**) — and coord B drops
  off the path entirely after first-touch.

These are starting points, not fixed constants. `skew` (≈30 s, the
possession-proof freshness in *Possession-proof binding*) is a separate,
tighter clock — it bounds replay of a single proof, not the discharge
lifetime — and is unrelated to `discharge_ttl`.

## coord A acquisition: anchoring every read on a live local key

The discharge predicate checks `liveness(owned)` and possession of
`owned`'s `volume.key`, so **coord A can only obtain a discharge for a
read it anchors on a live-binding volume whose key it holds.** This is
the acquisition-side invariant: *every `volume-ro` read routes through an
`owned` anchor whose binding is live (`names/<name> → owned`, state not
`Released`) and that is locally keyed.*
The role enforces it unconditionally — once `volume-ro` carries an
`volume-ro` TPC, every `assume-role` requires a discharge — so a read
that cannot produce an anchor must not sit on the `volume-ro` path.

### Threading the `owned` anchor

`volume-ro` is acquired at two seams, both of which already know the
anchor:

- **The volume process's demand-fetch** (IPC `provision_volume_ro`): the
  requester *is* `owned`. `authorize_target` already validates `target ∈
  {requester} ∪ lineage(requester)`; it carries `requester` through as the
  anchor.
- **Coordinator-internal dense reads** (`ScopedStores::read_volume`): the
  call site holds the live leaf being operated on. `read_volume(owned,
  target)` threads it; the per-`(owned, target)` `volume-ro` facade fetches
  an `volume-ro` discharge before `assume-role` (parallel to how
  `volume-rw` fetches `volume-rw`).

### Setup reads: claim-first ordering

Most reads anchor trivially — demand-fetch and prefetch run on a live
leaf. The exception is *volume setup* (fork, claim, start), which reads
`by_id` data while the local leaf is still being established. fork and
claim establish a *new* leaf, and the rule is **claim-first**: publish
the new fork's `volume.provenance` and rebind `names/<name>` to it
*before* any `by_id` read, so `owned = new_fork` is live and every
subsequent read anchors on it. `claim` already orders `mark_claimed`
ahead of its chain reads; `fork` adopts the same shape. start
re-establishes an *existing* leaf and anchors on its surviving key
(§ *`start` anchors on the key shadow*).

The anchor is also *materialised locally* before the first anchored
read: the discharge request is built from the anchor's own fork dir —
`volume.toml` carries the name coord B's liveness lookup resolves,
`volume.key` signs the possession proof — so both land at rebind
(claim, `claim --force`) or immediately after the shadow proof
(start), ahead of any `by_id` read.

### The provisional provenance must be recovery-correct — so its trust-anchors come from control-plane state

claim-first has a sharp constraint: the provisional `volume.provenance`
published before `mark_claimed` must be **complete and correct**. The
partial-fork crash-recovery walk (`skip_empty_intermediates`) reads it
back and trusts the `ParentRef`'s `snapshot_ulid` (the basis) and
`pubkey` (the parent's identity key); placeholders are unsafe. So both
trust-anchors must be available *without a `by_id` read* at fork-create
time — i.e. from control-plane (`coord-ro`) state:

- **Basis snapshot ULID.** A `latest_snapshot` field on the
  `names/<name>` record — a bare snapshot ULID pairing with the record's
  `vol_ulid`, the same convention as `handoff_snapshot`. The owner's
  publish path CASes it after each `User` manifest upload (single
  writer, best-effort, self-heals on the next publish — the same
  discipline as the `by_id` LATEST bump it mirrors); import completion
  writes it once on `Readonly` records, so `create --from
  <imported-name>` resolves in one GET. Fork reads `(vol_ulid,
  latest_snapshot)` from one record, atomically consistent under the
  record CAS — a rebind can never leave the basis pointing at a previous
  binding's volume. Eventual consistency is fine: a fork basing on a
  slightly older published snapshot just demand-fetches a little more
  later. (claim already has its basis control-plane — the
  `handoff_snapshot` on the Released record.)
- **Parent identity key.** Read from `meta/<parent>.pub` (`coord-base`),
  the same S3 copy coord B's lineage walk verifies against.

`latest_snapshot` is a `NameRecord` schema addition
(`name_record.rs` rejects unknown versions; schema changes are
fresh-bucket-only).

With the anchors sourced control-plane, fork and claim build the new
fork's provisional provenance from `coord-ro` + `meta/` (`coord-base`)
reads only, rebind the name, and then anchor every `by_id` read — basis
manifest verify, idx pulls, body warm, ancestor data — on the now-live
fork.

`by_id/<vol>/snapshots/LATEST` remains the data-plane liveness anchor:
the LATEST → manifest → HEAD resolution used by GC verification,
recovery enumeration, and remote-start hydration, written by the owner
under per-volume credential scoping and — unlike the name record —
surviving rebinds, so ancestry walks can still resolve a released
ancestor's snapshots. Every reader of that protocol is owner-anchored;
strangers discover a basis through the name record.

### Basis resolution per `--from` form

- `--from <vol_ulid>/<snap_ulid>` and `--from <name>/<snap_ulid>` carry
  the basis explicitly. Name resolution is one `names/<name>` GET; no
  basis lookup at all.
- `--from <name>` takes the record's `latest_snapshot` as the basis,
  pinned into the fork's provenance at create time.
- Bare `--from <vol_ulid>` has no record to consult — the name record is
  the discovery surface; raw ULIDs are for explicit pins — and requires
  the pinned form.

### `start` anchors on the key shadow

The third setup operation establishes no new leaf. Remote start
(`start_remote.rs::hydrate_remote_owned`) runs when `names/<name>`
points at a leaf this coordinator owns but `by_id/<leaf>/` is gone
locally (the stop → remove → start round trip). Liveness already
holds — the record still binds the leaf — so the anchor is the
leaf itself, and the question is possession: the in-dir `volume.key`
vanished with the directory. The surviving copy is the **key shadow**
(`data_dir/keys/<vol_ulid>.key`, written when claim/fork mints the
keypair), and it is start's possession proof:

- **Shadow-first ordering.** The hydrate runs: skeleton chain off
  `meta/*` (`coord-ro`, anchorless) → read the shadow and prove
  possession with it (the shadow key must match the leaf's published
  `volume.pub`) → the `by_id` basis reads (`volume-ro` against the
  leaf, and against the parent when the leaf never published a
  snapshot). The restore into the hydrated fork dir happens after the
  basis reads, from the already-proven shadow bytes.
- **No shadow ⇒ start fails.** There is no readonly fallback: a
  keyless leaf proves nothing, so its basis reads are unauthorisable
  regardless. A dead owner's volume is recovered from another host
  via `claim --force`, which is a claim, not a start.
- **The shadow write is load-bearing.** Every keypair-mint site
  (create, fork, claim, `claim --force`) aborts if the shadow write
  fails, so owned-but-keyless cannot arise on a live host.

### New-volume bootstrap: identity establishment is coordinator-plane

A brand-new volume cannot attest its own first write. `volume-rw`'s
policy covers `by_id/<vol>/*` plus the volume's two `meta/` trust
anchors, and its `volume-rw` discharge requires coord B to verify the
possession proof against `meta/<vol>.pub` — fetched from S3. For the
first-ever upload of that pub the dependency is circular: the upload
needs the discharge, the discharge needs the uploaded object. No
record ordering fixes this; the first write of a volume's trust
anchors is structurally un-attestable *by the volume*.

It is attestable by the **coordinator**: creating a volume's identity
is a coordinator act. The `meta/<vol>.{pub,provenance}` uploads ride
`coord-rw`, whose `sub`-gated policy already carries the strictly
stronger `names/*` write (a rogue holder could rebind any name;
creating identity objects adds no trust beyond that). `volume-rw`'s
policy shrinks to `by_id/<vol>/*` only.

The two anchors have different write disciplines. `volume.pub` is
write-once: a conditional create (`If-None-Match: *`), so a race or
replay cannot overwrite a published key, and crash-resume re-uploads
treat `AlreadyExists` as success (the content is deterministic for a
given keypair). `volume.provenance` has exactly one modeled rewrite:
claim and `claim --force` publish a *provisional* lineage at rebind
and rewrite it when the effective basis resolves (§ *The provisional
provenance must be recovery-correct*), so its uploads are plain puts.
Tigris IAM cannot *require* the create header (`DateLessThan` is its
only condition operator), so the create-only discipline on the pub is
client-side; against a malicious enrolled coordinator the bar is
`coord-rw` itself, exactly as for `names/*`.

A creation flow is then three ordered planes:

1. **Identity** (`coord-rw`): upload `meta/<vol>.pub` +
   `meta/<vol>.provenance`, create-only.
2. **Record** (`coord-rw`): CAS-create `names/<name>` binding the new
   vol_ulid — the claim-first fence.
3. **Data** (`volume-rw` + `volume-rw`): every `by_id/<vol>/` write,
   fully attested — the record exists (liveness) and the pub is
   fetchable (possession).

Fork and claim already order record-before-data (claim-first); their
only pre-record S3 writes were the meta uploads this section moves.
Import needed more — its entire drain ran pre-record — and gets the
next section.

### Import runs under an `Importing` record

Import's `names/<name>` record doubled as the completion gate: written
once at worker exit, because `NameRecord.size` is only known
post-extraction. That left every drain write unanchored. The record
moves to import start, in a state that names the window:

- **Start.** Spawn the worker; it writes `volume.pub`,
  `volume.provenance` (extent sources signed in), and — new —
  persists `volume.key` in the fork dir. The importing window *is*
  the volume's rw phase, and it gets the standard rw key treatment:
  the worker signs segments with the on-disk key, the coordinator
  builds `volume-rw` possession proofs from it, exactly like every
  other volume. No key shadow is written (nothing will ever
  resurrect; the flip destroys the key). The coordinator then runs
  the bootstrap planes: identity uploads (`coord-rw`, create-only),
  and CAS-create `names/<name>` with `state = Importing`, the new
  vol_ulid, this coordinator, and `size = 0` — `Importing` is what
  marks the size as not-yet-meaningful. `AlreadyExists` fails the
  import *before* download and extraction: the cross-coordinator
  uniqueness race is settled at start, not after both hosts have
  done the work.
- **During.** The serve-phase drain writes `by_id/<vol>/` under
  `volume-rw` + `volume-rw`; the `Importing` record is a bound state,
  so the liveness predicate accepts it, and the on-disk key signs
  the proofs. `record_latest_snapshot` bumps stay vol_ulid-guarded.
  Every lifecycle verb (claim, force-claim, release, start, stop)
  refuses an `Importing` record.
- **Completion.** CAS-flip `Importing → Readonly` carrying the real
  `size` and the import's `User` snapshot — and **destroy
  `volume.key`**. Cryptographic immutability attaches at
  publication: a `Readonly` record implies the key was destroyed at
  the flip, so nobody — including the importer — can ever sign
  another segment under the base. During the window the base is
  extendable by its importer, the same trust as any unpublished rw
  volume.
- **Failure.** The post-wait failure path CAS-deletes the record
  (ours and `Importing` only) alongside the local rollback; the
  crashed-import rescan cleanup does the same. A dead *host* leaves
  an `Importing` record visible and targetable — distinguishable
  from a healthy base, unlike a part-written `Readonly` — for a
  future cleanup verb.

Cross-host `--extents-from` rides the start ordering: extent-source
idx reads happen in the import block loop, before the serve phase, so
an importer-anchored `volume-ro` read of a foreign source is
possible only because the record exists from start.

### Recovery is a claim: force-release becomes `claim --force`

`release --force` was the one remaining foreign *write*: a coordinator
that owns nothing synthesised a handoff manifest from a dead volume's
published state and PUT it under `by_id/<dead>/snapshots/` — a write
`volume-rw` can never discharge, signed by a recovery key that
`ParentRef.manifest_pubkey` then had to carry through every lineage
walk. Every artefact that write produces exists only to serve the next
owner, so the rework gives the operation to the next owner: recovery is
`claim --force`, and ownership transfers *first*.

1. **Rebind on the stale record's basis.** A stale `Live`/`Stopped`
   record carries `latest_snapshot` — the dead volume's last
   owner-published snapshot, volume-signed. That is a complete,
   recovery-correct provisional basis: mint the fork, write the
   provisional provenance with `ParentRef = (dead_vol,
   latest_snapshot)`, and force-CAS `names/<name>` to the claimant. The
   forced CAS is the fence point. (A dead volume that never published
   a snapshot has no basis: the new fork takes over the dead fork's
   own `ParentRef` and step 2 re-owns every live segment.)
2. **Re-own the head delta, anchored.** The live segments above
   `latest_snapshot` — resolved from one post-CAS read of the dead
   volume's HEAD, the cut that defines the claim set — become the new
   fork's first segments. The reads of the dead volume's prefix ride
   `volume-ro` anchored on the claimant, which requires the dead volume
   to sit in the claimant's read set — as the declared parent when step 1
   found a basis, or via the new fork's `recovery_sources` in the no-basis
   case (§ *The no-basis re-own and `recovery_sources`*).
   The writes land under the claimant's own prefix and ride `volume-rw`.
   Per
   segment: verify the parent's signature over the index, re-sign the
   same index bytes with the fork's key — the segment signature covers
   `BLAKE3(header || index_bytes)` only, body integrity being the
   per-entry content hashes — and compose the new S3 object server-side
   (`UploadPartCopy` for the body; Tigris supports it). Segment ULIDs
   are retained so intra-delta dedup references stay coherent; the
   fork's first WAL ULID mints above the copied delta,
   `max(inputs).increment()`-style.

After this rework no synthesised manifest exists anywhere:
`ParentRef.manifest_pubkey` and the recovery-signer machinery
(`resolve_handoff_key_via_recovery`, the per-source attestation
keypairs) retire. Every manifest is signed by its volume's own key, and
every write in the system is `volume-rw`.

Fencing simplifies with it. The claimant's basis is an owner-published
snapshot, so every segment it references is already at or below the
dispossessed owner's GC floor; the head-delta ULIDs under the dead
prefix are referenced by nobody once re-owned, so a zombie owner's GC
compacting them is harmless. The one live race — the zombie reaping a
cut-set segment mid-copy — is held off by the retention window and the
owner-side reap gate, and bounded by the `volume-rw` liveness
re-attestation window: the zombie's discharges stop renewing the moment
the record is rebound. `docs/design/force-release-fencing.md` § *The
head-delta cut* carries the mechanism and walkthroughs.

An operator who wants to free a dead name without hosting its volume
runs `claim --force` followed by a normal `release`; the resulting
Released record carries a real volume-signed handoff.

#### The no-basis re-own and `recovery_sources`

When the dead volume never snapshotted, step 1 gives the new fork the
dead fork's *own* parent, so the dead volume is a **sibling** of the new
fork — absent from its `fork ∪ extent_index` content lineage — yet step 2
must read the dead volume's `by_id/` (HEAD, then each live segment) to
re-own it. So the rebind names the dead volume in the new fork's
`recovery_sources`: a bare-ULID list on `ProvenanceLineage`, signed into
the provenance and walked into the read set as leaves — like
`extent_index`, but with no snapshot pin, since the re-own reads the dead
volume's live HEAD, not a snapshot. That puts the dead volume in the read
set coord B vouches (and the local read path computes — the two stay
equal), so the `volume-ro` discharge is granted and the re-own proceeds.
`finalize` clears `recovery_sources` once the segments are re-owned,
leaving the steady-state `parent = <dead's parent>` shape: the dead
volume is correctly *not* part of the new fork's final content lineage —
after re-own its segments are the fork's own.

Only a transient `Recovering` lineage carries the grant — `Root`/`Fork`
structurally cannot — so its absence is the "recovery complete" signal,
and a `cat` of an in-flight fork's provenance shows exactly what it is
re-owning. coord B is untouched:
`recovery_sources` is the same volume-signed self-declaration that
already scopes every read (§ *The read set is exactly fork ∪
extent_index*) — a leaked `volume-ro` cred cannot widen it, because the
grant is written under the coordinator's write authority, not the read
credential. It expresses a transient read, not content derivation or
ownership, which is why it lives on a distinct, transient `Recovering`
lineage variant — collapsed to `Root`/`Fork` at finalize — rather than a
field every shape carries, and why it pins no snapshot. Pinned by
`elide-attestation`'s `forced_claim_recovery_source_vouches_the_dead_fork`
(the walk authorises the read) and `force_claim`'s
`never_snapshotted_root_reowns_everything` (finalize clears the grant).

### Foreign reads have no anchor — `volume fetch` is removed

`volume fetch` pulled a *foreign* volume's bytes without taking ownership:
a `by_id` read of a volume this host holds no key for, with no lineage
relationship to prove. It cannot anchor an `volume-ro` discharge and so
cannot sit on the attested `volume-ro` role. It is removed; the
warm-then-takeover workflow is reconstructable as `fork --from` (which
warms the owner-keyed `by_id/<source>/cache/` as a side effect of its
reads, since the body cache is keyed by the owning volume) followed by
`claim`.

## Possession-proof binding

The discharge request carries an Ed25519 **possession proof** signed by
`owned`'s `volume.key`, proving coord A holds the anchor volume's key
without revealing it. It is distinct from the macaroon's caveat-key
(`r`) mechanism: `r` binds the *discharge to the primary*; the
possession proof binds *coord A to the volume*.

**Signed payload** — domain-separated, NUL-joined canonical string
fields, following the `<domain>\0<field>…` convention already used by
`RECOVERY_SIGNING_DOMAIN` in `signing.rs`:

```
"elide-volume-possession-v1" \0 owned_ulid \0 target_ulid \0
  blake3_hex(cid) \0 ts \0 nonce_hex
proof = Ed25519_sign(volume.key[owned], payload)
```

**Request** (`POST /v1/discharge` to coord B):
`{ cid, name, owned, target, ts, nonce, proof }`. `cid` is opaque to
coord A; coord B decrypts it under the symmetric `K_M-B` it shares with
mint — the same CID-wrapping construction as the auth-service TPC's
`K_M-A`. `name` is carried for the liveness lookup.

**coord B verification — fail-closed, in order:**

1. **Recover `cid`.** AEAD-decrypt under `K_M-B` →
   `(r, client_id, org_id, mode)` with `mode ∈ {volume-rw, volume-ro}`
   baked in by mint at primary issuance (mint knows the role; coord B
   never trusts the primary, which it cannot MAC). `org_id` is available
   for discharge attribution.
2. **Freshness.** `|now − ts| ≤ skew` (≈30 s) and `(owned, nonce)`
   unseen; insert into a seen-cache bounded by `2 × skew`.
3. **Possession.** Recompute the payload, fetch `meta/owned.pub`,
   `verify(payload, proof)`. Proves possession of `owned`'s key.
4. **Liveness.** `names/<name>` must currently bind `owned`:
   `vol_ulid == owned ∧ state ≠ Released` (a wrong `name` simply fails
   to resolve to `owned`; see *One liveness check* for the state set).
   Applies to `owned` only; ancestors are frozen. Resolution reuses the
   claim-record model; its edge cases (e.g. an unnamed scratch volume)
   are the claim-record design's concern, not the binding's.
5. **Mode.** `volume-rw` ⟹ `target == owned`; `volume-ro` ⟹ `target ∈
   {owned} ∪ ancestors(owned)` via the shared signed-provenance walk.
6. **Discharge.** Mint a discharge macaroon rooted at `r` carrying
   attested `caveat.volume = target`, `exp ≤ now + discharge_ttl`.

**What each field binds:**

- **domain tag** — cross-protocol separation: a possession proof can
  never validate as a provenance / snapshot-manifest / segment signature,
  or vice versa — the discipline already applied to recovery manifests.
- **`blake3(cid)`** — ties the proof to *this* TPC instance. A captured
  proof cannot be lifted onto coord C's discharge request: coord C's
  primary carries a different `cid`, so the recomputed payload differs and
  the signature fails. This is the load-bearing anti-transfer binding.
- **`owned` / `target`** — fix which key signs and which prefix is
  vouched, so a proof cannot be retargeted across volumes.
- **`ts` / `nonce`** — bounded-window anti-replay, mirroring the `cnf`
  PoP's `ts` freshness; the seen-cache makes it single-use in the window.

**Why a stolen proof is inert.** The binding chain is
`proof → cid → primary → cnf → coord A`: the proof roots a discharge at
`r`, which verifies only against the one primary whose TPC embedded that
`r` (via `vid`), itself `cnf`-bound to coord A's `coordinator.key`. So a
replayed proof — or a stolen discharge — yields a credential usable only
by coord A. Freshness and the seen-cache are hardening on top of this
(they stop coord B being a free discharge oracle), not the sole defence.

## Every template value is MAC-verified or mint-computed

Self-asserted scoping is gone. Every value a policy template substitutes is
either a `{{caveat.X}}` (a first-party caveat on the credential, MAC'd under
the chain) or a `{{mint.X}}` (mint-computed, e.g. `{{mint.expiry}}`), plus
literal text for deployment constants. There is no self-asserted `req.*`
namespace and no server-side `env.*` / `attested.*` namespace — mint retired
all three (`docs/design/mint.md` § *Caveat provenance*; mint's
`design-always-attest.md` and `design-caveat-provenance.md` own the model).

The scoping volume is a `{{caveat.volume}}` of **attested provenance**.
Provenance is *derived* from the caveat name, not declared: a reserved name
(`sub`, `role`, `epoch`, …) is issuer-stamped by mint from its own authority;
any other name — here `volume` — is attested, so mint never stamps it itself.
The coordinator proposes it and coord B vouches it into the discharge, which
mint bakes into the credential as an ordinary MAC'd caveat:

| value | how it enters the credential | trust |
|---|---|---|
| `{{caveat.volume}}` | coord A proposes, coord B's discharge vouches, mint bakes | attested — MAC'd, rooted at coord B |
| `{{caveat.sub}}` | mint issuer-stamps from the enrolled principal | MAC'd under the keyring |
| `{{mint.expiry}}` | mint-computed | server-side |

A volume role's policy therefore has exactly one scoping source and it is not
the caller — the *no optional path for a correctness property* rule at full
strength. Whether a discharge is required is a static property of the sealed
template: a role binding any non-reserved caveat (here `volume`) is attested
by construction, so the verifier stays unconditional. The round-trip is cheap
(coord B is co-located with mint) and lazy (it rides the per-ancestor
first-touch acquisition).

`role` and `ttl` are **not** template values; they survive as plain request
*parameters* — `role` gated against the credential's `role` caveat, the
lifetime the role's sealed `ttl_seconds` clamped to the macaroon's `exp`.
Neither is ever `{{…}}`-substituted.

Because the scoping volume comes solely from a verified discharge (rooted at
`r`, attributable to coord B), never from a caveat a caller could append, the
provenance trap is closed by construction. The template's `{{caveat.X}}`
tokens are hashed into mint's seal, so rendering runs against the authored
template, not a drifted local copy; `volume` being non-reserved is what
guarantees a discharge value can never shadow a control caveat like `sub`.

## The attestation coordinator is a true (limited) coord instance

coord B is not a thin bespoke verifier — it is a real coordinator,
co-located with mint and designated as mint's discharge authority. It may
own no volumes of its own; its job is to discharge. Being a coordinator,
it already has everything the discharge predicate needs: S3 read,
provenance-signature verification, and claim-record resolution.

### The lineage walk shares its per-link step; the driver loops differ by source

The read path and coord B walk the **same signed lineage** from different
sources. The read path reads a volume's *local* copies
(`by_id/<vol>/volume.{provenance,pub}`) **synchronously** at volume open;
coord B reads the *S3* copies (`meta/<vol>.{provenance,pub}` — § *S3
access*) **asynchronously**, holding no local volume. A single async
function cannot serve both without forcing the synchronous open path onto
a runtime.

The **trust-critical per-link step is single-sourced** in `elide-core`:
the signature verify (`signing::verify_lineage_with_key` — parse a
`volume.provenance`, check it under the pubkey the *child* committed, the
root under its own `volume.pub`) and the `extent_index`-entry parser
(`volume::parse_lineage_pair` — validate both ULIDs, reject traversal).
Every walk bottoms out in these, so the definition of a valid link cannot
drift between vouching and reading.

The driver loops — fetch a volume's bytes, follow `parent`, accumulate the
set, detect cycles — differ by source and live with their consumer:

- the read path's synchronous local-file `walk_ancestors` /
  `walk_extent_ancestors` (`elide-core`);
- coord B's asynchronous `meta/`-prefix walk over fork ∪ extent
  (`elide-attestation::lineage::walk_lineage_set`); peer-fetch keeps its
  own fork-only `meta`/`by_id` ancestry walk. Both bottom out in the same
  `elide-core` per-link step.

**vouchable ≡ readable** is pinned by an equivalence test: coord B's
`walk_lineage_set(owned)` must equal the read path's `lineage_ulids(owned)`
plus `owned` itself over the same lineage. A change that made coord B
vouch for more or less than a reader can reach fails it.

coord B enrolls like any coordinator and **additionally enrolls as a
discharge authority**, establishing the symmetric `K_M-B` with mint the
same way the auth service establishes `K_M-A` (`docs/design/mint.md` §
*Mint configuration*, item #2; the TPC-CID wrapping key). The volume
roles' TPC names coord B; operator-authorisation TPCs continue to name
the auth service — a primary may carry both, discharged independently.

## S3 access: the verifier holds `attest-ro`, the minimal read set

Every read the discharge predicate makes is public signed metadata under
`meta/*` or `names/*`:

| check | object | prefix |
|---|---|---|
| possession | `meta/<owned>.pub` | `meta/*` |
| lineage walk | `meta/<vol>.provenance` (owned + each ancestor) | `meta/*` |
| liveness | `names/<name>` | `names/*` |

The verifier needs **zero `by_id/` access** — only public signed metadata,
never segment bodies. `coord-ro` would satisfy that (`docs/design/mint.md`
§ *`coord-ro`*: `GetObject` on `names/*`, `coordinators/*`, `events/*`,
`meta/*`), but two of its prefixes — `coordinators/*` and `events/*` — are
ones the discharge predicate never reads. So coord B holds **`attest-ro`**:
`coord-ro` narrowed to exactly `GetObject` on `meta/*` + `names/*`. A
compromise of the exposed discharge endpoint then reads only the two
prefixes it serves from, not the whole control plane — and still mutates
nothing.

The peer-fetch verifier (`docs/design/peer-segment-fetch.md`) is the
structural cousin: on `coord-ro` it does a near-identical trio — an
ETag-conditional `names/<name>` fence (our *liveness*), a
`coordinators/<B>/coordinator.pub` requester check, and a
signed-`volume.provenance` lineage walk (our *lineage*). The attestation
verifier reads strictly less — possession is proven against the volume key
in `meta/<owned>.pub`, not a coordinator key, so it makes no
`coordinators/*` read, and `attest-ro` drops that prefix peer fetch keeps.

No bootstrap loop: `attest-ro`, like `coord-ro`, is gated by `caveat.sub`,
not by a volume attestation, so coord B obtains it through ordinary
`assume-role` without needing a discharge from itself. Only `volume-rw` /
`volume-ro` carry the volume TPC.

### A separate crate and listener from peer fetch

Peer fetch and the discharge authority are different capabilities with
different exposure profiles. Segment fetch reads local `by_id/` bodies and
is **advertised to remote peers** (`coordinators/<id>/peer-endpoint.toml`),
so it needs a network-reachable address. Discharge reads only public signed
metadata under `attest-ro`, holds no `by_id/`, and is **not advertised** —
coord A learns where to POST from the location mint sealed into the
caveat — so it can live entirely off the network on a UDS.

So coord B is the **`elide-attestation` crate**, not a route bolted onto
the peer-fetch server: the discharge handler, the discharge-mint crypto,
and the signed-lineage walk over `meta/*` (`walk_lineage_set`). The
peer-fetch crate keeps only its fork-only auth walk and the segment GET
routes. The trust-critical per-link step stays single-sourced in
`elide-core` (`verify_lineage_with_key` + `parse_lineage_pair`); each crate
is a thin async driver over it, differing only by prefix (`by_id/` vs
`meta/`) and whether `extent_index` sources are unioned.

They run in **separate processes** — the volume-serving coordinator
(`serve`) exposes peer fetch; the dedicated authority (`attest`) exposes
discharge. Neither serves the other's routes, and a `serve` config that
declares `[attestation]` is rejected. **Each takes its own
scheme-discriminated `listen`** (`unix:<path>` | `<host>:<port>`, the
`[mint] url` convention), binding a dedicated listener that serves only that
mode's routes.

```toml
# serve — the volume coordinator advertises peer fetch
[peer_fetch]
listen = "0.0.0.0:8086"                      # TCP — advertised to remote peers

# attest — the dedicated discharge authority
[attestation]
listen = "[::]:8087"                          # 6PN TCP, or unix:<path> when same-host
discharge_key_file = "…"                     # K_M-B
```

Discharge stays off the public network either way: bind a `unix:` socket
when coord A shares the host, or a 6PN TCP address when the authority is its
own instance (the shipped `deploy/attest` shape). Two couplings remain:
peer-fetch's advertised
host must stay network-reachable (its `listen` is TCP-only — a `unix:`
value is rejected), and coord A must be able to reach the discharge
`listen`. The sealed location is the authority's
*identity* — a URL whose path is the discharge route — and is not
required to be dialable: coord A dials it directly by default, and when
coord B is off-network, coord A's `[mint] attestation_transport`
(`unix:<path>` | `http(s)://host:port`) supplies the connection while
the route still comes from the location's path. This is the same
location/transport split the operator-gate discharges use (the sealed
auth `location` vs the session's stored transport).

## coord B mints the discharge: crossing the mint/coordinator boundary

coord B lives in the coordinator tree — the `elide-attestation` crate,
its own listener (§ *A separate crate and listener*) — not in `mint`. But
minting a discharge *is* mint's macaroon crypto: recover `r` by
AEAD-decrypting the TPC `cid` under `K_M-B` (`decrypt_cid_attested`),
then mint a discharge macaroon rooted at `r` carrying
`caveat.volume = target` + `exp` (`mint_under_key`, `Macaroon::encode`).
All of it lives in `mint/`, a **deliberately standalone workspace**
(`exclude = ["mint"]` in the root `Cargo.toml`: mint must build, test,
and lint independently of elide).

The decision is to **reimplement these primitives in the coordinator
against the spec**, not to depend on `mint`. This extends the precedent
in `elide-coordinator/src/mint_client.rs`, which already reimplements the
macaroon *wire format* rather than importing it, and it keeps mint's
standalone-OSS build boundary intact — a path dependency from
elide-coordinator would couple mint's build to the elide workspace, which
the documented rationale rules out.

The cost is two implementations of a security primitive — the
keyed-BLAKE3 chain and the AEAD CID seal — which can drift. The
mitigation is **mandatory cross-implementation test vectors**: committed
known-answer fixtures (`(K_M-B, cid) → (r, client_id, org_id, mode)` and
`(r, caveats) → encoded discharge bytes`) exercised by *both* the mint
and coordinator suites, so any divergence in either direction fails CI.
This is load-bearing, not a nicety: with the canonical implementation in
a crate the coordinator cannot link, the vectors are the only thing
binding the two MACs to one answer.

The asymmetry with the lineage walk is deliberate. The walk is
single-sourced because `elide-core` is already a shared dependency — no
crate boundary forces a copy. The discharge crypto is reimplemented
because `mint` is unlinkable by design. Share code where the crate graph
allows it; pin with vectors only where it does not.

## Deployment and configuration surface

Three holders configure the attestation flow, each minimally. The split
keeps the requester (coord A) ignorant of where the authority lives and the
authority ignorant of who requests — the location/transport split of § *A
separate crate and listener from peer fetch* applied to config.

| holder | attestation config | why |
|---|---|---|
| **mint** (issuer) | `[attestation] location`; `K_M-B` | mint seals `location` and the `cid` (under `K_M-B`) into every attested TPC at issuance, so it holds both. |
| **coord A** (requester) | `[mint] attestation_transport` only | The discharge route is read from the caveat's own `location`; transport is only *how* to dial when that sealed location is not itself reachable. |
| **coord B** (authority) | `[attestation] listen`; `K_M-B` | The listener it binds, and the key to open the `cid`. Possession, lineage and liveness are read from `attest-ro`. |

**coord A holds no location.** The authority's identity rides every
attested TPC as its `location` field, MAC-bound and authoritative. coord A
discharges each third-party caveat at the authority *that caveat's*
`location` names — routing is per-caveat and intrinsic, so a primary
carrying both an attestation TPC and an operator-auth TPC routes each to its
own authority without coord A holding a config copy of either location. The
only attestation value coord A configures is `attestation_transport`: the
dial override for a sealed location that is not reachable as written (coord
B off-network on a UDS), supplying the connection while the route still
comes from the caveat. Absent, the location's host is dialled directly.

**`K_M-B` enters by holder.** mint holds it to *seal* the `cid`; coord B
holds it to *open* the `cid`. In the production shape the key never leaves
mint and coord B unwraps over the wire (§ *Proposed: `K_M-B` stays at
mint*); in the demo shape both hold it directly.

### Distributed demo — shared `K_M-B`

The demo tier mirrors the shared-`K_M-A` model (`docs/design/auth-service.md` §
*Proposed: distributed demo — shared `K_M-A`*). When mint and the
coordinator run on separate hosts, the production unwrap-at-mint exchange is
more machinery than a demo needs, so the trust anchor is shared directly:
**both sides source the same `K_M-B` from config** — a known, forgeable key
rather than one mint generates.

```toml
# mint-fly.toml — mint's demo attestation seal key
[attestation.demo]
k_m_b = "<base64 32-byte AEAD key>"

# deploy/attest/coord.toml — the dedicated coord B
[attestation]
k_m_b = "<base64 32-byte AEAD key>"   # identical value
```

The deploy renders one generated value into both files, so they cannot
drift. mint seals attestation `cid`s under it; the attestation instance
opens them locally to discharge — no unwrap round-trip, no out-of-band key
delivery. The `cid` construction and the discharge MAC are unchanged; only
the holder of the key differs, exactly as shared-`K_M-A` leaves mint's
discharge verifier untouched.

**Mint-side requirement (the one cross-repo change).** mint's
`[attestation.demo]` must source `K_M-B` from a `k_m_b` field rather than
generating it at first start — the `K_M-B` analog of the `k_m_a` field
`[auth.demo]` already carries. The colocated `[attestation.demo].socket`
that stands up mint's *own* discharge authority is unused in this shape: the
dedicated attestation instance is coord B, so mint seals `cid`s but serves
no discharge.

Demo-tier only: a shared forgeable `K_M-B` is offline discharge-forgery
capability for every attested credential (§ *Proposed: `K_M-B` stays at
mint*), which is exactly why production keeps it at mint.

## A dedicated attestation instance

Splitting coord B off the volume-serving coordinator gives the discharge
authority its own deployable, so its custody of `K_M-B` and its
availability are independent of the data plane. coord B is always its own
instance — the volume-serving coordinator is never also the authority. It
runs in one of two shapes, differing only in where `K_M-B` lives. Both hold
their own identity keypair, read possession / lineage / liveness through
ordinary `assume-role` (half-TTL refresh, like every coordinator
credential), serve only `POST /v1/discharge`, and drive the same
`DischargeState`:

1. **Dedicated instance, shared binary** — `elide-coordinator attest`.
   coord B in its own process and its own app, serving only the discharge
   route: it enrolls as the `attestation` profile (§ *Attestation-profile
   enrollment*), assumes `attest-ro`, builds the `DischargeState`, and
   binds the discharge listener — none of the supervisor, GC, IPC, or
   volume scan. It reuses `coordinator.toml` because it holds `K_M-B` (and
   `K_M-A` for the enroll gate) locally as the shared literals (§
   *Distributed demo — shared `K_M-B`*), which live in a key file, not a
   flag. The multi-coord shape with the demo's local `K_M-B`.
2. **Dedicated flags-only binary** — `elide-attestation serve`, no config
   file:

   ```
   elide-attestation serve \
     --listen [::]:8087 \                         # or unix:<path>
     --mint-url https://mint.example \
     --identity-dir /var/lib/elide-attestation \
     --bucket elide --endpoint https://t3.storage.dev --region auto
   ```

   The flags-only shape is available once `K_M-B` no longer lives on the
   instance — paired with § *`K_M-B` stays at mint*, where the CID is
   unwrapped over the wire and the instance holds no local secret. The
   process then consumes only a listen address, a mint endpoint plus
   enrolled identity (keypair + `credentials/attest-ro` under
   `--identity-dir`), and the store coordinates for its `attest-ro` reads
   (S3 keypairs arrive via `assume-role`, never via flags or env). The HA
   shape (§ *HA — N instances*).

## Attestation-profile enrollment

Enrollment today grants every approved `sub` the full coordinator role
set — the `Enrolled` record carries no role constraint, and
`COORD_ENROLL_ROLES` is coordinator-side convention. The grant becomes
explicit and typed:

- The `Enrolled` record carries a **granted role set**, declared by the
  enrollee at `/v1/enroll`, shown to the operator alongside the key
  fingerprint at approval, and covered by the record's body MAC.
  `enroll-exchange` refuses a role outside the grant.
- A **coordinator enrollment** grants the four coordinator roles, as
  today. An **attestation enrollment** grants `{attest-ro}` — and is the
  gate for the CID-unwrap endpoint (§ *Proposed: `K_M-B` stays at
  mint*).
- Each attestation instance enrolls **as its own `sub`**. The
  enrollment *is* the instance's key: individually granted,
  individually audited (every unwrap and `assume-role` logs the `sub`),
  individually revoked (`rev_epoch`).

## Proposed: `K_M-B` stays at mint — instances unwrap the CID over the wire

Today coord B holds `K_M-B` and decrypts the attested CID locally. HA
replication would put that key on every instance: one fleet-shared
secret whose theft is **offline** discharge-forgery for every
outstanding attested credential, revocable only by re-keying the
mint↔coord-B pair and re-minting every credential sealed under it.

Instead, **the CID key never leaves mint**. A new endpoint

```
POST /v1/unwrap-cid        op=unwrap-cid
{ "cid": "<hex>" }    →    { "r": "<hex>", "mode": "<string>" }
```

is PoP-signed by an attestation-enrolled `sub` (`X-Mint-Pop`, the
`assume-role` transport) and returns the `(r, mode)` a local decrypt
yields today. The instance caches `cid → (r, mode)`; the CID is stable
for its credential's lifetime, so steady-state discharges hit the
cache.

**No new information flows.** The instance learns exactly what local
decryption taught it; what changes is the gate — a fleet-shared key
file becomes a per-request, per-`sub`-authenticated, audited, revocable
call. Delivering `r` to the discharge authority is not a leak but the
TPC contract itself: the CID *is* the caveat root key encrypted to the
third party. And the key-distribution rule is intact — the prohibition
is on giving keys to *verifiers* (who could then forge what they
verify); coord B is the discharge *issuer*, and the discharge's
verifier is mint, whose keys never move. The discharge MAC chain is
unchanged: symmetric, rooted at `r`.

**Capability under compromise.** A stolen `K_M-B` forges discharges for
every credential, offline, silently, until fleet re-key. A compromised
instance yields its cached per-credential `r` values (each dead at its
credential's `exp`) plus an **online** oracle that logs every use at
mint and dies the moment its one `sub` is revoked.

**Availability.** Mint lands on the discharge path, but the verifier
already depends on mint at the half-TTL timescale for its `attest-ro`
refresh, and the unwrap cache covers already-seen credentials through
a mint outage. The marginal coupling is one POST per *new* credential,
against the 2–4 S3 GETs already in every discharge.

**What it retires.** `discharge_key_file` and the out-of-band `K_M-B`
distribution; the AEAD half of the cross-implementation crypto
(`decrypt_cid_attested` and its vector) — one of the two vector-pinned
reimplementations gone. The MAC-chain half (`mint_discharge`) and its
vector stay.

**`K_M-A` is unchanged.** A pairwise key between two sovereign roots is
the TPC composing as designed: it buys mutual offline-ness (mint
verifies auth discharges with no auth round-trip; auth issues with no
mint round-trip). The unwrap pattern earns its complexity only where
one side stops being a single principal — which is exactly what HA
replication does to coord B.

## Proposed: HA — N instances, one location, no shared secret

Multiple instances stand behind the one sealed location
(the location names the *authority*; instances are interchangeable
servers of it). Each instance's durable state is its identity directory
— its own enrollment keypair and `cnf`-bound `credentials/attest-ro` —
and nothing else: no `K_M-B`, no fleet secret, no disk state beyond
identity.

The discharge protocol is single-shot — one POST carrying
`cid, ts, nonce, proof`, one response — so no load-balancer affinity is
required. Every cache an instance holds is soft: `cid → r` re-fetches
from mint, the `attest-ro` credential re-assumes, and a restart loses
nothing durable.

The one per-instance cache with protocol meaning is the possession-proof
`seen` set: single-use of a proof is enforced per instance, so behind a
balancer a captured proof is usable at most once per instance within
the freshness window (±30 s skew). The exposure is bounded — a replay
re-mints a discharge the prover was already entitled to — and the
freshness window, not the cache, is the primary fence. Sticky routing
on `owned` restores global single-use if a deployment wants it.

Fleet operations are per-instance enrollment operations: scale-out is
one enroll ceremony and the new instance immediately serves every
outstanding credential (no recipient-set churn); decommission or
compromise is one `revoke`, leaving the rest of the fleet untouched.

## Trust properties

- **Secrecy of coord B is irrelevant.** It verifies public-key crypto and
  holds no secret. A malicious coord A cannot trick it into vouching for a
  volume whose key coord A does not hold. The only assumption is that
  coord B runs the honest check.
- **Graceful degradation.** In a single-coord deployment where coord A is
  its own attestation authority, the model is still sound (coord A can
  only prove possession of volumes it holds keys for) and simply adds
  nothing where there was nothing to protect. The security becomes
  load-bearing only in multi-coord — exactly where it is needed.
- **No new trusted state.** coord B reads and verifies the same signed
  surfaces (`volume.pub`, `volume.provenance`, `names/<name>`) the
  coordinators already treat as authoritative.

## Decided

- **`role == keypair`.** `assume-role` returns one keypair; no batch
  `assume-role`.
- **`volume-ro` stays lazy per-ancestor**, single-prefix keypair acquired
  on first demand-fetch — *not* one keypair spanning the chain. A
  chain-spanning keypair (multi-statement policy assembled in mint code)
  is orthogonal to attestation and only helps dense full-chain reads; not
  adopted (see *Credential model*).
- **No self-asserted template values.** Every `{{…}}` value is MAC-verified
  (`caveat.*` — issuer-stamped or attested) or mint-computed (`mint.*`); a
  discharge is required wherever a role binds a non-reserved caveat (so
  `volume-rw`/`volume-ro`, by construction). `role` / `ttl` remain request
  parameters. Provenance is derived from the caveat name and the template is
  sealed (see *Every template value is MAC-verified or mint-computed*).
- **Possession-proof binding** is fixed (see that section): domain-tagged
  Ed25519 over `owned ‖ target ‖ blake3(cid) ‖ ts ‖ nonce`, `blake3(cid)`
  the anti-transfer binding.
- **coord B is a true (limited) coord instance**; it enrolls as a
  discharge authority establishing `K_M-B` per the auth service's `K_M-A`
  pattern (see *The attestation coordinator…*).
- **The verifier holds `attest-ro`, the minimal read set** — its possession
  / lineage / liveness reads are all `meta/*` + `names/*`, with no `by_id/`
  access, so `attest-ro` grants exactly those two prefixes: `coord-ro`
  narrowed, dropping the `coordinators/*` + `events/*` the predicate never
  reads. No bootstrap loop (`attest-ro` is `caveat.sub`-gated, not
  volume-attested).
- **The lineage walk's trust-critical per-link step is single-sourced** in
  `elide-core` (the signature verify `verify_lineage_with_key` and the
  `extent_index`-entry parser `parse_lineage_pair`); the driver loops
  differ by source — the read path's sync local-file walks, and coord B's
  async `meta/` walk in `elide-attestation`; peer-fetch keeps its own
  fork-only ancestry walk. `vouchable ≡ readable` is
  pinned by an equivalence test (coord B's `walk_lineage_set(owned)` ==
  `lineage_ulids(owned)` ∪ `{owned}`). The read set is exactly
  `walk_ancestors ∪ walk_extent_ancestors`, complete by construction
  because write-time dedup is gated on the extent index rebuilt from
  precisely that union (see *The read set is exactly fork ∪ extent_index*).
- **coord B reimplements mint's discharge-mint crypto against the spec**,
  guarded by cross-implementation test vectors run in both suites — rather
  than depending on `mint` (which must build standalone) or duplicating it
  silently. Mirrors `mint_client.rs`'s wire-format reimplementation; the
  vectors are mandatory because the canonical MAC lives in an unlinkable
  crate (see *coord B mints the discharge*).
- **Attested names are non-reserved `caveat.*`, reserved-disjoint by
  construction; the discharge vocabulary is closed per type.** Attested
  growth is **named scalar caveats, never a map** — multiple attested
  fields are multiple named scalar caveats `(name, value)` (the existing
  caveat type), so the "all caveats are scalar" invariant in
  `docs/design/mint.md` is never revised. The names are only safe if the space
  is fenced, by two invariants:
  - **attested ∩ RESERVED = ∅** — by construction, since *attested* means
    *non-reserved*. A role's non-reserved `{{caveat.X}}` template tokens
    are its attested set (derived, not declared); mint hard-codes no
    attestable vocabulary, staying as agnostic to the authority's names as
    it is to the `mode`, and pulls attested values **by name from that
    sealed template**, never "whatever the discharge carries". A reserved
    control name (`aud, exp, sub, cnf, op, role, epoch, invite, scope`) is
    always issuer-stamped, never attested. So `caveat.sub` is always
    mint's, never a discharge's — and the discharge's caveats are never
    flattened into the primary's, so a discharge value can never shadow
    the primary's MAC-bound `caveat.sub`.
  - **The discharge's caveat vocabulary is closed per discharge type and
    fails closed.** mint dispatches discharge interpretation on the
    discharge type (kid / `location`). A *volume* discharge clears only
    its own bound caveat (`exp`) and attests `{volume}`; a
    caveat that is neither is **rejected**, not absorbed into the
    principal's control-clearing pass. So coord B — whose only job is to
    attest a volume — cannot reach the principal's control set, nor the
    auth authority's vocabulary (a volume discharge carrying `Scope` is
    invalid by vocabulary, just as an auth discharge carrying `volume`
    would be). Each authority emits only its own type's names.
- **The dedicated instance is `elide-coordinator attest`** (shape 2 of §
  *A dedicated attestation instance*): a subcommand serving only
  `POST /v1/discharge`, reusing `coordinator.toml` and the enroll →
  `assume-role` → `DischargeState` stack, with no data plane. It holds
  `K_M-B` (and `K_M-A` for the enroll gate) locally as the shared literals
  (§ *Distributed demo — shared `K_M-B`*). The flags-only
  `elide-attestation serve` binary (shape 3) is deferred until § *`K_M-B`
  stays at mint* removes the on-instance secret; it is the HA shape and
  earns its own crate boundary only then.
- **coord B obtains `attest-ro` by attestation-profile enrollment** (§
  *Attestation-profile enrollment*), not a hand-issued key: the `Enrolled`
  record carries a granted role set the enrollee declares at `/v1/enroll`,
  the operator ratifies at approval alongside the key fingerprint, and
  `enroll-exchange` refuses any role outside it. An attestation enrollment
  grants `{attest-ro}` and nothing else, so the verifier's read-only,
  `by_id/`-free property is mint-enforced, not voluntary. The mint-side
  contract is `docs/attestation-readonly-enrollment-spec.md`.
