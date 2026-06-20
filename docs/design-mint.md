# mint: how Elide consumes it

## Status

**Implemented; consumption view.** `mint` is a standalone,
macaroon-authenticated credential broker for Tigris — it holds the Tigris
admin credential off-host and vends short-lived, narrowly-scoped keypairs
against sealed role policies. It is a **separate OSS project** with its own
repository and design docs:
[`github.com/soulware/mint`](https://github.com/soulware/mint)
(`docs/design-mint.md`, `docs/design-always-attest.md`,
`docs/design-caveat-provenance.md`).

This document is **Elide's consumption view**: the role inventory the
coordinator assumes, how the coordinator's S3 call sites acquire and wield
those credentials, and the coordinator-side configuration. It deliberately does
**not** restate mint's internals — the macaroon / keyring construction, the
template seal, the enrollment / `assume-role` / `exchange-finalize` protocol and
endpoints, the caveat-provenance model — those live in the mint repo and are not
duplicated here.

The sealed artifact Elide runs mint with — the role policy templates and the
`mint-elide.toml` inventory — lives in `deploy/mint/` (`deploy/mint/README.md`
is the run-book). Per-volume ownership attestation (coord B) is
`docs/design-mint-volume-attestation.md`.

## How Elide uses mint

Tigris has no STS. Rather than share one broad long-lived key or hold an
org-global admin key on every host, the coordinator authenticates to mint with
its `coordinator.key` and assumes roles that render short-lived, scoped Tigris
keypairs.

- **Enrollment is once, operator-gated.** `elide coord enroll <invite>`
  provisions the coordinator's per-role credentials under `credentials/<role>`
  (the coord roles) and durable per-role intermediates under
  `credentials/<role>/_intermediate` (the attested volume roles). The operator
  approves the enrollment out of band. After that the daemon needs no operator.
- **`assume-role` is per-use, unattended.** Each call attenuates the held
  credential with an `exp` and exercises it; mint verifies the chain plus the
  `coordinator.key` proof-of-possession and returns a Tigris keypair. The
  credential's lifetime is the role's sealed `ttl_seconds`, clamped down to that
  `exp`.
- **Volume roles are attested, per volume.** `volume-rw` / `volume-ro` bind the
  non-reserved `{{caveat.volume}}`, which makes them *attested*: the durable
  intermediate is finalized per volume under a fresh coord-B discharge that
  vouches the target volume, baking `caveat.volume` into a per-volume credential
  (`design-mint-volume-attestation.md`). Control-plane roles (`coord-ro`,
  `coord-rw`) bind only reserved caveats, so they are issuer-only and assumable
  directly after enrollment.

## Caveat provenance (the part Elide authors)

A policy template draws scalar substitutions from two namespaces —
`{{caveat.X}}` (MAC-verified, credential-authored) and `{{mint.X}}`
(mint-computed, today only `{{mint.expiry}}`) — plus literal text for deployment
constants. Mint *derives* a caveat's provenance from its name (mint's
`docs/design-always-attest.md`):

- a `{{caveat.X}}` whose name is **reserved** (`sub`, `role`, `epoch`, …) is
  **issuer-stamped** — mint sets it from the enrolled principal;
- any **other** name is **attested** — the coordinator proposes the value and
  coord B vouches it before it bakes in.

Elide's roles bind exactly one non-reserved caveat, `volume`, on the two volume
roles; everything else is either reserved (`sub`) or a literal. The volume-data
bucket is a literal (`elide`) in each policy template — a deployment constant,
edited per site alongside `[store].bucket` in `mint-elide.toml`.

## Elide as customer: role inventory

Elide's coordinator authenticates to mint and assumes **four roles**,
scoped by purpose (read vs write) and reach (coordinator-wide vs
per-volume). None carries a third-party caveat: every credential is a
uniform key-bound service token, since operator authority is exercised
at enrollment (`deploy/mint/README.md`), not at `assume-role`.

| Role | Scope | Held by |
|---|---|---|
| `coord-ro` | read-only `names/* coordinators/* events/* meta/*` | every coordinator; the *only* credential the exposed peer-fetch verifier holds |
| `coord-rw` | the coordinator-wide write policy (`names/`, `events/`, own `coordinators/<sub>/`) | all coordinator-wide mutation paths |
| `volume-rw` | per-volume `by_id/<vol>/*` read+write, plus that volume's `meta/<vol>.{provenance,pub}` (**Split B** — per-volume) | per-volume writes (snapshot publish, fork, forced-claim re-own, drain, GC, reaper) |
| `volume-ro` | per-volume `by_id/<vol>/*` read (one credential per volume prefix; ancestor reads use a separate per-ancestor `volume-ro` credential, authorized by lineage), vended to the volume process | the coordinator (assumes), the volume (holds the keypair) |

**Why not the per-purpose split (Split A).** `design-iam-key-model.md`'s
in-process model fragmented the writer into one role per top-level
prefix because the coordinator held a single *long-lived* writer key
and there was no policy-rendering broker — separate keys held by
separate code paths were the only way to bound a leaked persistent
key's blast radius and to enforce the IAM-layer invariants
(`events/` append-only, `coordinators/` immutable).

Mint dissolves both premises. It **is** the policy-rendering broker:
the IAM-layer invariants live in `coord-rw`'s multi-statement
policy *template* (no `s3:DeleteObject` on `events/` or
`coordinators/`), not in key partitioning. And the keys it vends are
short-lived, on-demand, never persisted — the operational cost that
made consolidation expensive is gone (the same argument *Why Split B
is viable now* makes). Per-purpose **attribution** is free regardless,
from the `assume-role` audit log. What a per-purpose split would still
uniquely catch — a *vended Tigris keypair* leaking without the
identity key, within one TTL window — is narrow: every `coord-rw`
key is held by the one trusted coordinator process, which on
compromise can re-assume any role it is enrolled for anyway. The split
bought far more against a single persistent admin key than it does
against ephemeral broker-vended keys held by one principal.

Two splits survive on their own merits, not Split A's:

- **`coord-ro` is separate** because the peer-fetch verifier is
  LAN/internet-exposed and must hold a credential that *structurally*
  cannot mutate state or read `by_id/` bodies. A hard containment
  boundary, not an operational nicety.
- **`volume-rw` is per-volume** (Split B) because it crosses into
  per-volume blast-radius territory and is cheap precisely because
  mint vends it ephemerally — see *Why Split B is viable now*.

### TTL principle

Mint does no active key deletion: a key lives until its
`DateLessThan` expiry. **TTL is therefore the maximum revocation latency.**
Two consequences shape every TTL below:

- Write/delete capability earns a *tighter* TTL than read-only — a leaked
  write key is strictly worse than a leaked read key for the same scope.
- Coordinator-held keys can take short TTLs: the coordinator is a
  long-running process that refreshes proactively on a timer, and writes
  buffer in the WAL if a refresh briefly stalls. `volume-ro` is also
  coordinator-assumed (the volume holds only the resulting Tigris
  keypair); for a lazy volume the coordinator keeps that keypair warm so
  a cache-miss demand-fetch never waits on `assume-role`. The wider
  read-only window is justified by it being the narrowest scope in the
  system.

### `volume-rw` (Split B — per-volume)

Per-volume `by_id/` writer. Assumed by the coordinator the first time it
writes a given volume within a TTL window; the returned keypair is cached
in memory keyed by vol_ulid and re-assumed on miss/expiry. Structurally
identical to `volume-ro` but with write actions.

- **Required caveats:** `sub`, `aud=mint`, `exp`
- **Attested caveat:** `volume` — the target volume ULID, bound as
  `{{caveat.volume}}`. `volume` is non-reserved, so the role is *attested*:
  the coordinator proposes the value and coord B vouches it
  (`design-mint-volume-attestation.md`).
- **TTL:** 24h default. Not on the hot write path (cache holds the key for
  the window; WAL absorbs a brief refresh stall), and 24h bounds the
  write/delete revocation window on a single volume.
- **Policy:** `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` on
  `arn:aws:s3:::elide/by_id/{{caveat.volume}}/*`. Single volume
  only. The volume's `meta/` trust anchors are *not* here: they are
  written once at creation on `coord-rw` (identity establishment — the
  attestation doc § *New-volume bootstrap*; a volume cannot attest its
  own first write) and read on `coord-ro`.

GC and the reaper cross volume boundaries (read ancestor/input prefixes,
delete a consumed prefix). GC *input reads* compose by assuming `volume-ro`
for the inputs alongside `volume-rw` for the output volume rather than
widening `volume-rw`'s policy. (Reaper delete of a volume's own prefix is
covered by `volume-rw` on that volume.)

### `coord-rw`

Coordinator-wide write authority: name claim / rename / forced claim
/ rollback (`names/`), event-journal appends and reads (`events/`),
this coordinator's own identity records (`coordinators/<sub>/`), and
new-volume identity establishment (`meta/`). One role, one credential,
one keypair cache. The IAM-layer invariants ride the policy
*template*, not key partitioning:

- **Required caveats:** `sub`, `aud=mint`, `exp`
- **Caveat substitution:** `caveat.sub` (this coordinator's MAC-verified
  ULID, for the own-prefix statement).
- **TTL:** 1h. Control-plane, infrequent, refreshed on demand; the
  tightest coordinator TTL since it is the broadest write capability.
- **Policy:** a multi-statement document, each statement preserving
  the invariant its prefix carries:
  - `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` on
    `arn:aws:s3:::elide/names/*`.
  - `s3:GetObject`/`s3:PutObject` (**no** `s3:DeleteObject`) on
    `arn:aws:s3:::elide/events/*`. **`events/` append-only**
    is enforced here — no statement, in any role, grants delete on
    `events/`.
  - `s3:GetObject`/`s3:PutObject` (**no** `s3:DeleteObject`) on
    `arn:aws:s3:::elide/coordinators/{{caveat.sub}}/*`
    — own-prefix only, the coordinator's MAC-verified ULID from the caveat
    chain. **`coordinators/` immutability** is enforced here; a leaked key
    can rewrite only *this* coordinator's identity, never impersonate
    another, and never delete.
  - `s3:PutObject` (**no** `s3:DeleteObject`) on
    `arn:aws:s3:::elide/meta/*` — new-volume identity
    establishment (the attestation doc § *New-volume bootstrap*).
    `volume.pub` uploads are conditional creates (`If-None-Match: *`,
    write-once at the store layer); `volume.provenance` is a plain put
    (claim flows rewrite the provisional lineage once, at basis
    resolution). Tigris IAM cannot require the create header, so that
    discipline is client-side; the trust bar against a malicious
    holder is this role itself, which already carries the strictly
    stronger `names/*` rebind. Reads of `meta/*` stay on `coord-ro`.

No `s3:ListBucket` statement: every per-volume and control-plane
LIST in the coordinator runtime has been replaced by a deterministic
GET — latest-pointer (`snapshots/LATEST`,
`events/<name>/HEAD`) or maintained delta (`by_id/<vol>/HEAD`,
`docs/design-segment-index.md`). End state: no role carries
`ListBucket`. The orphan-reclamation pass that *does* need
bucket-global enumeration is an explicit operator maintenance verb,
authenticated separately, outside the coordinator runtime
(`docs/list-elimination-plan.md` § *Reconcile/repair without LIST*).

### `volume-ro`

Per-volume read of one volume's prefix. **Assumed by the coordinator**,
not the volume: the coordinator attenuates its credential (`exp`), names
the **target** volume in the request body (`volume`), calls `assume-role`
with its `coordinator.key` PoP, and uses the resulting **Tigris keypair**
for two read paths. A reader that needs an ancestor's segments obtains a separate
`volume-ro` credential for that ancestor — one credential per volume
prefix, each authorized by lineage (`design-mint-volume-attestation.md`):

1. **Volume process reads** — coordinator vends the keypair to the volume
   over the local handshake; the volume holds only that keypair, never
   holds a macaroon, never calls mint. Reaches S3 on hydration or the
   S3 fallback when peer-fetch is unavailable. Peer-fetch proper does
   not use it — that path is the Ed25519 `PeerFetchToken` against a
   peer's local bytes (`design-peer-segment-fetch.md`).
2. **Coordinator-side ancestor `.idx` reads** — `prefetch_indexes`'s
   warm-start chain walk reads each ancestor's `by_id/<a>/*` index
   bulk; each ancestor read rides a separate per-ancestor `volume-ro`
   credential (target = that ancestor, lineage-authorized). The
   provenance/pub skeleton reads that *discover* the chain
   (`pull_readonly_op`, and the skeleton pulls inside `prefetch_indexes`)
   are **not** `volume-ro` — they hit only `meta/*` and ride the warm
   `coord-ro` credential, so chain discovery costs no per-ancestor mint.

- **Required caveats:** `aud=mint`, `exp`
- **Attested caveat:** `volume` — the target volume ULID, bound as
  `{{caveat.volume}}`. `volume` is non-reserved, so the role is *attested*:
  the coordinator proposes the value and coord B vouches it
  (`design-mint-volume-attestation.md`).
- **TTL:** 1h. Both consumers tolerate it cleanly: non-lazy volume
  episodes complete in seconds; lazy volumes refresh proactively at
  half-life; coord-side prefetch completes in seconds. The tightest
  revocation window that keeps refresh off the hot path.
- **Keypair freshness — split by volume mode:**
  - *Non-lazy (default):* the coordinator assumes on demand. A hydrated
    volume serves from local cache and touches S3 only in bounded fetch
    episodes; a refresh stall there does not stall guest I/O, so the
    coordinator assumes a fresh keypair per episode (one local
    attenuation + one `assume-role`).
  - *Lazy:* cache-miss demand-fetch is synchronous to guest I/O, so the
    coordinator keeps a warm keypair cached per `vol_ulid` and refreshes
    it proactively (the `volume-rw` cache pattern), handing the volume a
    still-valid keypair off the hot path. Revocation window is the
    keypair `DateLessThan`, bounded by the minimal blast radius (read one
    volume's lineage).
- **Policy:** the per-volume RO shape — a single scalar resource, the
  exact ARN for the target volume (`by_id/{{caveat.volume}}/*`).

### Why Split B is viable now

`design-iam-key-model.md` § *Per-volume scoping for writes (rejected)*
rejected per-volume writer keys on two grounds. The mint redesign changes
one of them:

- *Confused-deputy enforcement is "modest"* — strengthened since: the
  per-volume target is attested by the attestation coordinator's
  discharge (`{{caveat.volume}}`), so per-volume IAM scoping is rooted in
  proven ownership, not caller assertion.
- *Operational cost* (N persisted policies, `ListPolicies` reconciliation,
  orphan reaping, refresh churn) — **dissolved**. Mint keys are short-lived,
  vended on demand, never persisted, expired by `DateLessThan`. No
  reconciliation, no orphans.

Per-volume **attribution** is obtained for free regardless of Split B —
every `AssumeRole` already logs the request body's `volume` (mint's audit log).
Split B's *additional* value over a coordinator-wide `volume-rw` is
purely per-volume IAM *enforcement* (the "modest" confused-deputy catch).
The remaining cost is `AssumeRole` call volume: ~one mint round-trip per
active volume per TTL window per coordinator, gated by Tigris IAM rate
limits (*Open questions* #9). The 24h TTL is the primary knob: longer →
fewer mints, larger leaked-key window.

### `coord-ro`

The baseline read-only credential every coordinator holds. Covers the
control-plane public state a coordinator reads as a matter of course:
name resolution and claim verification, peer-coordinator identity and
endpoint resolution, event-log and peer-discovery reads.

- **Required caveats:** `sub`, `aud=mint`, `exp` — the
  same coordinator-wide gate as the other `coord-*` roles.
- **TTL:** short (1h), like the other coordinator-held roles.
- **Policy:** `s3:GetObject` only, on `names/*`, `coordinators/*`,
  `events/*`, and `meta/*`:

```
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ControlPlaneReadOnly",
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": [
      "arn:aws:s3:::elide/names/*",
      "arn:aws:s3:::elide/coordinators/*",
      "arn:aws:s3:::elide/events/*",
      "arn:aws:s3:::elide/meta/*"
    ]
  }]
}
```

`meta/*` is every volume's `volume.provenance` / `volume.pub`
(`formats.md` § *Volume provenance*). Granting it bucket-wide lets a
coordinator walk any ancestor chain's provenance under this one warm
credential, so chain discovery costs no per-ancestor mint. The flat
`meta/` prefix exists so `meta/*` is a trailing wildcard (Tigris does not
match `*` mid-resource).

**Invariant: `coord-ro` is read-only and `by_id/`-free.** This is what
makes it safe to be the *only* credential held by the LAN/internet-
exposed peer-fetch HTTP verifier: a compromise of the exposed surface
can neither mutate state nor read segment bodies
(`design-iam-key-model.md` § *IAM-layer invariants*). `meta/*` does not
weaken this — it carries only the signed, already-public
`volume.provenance` / `volume.pub`, never segment bodies, which stay in
`by_id/`. The write-capable
`coord-rw` and `volume-rw` roles stay separate and are held only
by the non-exposed mutation paths. `coord-ro` must never accrete a
write action or any `by_id/` read; doing so silently breaks
exposed-surface containment.

The peer-fetch verifier needs no dedicated role and no `by_id/` access:
it uses `coord-ro` for the gap-free fence (per-request ETag-
conditional `names/<name>` read, coincident with the `claim --force`
S3 CAS) and the requester-pubkey check (`coordinators/<B>/
coordinator.pub`), and verifies lineage against the serving peer's
**own local** signed `volume.provenance` chain — see
`design-peer-segment-fetch.md` § *Peer verification* check 4.

The `ephemeral-fetch` key class from the prior model collapses into
`volume-ro` with a shorter TTL request. Operationally distinguishable via
audit log; same role config.

## Coordinator integration

### Coordinator configuration

The coordinator reaches mint through one `coordinator.toml` section:

```toml
# enable mint
[mint]
url = "unix:mint/mint_data/mint.sock"   # or "https://mint.host:8085"
# attestation discharge authority (coord B), when this deployment uses
# volume-ownership attestation (docs/design-mint-volume-attestation.md):
attestation_location = "https://coord-b.host:8086/v1/discharge"
# how to dial coord B when the location is not the connection (e.g. a
# co-located coord B off the network on a UDS); the request path still
# comes from attestation_location:
# attestation_transport = "unix:/run/elide/discharge.sock"
```

`url` is scheme-discriminated by mint's shared transport layer:
`unix:<path>` selects the UDS leg, `http(s)://host:port` the TCP leg.
UDS paths follow the same resolution rule as mint's own (relative
resolved against cwd, absolute verbatim). The section is
presence-enables, mirroring `[peer_fetch]`.

The section is deliberately thin. The coordinator's mint identity is
`coordinator.key` (already present for name-claims and provenance);
its per-role capability macaroons live one file per role under
`credentials/<role>` in the coordinator's `data_dir`, provisioned by
enrollment (`deploy/mint/README.md`), not by config; and `aud=mint` is fixed
inside the macaroon. Only the endpoint — and optionally
`connect_timeout` / `request_timeout` (humantime, mirroring
`[store]`) — is configurable.

`attestation_location` is set when credentials carry an attestation
third-party caveat (`docs/design-mint-volume-attestation.md`). It must
equal the location mint sealed into the caveat — the authority's
identity, a URL whose path is the discharge route; before
`assume-role`, the coordinator discharges a credential carrying a
third-party caveat at this exact location by proving possession of the
volume's `volume.key` (a `volume-rw` discharge for `volume-rw`) and
attaches the returned discharge to the bundle. Absent → no discharge is
fetched. The connection comes from `attestation_transport` when set
(coord B off-network on a UDS), else the location is dialled directly.

The coordinator credential plane has exactly two states: `[mint]`
present (per-volume scoping via the role inventory below), or absent
(the shared-key downgrade — local-store / no-IAM, every volume gets
the coordinator's own key). There is no in-process per-volume IAM
path: an optional path for the credential plane would mean the
per-volume scoping property does not actually hold.

### Coordinator store architecture

The role inventory (§ *Elide as customer*) defines the
*credentials*; this is how the coordinator's S3 call sites acquire and
wield them. The existing `ScopedStores` seam
(`elide-coordinator/src/stores.rs`) carries it, widened from two scopes
to three roles:

```rust
pub trait ScopedStores {
    fn base_ro(&self)               -> Arc<dyn ReadStore>;       // coord-ro
    fn writer(&self)                -> Arc<dyn ObjectStore>;     // coord-rw
    fn volume_rw(&self, v: &Ulid) -> Arc<dyn ObjectStore>; // volume-rw
}
```

`volume-ro` is not here — it is vended *to the volume process*, not
held by a coordinator call site (§ *Coordinator configuration*,
already wired).

**Role is a property of the code path, not of the key.** A mutation
path uses `writer()` for its *entire* `names/`+`events/`+own-
`coordinators/` interaction — including the reads that are part of a
mutation (`coord-rw`'s policy holds `s3:GetObject` on those
prefixes), so a name-claim/forced-claim CAS (`GET` ETag → conditional
`PUT`) runs wholly on one credential and is never split. It uses
`volume_rw(v)` for that volume's `by_id/`. Read-only paths and
the exposed peer-fetch verifier use `base_ro()`. There is **no
prefix-routing wrapper**: which credential a path wields is explicit at
the acquisition site and visible in review, not a runtime dispatch on
key strings. The boundary the doc requires ("`coord-ro` must never
accrete a `by_id/` read") is then a property the type system carries,
not a convention.

**`base_ro()` returns a narrow `ReadStore`, not `ObjectStore`.**

```rust
#[async_trait] pub trait ReadStore: Send + Sync {
    async fn get(&self, p: &Path)  -> object_store::Result<GetResult>;
    async fn head(&self, p: &Path) -> object_store::Result<ObjectMeta>;
}
```

`get`/`head` only — no `put`, `delete`, or `list` (no role carries
`ListBucket`; see `coord-rw` above). The exposed-surface
containment boundary is made *unrepresentable*, not merely
unauthorized: a path holding `base_ro()` cannot call a mutating method
because it does not exist on the type. This is the one boundary where
the type safety is load-bearing — `coord-ro` is the credential the
LAN/internet-exposed verifier holds. `writer()` and
`volume_rw()` keep the full `ObjectStore` surface (they feed
existing mixed-prefix helpers that legitimately need it; confusing the
two is an over-privilege *within the trusted coordinator*, not an
exposed-surface break). The concrete impls of those two carry a
`debug_assert!` that the key prefix matches the role — a test-time
tripwire, not the primary mechanism.

**Mixed-prefix ops** (`Release`: `by_id/` snapshot publish + `names/`
flip; import `mark_initial`; fork/claim publish) acquire **both**
handles, at the two touch-points where each prefix is written. The op
genuinely exercises two authorities; the code shows it. `stores` is
already threaded via `ctx`/`core` at nearly every call site, so this
is "call the role method matching this touch-point," not new
parameter plumbing.

**Keypair cache and proactive refresh.** Each role's `assume-role`
yields a short-lived Tigris keypair; the coordinator caches it and the
`object_store` instance built from it, keyed by role (and by
`vol_ulid` for `volume-rw`). A background task refreshes each entry
before its `DateLessThan` (the *TTL principle*: TTL is the maximum
revocation latency, so refresh well inside it — e.g. at half-life),
rebuilding the `object_store` on rotation; a brief refresh stall is
absorbed by the WAL for writes and is off the hot path for reads
(`coord-ro`/`coord-rw` 1h, `volume-rw` 24h, `volume-ro` 1h;
freshness for `volume-ro` is § *Elide as customer*'s split-by-volume-mode
rule).
First use assumes lazily. `PassthroughStores` stays the impl for the
local-store / no-`[mint]` case; the mint-backed `ScopedStores` impl is
selected when `[mint]` is configured.

This architecture is unit-testable in isolation but, like the rest of
the `[mint]` path, is not exercisable end-to-end until enrollment
provisions the `credentials/<role>` files.

**Future direction (separate work): a domain-typed S3 layer.** The
handles above are the *minimum* credential boundary —
`ObjectStore`/`ReadStore` typed by verb surface. The intended next
refinement is for each role to hand back the *operations its policy
authorizes* rather than a generic store: `coord-rw` →
`NameClaims` / `EventJournal` (get + append, **no** `delete` method —
the `events/` append-only invariant as a type, not a policy-template
property) / `OwnIdentity`; `volume-rw` → `VolumeData`; `coord-ro`
→ `ControlPlaneReader`. This makes wrong-prefix keys unconstructable
(S3 key layout moves inside the typed store, off the `format!` sites
scattered across `upload.rs`/`claim.rs`/`name_store.rs`/…) and the
IAM-layer invariants type-level. It is deliberately **not** part of
the `[mint]` cutover: its value is independent of where credentials
come from (equally worthwhile under `AWS_*`), it migrates hundreds of
S3 call sites, and it needs its own API-design pass (how conditional-
PUT/ETag, multipart, range-get surface as domain ops without leaking
`object_store`). It layers on the same role handles afterward, call
site by call site.

## References

- **mint** — [`github.com/soulware/mint`](https://github.com/soulware/mint):
  the service and its protocol, keyring, template seal, enrollment /
  `assume-role` / `exchange-finalize` endpoints, caveat-provenance model, and
  reference client. The authoritative source for everything not specific to how
  Elide consumes it.
- `deploy/mint/` — the sealed role inventory and `mint-elide.toml` Elide runs
  mint with (`deploy/mint/README.md` is the run-book).
- `docs/design-mint-volume-attestation.md` — per-volume ownership attestation
  (coord B): the discharge predicate and the coordinator's discharge
  acquisition.
- `docs/design-mint-template-seal.md` — pointer to mint's template-seal design.
- `docs/design-iam-key-model.md` — the per-volume IAM key-inventory and
  policy-scoping rationale mint's roles inherit.
