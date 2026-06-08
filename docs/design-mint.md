# mint: macaroon-authenticated credential vending for Tigris

## Status

**Proposed. Initial draft.** Supersedes `design-elide-mint.md` (PR #354).

The project name is TBD — "mint" is the working name in this draft. This will
become a **separate OSS project** distinct from Elide; the design doc lives in
`elide/docs/` during the design phase and will move to the project's own repo
once the shape is settled. Elide is the driving customer, but the design is
deliberately general-purpose for any Tigris consumer that needs scoped,
short-lived credential vending.

This doc builds on the macaroon construction in
[`design-auth-model.md`](design-auth-model.md) and replaces the on-host
sidecar shape proposed in `design-elide-mint.md`. The IAM-key inventory in
[`design-iam-key-model.md`](design-iam-key-model.md) collapses under this
design — see *Elide as customer* below.

## Why

Tigris has no STS — no native way to vend short-lived, narrowly-scoped
credentials. Consumers that want fine-grained access scoping today have to
either share a long-lived broadly-scoped credential across many actors, or
hold an admin-class credential locally and call `CreateAccessKey` themselves.

Both options are unacceptable for Elide and likely for many other Tigris
consumers:

- **Long-lived shared credential.** Defeats per-volume isolation; a single
  leaked key compromises every volume served from that bucket.
- **Local admin credential.** Tigris admin keys are org-global root (see
  `design-iam-key-model.md` § *Tigris admin keys are org-global root*). A
  compromise of any host holding admin yields full control of every bucket in
  the org. This is an unacceptable trust model for a multi-host fleet.

`mint` solves this by being a **standalone STS-shaped service for Tigris**:
holds the admin credential off-host, accepts macaroon-authenticated requests
from clients, mints scoped Tigris keypairs against pre-configured roles, and
returns them. Clients never see the admin credential; the credential plane is
strictly hierarchical.

The closest analogue in AWS terms is `AssumeRoleWithWebIdentity` plus session
tags — except the identity token is a macaroon (not a JWT), the variable
binding happens at issuance (because Tigris has no request-time variable
resolver), and the result is a real Tigris AccessKey/SecretKey pair (not a
signed session token, because Tigris has no session-token endpoint).

## Topology

```
   ┌──────────┐                  ┌──────┐                  ┌────────┐
   │ caller   │ ──── HTTPS ────▶ │ mint │ ─── Tigris IAM ▶ │ Tigris │
   │          │   macaroon-      │      │   admin creds    │        │
   │          │   authenticated  │      │                  │        │
   │          │ ◀── keypair ──── │      │ ◀── keypair ──── │        │
   └──────────┘                  └──────┘                  └────────┘
        │                                                       ▲
        │                  S3 data plane                        │
        └───── uses returned keypair against Tigris ────────────┘
```

The caller (e.g. an Elide coordinator) holds a macaroon **issued by the
mint itself** — minted once at enrollment, then attenuated by
the caller per request. The macaroon is a pure *capability* (which
roles this key-bound principal may assume, until when); the per-request
*exercise* parameters (role, TTL, and any role-specific scoping data
such as a `req.prefix`) travel in the request **body**, which is
covered by the caller's proof-of-possession signature (§ *Credential
macaroon & lifecycle*). The caller calls `mint`'s HTTP API, presenting the
(attenuated) macaroon, the PoP-signed body, and any discharge
macaroons. `mint` verifies the macaroon against its own root and any
third-party caveats, verifies the PoP signature over the body against
the macaroon's `cnf`, looks up the role, renders the role's
policy template from the verified caveats and the PoP-verified body,
calls Tigris IAM to mint a keypair under that policy, and returns the
keypair to the caller. The caller then uses the keypair directly
against Tigris's S3 endpoint.

`mint` is **never** in the data path. It is consulted only at credential
issuance and refresh.

## Trust model

### Layers

```
caller ↔ mint:       capability macaroon (MAC, mint root) + per-request
                     Ed25519 PoP over macaroon-tail ‖ body (ts in body)
mint  ↔ Tigris IAM:  admin credential (held by mint, never disclosed)
caller ↔ Tigris S3:  the freshly-minted scoped keypair
```

**mint is both issuer and verifier of the credential macaroon.** The
symmetric macaroon root key lives and dies inside the mint and is never
distributed: mint mints a caller's credential once (at the enrollment
exchange — § *Credential macaroon & lifecycle*), and verifies the attenuated
macaroon presented on every `assume-role`. Issuer and verifier being the same process is what
removes any root-distribution problem — there is no separate authority
to share the root with, and no "configure mint to trust the
coordinator's root" step.

The caller (e.g. a coordinator) is therefore **neither a macaroon issuer
nor a root holder**. It holds a macaroon and may only *attenuate* it
(append a narrowing `exp`), which needs the trailing MAC, never the root.
The per-volume target it scopes to rides the PoP-signed request body as
`req.volume`, not the caveat chain. A compromised caller can
only narrow authority it was already granted; it cannot forge authority
for another coordinator or volume.

Delegation to a *separate* authority — proving the caller's identity,
org membership, or SSO authentication — is **not** modelled as that
authority issuing the macaroon. It is a **third-party caveat**: mint
stamps "valid only if discharged by `<identity authority>` attesting
predicate P", and verifies the discharge against a key it shares with
that authority. The identity plane (who is this caller) and the
credential plane (what Tigris scope do they get) stay separate; the
managed login service discharges the caveat (a discharge authority, not
an issuer — the "login" is that discharge, not the registration verb).
See *Open questions* and *Future directions*.

The admin credential likewise lives and dies inside the mint process and
never reaches the caller.

### Mint configuration

Each mint instance is configured with:

1. **Its own root-key keyring** — an ordered set of `(kid, key)`
   generations plus a `current` pointer naming the one used to MAC
   *new* artefacts. Symmetric: mint both mints and verifies under the
   keyring's keys. The keyring never leaves the process and is never
   shared with a caller or any other authority. It lives at
   `<data_dir>/root_keys/<NNNN>` (one 64-hex file per generation,
   mode 0600) with a small `<data_dir>/root_keys/current` text file
   naming the active kid — `ls` shows the rotation history without
   any binary-only state. First start generates a CSPRNG `kid=0`
   only in demo mode (`[demo_auth].enabled`); a production instance
   must have `root_keys/` provisioned out-of-band — or be handed a key
   to seed (the multi-host shape — see *Root-key rotation*) — and fails
   closed otherwise.
   Verification accepts any kid still in the ring; minting always
   uses `current`. Rotation procedure lives in *Root-key rotation*
   below. The current **`invite`**
   is persisted in the store bucket at `_mint/invite` (see *Mint
   state in the store bucket*), not on disk — it must survive restart
   so the distributed invite macaroon stays valid, and keeping it
   bucket-side lets multiple mint processes share one value (HA /
   central-custodial deployments). Confidentiality of the invite is
   not load-bearing: it is distributed out-of-band and is a
   participation gate, not a secret. Only `mint invite --rotate`
   changes it.
2. **Zero or more third-party discharge keys** — one symmetric key per
   identity/discharge authority mint trusts to satisfy a third-party
   caveat. Absent in the minimal self-hosted deployment (no third-party
   caveat); present when an identity authority such as the managed login
   service is in use.
3. **One Tigris admin credential**, held in memory. It is
   read from the standard AWS environment variables
   (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, optionally
   `AWS_SESSION_TOKEN`) — the same convention the elide coordinator uses
   for its IAM-mode admin credential — **not** from the config file. The
   credential is a secret delivered by the environment (systemd
   `LoadCredential=`, a secrets manager); keeping it out of the TOML
   keeps secrets and role definitions on separate management planes.
   The admin credential is used **only on the IAM plane** —
   `CreateAccessKey` / `CreatePolicy` / `AttachUserPolicy` for vending
   role keypairs (`coord-*`, `volume-*`, and mint's own `mint-rw` —
   see *Mint state in the store bucket*). It is never used directly
   for `s3:*` operations against the store bucket.
4. **A set of role definitions** — see *Role configuration* below.
5. **Store configuration** (`[store]`) — where mint keeps its own state:
   `bucket` (the object-store bucket holding `_mint/*` — see below),
   plus optional `endpoint` and `region` for the S3 client mint builds
   to reach it. Operational transport only; **never** a template surface.
6. **Template values** (`[env]`) — a flat table of operator-defined
   scalar entries, surfaced to role policy templates as `{{env.X}}`
   (§ *Templating*): the bucket name(s) roles grant on, prefixes, region
   strings. The only server-side substitution source a role policy reads.
   Nested tables or arrays under `[env]` are a config error; the store
   bucket reaches a template only if the operator restates it here.

Role definitions, audience, store configuration, and `[env]` values are
static and file-backed. The macaroon keyring and admin credential are secrets and
are not plaintext TOML fields — the admin credential comes from the
AWS environment; the keyring lives under `<data_dir>/root_keys/`
(one 64-hex generation file per kid, plus a `current` pointer).

#### On-disk layout

A mint instance is named by its config file: `--config <path>`, else
the `MINT_CONFIG` environment variable, else `./mint.toml`. Setting
`MINT_CONFIG` lets operator commands run from any directory without
repeating `--config`; an explicit flag still wins. `mint serve` always runs against a
real S3-compatible backend: enrollment state in the store bucket
under `_mint/` (via the self-vended `mint-rw` keypair) and real
Tigris IAM for `assume-role`. There is no in-process dev backend;
operators wanting to exercise the flow without a public Tigris
account point at MinIO or a Tigris free-tier bucket. Test code
that needs a `Store` without a cloud dependency uses
`Store::open_in_memory` / `Store::open_local` directly, outside
the `serve` path.

The config also declares two optional directories, mirroring the
elide coordinator's `data_dir` (`coordinator.toml`):

- **`data_dir`** (default `mint_data`) — holds the macaroon keyring
  directory `root_keys/` (one file per generation, mode 0600, plus a
  `current` pointer). When `[auth]` is configured it also holds
  `auth-shared.key` (K_M-A — the TPC-CID wrapping key shared with the
  auth service) and the admin-plane `admin-service` + its machine key
  `admin-service.key` (§ *Admin service token*); the colocated demo additionally
  generates `auth-session.key` (K_session — the login-session root)
  here. The operator's login **session** is not kept here — it is
  per-user under `~/.config/mint`, shared with `mint client`
  (§ *Admin service token* — *Login & discharge*). Enrollment
  state (the current `invite` nonce, pending records, and the
  approved-coordinator registry) lives in the store bucket under
  `_mint/` so multiple mint processes can share one logical state
  (see *Mint state in the store bucket*); the bucket-side custodian
  is a self-vended `mint-rw` keypair, not the admin credential.
- **`roles_dir`** (default `mint_roles`) — role *policy templates*, one
  file per role (see *Role configuration*).

Both follow the coordinator's resolution rule: a relative value
(including the default) is resolved against the current working
directory, not the config file's parent; an absolute path is used
verbatim. Unlike the coordinator, mint has **no `--data-dir` override
flag** — a mint instance is fully described by its config file, so
running two instances is purely `mint.toml` + `mint2.toml` with distinct
`data_dir` values (and, if desired, a shared `roles_dir`). The override
flag would be unused surface; its absence is a decision, not an
oversight.

#### Mint state in the store bucket

Enrollment state lives in the store bucket (`[store].bucket`), under a
dedicated top-level prefix `_mint/` that no coordinator IAM role ever
names. Coordinators have no path to it through any issued macaroon. The
store bucket is configured independently of the bucket(s) roles grant on
(named via `[env]`) — they need not be the same bucket.

Mint does **not** use its admin credential directly for these bucket
operations. On startup mint self-vends an internal **`mint-rw`** Tigris
keypair via the same `KeypairMinter` machinery it uses for `coord-*`
and `volume-*` keys: `CreateAccessKey + CreatePolicy + AttachUserPolicy`
with policy scoped to `arn:aws:s3:::<store.bucket>/_mint/*` (all
verbs) and a `DateLessThan` matching the existing role-credential
cadence. The admin credential remains in memory for the IAM-plane
calls that vend `mint-rw` (and refresh it before expiry), but never
touches `s3:*`. Consequences:

- A request-handler bug that exposes the in-handler S3 credential
  leaks `_mint/*`-scoped read/write/delete plus bucket-wide
  `ListBucket` visibility (Tigris IAM accepts only `DateLessThan` as
  a condition operator, so the `s3:prefix` constraint that would
  scope LIST to `_mint/` is not expressible — Get/Put/Delete still
  match only `_mint/*` by Resource). Not org admin either way.
- Bucket audit logs cleanly separate routine enrollment plumbing
  (`mint-rw` access key) from IAM operations (admin access key).
- A process-memory compromise still yields admin, because admin must
  stay resident to vend any role key — that is structural.
- One scoped key suffices: a separate `mint-ro` for the invite-cache
  poll would add ceremony with no meaningful blast-radius reduction
  inside a single process.

```
_mint/invite                     — single object; body = nonce (hex)
_mint/clients/pending/<sub>.json — one per in-flight enrollment; small set,
                                   GC'd on a bound ≥ the ticket exp;
                                   body = {pub, invite, requested_by,
                                           first_seen, peer_ip}
_mint/clients/enrolled/<sub>     — long-lived; one per ever-approved sub
                                   body = {pub, approved_by, approved_at,
                                           fingerprint_shown, kid,
                                           rev_epoch, mac}
_mint/clients/revoked/<sub>      — revocation tombstone (sub revoked,
                                   awaiting re-approval); carries the
                                   high-water rev_epoch so approve resumes
                                   the counter
                                   body = {rev_epoch, revoked_by,
                                           revoked_at, kid, mac}
```

Every `_mint/clients/enrolled/<sub>` body is MAC'd by the keyring generation
that issued it: `mac = blake3_keyed(keyring[kid], "mint-approved-v1"
|| len(sub) || sub || len(pub) || pub || len(approved_by) ||
approved_by || len(approved_at) || approved_at ||
len(fingerprint_shown) || fingerprint_shown || rev_epoch)`. The
`sub` is in the MAC input (not just the object key) so a record
cannot be copied to a different `<sub>` and still verify. A holder
of a `mint-rw` bucket credential can `PutObject` to
`_mint/clients/enrolled/*` but cannot produce a valid MAC without the
keyring on local disk; mint's `get_enrolled` verifies and treats a
mismatch as "not approved" (the HTTP layer returns the same opaque
403 awaiting-approval signal so a client cannot distinguish forgery
from absence). Forgeries are logged loudly server-side for the
operator's forensic trail.

The split is intentional: `clients/pending/` is small and LIST-friendly
(rotation and GC walk it); `clients/enrolled/` is a growing per-coordinator
registry queried only by key (HEAD/GET on `<sub>`), never listed on a
hot path. Merging the two would force every exchange to GET a record
just to read an approval bit, and every rotation to LIST a set whose
size is unbounded by design.

Concurrency primitives (multi-instance mint is a goal — see *Admin
credential custody — deployment shapes* below):

- `record_pending`: `PUT _mint/clients/pending/<sub>.json` with
  `If-None-Match: *`. On 412, GET the existing record and run the
  idempotency / `(sub, pub)` conflict check unchanged.
- `approve`: `PUT _mint/clients/enrolled/<sub>` carrying the body MAC under
  the keyring's current kid, then `DELETE _mint/clients/pending/<sub>.json`.
  Re-approval against a *different* pub is a key-rotation
  acknowledgment and overwrites the registry record (under the
  current kid). The new record's `rev_epoch` is allocated from any
  `clients/revoked/<sub>` tombstone (then the tombstone is deleted) —
  see § *Revocation*.
- `revoke`: `PUT _mint/clients/revoked/<sub>` (the tombstone, at the
  high-water `rev_epoch`), then `DELETE _mint/clients/enrolled/<sub>` —
  ordered so a crash leaves the high-water recorded, never an enrolled
  record gone with no tombstone to resume from. See § *Revocation*.
- `is_enrolled` (exchange path): `GET _mint/clients/enrolled/<sub>` — one
  round-trip; the body MAC is verified before any of its fields are
  trusted, then the record's `pub` must be the key the exchange request's
  PoP verifies against. A MAC failure (forged record, or record left over from a
  retired kid) is collapsed into the same 403 awaiting-approval the
  client would see for a missing record.
- `migrate_approval_to_current_kid` (lazy migration): called
  opportunistically from the `/v1/enroll` fast path after a matched
  approval. If the record's kid is older than `current_kid`, mint
  re-MACs and PUTs back with `If-Match: <etag>`; a 412 means the
  record changed underfoot and the write is silently abandoned. The
  effect is that every active coordinator drifts its approval forward
  to the current kid on its next restart, without operator action.
- `rotate_invite`: `PUT _mint/invite`, then `LIST _mint/clients/pending/` and
  `DELETE` every record whose `invite` field is not the new value.
  `clients/enrolled/` is not touched.
- Pending GC: `LIST _mint/clients/pending/`, drop entries past a bound on their
  first-seen timestamp. `clients/enrolled/` is never GC'd.

Mint processes cache the invite locally with an ETag-conditional
refresh (~30s): a background poll issues `GET _mint/invite` with
`If-None-Match: <last-etag>` and accepts the cheap `304 Not Modified`
when the nonce is unchanged. Steady-state, `/v1/enroll` reads the
cached value and never blocks on a Tigris round-trip.

**The keyring does not move.** Enrollment state goes to the bucket;
every macaroon root key stays on local disk under
`<data_dir>/root_keys/`. Two consequences:
(1) deliberately, a bucket-credential compromise alone cannot mint
or forge credentials or approvals — the attacker would also need
filesystem access to one of the mint hosts to obtain the keyring.
(2) multi-instance mint deployments must replicate every `(kid, key)`
out-of-band (typically via the same secrets-manager mechanism that
delivers the admin Tigris credential), since instances sharing one
`_mint/` prefix must agree on the keyring or they will mint
artefacts the sibling cannot verify. Both `Keyring::open` (first
start) and `Keyring::add_and_promote` (rotation) accept a
caller-supplied key for this case: the operator provisions one
instance, captures the generated bytes, then re-runs the same op on
the peer with the supplied key so both converge on the same kid.

**First-start generation is gated on demo mode.** `mint serve`
auto-mints a fresh keyring only when `[demo_auth].enabled`; a
production instance with an empty `root_keys/` and no supplied key
fails closed (`macaroon keyring absent … provision root_keys/ … or
enable [demo_auth]`) rather than silently minting one. This makes the
multi-instance footgun structurally impossible: three production
instances booting with empty data dirs cannot each fabricate a
divergent master key — they must be pre-seeded with the same keyring
first. A new org's first production keyring is therefore generated
out-of-band (offline, or on a bootstrap instance) and distributed like
any other deploy-time secret.

**`K_M-A` is shared the same way.** `auth-shared.key` (the TPC-CID
wrapping key) must be byte-identical across every replica of a logical
mint. The `CID` mint stamps onto each third-party caveat is
`AEAD(K_M-A, r ‖ OrgId)` with no key-identifier field, and the
discharger holds a single `K_M-A` it decrypts every `CID` with:
`r` is recovered from the chain `VID` at verification but only from
the `CID` at discharge, so a credential whose `CID` was wrapped under
a replica-local key would fail to discharge wherever the request
lands. Replicas therefore cannot each enrol a distinct `K_M-A` — it is
a per-org key generated once by the auth service at mint enrollment
([`design-auth-service.md`](design-auth-service.md) § *Mint ↔ auth
enrollment*) and delivered to every replica by the same out-of-band
mechanism that replicates the keyring. The colocated demo auth role's
`auth-session.key` (K_session) carries the identical requirement
wherever that role is itself replicated.

### Root-key rotation

The keyring (`<data_dir>/root_keys/`) is the only secret state on
mint hosts; it follows a **retain-keychain with lazy migration**
model. The dominant industry pattern (AWS KMS, HashiCorp Vault
transit, JWKS, etc.) is to retain old key generations indefinitely
for verification while shifting new issuance to the current
generation; mint takes the same shape, with one elaboration that
falls out of mint owning the records it issues: opportunistic
re-MAC on natural touch, so approvals drift forward to the current
kid as their coordinators restart.

**Wire format.** Every macaroon and every `_mint/clients/enrolled/<sub>`
record carries the kid that MAC'd it (a 2-byte BE prefix in the
macaroon binary container; a `kid` JSON field on the approval).
Verification picks the named kid out of the keyring and replays the
chain — an absent kid (retired, or never existed) fails verification
with the same opacity as a bad MAC. The MAC seed binds the kid into
the chain (`blake3_keyed(key, "mint-macaroon-v2" || kid_be ||
nonce)`) so a leaked key cannot be replayed under a different kid
claim.

**Rotation procedure.** Two human steps in the common case:

1. **Add.** `Keyring::add_and_promote` generates (or accepts) a new
   key, writes the next `<NNNN>` file, repoints `current`. The
   previous generation stays in the ring for verification. For
   multi-instance deployments the operator captures the new key
   bytes and runs the same op on every peer with that key supplied —
   `add_and_promote` is idempotent for matching bytes, and refuses
   if the on-disk file disagrees.
2. **Drain naturally.** Every coordinator restart hits
   `/v1/enroll`. After a fast-path match the handler observes
   `record.kid != current_kid` and re-MACs the approval forward,
   with `If-Match` on the etag for multi-writer safety. Quiescent
   coordinators stay quiescent — their record sits on its issuing
   kid until they restart or until the kid is explicitly retired.

The two further admin actions are not part of routine rotation but
exist for the situations that need them:

3. **Retire** (`Keyring::retire`). Deletes the named kid from the
   ring. Anything still MAC'd under that kid stops verifying
   immediately. Per-kid retirement is fully independent — retiring
   kid 2 in a ring of {0, 1, 2, 3} leaves kids 0, 1, 3 untouched.
   The set of records killed by `retire(X)` is exactly the records
   whose body carries `kid == X` — enumerable via a LIST + per-record
   peek before the operator pulls the trigger.
4. **Sweep** (`Store::sweep_approvals_to_current_kid`). The
   force-converge admin operation: re-MAC every `_mint/clients/enrolled/<sub>`
   **and every `_mint/clients/revoked/<sub>` tombstone** under the
   current kid in one pass, regardless of natural touch. Used only when
   an operator wants to retire an older kid without waiting for lazy
   migration to drain it (e.g. immediate compliance action). Tombstones
   have no lazy-migration path of their own, so the sweep is the only
   way their high-water `rev_epoch` survives a kid retirement — without
   it, retiring a kid would silently drop the high-water and let
   re-approval revive dead credentials. Skips records that fail to
   verify under any kid in the ring — forgeries are never laundered
   forward.

**Compromise rotation.** If a kid is suspected compromised:
`retire` it immediately. Records that lazy-migration has already
drifted forward survive (the active fleet keeps working); dormant
records under the retired kid die and the corresponding
coordinators have to re-enroll. Sweeping *before* retire is wrong
in this case — it could re-MAC a record an attacker just forged
under the still-trusted old kid.

**Hygiene rotation.** Just `add_and_promote`; no other action
required. The ring accumulates one entry per cycle; the per-host
cost is ~32 bytes per kid and `u16` gives 65 535 generations.
Operators can `retire` ageing kids when ready; the
sweep-before-retire option is available if they want to migrate
stragglers first.

### Admin credential custody — deployment shapes

The same mint code supports three deployment shapes:

1. **Self-hosted.** Operator runs the mint on a machine they trust (typically
   not the same host as any volume daemon). Configures the admin credential
   directly. Full control; no third-party dependency. The canonical OSS
   deployment.
2. **Central custodial** (Elide-managed offering). Elide runs a hosted mint
   instance; the operator's admin credential is held by Elide. Easier setup,
   meaningful trust handoff. Customer interacts via the closed-source web
   console.
3. **Central proxy** (Elide-managed, customer-key offering). Elide runs the
   mint, but the admin credential it uses is one the customer provisioned and
   vended to Elide central. Customer can rotate/revoke at any time
   independently. Compliance-oriented deployments choose this.

(2) and (3) differ only in whose Tigris account the admin credential is
issued against — the mint software is identical.

## Operator authorization

Mint's admin endpoints — `POST /v1/admin/invite`,
`POST /v1/admin/invite/rotate`, `POST /v1/admin/enrollments`,
`POST /v1/admin/enroll/approve` — are
the operator's surface for managing invites and approving coordinator
enrollments. Every endpoint is a `POST` (even the reads), because the
proof-of-possession signs over the request body and every call carries
one. They are mounted on the UDS listener only
(§ *Proposed: dual-listen*); UDS filesystem permission gates
**transport**, not authority. Every admin call still carries the
`MintV1 <bundle>` Authorization shape used everywhere else — a
primary plus an auth-service discharge — so each call is exercised by
a specific operator under a specific authorization policy, and the
audit log can attribute actions to humans rather than to "whoever
could `connect(2)` to the socket".

### Admin service token

The primary in an admin bundle is a long-lived **admin service token** —
the deployment's machine identity for the admin plane — written by mint
at first start and read by the local `mint` CLI on each invocation. Its
caveats are the minimum needed to anchor the bundle:

```
caveats:
  aud = mint
  cnf = ed25519:<machine pubkey>
  TPC:  location = discharge URL (path = discharge route), VID/CID encrypted under K_M-A
```

No `op` and no `exp` on the base token. The operator attenuates
`op=admin:<verb>` onto the service token per call, so the verb binds to
that call's proof-of-possession over the attenuated tail; one endpoint
clears exactly its own verb. Per-call freshness rides on the discharge.
The token is inert without a fresh auth-service discharge satisfying its
third-party caveat.

**Two identities.** The admin plane separates the *machine* from the
*human*:

- The **machine key** is the service token's `cnf`. Mint generates the
  keypair when its files are absent — the token is minted before any
  operator key exists — and writes the seed to `<data_dir>/admin-service.key`. The CLI
  signs every admin request's PoP with it. It attests "this is the
  deployment's CLI", not which human is driving it.
- The **human session** is what `mint login` obtains from the auth
  service and gates discharge issuance. The auth service stamps the
  session's `Subject` into each discharge, so the audit log attributes
  `enroll approve` to a human even though the PoP is the machine's.

**Generation.** `mint serve` mints the service token whenever either
file is absent — a fresh deployment, a lost or partial pair, or `[auth]`
enabled on an existing deployment — under `K_M` (fresh nonce), writing
`<data_dir>/admin-service` together with the machine-key seed
`<data_dir>/admin-service.key`, both mode 0600. Re-minting is safe: the
`cnf` lives inside the token and nothing pins it out of band, so a
regenerated pair is simply a new valid identity (any lost copy is inert
without its key). Neither file is a network secret: the bundle is inert
without a fresh discharge, and any process without UDS access cannot
reach mint at all. Local-filesystem reach is the only reach either needs.

**Distribution.** None. The mint CLI on the same host reads both files
directly. No copy-paste, no out-of-band channel, no deployer secrets
pipeline. Cross-host operator access is out of scope here; remote
operators interact with mint through the coordinator for non-admin
paths, or wait for a future authenticated-TCP admin transport
(§ *Proposed: dual-listen* — *What this is not*).

**Login & discharge.** `mint login` authenticates at the auth service
and stores the session **per-user** under `$XDG_CONFIG_HOME/mint` (else
`~/.config/mint`), alongside the auth **transport** it dialled
(`auth-transport`). One login serves both planes: the same all-scopes
session backs the operator admin plane and `mint client`'s enroll /
exchange (see [`design-auth-service.md`](design-auth-service.md)
§ *Login flow*). Transport precedence is `--url`, else `--config`'s
`[demo_auth]` socket (flag, else `MINT_CONFIG`), else the remembered
`auth-transport`; `mint logout`
removes the session but leaves the transport, so a later bare
`mint login` re-authenticates at the same place. On each admin call the
CLI fetches a **discharge** for the service token's third-party caveat
from `POST <auth>/v1/discharge` at scope `mint:admin` (gated by the
session, which must carry that scope; recovering the discharge key from
the caveat's `CID` under `K_M-A`). The discharge carries `Subject`,
`Scope=mint:admin`, and a short `exp` and **no** `op`, so one fetch
satisfies every verb (the verb binds via the per-call attenuation).

The discharge **route** is the *path* of the service token's own TPC
`location`; the **transport** that path is dialed over is the one
remembered at `mint login` (`auth-transport`) — the `[demo_auth]` socket
in the colocated demo, a network endpoint for a standalone auth service.
`location` is the only auth
endpoint carried as a full URL, because it rides inside the macaroon and
must be self-contained; `/v1/login` and `/v1/discharge` are otherwise
fixed routes the CLI dials over that transport, and `mint logout` is
purely local. This mirrors how an enrolling client derives its discharge
route from the invite's TPC `location` (§ *Enrollment*). The CLI then attenuates
the call's `op=admin:<verb>` onto the service token, bundles `[service
token, discharge]`, and PoP-signs the attenuated tail with the machine
key.

**Rotation.** `mint admin-service rotate` re-mints the token under `K_M`
(new nonce, fresh machine keypair) and overwrites both files. Old
tokens remain verifiable until a revocation mechanism lands (see
*Open questions*); the discharge layer gates every individual call
regardless.

**Lifetime.** Effectively the deployment's. Per-call freshness is
supplied by the discharge's short `exp` and the per-request PoP, so
a long-lived service token does not weaken any property the per-call
check enforces.

### Why not gate admin on filesystem permission alone

UDS permission gates transport; it does not say which human is
calling. Two reasons we still require the bundle on top:

- **Identity attribution.** Multiple local users may share UDS
  access (the operator, the mint process, an unrelated service in the
  same group). The audit log needs to record which human performed
  `enroll approve`; the discharge's `Subject` — established at `mint
  login` and stamped by the auth service — is that record. Without it
  the human is unrecoverable from the request (the PoP only attests the
  shared machine key).
- **Authorization policy lives at auth-service.** "Who may operate
  this mint" is a policy decision belonging to the central
  authorization service, not to whoever was added to the mint group
  on the host. The discharge mechanism is the explicit interface where
  that policy is enforced; collapsing to filesystem permission would
  put the policy in `/etc/group`.

## Credential macaroon & lifecycle

A **credential macaroon** is the mint root attenuated to exactly one
coordinator identity **and exactly one role**: `op=assume-role`,
`aud=mint`, `sub=<coord-ulid>`, `cnf=ed25519:<coordinator.pub>`,
`role=<name>`, no `exp`. `(sub, cnf)` *is* the coordinator's identity
within the credential plane; `role` is the single authority that
credential carries. Because every caveat is scalar (§ *All caveats are
scalar*), one credential cannot enumerate a set of roles — so a
coordinator holds **one credential file per role it is authorized
for**, each minted by its own enrollment exchange (§ *Enrollment* (3)),
and a subsystem loads only the role credential it needs. They live one
file per role under a `credentials/` directory (`credentials/<role>`,
mode 0600), so `ls credentials/` shows exactly which roles are held.
Each is persisted in `data_dir`
alongside the identity key, loaded on every start, reused across
restarts. Per request and per managed
volume the coordinator appends a narrowing `exp` and names the target
volume in the request body (`req.volume`) before calling `assume-role`;
the stored macaroon is never sent unattenuated. **A credential does not expire**: once
PoP-bound a file-only leak is inert (the thief lacks `coordinator.key`)
and a key compromise renews regardless, so there is no re-issuance
cadence. The identity key is not rotated: a new key is a new
coordinator — new `coord-ulid`, new enrollment.

`sub` and `cnf` are partitioning caveats. A
coordinator self-asserts them only inside the enrollment exchange; a
credential carrying them exists only because mint re-minted it from root
after the operator vouched for the pairing (below). A coordinator can
never append them to an existing macaroon to widen authority — a
contradictory copy is unsatisfiable and fails closed.

The credential is **bound to the coordinator's Ed25519 identity** by the
`cnf` first-party holder-of-key caveat. `assume-role` honours
the macaroon only when the request carries a fresh Ed25519 signature, by
`coordinator.key`, over `BLAKE3(presented-macaroon-tail ‖
BLAKE3(request-body))` — the tail binds the proof to this exact
capability macaroon (role/`exp`), the body hash to this exact request
(role, TTL, scoping data such as `req.volume`).
Freshness is a `ts` field **inside the body** (unix seconds, ±skew
window) — already covered by `BLAKE3(request-body)`, so no separate
signed term and no header. The persisted file alone is therefore inert:
the only secret is the identity key the coordinator already protects
(name-claims, provenance, peer-fetch). The `(sub, cnf, role)` binding
rides every token and is checked against the macaroon root each call,
so verification carries no per-coordinator state of its own — with one
deliberate exception: `assume-role` reads the enrolled record's
**revocation epoch** to make a credential revocable (§ *Revocation*).
That same long-lived registry of approved coordinators
(`_mint/clients/enrolled/<sub>`, § *Enrollment* / *Mint state in the
store bucket*) also lets a previously approved key re-enroll without
operator intervention.

### Revocation

`mint enroll revoke <sub>` de-authorizes a coordinator and kills every
credential it holds. Revocation gates two things — **issuance** of new
credentials and **verification** of existing ones — because either
alone leaks: a held ticket or the re-enrollment fast path would re-mint
around an `assume-role`-only check.

**Issuance gate (structural).** The enrolled record's *presence* is what
authorizes a coordinator to obtain credentials — `/v1/enroll`'s
re-enrollment fast path and `/v1/enroll-exchange` both require
`_mint/clients/enrolled/<sub>` present with a matching `cnf`. Deleting
the record drops the coordinator to the slow path: it cannot exchange
again, and a held ticket exchanges against nothing, until an operator
re-approves.

**Verification gate (the epoch).** Each credential is stamped at the
exchange (§ *Enrollment* (3)) with the enrolled record's current
`rev_epoch` as a first-party `epoch=<n>` caveat, beside `sub`/`cnf`/
`role`. `assume-role` clears it against `_mint/clients/enrolled/<sub>`:
the record must be present and MAC-valid, its `cnf` must match the
credential's, and its `rev_epoch` must equal the credential's `epoch`.
This gate exists for the one job presence cannot do — keep credentials
minted before a revocation dead even after the *same* key is re-approved.

**Revoke.** `mint enroll revoke <sub>` deletes
`_mint/clients/enrolled/<sub>` and writes a tombstone
`_mint/clients/revoked/<sub>` carrying the **high-water `rev_epoch`** —
the value the killed credentials were stamped with — plus `revoked_by` /
`revoked_at`, MAC'd under the current kid. At once: every held credential
fails `assume-role` (its enrolled record is gone — fail-safe deny), a
held ticket fails `/v1/enroll-exchange` the same way, and the
re-enrollment fast path falls back to the operator-gated slow path. The
coordinator can mint nothing new and use nothing it holds.

**Re-approval.** Epoch allocation lives here, at the moment a new
generation is born. `mint enroll approve <sub>` sets the new enrolled
record's `rev_epoch` by:

- a `_mint/clients/revoked/<sub>` tombstone exists → tombstone's
  `rev_epoch` **+ 1** (then delete the tombstone);
- else an enrolled record is still present (key rotation / idempotent
  re-approval) → keep its `rev_epoch`;
- else (first-ever approval) → `0`.

Because the counter only ever advances, credentials minted before the
revocation carry a lower `epoch` and never clear again — even when the
same key re-enrolls.

**Latency.** Revoke stops *new* keypair minting immediately. Tigris
keypairs already vended live until their `DateLessThan` expiry (mint
does not recall IAM keys — § *Cleanup*), so live S3 access dies within
one keypair TTL: **TTL is the maximum revocation latency**. Instant
hard-kill (deleting the vended IAM keys) is possible but out of scope
for now.

**Properties.**

- *Fail-safe:* every gate denies on an absent or unverifiable enrolled
  record, so revocation is the *absence* of authority — not a flag a
  verifier must read correctly to make it bite.
- *Integrity, not freshness:* the MAC stops a `_mint/` writer forging a
  record or a `rev_epoch`, but not *replaying* one — restoring a
  previously-valid `enrolled/` record (or deleting the tombstone) can
  revive old-epoch credentials or un-revoke a coordinator. This is a
  residual of the `_mint/` trust class (which carries no signing
  capability); a different-key re-enrollment stays safe via `cnf`.
- *Verify ≠ clear:* the credential's MAC check stays pure and
  cacheable; the presence/`cnf`/`epoch` comparison is a clearing
  predicate against live state — cacheable only with bounded staleness,
  which adds to (never replaces) the keypair-TTL latency.
- *Still app-driven:* `assume-role` gains no operator gate; revocation
  is an out-of-band operator action that changes stored state the gates
  read, not a per-request discharge.

**Evolution.** The replay residual exists only because the live
revocation state sits in the shared bucket. To withstand a `_mint/`-level
adversary, move `rev_epoch` and the revoked flag to the auth-service — the
operator trust source — and have mint read them from a cached revocation
feed at exchange and `assume-role` (the denylist-at-the-authority pattern
in Fly.io's [*Operationalizing Macaroons*](https://fly.io/blog/operationalizing-macaroons/)).
The bucket records become binding/audit only, so replaying them is inert.
This design is forward-compatible: the credential already carries the
`epoch` caveat and `assume-role` already does a freshness clear — only the
*source* of the current value changes. The cost is a runtime
mint↔auth-service dependency on `assume-role`, served from last-known feed
state through an outage.

### Enrollment

Enrollment binds a coordinator's self-asserted `sub`/`cnf` to an
operator-approved key, gates that binding behind **three operator
decisions** — *enroll*, *approve*, and *exchange*, none of which need be
made by the same human — and then issues that many non-expiring,
single-role credentials.

**Three operator gates, then none.** Enrollment is the only place a live
operator participates. An *enrolling* operator authorizes a coordinator
to begin enrollment at all (the enroll gate, step (1)); an *approving*
operator confirms the coordinator's key (the approve gate, step (2));
an *exchanging* operator is present when the coordinator first pulls
its role credentials (the exchange gate, step (3)). Each gate is a
third-party caveat discharged by a logged-in operator; the three may be
different people, and mint records each `Subject` so the audit log
attributes every decision to a human.
Once a coordinator holds its credentials they are **long-lived service
tokens**: `assume-role` — swapping a credential for a Tigris keypair — is
**app-driven and never operator-gated**. No third-party caveat rides a
credential; operator authority lives entirely at enrollment, not at
runtime.

**Invite macaroon — the enroll gate.** At first start mint draws a
random nonce — the `invite` value — persists it at `_mint/invite` in the
store bucket (see *Mint state in the store bucket*) so every mint
process sharing that store bucket sees the same value, and emits the
invite macaroon: the root attenuated with `op=enroll`, `aud=mint`,
`invite=<current>`, **and a third-party caveat naming the auth service**.
It is non-expiring, carries no coordinator identity, and is distributed
out-of-band; one invite is reusable for every coordinator that enrolls
against this mint. The third-party caveat is what makes the invite a
gate rather than a free pass: it is inert without a fresh auth-service
discharge, so a coordinator can attempt enrollment only when a logged-in
operator has authorized the request. Confidentiality of the invite is
not load-bearing — the third-party caveat, not secrecy, is the gate.

**(1) `POST /v1/enroll` — the request.** The enrolling operator, logged
in at the auth service, fetches a discharge for the invite's
third-party caveat at scope `mint:enroll` (auth issues it only if the
operator's session carries that scope) and conveys it to the coordinator
(inert bytes — the discharge is useless without the rest of the bundle). The coordinator
attenuates the invite with `sub=<own id>` (Elide: the coordinator ULID)
and `cnf=ed25519:<own pub>` and presents `[invite ⊕ sub/cnf, coordinator
PoP over the body, operator discharge]`. Mint verifies the chain against
its root (`op=enroll`, `invite`=current), the PoP against the appended
`cnf`, and the discharge against the invite's third-party caveat —
clearing its `Scope` to `mint:enroll`; it
records a **pending enrollment** at `_mint/clients/pending/<sub>.json` —
`(sub, pub, invite, requested_by, first-seen ts, peer ip)`, where
`requested_by` is the discharge's `Subject` — and returns a **credential
ticket**: a macaroon minted fresh from root with `op=enroll-exchange`,
the same `sub`/`cnf`, `aud=mint`, a short `exp`, and **its own
third-party caveat** (the exchange gate — a distinct `CID` from the
invite's) requiring an operator discharge at exchange. The ticket is
role-agnostic and multi-use until its `exp`; the coordinator holds it in
memory across the wait for approval. A retried request with an identical
`(sub, pub)` is idempotent (fresh ticket, same record); a second request
for the same `sub` with a different `pub` is a conflict that surfaces to
the operator and never auto-resolves; a `pub` seen on a different `sub`
is anomalous (a new key is a new principal) and surfaced.
**Re-enrollment fast path.** Before writing the pending record, mint
checks `_mint/clients/enrolled/<sub>`: if it exists and its `pub` equals the
presented `cnf`, no pending record is written — the returned ticket
exchanges against the existing registry entry immediately, with no
second approval (the exchange gate still applies). If `clients/enrolled/<sub>`
exists with a *different* `pub`, a pending record is written as normal
and surfaces to the operator as a key-rotation acknowledgment (approval
there overwrites the registry record). The pending record's lifetime is
the ticket's: it is GC'd on a bound ≥ the ticket `exp` if not approved
by then, or deleted at approval time (step (2)). The enrolled entry at
`_mint/clients/enrolled/<sub>` is **not** transient — it persists for the life
of the coordinator identity and powers the fast path.

**(2) Operator approval — the approve gate.** `mint enroll approve
<sub>` is an admin-plane call (§ *Operator authorization*), so it
carries the **approving** operator's own auth-service discharge at scope
`admin` — a possibly different human, whose `Subject` the auth service
stamps. It
prints the pending record's `cnf` fingerprint and requires an
interactive y/N confirmation (default no); the operator confirms only
after matching it, through a trusted side channel, against what the
client reports (`mint client fingerprint`). That interactive
confirmation **is** the trust anchor binding `sub` to the rightful key;
the operator discharge is what attributes the decision to a human.
`--yes` skips the prompt for automation (the operator then asserts the
out-of-band check happened). On confirmation mint writes
`_mint/clients/enrolled/<sub>` with `{pub, approved_by, approved_at,
fingerprint_shown}` — `approved_by` is the admin call's discharge
`Subject` — and deletes `_mint/clients/pending/<sub>.json`. The recorded
approval is the operator-attested, audit-bearing artifact that later
credential issuance consults; it is the durable successor to the
in-flight pending record. Mint does not enforce `approved_by ≠
requested_by` — a single operator may both request and approve — but
both identities are recorded.

**(3) `POST /v1/enroll-exchange` — the exchange gate.** Collecting the
role credentials is an operator *bringing the client online*, so it is
gated too. An *exchanging* operator (logged in, possibly a third
human) fetches a discharge for the ticket's third-party caveat at scope
`mint:exchange` and conveys it to the coordinator. The coordinator
presents `[ticket, operator discharge]` with a `coordinator.key` PoP over
the body `{ts, role}`, once per role it needs. Mint verifies the ticket
chain (`op=enroll-exchange`, the short `exp`), the discharge against the
ticket's TPC — clearing its `Scope` to `mint:exchange` — and the PoP
against the ticket's `cnf`; requires `_mint/clients/enrolled/<sub>` to exist with
a `pub` equal to that `cnf`; and decides **is this `sub` permitted this
`role`**. The decision has a
floor and an upgrade: the **floor** (minimal self-hosted deployment) is
that `role` names a role in the mint config with no per-`sub`
restriction — role policies scope per coordinator by templating on
`sub`; the **upgrade** is a per-`sub` permitted-role set recorded on the
enrolled entry at approval time, so the approving operator decides not
just *that* a coordinator may enroll but *what* it may assume. On
success mint **re-mints from root** a credential (`op=assume-role`, the
same `sub`/`cnf`, `aud=mint`, `role=<requested>`, no `exp`, **no
third-party caveat**). The ticket is not consumed per role — one
discharge satisfies its TPC for every role exchanged within the
discharge's window, so the exchanging operator participates once. A
coordinator that has lost local state re-collects its credentials by
re-enrolling, which re-runs the exchange gate: re-materializing a
machine's credentials is itself an operator action.

**Rotation.** `mint invite --rotate` draws a new random
`invite`, persists it at `_mint/invite`, emits a fresh invite
macaroon, then LISTs `_mint/clients/pending/` and deletes every record whose
`invite` field is not the new value. The
`_mint/clients/enrolled/<sub>` registry is **not** touched: an outstanding
approval — and the credentials it backs — survive rotation, as do the
re-enrollment fast paths of every previously approved coordinator.
Restart preserves the nonce (it lives in the bucket); only explicit
rotation cancels in-flight enrollments.

Refresh cadences, distinct, in increasing trust cost:

- **Tigris keypair** — re-call `assume-role` with the held macaroon
  (*Open questions* #8).
- **Volume Tigris keypair** — the coordinator takes its `volume-ro`
  credential, appends `exp`, names the target volume in the request body
  (`req.volume`), calls `assume-role`, then vends the resulting keypair
  to the volume over the local handshake. On demand per fetch
  episode for non-lazy volumes; kept warm and refreshed proactively for
  lazy ones (the `volume-rw` cache pattern). The volume holds no
  macaroon; the keypair `DateLessThan` is the only lifetime here.

A credential itself has no refresh cadence — it does not expire (see
above); each is minted once, at the enrollment exchange for its role,
and carries no third-party caveat to re-discharge.

## Protocol

Four endpoints. `/v1/assume-role` and `/v1/verify` share a single
**verify+clear** core: walk the presented macaroon's chain MAC,
recursively verify any discharges by recovering `r` from each TPC's
`VID` to fixpoint, then clear the standard first-party caveats (`aud`,
`op=assume-role`, `cnf`+PoP, `exp` — including any per-forward `exp`
attenuation). A credential
carries no third-party caveat, so the discharge step is a no-op on the
`assume-role` path; it does real work at the three operator gates — the
invite at `/v1/enroll`, the ticket at `/v1/enroll-exchange`, and the CLI
service token at the admin verbs. `/v1/verify` returns the cleared
bundle's caveats and minimum `exp` so the caller can cache the
verdict. `/v1/assume-role` runs the same verify+clear and then **assumes
the role** — renders the role policy from the PoP-signed body's scoping
data (`req.volume`), mints a Tigris keypair. `/v1/enroll`
and `/v1/enroll-exchange` are the one-time bootstrap: `/v1/enroll` admits
a coordinator's operator-gated invite attenuation, records a pending
enrollment, and returns a ticket; `/v1/enroll-exchange` takes that
ticket plus an operator discharge and issues a role credential to an
already-approved coordinator.

### `assume-role`

```
POST /v1/assume-role
Host: <mint-instance>
Authorization: MintV1 mnt1_<b64url-primary>[,mnt1_<b64url-discharge>...]
X-Mint-Pop: <base64 Ed25519 signature>
Content-Type: application/json

{
  "ts": 1747000000,
  "role": "volume-ro",
  "ttl_seconds": 3600
}
```

Response:

```
200 OK
Content-Type: application/json

{
  "access_key_id": "tid_...",
  "secret_access_key": "...",
  "expiration": "2026-05-15T14:30:00Z"
}
```

### `verify`

```
POST /v1/verify
Host: <mint-instance>
Authorization: MintV1 mnt1_<b64url-primary>[,mnt1_<b64url-discharge>...]
X-Mint-Pop: <base64 Ed25519 signature>
Content-Type: application/json

{
  "ts": 1747000000
}
```

Response:

```
200 OK
Content-Type: application/json

{
  "valid": true,
  "expires_at": 1747000600,
  "caveats": [{"name": "aud", "value": "mint"}, ...]
}
```

The bundle is the same shape exercised at `/v1/assume-role` — the same
credential under the same per-request `exp` attenuation, with the target
volume carried in the body as `req.volume` (and, for an admin token, the
same discharge). The two endpoints share
the verify+clear core described above. The `op` caveat at both is
`assume-role`: `op`
names the authority a token carries, not the protocol verb. The
caller queries authority validity at `/v1/verify`, exercises it at
`/v1/assume-role`; mint clears the same caveats on the same bundle in
both cases.

### Enrollment endpoints

```
POST /v1/enroll              # invite (⊕ sub/cnf) + enrolling-operator discharge in MintV1 bundle
                             # X-Mint-Pop; body {ts}
                             # → 200 credential ticket (base64); fast path → proceed to exchange

POST /v1/enroll-exchange     # ticket + exchanging-operator discharge in MintV1 bundle
                             # X-Mint-Pop; body {ts, role}
                             # → 200 credential macaroon (base64), role-stamped
                             #   403 until approved · 401 on PoP/discharge/role failure
```

`/v1/enroll` carries the coordinator-attenuated invite in `Authorization:
MintV1 mnt1_<b64url>` together with the enrolling operator's discharge
in the same bundle, the PoP in `X-Mint-Pop`, and `{ts}` in the body.
Mint verifies the chain, the discharge against the invite's TPC, and the
PoP; records a pending enrollment (or none, on the fast path) and
returns a **credential ticket** carrying its own TPC (§ *Enrollment*
(1)).

`/v1/enroll-exchange` carries the **ticket** plus the exchanging
operator's discharge in the `MintV1` bundle, the PoP in `X-Mint-Pop`,
and `{ts, role}` in the body (the requested role rides the PoP-signed
body, so it is authenticated and audited like any exercise field). Mint
verifies the ticket chain, the discharge against the ticket's TPC, and
the PoP against the ticket's `cnf`; requires `_mint/clients/enrolled/<sub>` to
exist with a matching `pub`; and returns `200` with the role-stamped
credential, `403` until that `sub` has been approved, or the same opaque
`401` as `assume-role` on any failure (including a role this `sub` is not
permitted).

### Authentication

Authentication is uniform: every endpoint presents a macaroon in the
`Authorization` header, base64url-encoded — the coordinator-attenuated
invite at `/v1/enroll`, the credential ticket at `/v1/enroll-exchange`,
the attenuated credential at `/v1/assume-role` and `/v1/verify`, the CLI
service token at every `/v1/admin/*` endpoint (§ *Operator
authorization*). Any discharge macaroons for third-party caveats are
included in the same `MintV1` bundle; a TPC is present on the invite
(the enroll gate), the ticket (the exchange gate), and the CLI
service token (the admin plane), **never on a credential**, so those are
the bundles that carry a discharge. The mint verifies the presented
chain MAC against its own macaroon root, and each discharge against the
relevant third-party key (see
[`design-auth-model.md`](design-auth-model.md) for the construction).

The request also carries the proof-of-possession the `cnf` requires:
`X-Mint-Pop` is the base64 Ed25519 signature, by `coordinator.key`, over
`BLAKE3(macaroon-tail ‖ BLAKE3(request-body))`. Every macaroon at these
endpoints carries `cnf` — the coordinator appends it when attenuating
the invite, and mint carries it through the ticket and the credential.
PoP is required on all four endpoints. The body it covers differs by
endpoint: at `/v1/enroll` it is just the freshness `ts`; at
`/v1/enroll-exchange` it is `{ts, role}` (the requested role is
authenticated by the same signature); at `/v1/verify` it is `{ts,
discharges}` (the
discharge bundle is authenticated by the same signature); at
`/v1/assume-role` it is the full exercise body (§ *Request body*). The
freshness timestamp is **not** a header — it is a
`ts` field (unix seconds) *inside the body*, already covered by
`BLAKE3(request-body)`, so it needs no separate signed term. Only the
detached signature is a header (it cannot live in the body it signs).
The mint recomputes the digest over the **exact raw body bytes it
received** (hashed before parsing — no JSON canonicalization, which is
itself a footgun) and the presented macaroon's tail, verifies the
signature against the sealed `cnf`, and **then** reads `ts`
from the now-authenticated body and rejects it if outside the skew
window. Only after the signature verifies does any `req.*` body
field — `ts` included — become a trusted input. `cnf` is mandatory at
every endpoint that accepts a macaroon: absent, contradictory, or
malformed `cnf` — and any other PoP failure — resolves as `401`.

If verification fails — bad MAC, unknown root, malformed encoding,
wrong/absent `op` for the endpoint, stale `invite`,
missing or bad PoP — the mint returns
`401 Unauthorized` with no further detail (don't help an attacker
distinguish "wrong key" from "tampered caveats" from "bad PoP"). The
sole non-`401` authorization outcome is `/v1/enroll-exchange` returning
`403` for a not-yet-approved pending record — an awaited state, not an
auth failure.

### Request body

This section is the `/v1/assume-role` body; the `enroll` body carries
only `ts` and the `enroll-exchange` body `{ts, role}`. The request body
specifies the **exercise of authority** — what the caller is asking for right now within the bounds
the macaroon attests to. The
whole body is covered by the PoP signature (§ *Authentication*), so every
field is vouched for by `coordinator.key` and bound to this exact
macaroon and moment. Mint is **body-field-agnostic** in the same way it
is caveat-vocabulary-agnostic: it does not hard-code which fields are
meaningful. It parses the verified body into the `req.*` template
namespace; a role's policy template is the only thing that decides which
fields matter, by referencing them (strict mode — a template referencing
an absent `req.X` fails closed). Conventional fields:

- `ts` (required): the PoP freshness timestamp, unix seconds. Carried
  here, not in a header, so it is covered by the signature over the
  body; mint rejects it outside the ±skew window. Absent/garbled ⇒
  `401`.
- `role` (required, asserting): the caller's **independently-stated
  intent** — the role this subsystem believes it is exercising, sourced
  from its own config, **not** echoed from the loaded credential. Mint
  takes the authoritative role from the credential's `role` caveat
  (stamped at the enrollment exchange) and selects the policy from it,
  then requires `req.role` to **equal** that caveat; a mismatch
  fails closed. This is not a way to pick a role — it is a guard: a
  subsystem that loaded the wrong per-role credential file states one
  role while the file carries another, and the request is denied
  instead of silently exercising the wrong authority. It also keeps the
  PoP-signed body self-describing for the audit log. (Echoing the
  caveat back here makes the check vacuous — the value must be the
  caller's own intent.)
- `ttl_seconds` (optional): requested credential lifetime. Must be within
  the role's `min_ttl_seconds`..`max_ttl_seconds` and must not exceed the
  macaroon's `exp` caveat. Defaults to the role's `default_ttl_seconds`.
- `req.*` (role-specific): scalar scoping fields a role template names
  (e.g. the demo roles' `req.prefix`). They are **not** caveats: the
  caller computes them and asserts them here, authenticated by the PoP
  rather than the MAC chain. Mint neither knows nor requires a field
  except through the role template that names it.

### Response

On success: the freshly-minted Tigris keypair plus its absolute expiration.

On role mismatch (the credential's `role` is not in config,
`req.role` disagrees with it, or caveats don't satisfy role
requirements): `400 Bad Request` with a generic error.

On Tigris-side failure (rate limit, quota, admin credential rejection):
`503 Service Unavailable` with an error code indicating retry-ability.

Error model is deliberately coarse; see *Open questions*.

## Role configuration

### Schema

Roles are declared in the TOML config file (loaded at mint startup).
Each role's *metadata* stays in `mint.toml`; its *policy template* lives
in its own file under `roles_dir`, named `<name>.json` by default:

```toml
[[role]]
name = "volume-ro"
min_ttl_seconds = 60
max_ttl_seconds = 604800     # 7 days
default_ttl_seconds = 86400  # 1 day
# template: <roles_dir>/volume-ro.json (the default; no policy_file needed)

[role.template]
req = ["volume"]             # the policy substitutes {{req.volume}}
```

Credentials carry no third-party caveat: operator authority is exercised
at enrollment (§ *Enrollment*), not at `assume-role`, so there is no
per-role discharge knob. Every role's issued credential is a uniform
key-bound service token, and the verifier's chain walk is the same for
all of them.

```jsonc
// <roles_dir>/volume-ro.json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ReadVolume",
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::{{env.bucket}}/by_id/{{req.volume}}/*",
    "Condition": {
      "DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}
    }
  }]
}
```

The template filename defaults to `<name>.json`; an optional
`policy_file` on a role overrides it (for a non-`.json` name, or to
point two roles at one shared template). Whether derived or explicit,
the filename is resolved against `roles_dir` and must be a single normal
path component — parsed, not substring-checked: `Path::new` of it must
yield exactly one `Component::Normal`. That rejects path separators,
absolute paths, `.`, `..`, parent traversal, and the empty string in one
predicate, so neither a role name nor a `policy_file` can reach outside
the roles directory. Because the default derives from `name`, an unsafe
role name (one containing a separator or `..`) is rejected by the same
check — distinctly diagnosed (`BadDerivedPolicyName`) from a bad
explicit `policy_file` (`BadPolicyFileName`), pointing the operator at
the actual fix. The guarantee is name-level: a symlink *inside*
`roles_dir` is still followed, but `roles_dir` shares `mint.toml`'s
custody, so its contents are the operator's own, not an external-input
boundary. The role inventory — names and TTL bounds —
stays visible at a glance in one `mint.toml`; only the multi-line
JSON policy template, which is awkward to lint and diff inside a
TOML triple-quoted string, moves to a per-role file. The policy is
mandatory: a role whose template file is absent is a config error
(`ReadPolicyFile`); there is no inline form.

### Templating

A role's policy template is **JSON** carrying `{{ ns.key }}` scalar
substitution tokens, each token sitting inside a JSON *string value*.
Rendering parses the template as JSON, substitutes into the string
leaves, and re-serialises. Mint runs no templating engine — the grammar
is exactly `{{ namespace.key }}` scalar lookup, so a small scanner
replaces the engine and its dependency.

Two security properties fall out of that shape rather than from a bespoke
check:

- **Injection-proof.** A substituted value is placed into an
  already-parsed JSON string and the document is re-serialised, so the
  serialiser escapes any `"`/`\` the value contains — a value can never
  break out of its slot, whatever its content (a value that itself
  contains `{{…}}` is inert text, never re-scanned). The rendered output
  is valid JSON by construction.
- **Substitution is string-positioned, structurally.** A `{{…}}` token
  anywhere but inside a string value — an array element, an object key, a
  bare position — makes the template invalid JSON. That is rejected when
  the template is parsed: at **seal authoring** (`POST /v1/admin/seal`,
  alongside the env-key check) and again at render time. JSON validity
  *is* the "this token sits in a safe position" assertion; there is no
  separate positional check to forget.

Seal authoring also **lints token shape**: every `{{…}}` must be a
well-formed `namespace.key` scalar path. A leftover engine-ism
(`{{#each}}`), a namespace-less or empty token, or an unterminated `{{`
would fail the render closed, so the lint surfaces it at publish — a
sealed template is one the renderer can actually render. (Absent *values*
are not linted: a `req`/`caveat`/`mint` field's value is not known until a
request, so that stays a render-time strict-mode concern.)

The mint substitutes four classes of variable, each with an explicit,
distinct trust provenance:

- `{{env.X}}` — values from the mint's `[env]` table, a flat set of
  operator-defined scalars (bucket name(s), prefixes, region), as a plain
  path. Server-side, never caller-controlled — and **sealed**: at seal
  time the `[env]` values are materialised into the sealed surface
  (`sealed/env.json`, pinned by the seal's `env_blake3`), so the request
  path renders the *sealed* env, never the live config. Every `{{env.X}}`
  a template references must name a key in `[env]`; this is enforced when
  a seal is authored
  (`POST /v1/admin/seal`) — a seal cannot pin templates referencing
  undefined env values — so the gap surfaces at publish time, not as a
  fail-closed render. It is deliberately *not* checked at config load:
  serving is decoupled from the live config, so a drifted local template
  never blocks a host from serving its already-sealed roles.
- `{{req.X}}` — scalar fields from the PoP-verified request body (bound to
  `coordinator.key`, this macaroon's tail, and this moment — §
  *Authentication*). Available **only** after the PoP signature is
  verified. They render directly. This is the channel for the
  honest-but-unverified scoping data the caller computes — including the
  per-volume target, which rides the body as `req.volume`
  (`by_id/{{req.volume}}/*`). Mint transmits it into the policy, the PoP
  authenticates *who* asserted it, mint never validates the value.
- `{{mint.X}}` — values computed by the mint at request time, as a
  plain path. v1 set: `mint.expiry` (the issued credential's expiry as an
  RFC 3339 / ISO 8601 instant — `now + min(requested TTL, role
  `max_ttl_seconds`, macaroon `exp` − now)`). This is the mint's clamped
  output, not the macaroon's raw `exp` caveat: it can be strictly tighter
  and never looser, so a template substitutes `mint.expiry` here. The
  `mint.*` namespace is closed to this server-computed set; seal authoring
  rejects a template referencing any other `mint.X`, so an unknown key
  fails at publish, not at render.
- `{{caveat.X}}` — the **MAC-verified** value of the macaroon's caveat
  named `X`, as a plain path. v1 exposes one: `caveat.sub`, the
  enrolment-immutable principal, for `coord-rw`'s own-identity prefix
  (`coordinators/{{caveat.sub}}/*`). The value is sourced from the
  verified caveat chain — never echoed through the request body — so it
  is rooted in the mint's macaroon root and cannot be forged by the
  caller. A name with ≥2 disagreeing occurrences resolves *unsatisfiable*
  and is **omitted** (never collapsed to one of the disagreeing values),
  so a `{{caveat.X}}` over it fails the render closed under strict mode —
  a holder cannot smuggle a forged value past the renderer with a
  contradictory appended copy. Only caveat names that are legal path
  segments are referenceable; `sub` is, colon-namespaced names (`elide:…`)
  are not, and none of those is a substitution source.

A macaroon caveat plays two distinct, never-conflated roles. As a
**predicate** it is *checked* — the role gate clears it against the
credential and live request context (§ *Macaroon caveat conventions*);
this verify/clear path is the only thing that grants or denies. As
**data** its MAC-verified value may also be substituted via
`{{caveat.X}}` (above), read-only. The per-volume target, by contrast, is
honest-but-unverified caller assertion and rides the body as `req.volume`,
not a caveat. All four classes are strict — a token naming an absent key,
a non-string `req` field, or anything that is not a `namespace.key`
scalar path fails the render closed, never a silent empty string.

#### Declared request contract

The two **request-supplied** namespaces — `req.*` (PoP-signed body fields)
and `caveat.*` (MAC-verified caveat names) — are declared per role in a
`[role.template]` subtable, the role's *request contract*:

```toml
[[role]]
name = "coord-rw"
# … TTL bounds, policy_file …

[role.template]
caveat = ["sub"]      # the template binds {{caveat.sub}}
```

```toml
[[role]]
name = "volume-ro"
# …

[role.template]
req = ["volume"]      # the template substitutes {{req.volume}}
```

The contract is the authoritative set for those two namespaces, validated
in three places so the same declaration is checked at authoring,
attestation, and request time:

- **Seal authoring** (`POST /v1/admin/seal`) cross-checks each template's
  actual `{{req.X}}` / `{{caveat.X}}` tokens against the declaration —
  **exact match**, absent subtable = the empty set. A typo (`{{req.volm}}`
  against a declared `volume`) or a dropped binding (a `coord-rw` template
  that forgets `{{caveat.sub}}` and so would mis-scope to
  `coordinators/*/*`) fails at publish instead of silently mis-scoping a
  live credential. This is the same move as sourcing the principal from
  `caveat.sub` rather than a body field: it takes a security binding off
  "the author remembered to" and puts it on "the system enforces."
- **Sealing.** The declared contract is part of the attested surface — it
  is sealed alongside the policy hash and TTL bounds (`SealedRole`) and
  MAC'd into the seal. A host enforces the contract that was *authored*,
  never a drifted local one; `mint role inspect` flags a local
  `[role.template]` that no longer matches the seal.
- **Request time.** Before render, the request path enforces the sealed
  contract against the live request: every declared `req` field must be a
  string in the PoP-verified body, every declared `caveat` name must
  resolve to a single value in the MAC-verified chain. A missing input is
  a clean `400` (a client fault) rather than a render-time failure.
  Render-time strict mode remains the backstop.

This completes a symmetric picture: every namespace's surface is validated
at seal against an authoritative set — `env.*` against `[env]`, `mint.*`
against the closed server set, and `req.*` / `caveat.*` against the
declared contract.

The mint **does not** ship a general-purpose policy DSL. The role-facing
surface is scalar substitution of `{{env.*}}`, `{{mint.*}}`, `{{req.*}}`,
and `{{caveat.*}}` tokens into the JSON string leaves. No role iterates a
list — every role's policy is straight scalar substitution. List
iteration, conditional blocks, arithmetic, value transformations, and
dynamic resource construction beyond straight substitution are
deliberately out of scope. Roles
requiring more expressive policies should be split into multiple roles.

### Per-volume read credentials

A `volume-ro` credential scopes to a **single** prefix, `by_id/<vol>/*`,
and a reader that needs an ancestor's segments obtains a separate
`volume-ro` credential for *that* ancestor. No template iterates a list:
`volume-ro`'s policy is a single scalar resource
(`by_id/{{req.volume}}/*`), the per-volume target carried in the
PoP-signed request body, which keeps least-privilege tight — a leaked
`volume-ro` credential grants one volume's prefix, not a whole lineage.

The read path is keyed by owner. The demand-fetch interface
(`elide_core::segment::SegmentFetcher`) takes `owner_vol_id` per call and
issues exactly one GET against that owner's prefix; the coordinator's
`ScopedStores` vends a single-prefix `read_volume(vol)`. The
per-owner routing key is present at every read site:

- **Volume serve-time demand-fetch (hot path).** The running volume's
  `RemoteFetcher` (`elide-fetch`) holds a **per-owner credential cache**
  (`owner_vol_id` → store), each entry acquired on first fetch from that
  owner through the coordinator's `Credentials` IPC and idle-dropped
  independently; `fetch_extent` selects the store by the `owner_vol_id`
  it already receives.
- **Prefetch index fan-out** (`coordinator::prefetch`). Each fan-out task
  reads only its own fork's prefix via `read_volume(task_vol)`.
- **Filemap generation** (`generate_filemap`, offline
  `import --extents-from`). Its range fetcher reads fragment bodies that
  may live in any ancestor prefix; it routes per fragment through the same
  per-owner store selection.

The `Credentials` IPC and mint's `assume-role` body carry a single
**target** volume, and mint issues a single-prefix credential for that one
named volume.

**Authorization.** Because the request **names** the target owner, the
coordinator authorizes each request at the IPC boundary against
`target ∈ {requester} ∪ lineage(requester)`, re-deriving the requester's
lineage from local provenance, and refuses otherwise. Without this check a
volume could request a read credential for any volume. The lineage walk
lives at this authorization boundary; mint itself only ever issues a
single-prefix credential for one named volume. A volume that demand-pages
across `K` ancestors holds up to `K` cached per-owner credentials, each
acquired on first fetch and amortised over the credential TTL; a volume
reading only its own data holds one.

The scalar `req.*` channel is untouched: roles use `{{req.volume}}`,
so the `req` namespace and the renderer's injection hardening remain.

### Required caveats

Every assume-role credential must carry `sub` (principal), `aud`
(audience), and `exp` (expiry). This set is **hard-coded and identical
for every role** — not a per-role config knob — and is checked for
presence before any role-specific gate, so a credential missing one is
denied before policy rendering. `aud` and `exp` additionally have their
*values* checked (audience equality and the TTL clamp below); `sub` is
presence-gated — its value is MAC-authentic and its holder is proven by
the `cnf`+PoP gate (§ *Authentication*). That MAC-authentic `sub` value
is also exposed to a policy as `{{caveat.sub}}` (`coord-rw`'s
own-identity prefix); honest-but-unverified scoping data a role needs
(the per-volume target) instead rides the PoP-signed body as `req.*`. The
renderer fails closed on any absent field it references, of either class.

### TTL bounds

`min_ttl_seconds` / `max_ttl_seconds` / `default_ttl_seconds` bound the
credential's lifetime. The granted TTL is:

```
granted_ttl = min(
    requested_ttl_or_default,
    max_ttl_seconds,
    macaroon.exp - now  // can't outlive the macaroon
)
```

`min_ttl_seconds` exists to reject silly requests (e.g. `ttl_seconds: 1`).

## Macaroon caveat conventions

The mint is **caveat-vocabulary-agnostic** — it doesn't hard-code which
caveat names are meaningful. Role configs reference whatever caveats they
need by name, and the macaroon issuer is responsible for putting the right
caveats in.

That said, several caveats are **conventional** across uses:

### Standard caveats

Names split by provenance. **Borrowed** caveats reuse a registered
claim verbatim — the abbreviation *is* the standard, so a consumer who
knows JWT knows the semantics with no lookup. **Coined** caveats name a
mint-specific concept with no registered equivalent; they are readable
lowercase words, deliberately *not* in the registered-claim style, so a
reader does not hunt for them in an RFC.

Borrowed (RFC 7519 / RFC 7800):

- **`aud`** (string, scalar; RFC 7519). Names the service the macaroon
  is intended for. Prevents a macaroon scoped for one service (e.g.
  coord-internal IPC) from being replayed at another (e.g. mint). Mint
  config declares its own audience (e.g. `"mint"`) and rejects macaroons
  whose `aud` doesn't match.
- **`exp`** (uint64 unix seconds, scalar; RFC 7519). Standard expiry.
  Multiple `exp` caveats narrow to the minimum — a numeric
  intersection, not a list.
- **`sub`** (string, scalar; RFC 7519). The opaque principal the
  credential is about and bound to. Mint treats it as opaque: it keys
  the pending table on it and the operator approves it. The Elide
  instantiation puts a coordinator ULID here. The gate *checks* it for
  presence; its MAC-verified value is also exposed to a policy as
  `{{caveat.sub}}`, so a coordinator that needs its own ULID in an ARN
  reads it there (`coord-rw`'s own-identity prefix) rather than asserting
  it. Coordinator-self-asserted in enrollment; survives into a credential
  only via the re-mint-from-root after operator approval.
- **`cnf`** (string, scalar; RFC 7800). The holder-of-key the request
  must prove possession of — scalar-encoded (`ed25519:<pub>`), **not**
  the JWT `cnf` JSON object. Every `assume-role` (and enrollment)
  request carries a fresh Ed25519 signature by `coordinator.key` over
  `tail ‖ BLAKE3(body)`, verified against this key. Makes the credential
  key-bound, not a bearer.

Coined (mint-specific; no registered equivalent):

- **`op`** (string, scalar). Names the authority a token carries:
  `enroll`, `enroll-exchange`, or `assume-role`. Mint stamps it at every
  point it mints — the invite (`enroll`), the ticket (`enroll-exchange`),
  and each credential (`assume-role`). Each endpoint **positively
  requires** the value it accepts: `/v1/enroll` ⇒ `enroll`,
  `/v1/enroll-exchange` ⇒ `enroll-exchange`, `/v1/assume-role` and
  `/v1/verify` ⇒ `assume-role` (verify queries the same authority
  assume-role exercises). No endpoint tests for absence. Immutable by
  construction: a coordinator can only append, and a contradictory copy
  is unsatisfiable.
- **`role`** (string, scalar). The single role this credential may
  assume — **always present** on a credential. Mint stamps it into the
  root chain at the enrollment exchange (§ *Enrollment* (3)) — the
  `(sub, role)` authorization point — so it is not coordinator-appendable
  to widen, and a contradictory second copy is unsatisfiable. Mint
  selects the role policy from it and requires the request's asserted
  `req.role` to equal it. There is no role-less ("omnibus")
  credential: a credential carries exactly one role.
- **`invite`** (string, scalar). Carried only by the invite
  macaroon. Mint stores one current random nonce (persisted, same
  custody as the root) and rejects any invite whose `invite` value
  ≠ current. `mint invite --rotate` draws a new nonce; equality only,
  no ordering.

### Namespacing

The standard caveats above (`aud`/`exp`/`sub`/`cnf`/`op`/`role`/
`invite`) are un-namespaced — they are the mint mechanism, common to
every consumer. Consumer-specific caveats are conventionally prefixed to
indicate their issuer or domain, avoiding collisions between issuers.
Caveats are *checked* predicates the role gate clears; a caveat's
MAC-verified value may additionally be substituted into a policy as
`{{caveat.X}}` (§ *Templating*). (`sub` is the principal even for Elide —
there is no `elide:`-prefixed coordinator caveat; the coordinator ULID is
simply the `sub` value, read by a policy as `caveat.sub` when a role
needs it.)

### All caveats are scalar

There are no list-valued caveats. Every caveat is a scalar capability
predicate that attenuates by AND (repeated occurrences must agree;
`exp` narrows to the numeric minimum). No role takes a list-shaped input
either: a `volume-ro` credential scopes to a single volume prefix, and a
reader that needs an ancestor's segments makes a separate lineage-authorized
credential request for that ancestor (§ *Per-volume read credentials*).
This keeps the macaroon library to scalar caveats plus the holder-of-key
extension; no list-valued caveat type, no intersection semantics, no chain
whose effective value depends on occurrence order.

### Partitioning vs. narrowing caveats

Caveats split into two kinds by where their value originates:

- **Partitioning** — `op`, `invite`, `sub`, `cnf`, `role`.
  Identify what the token is for and bind the principal.
  `op`/`invite` are mint-stamped at each mint point; `sub`/`cnf` are
  coordinator-self-asserted inside enrollment and `role` is
  mint-stamped at the enrollment exchange — all three survive into a
  credential only via the re-mint-from-root that follows operator
  approval (see *Credential macaroon & lifecycle*). A caller never alters any of
  them — an appended contradictory copy is unsatisfiable and fails
  closed, never silently dropped.
- **Narrowing** — `exp`. Coordinator-appended, restricting an existing
  grant's expiry for per-credential blast-radius reduction.

Honest-but-unverified scalar scoping data a role names — the per-volume
target `req.volume` — is neither: it is not a capability the macaroon
attests, it is a per-request assertion the caller computes and the PoP
authenticates. It therefore belongs in the signed body, not the caveat
chain — see *Request body*. A coordinator's own ULID is **not** in this
class: it is the MAC-verified `sub` caveat, read by a policy as
`caveat.sub`, so it is unforgeable rather than self-asserted.

### Clearing context: per-macaroon, not a flattened union

**Proposed.** A bundle is a primary plus its discharges. Each is a
distinct macaroon, MAC'd under a distinct key (`K_M` for the primary,
the recovered `r` for a discharge), bound to the others *structurally* —
the discharge's caveat key `r` is recovered from the primary's `VID`, so
the cryptographic binding is the chain, never agreement between two
caveat *values*. A caveat is therefore a restriction on the **one
macaroon it sits on**, cleared in that macaroon's context, and the
verify+clear core must not merge the bundle's caveats into a single flat
set before clearing. (The PoP/`cnf` check already works this way — it is
evaluated against the primary's caveats and tail alone, never the
bundle.) Two kinds of caveat, two clearing rules:

- **Predicate caveats** — `aud`, `op`, `invite`. Answer "is *this*
  macaroon valid for *this* request?" and are cleared against the
  **request context** (the audience, the authority/verb, the current
  nonce). They never need to be compared *to each other* across
  macaroons — they meet only at the shared request value. The discharge
  attests its gate with `op` too (e.g. `op=admin:invite-read`), cleared
  against the dispatched verb exactly as the primary's `op` is — no
  cross-macaroon reconciliation. (`op` is the scalar operation predicate
  on both primary and discharge; `Scope` survives only as the *granted
  set* on a session, a membership shape `op` can't express.)
- **Attestation caveats** — `sub`, `cnf`, and the auth discharge's
  `OrgId`/`ClientId`. Identities a macaroon *carries*, consumed
  downstream, **never cleared against a request value and never merged
  across macaroons**. The primary's `sub` (the cnf-bound coordinator — a
  service identity) and the discharge's `sub` (the authenticated human the
  auth service attests) are two different facts in two different contexts;
  each is read where it belongs and they never collide.

`exp` is the **sole caveat combined across the bundle**: the effective
deadline is the minimum over every macaroon's `exp`, because "valid
until" is the one property that is legitimately monotonic across the
chain (§ *Standard caveats*). Everything else clears per-macaroon.

The downgrade-footgun protection (a repeated caveat with a contradictory
value is *unsatisfiable*, never silently dropped — § *All caveats are
scalar*) is **per-macaroon**: a single chain that contradicts itself
fails closed. Two macaroons bearing the same caveat name with different
values is *not* a contradiction — it is two attestations in two
contexts, which is precisely why `sub` names the coordinator service
identity on the primary and the authenticated human on the discharge
without conflict.

This retires the flattened-union clear; with the discharge cleared in its
own context its principal is simply `sub`, superseding the `Subject`
coinage that existed only to dodge the union collision. It also subsumes
the volume-attestation
`attested.*` fencing question (`design-mint-volume-attestation.md`): a
discharge can no longer inject a control or `caveat.*` name into the
primary's cleared identity, because the two namespaces are never merged —
the attestable set is simply what mint reads from the discharge's own
context.

This is the clearing model in Fly's `macaroon-thought.md` — every caveat
an independent predicate, no agreement or hidden state between them. We
extend it in exactly one place: because mint templates a MAC-verified
caveat value into a policy (`caveat.sub`), clearing must track each
caveat's source macaroon — a step an in-process authorizer that never
reads a caveat as data does not need. (Fly's typed-caveat enum would keep
the two `sub`s from ever being confused by construction; mint stays
string-named for the vocabulary-agnostic property and relies on
per-context clearing instead.)

> **Delta when implemented.** Restructure the verify+clear core
> (`mint/src/http.rs::verify_and_clear`) to clear `aud`/`op`/`exp`
> per-macaroon against the request context rather than `resolve`-ing over
> an `aggregated` union; `ClearedBundle` exposes the primary's and the
> discharges' cleared caveats by source, not one flat list (the role gate
> reads the primary's, the operator gates read the discharge's). Rename
> the auth discharge's `Subject` caveat to `sub` and its `Scope` caveat to
> `op` (`design-auth-service.md`; `mint/src/auth.rs`) — the session keeps
> `Scope` as its granted set — and register `OrgId` / `ClientId` as named
> constants. Retire the `Subject`→`Principal` rename — it is no longer
> needed.

### Caveat field inventory (Elide)

The complete caveat vocabulary the Elide roles draw on. Every caveat is a
**checked predicate** the role gate clears; a caveat's MAC-verified value
may additionally be substituted into a policy as `{{caveat.X}}` (only
`caveat.sub` is, today). A caveat **gates** authorization: the hard-coded
universal set `sub`/`aud`/`exp`, plus the `op`/`invite`/`role` gates.
Honest-but-unverified scoping data a policy template needs (the target
volume) rides the PoP-signed body as `req.*`; the coordinator's own ULID
is the MAC-verified `caveat.sub`, not a body field.

| Caveat | Type | Scalar/List | Issuer | Purpose |
|---|---|---|---|---|
| `aud` | string | scalar | macaroon issuer | Gate only — must equal `mint`. Cross-service replay defense. |
| `op` | string | scalar | mint, at each mint point | Gate only — endpoint partition (`enroll` / `enroll-exchange` / `assume-role`); each endpoint positively requires its value. |
| `invite` | string | scalar | mint, on first start / rotate | Gate only — invite macaroon must carry the current value. |
| `exp` | uint64 (unix s) | scalar | issuer | Gate — caps granted TTL (`min(req, role.max, exp−now)`); multiple narrow to the minimum. |
| `role` | string | scalar | mint, at the enrollment exchange | Gate **and** selects the role policy — the single role this credential carries; always present, and the request's asserted `req.role` must equal it. |
| `sub` | string (opaque; Elide: coord-ulid) | scalar | coordinator-self-asserted in enrollment; survives into a credential only via re-mint-from-root after operator approval | Gate on every role (universally required, presence-only); defines the credential macaroon. Its MAC-verified value is also read by a policy as `caveat.sub` (`coord-rw`'s own-identity statement, `coordinators/{{caveat.sub}}/*`). |
| `cnf` | string (`ed25519:<pub>`, scalar-encoded) | scalar | coordinator-self-asserted alongside `sub` | First-party proof-of-possession — every `assume-role` request must carry a fresh Ed25519 signature by `coordinator.key` over `tail ‖ BLAKE3(body)` (freshness `ts` rides in the body), verified against this key. Makes the credential key-bound (not a bearer) and authenticates the request body. |

The per-volume target is **not** a caveat: it rides the PoP-signed body
as `req.volume`. Scalar `req.*` scoping fields are not in this table —
they are not caveats (§ *Request body*).

Per-role gate matrix (template substitutions are listed in each role's
definition below):

| Role | `aud` | `exp` | `sub` |
|---|---|---|---|
| `volume-rw` | ● | ● | ● |
| `coord-rw` | ● | ● | ● |
| `coord-ro` | ● | ● | ● |
| `volume-ro` | ● | ● | |

The four substitution classes (listed here so the issuer's surface is
unambiguous):

- `{{env.X}}` — server-side config; Elide uses `env.bucket`. Never
  caller-controlled.
- `{{req.X}}` — PoP-verified scalar request body; Elide roles use
  `req.volume` (the per-volume target). Vouched for by `coordinator.key`,
  never validated by mint.
- `{{mint.X}}` — mint-computed at issuance; Elide uses `mint.expiry`.
- `{{caveat.X}}` — MAC-verified caveat value; Elide uses `caveat.sub`
  (a coordinator's own ULID, `coord-rw`'s own-identity prefix). Rooted in
  the mint's macaroon root, not caller-asserted.

Notes:

- **Every caveat is scalar.** The one macaroon-library extension this
  inventory requires is the first-party holder-of-key caveat for
  `cnf` (#16). No list-valued caveat type is needed: no role takes a
  list-shaped input — scalar `req.*` fields ride the PoP-signed body, not
  the caveat chain.
- **`coord-rw`'s own-identity statement uses `caveat.sub`**
  (`coordinators/{{caveat.sub}}/*`, own-prefix write) — the coordinator's
  MAC-verified ULID, sourced from the caveat chain, not the body, so it
  cannot name another coordinator's prefix. Everywhere else `sub` is a
  gate only; the other statements use prefix wildcards (`names/*`,
  `events/*`) and `coord-ro` reads `coordinators/*`.
- **`coord-ro` is the read-only baseline every coordinator holds**, and
  the only credential the LAN/internet-exposed peer-fetch verifier holds.
  Coordinator-wide read of `names/*` / `coordinators/*` / `events/*` /
  `meta/*`, gated by `sub` like the other `coord-*` roles.

## Elide as customer: role inventory

Elide's coordinator authenticates to mint and assumes **four roles**,
scoped by purpose (read vs write) and reach (coordinator-wide vs
per-volume). None carries a third-party caveat: every credential is a
uniform key-bound service token, since operator authority is exercised
at enrollment (§ *Enrollment*), not at `assume-role`.

| Role | Scope | Held by |
|---|---|---|
| `coord-ro` | read-only `names/* coordinators/* events/* meta/*` | every coordinator; the *only* credential the exposed peer-fetch verifier holds |
| `coord-rw` | the coordinator-wide write policy (`names/`, `events/`, own `coordinators/<sub>/`) | all coordinator-wide mutation paths |
| `volume-rw` | per-volume `by_id/<vol>/*` read+write, plus that volume's `meta/<vol>.{provenance,pub}` (**Split B** — per-volume) | per-volume writes (snapshot publish, fork, force-release, drain, GC, reaper) |
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

Mint does no active key deletion (§ *Cleanup*): a key lives until its
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
- **Request body:** `volume` (the target volume ULID, `req.volume`).
- **TTL:** 24h default. Not on the hot write path (cache holds the key for
  the window; WAL absorbs a brief refresh stall), and 24h bounds the
  write/delete revocation window on a single volume.
- **Policy:** `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` on
  `arn:aws:s3:::{{env.bucket}}/by_id/{{req.volume}}/*`,
  plus the volume's two exact `meta/{{req.volume}}.provenance`
  and `meta/{{req.volume}}.pub` objects (the drain uploads
  them; force-release reads `volume.pub`). Single volume only.

GC and the reaper cross volume boundaries (read ancestor/input prefixes,
delete a consumed prefix). GC *input reads* compose by assuming `volume-ro`
for the inputs alongside `volume-rw` for the output volume rather than
widening `volume-rw`'s policy. (Reaper delete of a volume's own prefix is
covered by `volume-rw` on that volume.)

### `coord-rw`

Coordinator-wide write authority: name claim / rename / force-release
/ rollback (`names/`), event-journal appends and reads (`events/`),
and this coordinator's own identity records
(`coordinators/<sub>/`). One role, one credential, one keypair cache.
The IAM-layer invariants ride the policy *template*, not key
partitioning:

- **Required caveats:** `sub`, `aud=mint`, `exp`
- **Caveat substitution:** `caveat.sub` (this coordinator's MAC-verified
  ULID, for the own-prefix statement).
- **TTL:** 1h. Control-plane, infrequent, refreshed on demand; the
  tightest coordinator TTL since it is the broadest write capability.
- **Policy:** a multi-statement document, each statement preserving
  the invariant its prefix carries:
  - `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` on
    `arn:aws:s3:::{{env.bucket}}/names/*`.
  - `s3:GetObject`/`s3:PutObject` (**no** `s3:DeleteObject`) on
    `arn:aws:s3:::{{env.bucket}}/events/*`. **`events/` append-only**
    is enforced here — no statement, in any role, grants delete on
    `events/`.
  - `s3:GetObject`/`s3:PutObject` (**no** `s3:DeleteObject`) on
    `arn:aws:s3:::{{env.bucket}}/coordinators/{{caveat.sub}}/*`
    — own-prefix only, the coordinator's MAC-verified ULID from the caveat
    chain. **`coordinators/` immutability** is enforced here; a leaked key
    can rewrite only *this* coordinator's identity, never impersonate
    another, and never delete.

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
prefix, each authorized by lineage (§ *Per-volume read credentials*):

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
- **Request body:** `volume` (the target volume ULID, `req.volume`).
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
  exact ARN for the target volume (`by_id/{{req.volume}}/*`).

### Why Split B is viable now

`design-iam-key-model.md` § *Per-volume scoping for writes (rejected)*
rejected per-volume writer keys on two grounds. The mint redesign changes
one of them:

- *Confused-deputy enforcement is "modest"* — unchanged. The per-volume
  target is honest-but-unverified `req.volume` scoping data; per-volume
  IAM remains a redundant belt over the name-claim lineage.
- *Operational cost* (N persisted policies, `ListPolicies` reconciliation,
  orphan reaping, refresh churn) — **dissolved**. Mint keys are short-lived,
  vended on demand, never persisted, expired by `DateLessThan`. No
  reconciliation, no orphans.

Per-volume **attribution** is obtained for free regardless of Split B —
every `AssumeRole` already logs the request body's `volume` (§ *Audit log*).
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
      "arn:aws:s3:::{{env.bucket}}/names/*",
      "arn:aws:s3:::{{env.bucket}}/coordinators/*",
      "arn:aws:s3:::{{env.bucket}}/events/*",
      "arn:aws:s3:::{{env.bucket}}/meta/*"
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
conditional `names/<name>` read, coincident with the `release --force`
S3 CAS) and the requester-pubkey check (`coordinators/<B>/
coordinator.pub`), and verifies lineage against the serving peer's
**own local** signed `volume.provenance` chain — see
`design-peer-segment-fetch.md` § *Peer verification* check 4.

The `ephemeral-fetch` key class from the prior model collapses into
`volume-ro` with a shorter TTL request. Operationally distinguishable via
audit log; same role config.

## Operational

### Deployment

The mint is a single static binary with one HTTPS listener and an outbound
Tigris IAM client. Reasonable hardware: small (single-core CPU, minimal
memory). Throughput-bounded by Tigris IAM API rate limits, not by mint
itself.

Standard production deployment: behind a TLS-terminating reverse proxy or
serving TLS directly, with the admin credential delivered into the
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment via systemd
`LoadCredential=` or equivalent secrets-management.

### Transport

The transport is a property of the deployment shape, not a global
default. The three shapes in *Admin credential custody* are all
network-remote — the self-hosted canonical case puts mint on a
separate trusted machine, and central custodial/proxy are off-host by
construction — so for them TCP behind TLS is the only correct
transport, and the macaroon + PoP auth is load-bearing precisely
because the link is untrusted. There is a fourth shape the bundled
single-host dev / kick-the-tyres setup, coordinator and mint
co-resident on one box, matching the `coord run` / `coord start`
flavours in `docs/design-deployment-modes.md` — for which a Unix
domain socket is the better transport:

- no port allocation and no accidental network exposure;
- no TLS to stand up for a same-host hop;
- filesystem-permission scoped, with the socket's lifecycle and
  inspectability tied to a path under `data_dir`, consistent with the
  coordinator's existing UDS IPC (`control.sock`, `log.sock`: clean
  stale dentry → bind → chmod `0o666`);
- the auth model is unchanged — the macaroon + Ed25519 PoP still
  applies over a UDS; UDS neither weakens it nor substitutes for it.

mint supports two listener transports, selected per deployment shape
rather than replacing one with the other, via two mutually-exclusive
top-level config keys:

- **TCP** (`bind = <host:port>`) — the network shapes; TLS terminated
  ahead of or by mint. The production transport, and the default: when
  neither key is set the listener is TCP `127.0.0.1:8085`. `mint serve
  --bind <host:port>` overrides the config and forces TCP (the
  single-host TCP override).
- **UDS** (`socket = <path>`) — the single-host dev shape. Mutually
  exclusive with `bind`; selecting the socket is the deliberate act
  that makes a mint instance local-only. The path follows the same
  resolution rule as `data_dir` / `roles_dir` (relative resolved
  against cwd, absolute verbatim); an empty value (`socket = ""`)
  selects UDS at the default `<data_dir>/mint.sock`. The socket is
  recreated on bind (stale dentry removed first), chmod `0o666` so a
  non-root coordinator can connect. The reference client targets it
  with `--socket <path>` (UDS-only, same-host); the macaroon and PoP
  are identical to the TCP leg coordinators use — the transport seam is
  the only thing that differs.

The server accepts a `tokio::net::UnixListener` directly through
`axum::serve` (axum 0.8). The client UDS leg is the one place mint
drops below `reqwest` — which has no UDS support — to `hyper` dialed
through `hyperlocal`'s `UnixConnector`; the TCP leg stays on
`reqwest`. mint is its own workspace, so the axum 0.8 dependency is
contained to it.

#### Proposed: dual-listen (UDS + TCP simultaneously)

The mutual-exclusion of `bind` and `socket` couples two unrelated
concerns: which transport coordinators (clients) reach mint over, and
which transport an operator runs admin commands over. They are
unrelated because admin and public traffic have different audiences
(human operator on the mint host vs remote coordinator), different
frequencies (one approval per coordinator vs every assume-role), and
different transport constraints (admin is local-only by construction;
public traffic crosses hosts). Both use the same `MintV1` bundle
shape for authority (§ *Operator authorization*); UDS filesystem
permission gates which processes may reach the admin routes at all,
not what authority those processes may exercise once connected.

Today, picking TCP for coordinators forfeits a working admin path
(no UDS) and picking UDS for admin forfeits remote coordinators (no
TCP). Every realistic deployment wants both:

| Deployment | Coordinators reach mint via | Operator admin via |
|---|---|---|
| Single-host bundled (`coord run`) | UDS (co-resident) | UDS |
| Self-hosted multi-host | TCP (off-host) | UDS (local SSH) |
| Central-custodial (Elide-managed) | TCP (off-host) | UDS (Elide SSH) |
| Forward-looking k8s / web console | TCP | future authenticated TCP |

**Proposed:** drop the mutual-exclusion check on `bind` and `socket`;
when both are set, `serve` binds both listeners under a
`tokio::join!`. The router is split:

- **UDS listener** mounts the public routes
  (`/v1/assume-role`, `/v1/enroll`, `/v1/enroll-exchange`) *and* the
  operator routes (`/v1/admin/…` — see *Mint state in the store
  bucket* / *Operator endpoints*). Filesystem permission on the socket
  gates *transport*; the `MintV1` bundle (admin service token +
  auth-service discharge + PoP, § *Operator authorization*) gates
  *authority* on the admin routes, exactly as the same bundle shape
  gates `/v1/assume-role` on either listener.
- **TCP listener** mounts the public routes *only*. Admin routes are
  structurally unreachable on this listener — not "returned 404",
  not "401" — they are not registered in the router the TCP socket
  serves. This is the property the current admin-on-UDS design
  relies on; preserving it is non-negotiable.

The "TCP-only, no admin" shape becomes "no `socket` → no admin";
`mint invite` / `mint enroll …` against such a config fails with a
clear message ("admin requires `socket` in `mint.toml`"). The
operator's choice is to add `socket` (and SSH or be on-host to use
it) or stand up the still-future authenticated-TCP-admin transport.

**What this is not.** A TCP admin surface. The bundle shape exists
(§ *Operator authorization*), but the admin service token is
distributed by local-filesystem read of `<data_dir>/admin-service`; a
cross-host operator would need a separate distribution path for the
token, and that reintroduces all the network-credential concerns the
local-only model collapses. A future TCP admin transport is therefore
**additive** when it lands (a third optional listener with its own
router) and does not require revisiting the dual-listen decision here.

**Cost.** One config-validation rule drops; one `serve` branch
replaces a `match` with `tokio::join!`; the existing UDS-side router
construction is reused unchanged. No new config keys; no protocol
change; no client change (coords already pick `unix:` vs `http(s)://`
via the `[mint] url` scheme, which can now legitimately be either
even when both listeners exist on the server side).

### Coordinator configuration

**Proposed.** The coordinator reaches mint through one new
`coordinator.toml` section:

```toml
# enable mint
[mint]
url = "unix:mint/mint_data/mint.sock"   # or "https://mint.host:8085"
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
enrollment (§ *Enrollment*), not by config; and `aud=mint` is fixed
inside the macaroon. Only the endpoint — and optionally
`connect_timeout` / `request_timeout` (humantime, mirroring
`[store]`) — is configurable.

The coordinator credential plane has exactly two states: `[mint]`
present (per-volume scoping via the role inventory below), or absent
(the shared-key downgrade — local-store / no-IAM, every volume gets
the coordinator's own key). There is no in-process per-volume IAM
path: an optional path for the credential plane would mean the
per-volume scoping property does not actually hold.

### Coordinator store architecture

**Proposed.** The role inventory (§ *Elide as customer*) defines the
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
prefixes), so a name-claim/force-release CAS (`GET` ETag → conditional
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

### Reference client & demo

The full flow is exercisable end-to-end from the `mint` binary alone —
no `elide-*` dependency. The same binary carries the server, the
operator subcommands, and a **reference client** that plays the
coordinator's half generically (it also doubles as the conformance
harness `tests/enroll.rs` exercises).

Operator / server (every `<cfg>` defaults to `MINT_CONFIG` then
`./mint.toml` when `--config` is omitted):

```
mint serve <cfg> [bind]            # HTTP service
mint login [--url <u>|--config <c>] [--subject <s>]  # auth session for the admin plane AND `mint client` (gates discharge issuance); remembers the transport
mint logout                        # remove the session (keeps the remembered auth transport)
mint invite [--rotate]             # print current invite macaroon / rotate the nonce
mint enroll list                   # sub, state (pending|enrolled), cnf fingerprint,
                                   #   peer ip (pending only), age / approved_at
mint enroll approve <sub>          # approve a pending record
mint enroll revoke <sub>           # revoke a coordinator: kill its credentials, drop to slow path
mint role list                     # configured roles: name, TTL bounds
mint role inspect <name>           # one role: bounds, policy source, raw template + ref surface
```

Reference client (the ed25519 keypair is minted lazily on first use and
persisted as `client.key`/`client.pub`; `<id>` is the opaque `sub`). The
client is UDS-only, same-host: `enroll`/`exchange`/`assume-role` dial the
local daemon at `--socket <path>`, else the `MINT_CONFIG` listener
socket, else `<data_dir>/mint.sock`:

```
# Log in once with the shared top-level `mint login` (above); enroll and
# exchange use that session to discharge the invite + exchange gates.
mint client enroll       <sub> <macaroon>               # attaches the enrolling-operator discharge → credential ticket
mint client exchange     <role>                          # ticket + exchanging-operator discharge; 403 until approved → credentials/<role>
mint client credential list                              # held per-role credentials (local-only)
mint client credential inspect <role>                    # narrate one credential's caveat chain
mint client assume-role  --request '{"prefix":"x"}' <role>   # role from the credential → Tigris keypair
                                                             #   (no discharge: credentials carry no TPC)
```

A worked `examples/` script chains them: `serve` (background) →
`mint login` → `client enroll` → operator `enroll approve` → `client
exchange <role>` (once per role) → `client assume-role`, printing the
returned Tigris keypair.

**Operator auth.** The operator commands (`invite`, `enroll
list/approve`) hit discharge-gated admin endpoints
(§ *Operator authorization*). `mint serve` writes the **admin-service** and
its machine key (`<data_dir>/admin-service` + `admin-service.key`, mode 0600)
whenever either is absent; the operator runs `mint login` once to obtain a session,
and each command then fetches a discharge for the admin-service's
third-party caveat and presents `[admin-service, discharge]` + a PoP. There
is no bearer admin macaroon. `serve` also auto-seals the templates on a
genuine first start
(see [`design-mint-template-seal.md`](design-mint-template-seal.md)),
so the demo needs no explicit `mint seal` step.

**Backend.** `serve --tigris` selects the real Tigris IAM minter — a
self-contained AWS IAM Query-API client (`CreateAccessKey` →
`CreatePolicy` → `AttachUserPolicy`, SigV4-signed against
`https://iam.storage.dev`, overridable via `MINT_IAM_ENDPOINT`), ported
into `mint/` rather than shared with `elide-tigris-iam` so the crate
keeps zero `elide-*` deps. It hard-errors at startup without a Tigris
admin credential in the `AWS_*` environment, so a misconfiguration
fails fast rather than at the first request. Without `--tigris`,
`serve` wires the deterministic fake minter (no account needed).
Consequence for CI: the `invite` / `enroll` / `enroll-exchange` legs
and the fake-minter `assume-role` are hermetic and run anywhere; the
real-Tigris `assume-role` end-to-end is VM-only.

**Demo role config** is a minimal `read` / `write` pair over a single
`{{req.prefix}}` (shipped as `examples/mint-demo.toml`) — distinct from
the full Elide role inventory below. Both are plain key-bound roles;
neither credential carries a TPC. The operator-authorisation loop is
exercised at **enrollment**, not at `assume-role`: the config colocates
the demo auth role (`[auth] demo_enabled`), so `client enroll` discharges
the invite's TPC (the enroll gate) and `client exchange` discharges the
ticket's TPC (the exchange gate), each fetching a discharge from the auth
socket and presenting the bundle. `assume-role` against either role then
needs no discharge. This is the mint CLI proving the consumption side
before any `elide-*` client.

### Audit log

Every `AssumeRole` call produces an audit entry. Minimal field set:

- `timestamp`
- `request_id` (uuid, surfaced to caller in `X-Request-Id`)
- `caller_address` (IP, for forensics)
- `macaroon_nonce` (per-token nonce from the macaroon)
- `macaroon_caveats` (sanitised — names + values, never secrets)
- `role`
- `granted_ttl_seconds`
- `outcome` (`granted` / `denied:<reason>` / `tigris_error:<code>`)
- `tigris_access_key_id` (if granted)

Audit log is local (file-based) in v1. Shipping to external sinks is an
operational concern, not a mint concern.

### Failure modes

- **Tigris IAM rate limit hit.** Mint returns `503` with `Retry-After`.
  Callers retry with backoff. Mint may internally smooth bursts via a token
  bucket if rate-limit pain emerges.
- **Tigris admin credential rejected.** Mint returns `503` and logs loudly;
  manual operator intervention required to refresh the admin credential.
- **Macaroon-root rotation.** TBD — see *Open questions* #3 / #14.

### Cleanup

Tigris keypairs minted by the mint have `DateLessThan` policies, so they
expire automatically. Mint does **not** track issued keypairs to delete them
explicitly — that would require holding per-keypair state and trying to call
`DeleteAccessKey` on expiry, which is failure-prone and doesn't improve
security (the policy expiry already enforces the bound).

For operational visibility, the audit log records every issuance; operators
can correlate Tigris-side access key activity with mint audit entries.

## Open questions

These are genuinely unsettled — flagging them rather than committing
prematurely.

1. **Project name.** "mint" is the working name; not committed. Candidates:
   `tigris-mint`, `macaroon-iam-broker`, a fresh name. Decision needed before
   the project moves to its own repo.
2. **Multi-tenancy shape.** v1 is single-tenant-per-instance. Whether v2
   should support multi-tenant per instance (each tenant with its own trust
   root, admin credential, role set) or stay single-tenant with per-tenant
   deployments is open. Multi-tenant per instance is more useful for
   centralised offerings; single-tenant is structurally simpler.
3. **Macaroon-root rotation.** A single static mint-held root fits v1,
   but rotation needs a story: rotating it invalidates every
   outstanding macaroon (mint is the issuer, so a re-issue sweep is
   possible but not free). Options: dual-key acceptance during an
   overlap window, a re-issue-on-rotate flow. Tied to #14. Probably
   defer to v2.
4. **Peer-fetch scope — settled.** There is no dedicated peer-fetch
   role; the verifier uses `coord-ro` (read-only `names/*` /
   `coordinators/*` / `events/*`). Lineage is verified by the serving
   peer against its own *local* signed `volume.provenance`, not via S3.
   The force-release fence is gap-free via the per-request ETag-
   conditional `names/<name>` read (fence coincident with the S3 CAS).
5. **Mid-path wildcard verification.** Not on the v1 critical path:
   `volume-rw` uses a single-volume *trailing* wildcard
   (`by_id/{{req.volume}}/*`), `volume-ro` uses the same
   single-volume trailing wildcard, and `coord-ro` touches no `by_id/` at
   all — none need mid-path `*`. It is only a constraint on a future role wanting
   `by_id/*/<something>` shape. Empirical test still worth running once,
   but does not block the current inventory.
6. **Caveat library schema — resolved.** No list-valued caveat is
   needed. No role takes a list-shaped input: a `volume-ro` credential
   scopes to a single volume prefix, and ancestor reads use separate
   lineage-authorized per-ancestor credentials. All caveats are scalar;
   the only macaroon-library
   extension over `design-auth-model.md`'s scalar caveats is the
   holder-of-key caveat (#16). This also removes the occurrence-order
   /effective-vs-last hazard a list caveat would carry.
7. **HTTP API surface beyond `AssumeRole`.** Likely additions: `ListRoles`
   (caller discovers what's available), `GetRole` (caller introspects role
   requirements), health endpoint. None blocking for v1; design once
   real callers ask.
8. **Caller-side credential refresh.** Should mint return a refresh token,
   or should callers just re-call `AssumeRole` on expiry? STS does the
   latter; same answer probably right here. Worth being explicit.
9. **Tigris IAM rate-limit headroom — gates Split B.** This is no longer a
   "defer unless workload demands" item: per-volume `volume-rw` (Split B)
   makes `AssumeRole` volume scale with active volumes — roughly one mint
   round-trip per active volume per TTL window per coordinator, each one a
   Tigris `CreatePolicy`+`CreateAccessKey`+`AttachUserPolicy` sequence.
   Tigris publishes no IAM rate limit. The 24h `volume-rw` TTL is the
   primary knob (longer → fewer mints, larger leaked-key window); mint-side
   per-root rate limiting / burst smoothing may also be needed. Measuring
   Tigris IAM headroom at realistic volume counts is the gate before Split B
   is committed to implementation.
10. **What lives in the mint vs in the closed-source web console.** The
    mint is the credential plane. The web console handles user identity
    (SSO), org/tenant management, key custody UX, audit visualisation, and
    multi-coordinator dashboarding. The exact API boundary between them
    (does the console talk to mint over the same `/v1/assume-role`, or via
    a privileged management interface?) is TBD.
11. **GC / reaper cross-volume composition under per-volume `volume-rw`.**
    `volume-rw` is scoped to a single volume's `by_id/<vol>/*`. GC reads
    input/ancestor prefixes that belong to *other* volumes and the reaper
    deletes a fully-consumed volume's prefix. The sketched answer (GC input
    reads via a separately-assumed `volume-ro`; the output write and the
    reaper's own-prefix delete via `volume-rw` on the target volume) is
    stated in the role inventory but not fully specified — the exact set of
    roles a GC pass assumes, and whether the reaper's delete wants its own
    narrower role, is open.
12. **Eliminate the `ListBucket` statement — done.** Plan in
    `docs/list-elimination-plan.md` (P1–P5), shipped across PRs
    #395–#399 (docs) and #400–#403 (impl). Every coordinator-runtime
    LIST is now a deterministic GET: name-axis ordering via
    `events/<name>/HEAD` (bounded window of the last N signed
    records, `prev_event_ulid` chain backing); per-vol stable
    snapshot via `by_id/<vol>/snapshots/LATEST`; post-snapshot
    delta via `by_id/<vol>/HEAD`
    (`docs/design-segment-index.md`); per-vol handoff via the
    CAS'd `names/<name>` record, not a snapshot LIST. The
    standalone reaper task is gone — reap is a tick-folded step
    inside the per-volume orchestrator, consuming HEAD's
    `Superseded` edges. `coord-rw`'s `ListBucket` statement
    is removed from its role template and from the inventory
    above; `volume-rw` never had it. The bucket-global
    enumeration hole closes entirely. Orphan reclamation (the
    one remaining LIST need) is an explicit operator-privileged
    maintenance pass, deliberately outside the runtime surface
    (`docs/list-elimination-plan.md` § *Reconcile/repair without
    LIST*).
13. **Enrollment surface — settled.** See § *Enrollment*: **three
    operator gates, each a third-party caveat on a carried macaroon**. A
    reusable non-expiring invite carries the *enroll* TPC → the
    enrolling operator discharges it and the coordinator self-asserts
    `sub`/`cnf` at `POST /v1/enroll`, which records a pending record
    (`requested_by`) and returns a short-lived **ticket** carrying its
    own *ticket* TPC → the approving operator approves a displayed pubkey
    fingerprint via the admin plane, recording `_mint/clients/enrolled/<sub>`
    (`approved_by`) → the exchanging operator discharges the ticket's
    TPC and the coordinator presents `[ticket, discharge]` + PoP at `POST
    /v1/enroll-exchange {ts, role}`, which re-mints a single-role
    credential from root with **no third-party caveat**. Three operator
    decisions are captured (enroll + approve + exchange, none required
    to differ); after that a credential is a long-lived service token and
    `assume-role` is operator-free. Role authorization gates `(sub,
    role)` at exchange — floor is "role is in the mint config" (per-`sub`
    scoping lives in role policy templating on `sub`), upgrade is a
    per-`sub` permitted-role set recorded on the enrolled entry at
    approval time. `invite` is the rotation knob; `op` partitions the
    three macaroon-bearing endpoints.
    *Open within this question:* the exact wire shape of that recorded
    permitted-role set is unsettled — a flat allowlist on the enrolled
    record is the leading candidate.
14. **Root-key durability and rotation.** *Resolved:* mint persists a
    `(kid, key)` keyring at `<data_dir>/root_keys/` (one 64-hex file
    per generation, mode 0600, plus a `current` pointer). Rotation
    is the retain-keychain + lazy-migration shape described in
    *Root-key rotation*: add generations additively, drain approvals
    forward on natural coordinator restarts, retire individual kids
    when ready. Losing `data_dir` still invalidates every outstanding
    macaroon — recovery is re-invite + re-enroll. Whether `data_dir`
    warrants backup/replication is a separate operational call from
    rotation and remains open.
15. **Third-party-caveat construction.** The operator gates are
    third-party caveats (mint shares a symmetric key per discharge
    authority; the caveat carries a verification key encrypted to that
    authority; the holder presents discharge macaroons).
    `design-auth-model.md` documents only scalar first-party caveats
    today; the third-party construction and its discharge-bundle wire
    format on the invite at `/v1/enroll` (enroll gate), the ticket at
    `/v1/enroll-exchange` (exchange gate), and the admin service token
    (admin plane) need specifying. The anchor split is settled: the
    minimal self-hosted deployment is anchored by operator approval of a
    displayed fingerprint (§ *Enrollment*); the third-party caveats on
    the invite and the ticket are the enrolling- and exchanging-operator
    gates layered on top. *Resolved:* per-coordinator de-authorization is
    the revoke mechanism (§ *Revocation*) — `mint enroll revoke <sub>`
    deletes the enrolled record (so the coordinator can mint nothing new
    until re-approved), and the `epoch` carried on each credential keeps
    already-issued credentials dead through any later re-approval. Bounded
    by the keypair TTL. Re-attestation of a live coordinator (e.g. a
    managed customer who left) is that revoke, then a deliberate approve.
16. **PoP caveat wire detail.** `cnf` is decided (first-party
    holder-of-key; credential is key-bound, not a bearer; the signed
    payload is `BLAKE3(presented-macaroon-tail ‖ BLAKE3(request-body))`
    so the proof also authenticates the body — see *Credential macaroon
    & lifecycle*, *Authentication*). The body hash is over the **exact
    raw bytes received**, hashed before parsing — no JSON
    canonicalization (a canonicalization mismatch is a signature-bypass
    footgun). Freshness is a **±skew window** on a `ts` field carried
    *in the body* (not a header — it is already covered by the body
    hash, so no separate signed term and one fewer header); stateless,
    no mint-issued nonce (DPoP's `iat`-skew anchor; prior art: RFC 7800
    `cnf` PoP key, RFC 9449 DPoP). Tail-binding pins the proof to the
    exact macaroon, body-hash binding to the exact request, the in-body
    `ts` + skew window bounds replay. The signature stays a header
    (`X-Mint-Pop`) — it cannot live in the body it signs; folding
    it in as a structural envelope would reintroduce a framing/
    canonicalization boundary. What remains is only the encoding
    (working draft: `X-Mint-Pop` base64 Ed25519 signature, body
    `ts` unix seconds, skew bound) — an implementation detail, not a
    design fork.

## Future directions

These do not affect v1 but are anticipated extensions worth designing
around:

- **Third-party caveats.** No longer purely a future direction — they
  are the mechanism for delegation to an identity authority under the
  issuer-and-verifier model (*Trust model*; *Open questions* #15). The
  mint's verification path handles discharge bundles; the chained-MAC
  construction accommodates them with no change beyond accepting
  discharge macaroons in the request. What remains future is the
  concrete construction and wire format, tracked as #15.
- **Backend-agnostic roles.** The role config language doesn't assume Tigris
  specifically — it's IAM-policy-template-shaped. Other backends (native
  AWS, S3-compatibles with IAM) could be plugged in by swapping the
  Tigris-IAM-API client for an equivalent. Worth deciding before v1 whether
  to design the role config explicitly backend-agnostic or to keep it
  Tigris-specific and refactor later.
- **Federation across mint instances.** Multi-root trust support enables
  federation: one mint trusts macaroons issued by another's authority.
  Allows mint instances to chain (e.g. a regional mint trusting a global
  identity mint).
- **Replacing template rendering with request-time variables.** If Tigris
  ever ships request-time variable resolution (`${session.X}` in policies),
  the mint could store policies once with variables and resolve at request
  time rather than rendering per issuance. The role config schema would
  not need to change; only the renderer.
- **List-roles authorisation discovery.** Beyond a flat `ListRoles`,
  callers may want "which roles can this specific macaroon assume." The
  macaroon's caveats determine eligibility; computing the answer requires
  checking the universal `sub`/`aud`/`exp` set plus the caveats each role's
  template references. Cheap to compute, useful for UX in the web console.

## References

- [`design-auth-model.md`](design-auth-model.md) — macaroon construction
  shared with this design.
- [`design-iam-key-model.md`](design-iam-key-model.md) — Elide's IAM key
  inventory and policy-scoping rationale. Under this design the
  monolithic writer is kept (its invariants enforced in mint's policy
  template, not by per-purpose key partitioning) and split per-volume
  for `by_id/` (Split B); the per-purpose split is unnecessary with
  mint as the policy-rendering broker.
- AWS STS docs: [`AssumeRoleWithWebIdentity`][assume-role-web-identity],
  [session tags][session-tags] — the closest AWS analogue for the
  identity-token-to-scoped-credential flow.
- Tigris IAM docs:
  [policy support](https://www.tigrisdata.com/docs/iam/policies/),
  [supported actions](https://www.tigrisdata.com/docs/iam/policies/supported-actions/).

[assume-role-web-identity]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
[session-tags]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
