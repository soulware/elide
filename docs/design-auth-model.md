# Auth model: operator tokens, isolation

This doc captures the coordinator's destructive-verb auth surface in one
place: how human operators authenticate the CLI's destructive verbs, what
the coordinator's audit log records, and what the scheme does and does not
enforce given the same-host trust model.

The underlying macaroon construction — chained keyed-BLAKE3 MAC, per-token
struct-level nonce, AND-of-predicates caveat evaluation — is shared with
volume macaroons and is documented in
[`architecture.md`](architecture.md#proposed-s3-credential-distribution-via-macaroons).
This doc layers the operator-token-specific surface on top of that
foundation:

- **Volume macaroons** — minted on `register`, PID-bound, scope-bound. Used
  by volume processes to request short-lived read-only S3 credentials.
  Implemented. Construction and registration flow live in `architecture.md`.
- **Operator tokens** — minted on `elide token create` (IPC), not
  PID-bound, attenuated per use by the CLI to the narrowest volume/expiry
  needed. Today they gate a single proof-of-concept verb. The settled
  direction — operator tokens authorise the coordinator's *S3 write*
  credential acquisition, not a hand-enumerated verb list — is in
  *Proposed: operator tokens gate S3 writes, not verbs* below.
- **Isolation model** — the surrounding context that explains what either
  scheme can enforce on a shared-uid host.

## Operator tokens

Operator tokens are coordinator-wide macaroons issued to human operators.
The gating mechanism below is a **proof of concept**: it currently wires
exactly one verb, `remove`. `remove` is a poor exemplar — it deletes only
the local cache directory and is fully reversible by re-pulling from S3,
so it neither loses data nor demonstrates the property the token is meant
to enforce. The PoC should move to `claim` / `release`, which actually
mutate shared S3 state (the `names/<name>` ownership record). The settled
direction supersedes per-verb gating entirely — see *Proposed: operator
tokens gate S3 writes, not verbs* below.

### Issuance

```
elide token create [--expires 30d]
```

This is an IPC verb (`Request::MintOperatorToken`) against `control.sock`.
The coordinator mints with its in-memory root key and returns the encoded
macaroon plus the per-token nonce (hex) and expiry; the CLI prints the
token to stdout, upserts it into `~/.elide/tokens.toml`, and logs the
nonce/expiry plus the file path to stderr.

`~/.elide/tokens.toml` is a per-user file (mode 0600 under `$HOME`) with
one entry per coordinator, keyed by that coordinator's canonical
data_dir:

```toml
[[coordinator]]
data-dir = "/srv/elide-a"
operator-token = "MDAxMG..."

[[coordinator]]
data-dir = "/home/op/elide_data"
operator-token = "MDAxNm..."
```

Keeping the trust boundary per-user while keying by data_dir lets
several coordinators run on one host without sharing a token. `token
create` rewrites only the addressed coordinator's entry; the others
survive the upsert. Gated verbs resolve the token in precedence order:
`--token`, then `ELIDE_OPERATOR_TOKEN`, then the entry whose `data-dir`
matches the canonical data_dir the CLI used to reach the socket.

`elide token list` prints one row per entry — data_dir, token nonce,
and expiry — decoding the stored macaroon for the nonce and narrowest
`NotAfter` without contacting any coordinator. `elide token remove
<nonce>` deletes a single entry, selected by the nonce from that
listing rather than by path, so a stale entry can be cleaned up after
its coordinator's data_dir is gone.

The mint endpoint is ungated beyond socket reachability. The trust floor
for "can mint an operator token" is "can reach the coordinator's unix
socket," which is the same floor as "can perform every other coordinator
operation." There is no separate gate to add here without moving the trust
boundary, and that move requires off-host transport, which is out of scope.

`--expires` defaults to 30 days. The default is configurable down for
tests; there is no indefinite-lifetime option.

### Caveats

The minted root token carries:

| Caveat | Value | Purpose |
|---|---|---|
| `Role` | `Operator` | Distinguishes from volume tokens |
| `NotAfter` | mint + `--expires` | Required; bounded lifetime |

It does **not** carry a `Volume` or `Op` caveat — the root token is
coordinator-wide and verb-agnostic. Volume and op scoping happen per use,
via attenuation.

Each minted token also carries a per-token 16-byte random struct-level
nonce (generated inside `mint`; not a caveat). The nonce is mixed into the
MAC seed so two tokens minted with identical caveats still have distinct
MACs and gives each token a stable hex identifier for audit logging — see
*Audit log* below.

### CLI-side attenuation per use

Each destructive CLI verb appends caveats before sending the token to the
coordinator. Attenuation narrows by three axes: operation, volume, expiry.

```
stored:     Role=Operator, NotAfter=<+30d>           (nonce on the struct)
on the wire (elide volume remove myvm):
            Role=Operator, NotAfter=<+30d>,
            Op=Remove, Volume=myvm, NotAfter=<now+60s>
```

The attenuation is performed entirely in the CLI — no coordinator
round-trip — by calling `Macaroon::attenuate` three times against the
stored token's trailing MAC. AND-of-predicates evaluation in the verifier
means appending a *looser* `NotAfter` cannot widen authority; the original
30-day bound is still in the chain and still checked.

The wire token is therefore single-operation, single-volume,
very-short-lived, and useless to anyone who intercepts it after the fact.
The persistent stored token never leaves the operator's machine in
narrowed form.

### Typed operation surface

The `Op` caveat is typed, not a free string. The coordinator-side enum
enumerates every gated verb:

```rust
pub enum OperatorOp {
    Remove,
    // PoC only. Do not add variants — the per-verb model is
    // superseded; see *Proposed: operator tokens gate S3 writes,
    // not verbs*. The one pre-mint change is moving the PoC hook
    // to `claim` / `release`.
}
```

The dispatcher hands the verifier the `OperatorOp` it is about to execute
(`verify_operator(..., OperatorOp::Remove, target_volume)`). The verifier
requires the chain to carry the matching `Op` caveat. Unknown op-bytes on
the wire → `OperatorReject::Malformed` (fail closed).

Two consequences worth calling out:

- **Exhaustiveness.** Adding a new gated verb is "add an enum variant and
  a dispatch arm." A new verb cannot accidentally inherit authority from
  an existing operator token, because operator tokens are minted as
  `Op = ∅` and only the CLI's attenuation step adds the op caveat for the
  specific verb being invoked.
- **The op caveat must match the entry-point IPC verb,** not any
  sub-operation a handler dispatches internally. Today every gated verb
  is a single dispatch and this is moot, but if a future verb fans out
  into authenticated sub-calls, the design choice is either to
  re-attenuate per sub-call (more macaroon-like) or to document that the
  entry-point caveat is what matters.

### Verifier shape

Operator tokens have no `Pid` or `Scope`, so they don't fit the volume
`VerifyCtx` from `architecture.md`. The macaroon module exposes a
parallel verifier:

```rust
pub struct VerifyOperatorCtx<'a> {
    pub now_unix: u64,
    pub op: OperatorOp,
    pub op_volume: &'a str,
}

pub fn check_operator_caveats(
    m: &Macaroon,
    ctx: &VerifyOperatorCtx<'_>,
) -> Result<(), OperatorReject> { /* AND-of-predicates over Role / Op / Volume / NotAfter */ }
```

Top-level `verify_operator` is `parse` → `verify` (MAC, shared with volume
macaroons) → `check_operator_caveats`. Rejection reasons (`Malformed`,
`BadMac`, `WrongRole`, `Expired`, `WrongOp`, `VolumeMismatch`,
`MissingVolume`, `MissingOp`) are exposed as a typed `OperatorReject` enum
so callers can log without leaking variant-level detail to the wire — the
IPC `Err` body is the coarse string `"operator token rejected (..)"`.

### Audit log

The coordinator logs every operator-token event under
`target = "operator_token::authn"`:

- `event = "mint"` — on `Request::MintOperatorToken`. Fields:
  `nonce` (the struct-level hex), `expires_unix`.
- `event = "verify"` — on a successful gated verb. Fields:
  `op` (`OperatorOp::as_str`), `volume`, `nonce`.
- `event = "reject"` — on any rejection. Fields: `op`, `volume`,
  `reason` (`OperatorReject` variant).

The `nonce` field uses the same name as the volume-macaroon
`creds::issuance` log target — one audit-id concept across both token
kinds, so a single grep correlates mint → use without bookkeeping the two
schemes separately.

Rejection reasons are intentionally coarse on the wire — finer detail
would help an attacker probe token state — but the full
`OperatorReject` variant is logged locally for operator debugging.

## Isolation model

Volume processes on the same host share a uid and a filesystem. This has
direct consequences for what the macaroon scheme can and cannot enforce.

**What macaroons do not enforce — local filesystem.** A compromised volume
process can read or corrupt any other volume's local directory directly,
without touching the coordinator. Macaroons provide no protection here.
Proper local isolation requires OS-level mechanisms: separate uids per
volume, Linux user namespaces, or running each volume in its own
container. This is a separate layer and is not addressed by the current
design.

**What macaroons do enforce — S3.** S3 credentials are scoped by IAM to a
specific volume's prefix. This enforcement is external to Elide — AWS (or
equivalent) rejects requests that exceed the credential's scope regardless
of what the caller claims. The macaroon scheme ensures a volume process
can only obtain credentials for its own volume. A compromised `myvm`
process cannot request credentials for `othervm`, so it cannot read,
write, or delete `othervm`'s S3 objects even with full local filesystem
access.

**What operator tokens provide — audit + ceremony, not access control.**
Requiring an operator token for coordinator mutations raises the bar
slightly over bare socket access, and provides an audit trail. It does
not prevent a compromised local process from achieving the same effect
via direct filesystem manipulation (`rm -rf` on the volume dir achieves
`remove` without going through the coordinator). The value is
auditability, forced ceremony for destructive verbs, and per-request
attenuation — not a hard security boundary against a local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Coordinator mutations | Operator token + audit log | Coordinator (defense-in-depth) |

## Proposed: operator tokens gate S3 writes, not verbs

**Status: proposed. Not yet implemented. The section above describes the
current PoC; this section describes the settled direction and the one
binding question that the [`mint`](design-mint.md) cutover must answer.**

### The principle

The original intent of operator tokens was never "gate destructive
verbs." It was: **any operation that mutates S3 state must be
authorised.** `remove` was a proof-of-concept hook, not the model. Three
framings were considered and rejected as the organising axis:

- *Destructive verbs* — `remove`'s default form is a reversible local
  cache drop; the destructive/reversible line does not fall on verb
  boundaries.
- *`--force` flags* — narrows the gate to irreversibility escape
  hatches, but says nothing about the routine S3 writes that are the
  actual point.
- *Ownership ops only* — closer (`claim` / `release` do write shared S3
  state), which is why they are the right *PoC*, but still an
  enumeration, not the principle.

The principle is read-vs-write **against S3**: read paths are an
unauthorised baseline; every S3 mutation requires operator
authorisation.

### Why this cannot be expressed today, and becomes structural under mint

Today the coordinator is *both* the macaroon issuer and the holder of
IAM admin that writes S3. Enforcing "every S3 mutation is authorised"
in that architecture means intercepting every code path that touches the
bucket (breadcrumb writes, snapshot uploads, `names/` flips, IAM
teardown) and bolting a token check onto each — a leaky enumeration and
exactly the "optional path for a correctness property" this project
rejects. There is no chokepoint, which is why `remove` could only ever
be a PoC.

`mint` (see [`design-mint.md`](design-mint.md)) creates the chokepoint.
Once mint is split out, the coordinator cannot write S3 with ambient
admin creds: to mutate it must call `mint /v1/assume-role` with a
macaroon and obtain a write-capable keypair (`volume-rw`, `coord-names`,
the Split-A writer roles). Reads need only `coord-ro`, the read-only
baseline every coordinator already holds. "Every S3 mutation is
authorised" then holds *architecturally* — enforced by IAM at the single
point write credentials are acquired — rather than by scattered
in-coordinator checks.

### Issuer and the human-authorisation point

The mint cutover settles the issuer: mint is the sole issuer and
verifier, with a single root that never leaves it (`design-mint.md` §
*Trust model*). Human authorisation does not enter by *which authority
issues* — it enters as a **third-party-caveat discharge**: the
coordinator holds a primary macaroon; a write window additionally
requires a discharge from an identity authority (the managed `elide
operator login` service) attesting a human authorised it. The concrete
shape of that auth service is in *Proposed: central auth service
issues operator sessions* below.

### Until then

Do not extend `OperatorOp` with more verbs — wiring additional verbs
into the PoC entrenches the per-verb model the mint cutover dissolves.
The only PoC change worth making before mint is moving the hook from
`remove` (misleading: local-cache-only) to `claim` / `release` (genuine
shared-S3-state mutations).

## Proposed: central auth service issues operator sessions

**Status: proposed. Not yet implemented. Builds on *operator tokens gate
S3 writes, not verbs* above by replacing the local operator-token
issuer with a central auth service and a third-party-caveat discharge
flow.**

### Principle

The PoC mints operator tokens locally on the coordinator and trusts
"can reach the unix socket" as the identity floor. The settled
direction removes that local-mint surface entirely:

- The **central auth service** is the sole issuer of operator session
  macaroons and per-op discharges.
- The **coordinator** becomes a verifier only — it holds the auth
  service's verification key but cannot mint operator tokens.
- The **`~/.elide/tokens.toml`** file and `Request::MintOperatorToken`
  IPC verb both go away.

Every operator IPC verb requires a valid session **and** a fresh
discharge. Volume↔coord IPC (PID-bound volume macaroons) is unchanged
— the new gate is on operator IPC only.

### Tenancy and enrollment

The auth service is multi-tenant; coordinators and operators belong
to organisations. **Org-scoping is the primary isolation boundary**
and is enforced by construction (mandatory `OrgId` caveat), not by
ACL.

- **Auth service is global** — one logical service across all orgs.
  Self-hosted deployments may run their own instance; the protocol
  shape is identical.
- **Mint is per-org** — one mint instance (or HA replicas of one
  logical mint) per organisation. Mint is the org's identity hub
  inside the protocol.
- **Coords belong to a mint** — a coord is enrolled to exactly one
  mint and therefore to exactly one org.
- **Operators may belong to multiple orgs** — sessions are always
  scoped to one org. A session for org X carries `OrgId=X` and
  verifies only at coords enrolled to org X.

Two enrollment flows, with mint as the org-identity broker. There is
no direct coord ↔ auth-service relationship; the auth service holds
no per-coord state.

**Mint ↔ auth service** — slow cadence, once per org lifetime plus
occasional rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, NotAfter=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint generates its keypair, POSTs `<auth>/v1/mint/enroll` with
   the token.
5. Auth service verifies the token, records org X as activated,
   returns the verification pubkey to mint.
6. Mint persists its OrgId + auth-service URL + verification pubkey.

The auth service does not retain mint's pubkey — mint never signs
artefacts the auth service verifies. The enrollment is effectively
one-way: mint learns from the auth service.

**Coord ↔ mint** — per-coord deployment cadence. Extends the existing
coord-mint enrollment with auth-service distribution.

1. Mint admin generates a one-shot coord-enrollment token signed by
   mint's own key: `OrgId=X, Purpose=CoordEnroll, NotAfter=now+15m`.
2. Coord admin runs `elide-coordinator setup --enrollment-token
   <token>`.
3. Coord generates its keypair, POSTs to mint with the token + its
   pubkey.
4. Mint verifies the token, records `(coord-ulid, pubkey)` under
   org X, returns to coord:
   - `OrgId=X` binding
   - Auth-service URL
   - Auth-service verification pubkey
   - Coord's S3 cred-issuance privileges (existing mint surface)
5. Coord persists all of the above in its `data_dir`.

After enrollment the coord verifies sessions locally using the pinned
pubkey and accepts only those carrying `OrgId=X`. There is no
ongoing coord ↔ auth-service relationship for verification.

**Auth-service key rotation.** The pinned auth-service pubkey is a
liveness concern. Resolution is pull-on-verify-fail: when a coord's
MAC check fails on an otherwise well-formed session, the coord asks
its mint for the current auth-service pubkey, refreshes its pin if
mint reports a new key, and retries. Mint keeps its own pin fresh
via its existing auth-service relationship; coord lazily catches up.
The auth service is responsible for overlapping rotation windows
long enough that pull-on-fail is bounded by one MAC retry per
in-flight session at most.

### Login flow

`elide operator login` supports two modes. The CLI selects mode by
whether `ELIDE_OPERATOR_API_KEY` is set; both end at the same
artefact (a session macaroon stored once, per-user, replacing
`~/.elide/tokens.toml`), so coord and mint cannot tell which mode
produced a given session.

The stored session is org-scoped (mandatory `OrgId` caveat) and
covers every coordinator within that org that trusts the same auth
service. Operators in multiple orgs need separate sessions per org.

**Interactive (device-code).** The day-to-day human flow. The CLI
runs entirely server-side and the operator's browser runs on their
local laptop; SSH is the expected calling context, not an edge case.

1. CLI POSTs `<auth>/v1/login/start` → device code + verification URL.
2. CLI prints the URL and code to the terminal and begins polling
   `<auth>/v1/login/poll`.
3. The operator opens the URL on their **local** browser (the laptop
   they SSH'd from, not the server), enters the code, completes
   authentication, and — for multi-org operators — picks an org from
   the auth service's UI mid-flow. The auth service mints the session
   bound to the selected org.
4. `/v1/login/poll` returns the session macaroon; CLI stores it.

`elide operator login --org <name>` is an explicit override for
scriptable cases. For single-org operators the auth service may skip
the picker and issue directly.

No X11 forwarding, no port forwarding, no remote browser launch. This
matches the `gh auth login` / `gcloud auth login` / `aws sso login`
convention.

**Non-interactive (API key).** For CI, automation, headless tooling.

1. Operator obtains a long-lived API key from the auth service (out
   of band; the auth service owns issuance, rotation, revocation).
2. Caller sets `ELIDE_OPERATOR_API_KEY=<key>` and runs `elide
   operator login`.
3. CLI POSTs `<auth>/v1/login/api-key` with the key, receives a
   session macaroon, stores it.

The key is read from the environment, never accepted on argv (would
appear in `ps`). The auth service typically issues shorter-lived
sessions for API-key logins than for interactive ones, and may add a
`MachineAccount=true` caveat to discharges so audit can distinguish
automated from human actions — both are auth-service-side policy,
not CLI surface.

### Reachability

The auth service must be reachable from two places:

- **The server** (coord + mint) — for verification-key fetch at
  startup and discharge verification per request.
- **The operator's laptop browser** — for the interactive flow only.

In a hosted deployment this is one public URL. In self-hosted prod
the same URL has to be reachable from operator workstations (usually
via the same VPN the operators use to SSH in). Non-interactive
deployments need only the first reachability path.

### Session and discharge macaroons

The auth-service-issued chain uses **Ed25519 signatures**, not the
keyed-BLAKE3 MAC used by volume macaroons in `architecture.md`. The
asymmetric scheme is required by the topology: one issuer (auth
service), many verifiers (every coord, every mint). A shared MAC key
would let any verifier forge sessions, which is a non-starter. The
chained-caveat structure (per-token nonce, AND-of-predicates
evaluation) is otherwise identical. Volume macaroons remain on the
keyed-BLAKE3 construction since coord is both issuer and verifier
there.

Two macaroon classes:

- **Session macaroon** — issued by the auth service on login. Carries
  `OrgId`, `Role=Operator`, `Subject=<sub>`, `NotAfter=<session_expiry>`,
  plus a third-party caveat with `location = <auth>`. Verifying it
  requires a discharge.
- **Per-op discharge** — short-lived, op- and volume-scoped. The CLI
  obtains one per IPC call (or per short window) by presenting the
  session to `<auth>/v1/discharge` with the narrowing it needs
  (`Op=Claim, Volume=myvm, NotAfter=now+60s`). The discharge inherits
  the session's `OrgId`.

Replacing the PoC's CLI-side `Macaroon::attenuate` with an auth-service
round-trip is the audit point: the discharge issuer is the only thing
that can produce a narrowing, so the auth log on the auth service
records every operator action centrally.

### Identity and policy

The session carries three identity claims:

- **OrgId is mandatory and enforced.** Set by the auth service from
  the org selected at login. Coord and mint reject any session or
  discharge whose `OrgId` doesn't match their enrolled OrgId. This
  is the protocol's primary multi-tenant isolation boundary — see
  *Tenancy and enrollment* above.
- **Subject is mandatory and opaque.** A stable identifier (UUID,
  OIDC `sub`, opaque token) chosen by the auth service. Not a
  username or email — those change. The auth service is responsible
  for keeping `Subject` stable for a given human across renames and
  IdP changes.
- **User is optional and audit-only.** An optional discharge caveat
  carrying a human-readable display name. Coord logs both. `Subject`
  is the policy key; `User` is the display string.

Beyond OrgId enforcement, coord performs no subject-keyed policy in
the initial design. All access control — allow-listing, RBAC,
per-volume ACLs — lives at the auth service. Coord verifies caveats
on the discharge and logs the Subject; the auth service decided what
caveats to mint by consulting whatever policy it implements.

This pushes policy where macaroons assume it lives: at the issuer,
not the verifier. The verifier stays mechanical — caveats are the
contract.

For self-hosted / single-tenant deployments the auth service's
policy can be minimal ("any enrolled user can do anything"). For
managed / hosted deployments the auth service grows whatever RBAC
machinery the product needs, encoded into discharge caveats. Either
shape works without coord changes.

Adding new policy caveats later — `Roles`, `Tenant`, etc — is a
wire-format change (unknown caveat variants fail closed in the
verifier), so it ships with a coord update. Acceptable for a
tightly-versioned system; not free, so additional caveats are added
only when needed, not pre-reserved on speculation.

Coord log shape:

```
INFO operator_token::authn event=verify op=Release volume=myvm
  org=org_7vh3... subject=usr_2k9q... user=alice@example.com
```

### Cadence

The two macaroon classes have different lifetimes and refresh rhythms.

**Sessions: ~7 days, refreshed only by re-running `elide operator
login`.** Default lifetime is auth-service policy. There is no sliding
renewal — when the session expires, the next IPC call fails with a
clear error and the operator runs `login` again. Non-interactive
(API-key) sessions are typically shorter (e.g. 1 hour); the API key is
the long-lived credential and the session is its derived form.

**Discharges: ~60s, fetched per operator IPC verb in the initial
design.** Each call narrows to (`Op`, `Volume`) for that specific
verb. The auth service issues mechanically — no per-op re-prompt to
the human; session validity is the human-interaction gate. Step-up,
approval, and risk-tiered re-prompt are future extensions that compose
cleanly on the macaroon construction (extra caveats like
`MaxSessionAge=300s`, or third-party caveats to a separate verifier)
but are out of scope here.

**Discharge lifetime vs op duration.** A 60s discharge can expire
mid-op for long-running verbs (`snapshot`, `gc`). This is fine: the
discharge is checked at the entry-point IPC verb only, matching the
"op caveat must match the entry-point" rule from *Typed operation
surface* above. Once coord has dispatched and (for writes) mint has
issued a write-capable cred, the cred's own short lifetime bounds the
in-flight work.

**Replay window.** Within its 60s NotAfter a discharge is theoretically
replayable. The initial design does not add nonce-caching at coord:

- Most operator IPC verbs are idempotent at the coord layer.
- The audit signal is preserved — every reuse leaves a coord-side
  verify entry, divergent from the auth-service issuance count.
- If a specific verb turns out to be non-idempotent and
  replay-sensitive, the discharge can carry a per-request nonce caveat
  as a per-verb addition.

### Audit anchors

The design produces two correlated audit streams:

- **Auth service log** — every discharge issued (subject, op, volume,
  expiry).
- **Coordinator log** — every operator IPC verified (op, volume,
  subject).

Normally one-to-one. Divergences are forensic signal:

| Auth log | Coord log | Meaning |
|---|---|---|
| present | present | Normal |
| present | absent | Discharge issued but never used — cancelled CLI, network drop |
| present | duplicate | Replay within window — investigate |
| absent | present | Should be impossible — auth-service signing key compromise, or coord pubkey pin wrong |

The "should be impossible" row is the security-relevant one. If it
ever fires, the auth service's signing key has leaked or coord is
pinned to the wrong verification key.

### Verification: two enforcement points, one auth service

- **Coordinator** verifies session + discharge on every operator IPC
  verb. Uses the auth-service verification key it received from mint
  at enrollment, pinned in its persistent state and refreshed lazily
  on MAC failure (see *Tenancy and enrollment* above). Checks the
  session's `OrgId` matches the coord's enrolled OrgId. No round-trip
  to the auth service on verify.
- **Mint** verifies a discharge on every `assume-role` call that
  issues write-capable creds (`volume-rw`, `coord-names`, Split-A
  writers). Reads (`coord-ro`) remain unauthenticated. Same `OrgId`
  check: the discharge must match mint's own enrolled OrgId. This is
  the architectural chokepoint from *operator tokens gate S3 writes,
  not verbs* above; the third-party-caveat anchor sits on the primary
  macaroon mint requires for write windows.

Both verifiers trust the **same** auth service. Removing one
enforcement point doesn't silently lose the other.

### API surface

Concrete HTTP endpoints. All requests and responses JSON; all
endpoints versioned under `/v1/`.

**Auth service — operator-facing.**

`POST /v1/login/start` (anonymous) — initiate device-code flow.
Request:

```json
{ "client_id": "elide-cli", "client_version": "1.2.3" }
```

Response 200, modelled on RFC 8628:

```json
{
  "device_code": "<opaque>",
  "user_code": "ABCD-WXYZ",
  "verification_uri": "https://auth.elide.example/device",
  "verification_uri_complete": "...?user_code=ABCD-WXYZ",
  "expires_in": 600,
  "interval": 5
}
```

`POST /v1/login/poll` (anonymous; `device_code` is the proof) — poll
for completion. Request:

```json
{ "device_code": "<opaque>" }
```

Response 200 (complete):

```json
{ "session": "<macaroon>", "expires_at": "...", "org_id": "org_..." }
```

Response 400 with body `{ "error": "authorization_pending" | "slow_down" |
"expired_token" | "access_denied" }` (RFC 8628 vocabulary).

`POST /v1/login/api-key` (Bearer API key in `Authorization` header) —
non-interactive session exchange. Response shape matches
`/login/poll` success. 401 invalid, 403 disabled.

`POST /v1/discharge` (Bearer session) — issue per-op discharge.
Request:

```json
{ "op": "Release", "volume": "myvm", "ttl_seconds": 60 }
```

Response 200:

```json
{ "discharge": "<macaroon>", "expires_at": "..." }
```

401 session expired, 403 policy denies, 422 unknown op.

**Auth service — public.**

`GET /.well-known/elide-auth-keys` (anonymous) — JWKS-equivalent.
Current and recently-rotated verification pubkeys. Mint polls this
and relays current key to enrolled coords.

```json
{
  "keys": [
    {
      "kid": "kp_2026q2",
      "alg": "EdDSA",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url>",
      "expires_at": "..."
    },
    { "kid": "kp_2026q1", "...": "...", "deprecated": true }
  ]
}
```

**Auth service — mint-facing.**

`POST /v1/mint/enroll` (anonymous; enrollment token is the proof) —
one-shot mint enrollment. Request:

```json
{ "enrollment_token": "<opaque>" }
```

Response 200:

```json
{
  "org_id": "org_7vh3...",
  "auth_service_pubkey": { "kid": "...", "alg": "EdDSA", "x": "..." }
}
```

400 invalid / expired / already-used token. Mint does not transmit
its own pubkey — the auth service never verifies anything mint signs.

**Mint — coord-facing.**

`POST /v1/coord/enroll` (anonymous; mint-signed token is the proof) —
one-shot coord enrollment. Request:

```json
{ "enrollment_token": "<mint-signed opaque>", "coord_pubkey": "<base64>" }
```

Response 200:

```json
{
  "coord_ulid": "01HXY...",
  "org_id": "org_7vh3...",
  "auth_service_url": "https://auth.elide.example/",
  "auth_service_pubkey": { "kid": "...", "alg": "EdDSA", "x": "..." }
}
```

Mint persists `(coord_ulid, coord_pubkey)` for its existing
cred-issuance auth path. Coord persists the full response in its
`data_dir`.

`GET /v1/auth/pubkey` (coord-authenticated via the cred-issuance
path) — current auth-service pubkey. Used by coord on
pull-on-verify-fail (see *Tenancy and enrollment*).

```json
{ "auth_service_pubkey": { "kid": "...", "alg": "EdDSA", "x": "..." } }
```

Mint's existing cred-issuance endpoints (`assume-role` and friends)
are unchanged in shape but now additionally verify the supplied
discharge against mint's enrolled OrgId.

### Config

Coord and mint hold different config surfaces because the auth-service
binding reaches coord transitively through mint.

`coordinator.toml` points at mint for enrollment; it carries no
auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint, OrgId, auth-service URL, and verification pubkey all land in
the coord's `data_dir` at `elide-coordinator setup` time and are
not human-edited thereafter.

Mint's config carries the `[auth]` block pointing at the auth
service:

```toml
[auth]
endpoint = "https://auth.elide.example/"
```

Mint persists its OrgId and the auth-service verification pubkey to
its own state at `elide-mint setup --enrollment-token` time. The
verification pubkey is refreshed via auth-service rotation
notifications; mint relays the current value to coords on demand
(see *Tenancy and enrollment* above).

### Mint as auth (demo only)

For dev, test, and demo deployments, mint can mount the auth route
handlers itself:

```toml
# mint config
[auth]
demo-enabled = false   # default
```

When `true`, mint serves `/v1/login/*` and `/v1/discharge` alongside
its cred-issuance routes, rubber-stamping every request — no browser,
no real authentication. Mint's `[auth] endpoint` points at itself,
and coord enrollment hands coords mint's own pubkey as the
"auth-service" verification key, so the coord codepath is identical
to prod. Enrollment tokens are also rubber-stamped: a coord can
enroll with any token (or none) and is assigned `OrgId=demo`.

Two startup-time safety checks when `demo-enabled = true`:

- Mint refuses to start unless bound to loopback / UDS. Removes the
  "I turned it on for a test and forgot" foot-gun.
- Mint logs `WARN auth=demo: all operator sessions are unauthenticated`
  at startup and per issued session.

Both are config-time checks, not per-request branches — the verifier
in coord and mint stays unconditional. The mint binary has no
webauthn / OIDC / SAML code; production auth implementations live in
the separate auth service binary only.

The canonical test-fixture pattern is **demo mint + non-interactive
login**: a single mint process with `demo-enabled = true` bound to a
UDS, plus `ELIDE_OPERATOR_API_KEY=test` on the harness. The full wire
flow (login → discharge → IPC verify → mint discharge verify) runs
end-to-end with no browser and no `#[cfg(test)]` shortcuts anywhere
in coord, mint, or the macaroon verifier. Demo mint logs `WARN
auth=demo: api-key login (key prefix=…)` with the key truncated to
~8 chars so accidental real-key submissions to a dev mint are
visible.

### Deployment shapes

| Deployment | Auth packaging | Auth backend |
|---|---|---|
| Dev / test / demo | mint serves auth routes (`demo-enabled = true`) | rubber-stamp, instant session |
| Single-tenant self-hosted prod | separate auth service binary | real (webauthn / OIDC / …) |
| Multi-tenant hosted | separate auth service binary | real, full SSO |

Mint-as-auth is fine as long as there is **one identity authority**
(single mint or HA replicas of one logical mint with a shared key).
With multiple distinct mints — sharded by tenant / region — one would
have to be nominated as the auth-primary, which is effectively a
separate logical auth service in shared packaging. At that point
splitting the binaries is cleaner.

### Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange, so
requiring the auth service reachable adds no new failure mode. There
is no offline escape hatch for operator login. The deployment story
is "online or not running."

### Wide discharges (deferred)

The initial design fetches one discharge per operator IPC verb. A
"wide" discharge — a single discharge covering multiple ops or a
longer window (e.g. `Op=Any, Volume=myvm, NotAfter=now+5m`) — is left
open as a possible later extension if real workloads make per-call
round-trips a bottleneck.

Tradeoffs to weigh before adopting:

- **Audit fidelity.** One discharge issuance currently corresponds to
  one intended action. A wide discharge breaks the 1:1; the auth
  service's log moves from "every op" to "every issuance window," and
  per-action attribution rests entirely on the coordinator log.
- **Leak exposure.** A wide discharge that escapes confers more
  authority for longer than the 60s narrow form.
- **Issuance shape.** The macaroon construction and verifier paths need
  no change — only the auth service's issuance policy and the CLI's
  caching layer. The natural CLI surface is an opt-in flag enabling
  the wider window for a fixed duration, with narrow per-call as the
  default.

### Per-coord scoping within an org (deferred)

Sessions cover every coord within the operator's org. Per-coord
scoping — a `CoordId` caveat narrowing a session to specific coords
within the same org — is left open as a possible later extension for
operators who admin many coords in one org and want per-coord
blast-radius limits. The macaroon construction accommodates it
cleanly (one more caveat variant, verifier check against the coord's
own ULID); the auth service would need a per-coord policy surface.
Out of scope for the initial design.

### Migration from PoC

Clean break. The change that lands the central auth service removes:

- `~/.elide/tokens.toml`
- `Request::MintOperatorToken` IPC verb
- The `OperatorOp` / `verify_operator` PoC plumbing
- Coord-side root-key state used to mint operator tokens

No compatibility shim. Operators with existing PoC tokens must run
`elide operator login` against the new auth service. Coords stood up
under the PoC must be re-enrolled via `elide-coordinator setup
--enrollment-token` after their org has been activated (mint
enrollment). Cleanup of stale on-disk state is manual; no migration
tooling ships.

## Open questions (legacy PoC)

These apply to the PoC operator-token surface above; the *central auth
service* proposal supersedes them.

- **Bootstrap.** First-ever `elide token create` against a fresh
  coordinator has no offline escape hatch (there is no
  `elide-coordinator token create` subcommand under this design). If the
  coordinator socket is unreachable, there is no way to mint. Likely fine
  — destructive verbs are coordinator-mediated anyway — but worth noting.
- **Token rotation UX.** No `revoke` command. A leaked token is mitigated
  by its `NotAfter` and by re-keying the root (which invalidates all
  tokens, including volume macaroons). Whether root rotation needs a
  dedicated verb or can stay manual is open.

## Future directions

These do not affect the design above; they describe extensions that slot
in cleanly when the threat model or deployment shape warrants them.
- **Root key in a separate signing process.** Today the coordinator
  holds the root key in memory. Splitting it into a standalone signing
  service reduces blast radius (coordinator compromise can no longer
  forge across the fleet), gives mint operations an independent audit
  boundary, and enables TPM/HSM backing. Verify is hot — every
  operator-token IPC and every volume `credentials` request — so the
  likely shape is per-coordinator derived keys (signing service issues
  an HKDF-derived sub-key the coordinator uses to verify locally) rather
  than RPC-on-verify. Mint is rare enough to comfortably stay RPC. Worth
  doing when there is more than one coordinator host, or when the
  coordinator's trust level is bounded below the key's.
