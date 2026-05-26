# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
session credentials and per-op discharges. It builds on the principle
established in
[`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-s3-writes-not-verbs)
— **every S3 mutation requires operator authorisation** — and is the
concrete shape of the *third-party-caveat discharge* anchor mint
requires for write-capable cred issuance.

**Status: proposed. Not yet implemented.**

## Principle

The design rests on one structural property: **the auth service's
round-trip is non-bypassable by the math, not enforced by coord's
code paths**. Every primary macaroon carries a third-party caveat
that requires an auth-service discharge; that caveat is woven into
the primary's HMAC chain, so no party who cannot mint primaries can
strip it. A compromised coord can verify, dispatch, and even
attenuate, but cannot produce traffic that mint or coord would accept
without a live auth-service-signed discharge.

To make that property hold, three things are true:

- **Mint is the sole holder of macaroon-MAC capability for the
  operator-authorisation chain.** Mint's root key never leaves it.
  Coord holds cached macaroons (verification anchors), not MAC keys.
  (Volume macaroons are a separate surface — coord-issued, because
  coord is the trust source for the claim they attest. See
  [`design-auth-model.md`](design-auth-model.md#two-surfaces-two-trust-sources).)
- **Coord is a cached verifier on the operator-authorisation chain.**
  At enrollment coord receives a primary macaroon mint issued for
  it. Coord stores it and never sees mint's root or any derived MAC
  key. Operator IPC bundles verify by walking the cached primary's
  chain forward into CLI-added attenuations — no MAC root key is
  needed for that direction.
- **The auth service is an asymmetric signer.** Discharges are
  Ed25519-signed assertions over discharge predicates. Coord and mint
  hold the auth service's public key; only the auth service can mint
  discharges. Symmetric forgery of discharges is structurally
  impossible.

Volume↔coord IPC (PID-bound volume macaroons) is unchanged — the new
gate is on operator IPC only. Operator IPC verbs are currently
ungated; this design re-gates them.

## Tenancy and enrollment

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
occasional pubkey rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, NotAfter=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint POSTs `<auth>/v1/mint/enroll` with the token.
5. Auth service verifies the token, records org X as activated,
   returns `(OrgId, K_auth_pub, key_id)`.
6. Mint persists `(OrgId, auth-service URL, K_auth_pub, key_id)`.

The shared state between mint and the auth service is just the
auth-service public key — public information, pin-rotated. No
symmetric secrets cross the org boundary.

**Coord ↔ mint** — per-coord deployment cadence.

1. Mint admin generates a one-shot coord-enrollment token signed by
   mint: `OrgId=X, Purpose=CoordEnroll, NotAfter=now+15m`.
2. Coord admin runs `elide-coordinator setup --enrollment-token
   <token>`.
3. Coord POSTs to mint with the token.
4. Mint verifies the token, allocates `coord_ulid`, derives an
   ephemeral chain key `K_M.derive(coord_ulid)`, and mints a
   **primary macaroon** for this coord:
   - First-party caveats: `CoordId=<coord_ulid>, OrgId=X`
   - Third-party caveat: `(location=<auth-url>, caveat_id)` where
     `caveat_id` is an opaque routing blob containing
     `(CoordId, OrgId, key_id)` — see *Macaroons in this design*
   - Chain MAC'd with the ephemeral chain key, which mint discards
5. Mint returns `(coord_ulid, primary, OrgId, auth-service URL,
   K_auth_pub, key_id)`.
6. Coord persists all of the above in its `data_dir`.

After enrollment coord verifies operator IPC bundles entirely
locally. Mint stays stateless across coords — it can re-derive the
chain key from `K_M + coord_ulid` whenever it needs to re-verify a
presented primary.

## Keys and what each party holds

| Party | Holds | Can mint primary? | Can mint discharge? |
|---|---|---|---|
| Mint | `K_M` (root MAC key) | yes | no |
| Auth service | `K_auth_priv`, `K_session` | no | yes |
| Coord | cached primary, `K_auth_pub` | no | no |

`K_M` never leaves mint. `K_auth_priv` never leaves the auth service.
Coord holds only cached macaroons (the primary) and public keys (the
auth-service pubkey). No symmetric key is shared across party
boundaries.

## Macaroons in this design

Three artefacts.

**1. Primary macaroon.** Mint-issued, coord-held. One per coord,
minted at coord enrollment. Same chained-keyed-BLAKE3 construction
as volume macaroons.

- First-party caveats: `CoordId=<coord_ulid>, OrgId=<org>`
- Third-party caveat: `(location=<auth-url>, caveat_id)`
  - `caveat_id` is an opaque blob carrying `(CoordId, OrgId,
    key_id)`; not secret, not encrypted under any key — it is
    routing/binding metadata the auth service reads to know what
    discharge to mint
- Chain MAC'd with `K_M.derive(coord_ulid)`, an ephemeral key mint
  computes on demand and never persists

Coord stores the macaroon bytes and treats them as its verification
anchor — never sees the chain key.

**2. Session credential.** Auth-service-issued, CLI-held. One per
operator login, ~7 day lifetime. Used only between CLI and auth
service — coord and mint never see it.

Structurally a macaroon MAC'd under `K_session` (auth-service-only
root). Carries `(Subject, OrgId, NotAfter)`. The auth service holds
both ends so the symmetric construction is natural.

**3. Per-op discharge.** Auth-service-signed, ~60s lifetime. One per
operator IPC verb, bound to a specific target coord.

```
discharge = (predicate, signature)
predicate = (CoordId, OrgId, Subject, Op, Volume, NotAfter, key_id)
signature = Ed25519_sign(K_auth_priv, predicate)
```

The discharge is a signed assertion, not a macaroon. `CoordId` and
`OrgId` in the predicate bind the discharge to one specific coord's
primary — replaying a discharge issued for coord-A against coord-B
fails the binding check. `key_id` identifies which auth-service
pubkey signed, supporting rotation.

The CLI obtains a per-op discharge by presenting its session
credential and the target coord's `caveat_id` to `<auth>/v1/discharge`.
The auth service verifies the session, applies policy, signs the
discharge under `K_auth_priv`, returns it.

## Verification

**Coord on every operator IPC verb:**

1. Extract the primary from the bundle. Confirm its prefix (caveats
   + tag) matches coord's cached primary byte-for-byte; if the CLI
   added attenuations, walk them forward from the cached final tag
   (standard HMAC chain extension — no root key needed) and verify
   the final tag.
2. Read the TPC's `caveat_id` from the primary.
3. Verify `Ed25519_verify(K_auth_pub[key_id], signature, predicate)`
   on the presented discharge.
4. Cross-check `CoordId` and `OrgId` in the predicate against the
   primary's first-party caveats. Cross-check `CoordId` against
   coord's own ULID, `OrgId` against coord's enrolled OrgId.
5. Check `Op` matches the dispatched verb, `Volume` matches the
   target, `NotAfter` is in the future.
6. If all pass, dispatch. If any fail, reject.

**Mint on every `/v1/assume-role` call:**

Same checks. Re-derives the chain key from `K_M + CoordId` to verify
the primary's chain, then verifies the discharge with `K_auth_pub`.
Mint does not trust coord's check — it re-runs verification from
scratch. Defense in depth: a compromised coord can still make
`/v1/assume-role` calls, but cannot bypass mint's check.

### Why this composition holds the principle

The TPC is a first-party caveat in the primary, so its presence
contributes to the chain tag. Stripping it would require either
recomputing the chain (needs the MAC root — mint only) or producing
a different macaroon with a different identifier (which the auth
service has no commitment to discharge). So **every accepted bundle
must include a real auth-service discharge for the operator's
identity** — not because coord chooses to enforce it, but because no
shorter bundle has a valid chain tag.

Each coord's primary is structurally independent. A discharge signed
for coord-A's primary names `CoordId=A` in its predicate; presenting
that discharge against coord-B's primary fails the cross-check at
step 4. Compromise of any single coord cannot produce traffic that
verifies against any other coord.

## Caller authentication is separate

Mint's bundle verification proves the *operator* authorised this
specific op. It does not prove the *caller* is a legitimate coord.
Coord-to-mint caller authentication uses mint's existing
cred-issuance auth path (the volume-macaroon-keyed mechanism mint
already has — unchanged by this design). Both are required for mint
to issue write-capable creds: caller-auth proves it's a real coord,
the bundle proves a human authorised the op.

## Login flow

`elide operator login` supports two modes. The CLI selects mode by
whether `ELIDE_OPERATOR_API_KEY` is set; both end at the same
artefact — a session credential stored once, per-user, in a file
under `~/.elide/`. The session is org-scoped (mandatory `OrgId`
caveat) and covers every coordinator within that org. Operators in
multiple orgs need separate sessions per org.

**Interactive (device-code).** The day-to-day human flow. The CLI
runs entirely server-side and the operator's browser runs on their
local laptop; SSH is the expected calling context, not an edge case.

1. CLI POSTs `<auth>/v1/login/start` → device code + verification URL.
2. CLI prints the URL and code to the terminal and begins polling
   `<auth>/v1/login/poll`.
3. The operator opens the URL on their **local** browser (the laptop
   they SSH'd from), enters the code, completes authentication, and
   — for multi-org operators — picks an org from the auth service's
   UI mid-flow. The auth service mints the session bound to the
   selected org.
4. `/v1/login/poll` returns the session credential; CLI stores it.

`elide operator login --org <name>` is an explicit override for
scriptable cases. For single-org operators the auth service may skip
the picker and issue directly. No X11 forwarding, no port forwarding,
no remote browser launch. Same convention as `gh auth login` /
`gcloud auth login` / `aws sso login`.

**Non-interactive (API key).** For CI, automation, headless tooling.

1. Operator obtains a long-lived API key from the auth service (out
   of band; the auth service owns issuance, rotation, revocation).
2. Caller sets `ELIDE_OPERATOR_API_KEY=<key>` and runs `elide
   operator login`.
3. CLI POSTs `<auth>/v1/login/api-key` with the key, receives a
   session credential, stores it.

The key is read from the environment, never accepted on argv (would
appear in `ps`). The auth service typically issues shorter-lived
sessions for API-key logins than for interactive ones, and may add a
`MachineAccount=true` caveat to per-op discharges so audit can
distinguish automated from human actions — both are auth-service-side
policy, not CLI surface.

### Per-IPC discharge fetch

For each operator IPC verb the CLI:

1. Knows it's about to call coord-X. Fetches coord-X's `caveat_id`
   from coord directly if not cached (coord exposes it; the value is
   not secret).
2. POSTs to `<auth>/v1/discharge` with the session credential in
   `Authorization: Bearer`, body
   `{caveat_id, op: "Release", volume: "myvm", ttl_seconds: 60}`.
3. Auth service:
   - Verifies the session credential with `K_session`.
   - Reads `(CoordId, OrgId, key_id)` from `caveat_id`.
   - Cross-checks the `OrgId` against the session's `OrgId`.
   - Applies its policy (is this Subject allowed to do this op on
     this volume against this coord?).
   - Signs the discharge predicate with `K_auth_priv`.
4. CLI sends `(per-op discharge, IPC body)` to coord-X. The session
   never leaves the CLI ↔ auth-service channel.

## Reachability

The auth service must be reachable from two places:

- **Mint** — at mint enrollment (to obtain `K_auth_pub`) and for
  pubkey rotation. Coord and mint do not contact the auth service to
  verify discharges; verification is fully local once enrollment has
  completed.
- **The operator's CLI machine** — for `elide operator login` and
  per-IPC `/v1/discharge` fetches. The interactive flow also needs
  the auth service reachable from the operator's laptop browser.

In a hosted deployment this is one public URL. In self-hosted prod
the same URL has to be reachable from operator workstations (usually
via the same VPN the operators use to SSH in).

## Identity and policy

The per-op discharge carries three identity claims:

- **OrgId is mandatory and enforced.** Set by the auth service from
  the org selected at login. Coord and mint reject any discharge
  whose `OrgId` doesn't match their enrolled OrgId.
- **Subject is mandatory and opaque.** A stable identifier (UUID,
  OIDC `sub`, opaque token) chosen by the auth service. Not a
  username or email — those change. The auth service is responsible
  for keeping `Subject` stable for a given human across renames and
  IdP changes.
- **User is optional and audit-only.** A display-name caveat coord
  logs alongside `Subject`. `Subject` is the policy key; `User` is
  the display string.

Beyond OrgId enforcement, coord performs no subject-keyed policy in
the initial design. All access control — allow-listing, RBAC,
per-volume ACLs — lives at the auth service. Coord verifies the
discharge predicate and logs the Subject; the auth service decided
what predicate to sign by consulting whatever policy it implements.

This pushes policy where macaroons assume it lives: at the issuer,
not the verifier. The verifier stays mechanical — the signed
predicate is the contract.

For self-hosted / single-tenant deployments the auth service's
policy can be minimal. For managed / hosted deployments the auth
service grows whatever RBAC machinery the product needs, encoded
into the discharge predicate.

Adding new predicate fields later is a wire-format change (unknown
fields fail closed in the verifier), so it ships with a coord
update. Acceptable for a tightly-versioned system; fields are added
only when needed.

Coord log shape:

```
INFO operator_token::authn event=verify op=Release volume=myvm
  org=org_7vh3... subject=usr_2k9q... user=alice@example.com
```

## Cadence

**Sessions: ~7 days, refreshed only by re-running `elide operator
login`.** Default lifetime is auth-service policy. There is no sliding
renewal — when the session expires, the next IPC call fails with a
clear error and the operator runs `login` again. Non-interactive
(API-key) sessions are typically shorter (e.g. 1 hour); the API key
is the long-lived credential and the session is its derived form.

**Discharges: ~60s, fetched per operator IPC verb in the initial
design.** Each call narrows to (`Op`, `Volume`) for that specific
verb. The auth service issues mechanically — session validity is the
human-interaction gate.

**Discharge lifetime vs op duration.** A 60s discharge can expire
mid-op for long-running verbs (`snapshot`, `gc`). The discharge is
checked at the entry-point IPC verb only, matching the "op caveat
must match the entry-point" rule from
[`design-auth-model.md`](design-auth-model.md#typed-operation-surface).
Once coord has dispatched and (for writes) mint has issued a
write-capable cred, the cred's own short lifetime bounds the
in-flight work.

**Replay window.** Within its 60s NotAfter a discharge is
theoretically replayable. The initial design does not add
nonce-caching at coord:

- Most operator IPC verbs are idempotent at the coord layer.
- The audit signal is preserved — every reuse leaves a coord-side
  verify entry, divergent from the auth-service issuance count.
- If a specific verb turns out to be non-idempotent and
  replay-sensitive, the predicate can carry a per-request nonce
  field as a per-verb addition.

## Audit anchors

The design produces two correlated audit streams:

- **Auth service log** — every discharge issued (subject, op, volume,
  expiry).
- **Coordinator / mint log** — every operator IPC verified (op,
  volume, subject).

Normally one-to-one. Because only the auth service holds
`K_auth_priv`, the auth-service log is authoritative: every
discharge accepted anywhere must correspond to one issued by the
auth service. Divergences:

| Auth log | Coord/mint log | Meaning |
|---|---|---|
| present | present | Normal |
| present | absent | Discharge issued but never used — cancelled CLI, network drop |
| present | duplicate | Replay within 60s window — investigate |
| absent | present | Auth-service private key compromise |

The last row is unambiguous: an accepted discharge with no
corresponding issuance can only arise from `K_auth_priv` leakage.

## Key rotation

Three keys can be rotated. All use overlap windows and
pull-on-verify-fail.

### `K_auth_priv` / `K_auth_pub` rotation

Routine cadence (e.g. quarterly) or in response to suspected
compromise. The auth service runs with both old and new keypairs
during an overlap window, signing new discharges with the new key
and stamping `key_id`.

Distribution:

1. Auth service publishes the new key alongside the old via
   `GET /.well-known/elide-auth-keys`.
2. Mint pulls on its own cadence and relays via `GET
   /v1/auth/pubkey` to enrolled coords.
3. Coord stores both, indexed by `key_id`. The discharge's `key_id`
   selects the verifying key.
4. After the overlap window, auth service drops the old private key;
   mint and coord drop the old public key on their next pull.

Pull-on-verify-fail: if coord sees a discharge with an unknown
`key_id`, it fetches the current pubkey set from mint before
rejecting.

### `K_M` rotation (mint's root)

The heaviest event in the system. Triggered by routine mint-root
rotation (annual / biennial) or if `K_M` is suspected compromised
(anyone with `K_M` can mint primaries for any coord under this mint).

When `K_M` rotates, the per-coord chain key derivation changes. Mint
runs with both `K_M_old` and `K_M_new` during a grace window:

1. Mint admin runs `elide-mint rotate-root`. Mint generates `K_M_new`,
   retains `K_M_old` for a configurable window.
2. During the window, mint accepts primaries derived under either
   key (tries `K_M_new.derive(coord_ulid)` first, falls back to
   `K_M_old.derive(coord_ulid)`).
3. Each coord, on its next mint interaction (assume-role, primary
   refresh, or proactive heartbeat), is detected as still on the old
   primary. Mint mints a fresh primary under `K_M_new` and returns
   it.
4. Coord swaps its stored primary atomically.
5. After the grace window, mint drops `K_M_old`. Coords still on old
   primaries become unverifiable at mint until they re-enroll
   manually.

Coord's local verification path is unaffected throughout — the
stored primary is the anchor, and swapping it is the entire
operation. There is no separate "chain key" to swap because coord
doesn't hold one.

For emergency rotation, the grace window should be aggressive and
mint should signal coords to refresh proactively. Coords offline for
the entire window require manual re-enrollment.

### `K_session` rotation (auth-service-only)

Trivial: only the auth service holds `K_session`. Rotation
invalidates existing sessions; operators re-run `login`. Grace
window optional — the auth service can keep `K_session_old` to
honour in-flight sessions until their `NotAfter` expiry.

### Summary

| Key | Affects | Coord-side impact |
|---|---|---|
| `K_auth_pub` | Discharge sig verification | Pull new pubkey from mint; index by `key_id` |
| `K_M` | Primary chain key derivation | Pull fresh primary from mint; swap stored anchor |
| `K_session` | Sessions invalidated | None |

## API surface

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
{ "session": "<credential>", "expires_at": "...", "org_id": "org_..." }
```

Response 400 with body `{ "error": "authorization_pending" | "slow_down" |
"expired_token" | "access_denied" }` (RFC 8628 vocabulary).

`POST /v1/login/api-key` (Bearer API key in `Authorization` header) —
non-interactive session exchange. Response shape matches
`/login/poll` success. 401 invalid, 403 disabled.

`POST /v1/discharge` (Bearer session) — issue per-op discharge.
Request:

```json
{
  "caveat_id": "<base64>",
  "op": "Release",
  "volume": "myvm",
  "ttl_seconds": 60
}
```

Response 200:

```json
{
  "discharge": {
    "predicate": {
      "coord_id": "01HXY...",
      "org_id": "org_7vh3...",
      "subject": "usr_2k9q...",
      "op": "Release",
      "volume": "myvm",
      "not_after": "...",
      "key_id": "kp_2026q2"
    },
    "signature": "<base64 Ed25519 signature>"
  },
  "expires_at": "..."
}
```

401 session expired, 403 policy denies, 422 unknown op.

**Auth service — public.**

`GET /.well-known/elide-auth-keys` (anonymous) — JWKS-equivalent.
Current and recently-rotated verification pubkeys, indexed by
`key_id`. Mint polls this and relays to enrolled coords.

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
  "auth_pubkey": { "kid": "kp_2026q2", "alg": "EdDSA", "x": "..." }
}
```

400 invalid / expired / already-used token. The shared state between
mint and auth service is just the pubkey — public information.

**Mint — coord-facing.**

`POST /v1/coord/enroll` (anonymous; mint-signed token is the proof) —
one-shot coord enrollment. Request:

```json
{ "enrollment_token": "<mint-signed opaque>" }
```

Response 200:

```json
{
  "coord_ulid": "01HXY...",
  "primary_macaroon": "<base64 macaroon>",
  "org_id": "org_7vh3...",
  "auth_service_url": "https://auth.elide.example/",
  "auth_pubkey": { "kid": "kp_2026q2", "alg": "EdDSA", "x": "..." }
}
```

Coord persists the full response in `data_dir`. The primary carries
caveats `(CoordId, OrgId)` plus a TPC `(location=<auth_service_url>,
caveat_id)`. `caveat_id` is opaque routing metadata: the CLI fetches
it from coord and includes it in `/v1/discharge` requests.

`GET /v1/coord/caveat-id` (anonymous; served by coord on a local
endpoint) — CLI fetches the coord's TPC `caveat_id`. Not secret.

```json
{ "caveat_id": "<base64>" }
```

`GET /v1/auth/pubkey` (coord-authenticated via the cred-issuance
path) — current auth-service pubkey set. Used by coord on
pull-on-verify-fail and during routine rotation refresh.

```json
{
  "keys": [
    { "kid": "kp_2026q2", "alg": "EdDSA", "x": "..." },
    { "kid": "kp_2026q1", "...": "...", "deprecated": true }
  ]
}
```

`POST /v1/coord/primary-refresh` (coord-authenticated) — coord
requests a fresh primary after `K_M` rotation. Response shape
matches the `primary_macaroon` field of `/v1/coord/enroll`.

Mint's existing cred-issuance endpoints (`assume-role` and friends)
are unchanged in shape but now additionally accept and verify a
`(primary, discharge)` bundle for ops requiring operator
authorisation.

## Config

`coordinator.toml` points at mint; it carries no auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint URL, OrgId, auth-service URL, auth-service pubkey set, and the
primary macaroon all land in the coord's `data_dir` at
`elide-coordinator setup` time.

Mint's config carries the `[auth]` block pointing at the auth
service:

```toml
[auth]
endpoint = "https://auth.elide.example/"
```

Mint persists its OrgId and the auth-service pubkey set at
`elide-mint setup --enrollment-token` time. The pubkey set is
refreshed via auth-service rotation; mint relays the current set to
coords on demand.

## Mint as auth (demo only)

For dev, test, and demo deployments, mint can mount the auth route
handlers itself:

```toml
# mint config
[auth]
demo-enabled = false   # default
```

When `true`, mint serves `/v1/login/*` and `/v1/discharge` alongside
its cred-issuance routes, rubber-stamping every request — no
browser, no real authentication. Mint generates its own Ed25519
keypair as the "auth-service" key at demo startup, embeds the pubkey
in coord-enrollment responses, and signs discharges with the private
half. The coord codepath is identical to prod. Enrollment tokens are
also rubber-stamped: a coord can enroll with any token (or none) and
is assigned `OrgId=demo`.

Two startup-time safety checks when `demo-enabled = true`:

- Mint refuses to start unless bound to loopback / UDS.
- Mint logs `WARN auth=demo: all operator sessions are
  unauthenticated` at startup and per issued session.

The verifier in coord and mint stays unconditional. The mint binary
has no webauthn / OIDC / SAML code; production auth implementations
live in the separate auth service binary only.

The canonical test-fixture pattern is **demo mint + non-interactive
login**: a single mint process with `demo-enabled = true` bound to a
UDS, plus `ELIDE_OPERATOR_API_KEY=test` on the harness. The full
wire flow (login → discharge → IPC verify → mint discharge verify)
runs end-to-end with no browser and no `#[cfg(test)]` shortcuts.

## Deployment shapes

| Deployment | Auth packaging | Auth backend |
|---|---|---|
| Dev / test / demo | mint serves auth routes (`demo-enabled = true`) | rubber-stamp, instant session |
| Single-tenant self-hosted prod | separate auth service binary | real (webauthn / OIDC / …) |
| Multi-tenant hosted | separate auth service binary | real, full SSO |

Mint-as-auth is fine as long as there is one identity authority
(single mint or HA replicas of one logical mint with a shared key).
With multiple distinct mints — sharded by tenant / region — one
would have to be nominated as the auth-primary, which is effectively
a separate logical auth service in shared packaging. At that point
splitting the binaries is cleaner.

## Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange, so
requiring the auth service reachable for operator login adds no new
failure mode.

## Wide discharges (deferred)

The initial design fetches one discharge per operator IPC verb. A
"wide" discharge — a single discharge covering multiple ops or a
longer window (e.g. `Op=Any, Volume=myvm, NotAfter=now+5m`) — is left
open as a possible later extension.

Tradeoffs to weigh before adopting:

- **Audit fidelity.** One discharge currently corresponds to one
  intended action. A wide discharge breaks the 1:1; the auth-service
  log moves from "every op" to "every issuance window."
- **Leak exposure.** A wide discharge that escapes confers more
  authority for longer than the 60s narrow form.
- **Issuance shape.** Verifier paths are unaffected — only the auth
  service's issuance policy and the CLI's caching layer change.

## Per-coord scoping within an org (deferred)

The primary already carries `CoordId`, so verification is naturally
scoped to the verifying coord. What's deferred is **auth-service-side
per-coord narrowing of discharges**: an operator who admins many
coords in one org but wants per-coord blast-radius limits would
benefit from sessions that authorise ops only against specific coords
(e.g. session valid only for `CoordId ∈ {A, B}`). The predicate
accommodates it cleanly with an `AllowedCoords` field plus a verifier
check; the auth service would need a per-coord policy surface.

## Migration from PoC

Clean break. The PoC operator-token surface has been removed from
the codebase (`~/.elide/tokens.toml`, `Request::MintOperatorToken`,
the `OperatorOp` / `verify_operator` plumbing, the `elide token`
subcommands). Operator IPC verbs are currently ungated; the central
auth service re-gates them uniformly when it lands.

Operators with stale `~/.elide/tokens.toml` files must remove them
manually. Coords that were stood up under the PoC must be re-enrolled
via `elide-coordinator setup --enrollment-token` after their org has
been activated.
