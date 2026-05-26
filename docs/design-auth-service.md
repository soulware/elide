# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
session and per-op discharge macaroons. It builds on the principle
established in
[`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-s3-writes-not-verbs)
— **every S3 mutation requires operator authorisation** — and is the
concrete shape of the *third-party-caveat discharge* anchor mint
requires for write-capable cred issuance.

**Status: proposed. Not yet implemented.** The prior local
operator-token PoC has been removed from the codebase; operator IPC
verbs are currently ungated. This design re-introduces operator
authorisation via a central auth service and a third-party-caveat
discharge flow.

## Principle

The PoC minted operator tokens locally on the coordinator and trusted
"can reach the unix socket" as the identity floor. That surface has
been removed (see *Migration from PoC* below). The settled direction
uses the macaroon **third-party-caveat discharge** mechanism end to
end — all macaroons are chained keyed-BLAKE3 MAC, identical
construction to volume macaroons.

- **Mint is the sole primary issuer.** Mint's root MAC key never
  leaves it. Mint signs a primary macaroon for each coord at
  enrollment time; this primary carries a third-party caveat naming
  the auth service.
- **The auth service issues discharges only.** A discharge satisfies
  the third-party caveat embedded in mint-issued primary macaroons,
  attesting that an operator of the named org authorised the
  request. The auth service never issues primary macaroons.
- **Coord and mint verify locally.** Each holds the keys it needs
  (a per-coord MAC key derived from mint's root for coord; mint's
  root + the per-org discharge key for mint) without round-tripping
  to the auth service on verify.
- Operator IPC verbs are currently **ungated** pending this design.

Once landed, every operator IPC verb requires the operator to
present a fresh discharge alongside coord's primary macaroon.
Volume↔coord IPC (PID-bound volume macaroons) is unchanged — the new
gate is on operator IPC only.

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
no per-coord state. The keys established at enrollment are:

- `K_M` — mint's root MAC key. Generated at mint setup, never leaves
  mint.
- `K_vid_org` — a per-org symmetric key shared between mint and the
  auth service. Established at mint-enrollment. Used as the **vid
  key** in third-party caveats: mint embeds `K_vid_org` into each
  coord's primary macaroon (so the macaroon's holder can recover it
  during verification), and the auth service uses `K_vid_org` to sign
  every discharge it issues for org X.
- `K_coord = HKDF(K_M, coord_ulid)` — a per-coord MAC key. Mint
  re-derives it on demand from `K_M`; coord receives a copy at
  enrollment for verifying its own primary.

**Mint ↔ auth service** — slow cadence, once per org lifetime plus
occasional rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, NotAfter=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint POSTs `<auth>/v1/mint/enroll` with the token.
5. Auth service verifies the token, records org X as activated,
   generates `K_vid_org`, and returns it to mint.
6. Mint persists `K_vid_org` + auth-service URL + OrgId.

**Coord ↔ mint** — per-coord deployment cadence. Extends the existing
coord-mint enrollment with primary-macaroon issuance.

1. Mint admin generates a one-shot coord-enrollment token signed by
   mint's own key: `OrgId=X, Purpose=CoordEnroll, NotAfter=now+15m`.
2. Coord admin runs `elide-coordinator setup --enrollment-token
   <token>`.
3. Coord POSTs to mint with the token.
4. Mint verifies the token, allocates `coord_ulid`, derives
   `K_coord = HKDF(K_M, coord_ulid)`, and mints a **primary macaroon**
   for this coord:
   - First-party caveats: `CoordId=<coord_ulid>, OrgId=X`
   - Third-party caveat: `(location=<auth-url>, caveat_id="discharge/<OrgId>", vid=K_vid_org)`
     — i.e., the vid that auth-service discharges will use is
     `K_vid_org`, embedded so the chain-key holder can recover it
   - Chain MAC'd with `K_coord`
5. Mint returns to coord: `coord_ulid`, `K_coord`, the primary
   macaroon, auth-service URL, `OrgId`.
6. Coord persists all of the above in its `data_dir`.

After enrollment, coord verifies operator IPC bundles locally with
no round-trip to mint or the auth service.

**K_vid_org rotation.** Rotation is mint↔auth-service business.
When the auth service rotates `K_vid_org`, every existing primary
macaroon's TPC vid is stale — discharges signed with the new
`K_vid_org` won't verify against the old vid embedded in the
primary. Resolution is pull-on-verify-fail: when a coord's discharge
verification fails on an otherwise well-formed bundle, the coord
asks mint (`GET /v1/coord/primary`) for a fresh primary embedding
the current `K_vid_org`, swaps its stored primary, and retries. Mint
keeps `K_vid_org` fresh via its existing auth-service relationship;
coord lazily catches up. The auth service is responsible for
overlapping rotation windows long enough that pull-on-fail is
bounded by one retry per in-flight verification at most.

## Login flow

`elide operator login` supports two modes. The CLI selects mode by
whether `ELIDE_OPERATOR_API_KEY` is set; both end at the same
artefact — a **session discharge** stored once, per-user, in a file
under `~/.elide/`. ("Session" is shorthand: structurally it's a
macaroon signed under `K_vid_org` with broad caveats — `Subject`,
`OrgId`, `NotAfter+7d` — that the CLI later trades to the auth
service for per-op discharges.)

The stored session is org-scoped (mandatory `OrgId` caveat) and
covers every coordinator within that org. Operators in multiple
orgs need separate sessions per org.

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
   discharge bound to the selected org.
4. `/v1/login/poll` returns the session discharge; CLI stores it.

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
   session discharge, stores it.

The key is read from the environment, never accepted on argv (would
appear in `ps`). The auth service typically issues shorter-lived
sessions for API-key logins than for interactive ones, and may add a
`MachineAccount=true` caveat to per-op discharges so audit can
distinguish automated from human actions — both are
auth-service-side policy, not CLI surface.

**Per-IPC discharge fetch.** The session is *not* what coord/mint
see. For each operator IPC verb, the CLI:

1. POSTs the session discharge to `<auth>/v1/discharge` with the
   narrowing it needs (`op=Release, volume=myvm, ttl_seconds=60`).
2. Auth service validates the session against its own state,
   confirms the requested narrowing is within session policy, and
   mints a **per-op discharge**: macaroon signed under `K_vid_org`
   with caveats `(Subject, OrgId, Op, Volume, NotAfter=now+60s)`.
3. CLI sends `(per-op discharge, IPC body)` to coord. The session
   discharge never leaves the CLI ↔ auth-service channel.

## Reachability

The auth service must be reachable from two places:

- **Mint** — at mint enrollment (to obtain `K_vid_org`) and for
  `K_vid_org` rotation. Coord and mint do not contact the auth
  service to verify sessions or discharges (both are verified
  locally with keys held since enrollment).
- **The operator's CLI machine** — for `elide operator login` and
  per-IPC `/v1/discharge` fetches. The interactive flow also needs
  the auth service reachable from the operator's laptop browser.

In a hosted deployment this is one public URL. In self-hosted prod
the same URL has to be reachable from operator workstations (usually
via the same VPN the operators use to SSH in). Verification at coord
and mint is fully offline once enrollment has completed.

## Macaroons in this design

Same chained-keyed-BLAKE3 construction as volume macaroons in
`architecture.md` — per-token nonce, AND-of-predicates evaluation.
No new primitive. The design uses macaroons' built-in **third-party
caveat** mechanism to compose a mint-issued primary with auth-service
discharges, without any party holding another's signing key.

Three artefacts:

**1. Primary macaroon.** Mint-issued, coord-held. One per coord,
minted at coord enrollment.

- First-party caveats: `CoordId=<coord_ulid>, OrgId=<org>`
- Third-party caveat: `(location=<auth-url>, caveat_id="discharge/<org>", vid=K_vid_org)`
- Chain MAC'd with `K_coord = HKDF(K_M, coord_ulid)`

Coord stores this primary. Mint stays stateless (re-derives `K_coord`
on demand).

**2. Session discharge.** Auth-service-issued, CLI-held. One per
operator login, ~7 day lifetime.

- Caveats: `Subject=<sub>, OrgId=<org>, NotAfter=<login_time+7d>`
- Chain MAC'd with `K_vid_org` as root

Used only between the CLI and the auth service. Coord and mint
never see it.

**3. Per-op discharge.** Auth-service-issued, ~60s lifetime. One per
operator IPC verb.

- Caveats: `Subject, OrgId, Op, Volume, NotAfter=now+60s` (plus
  optional `User` for display; optional `MachineAccount=true` for
  non-interactive sessions)
- Chain MAC'd with `K_vid_org` as root

The CLI obtains a per-op discharge by presenting its session
discharge to `<auth>/v1/discharge`. The auth service validates the
session, applies its policy, and mints the narrowed per-op discharge.
The CLI sends `(per-op discharge, IPC body)` to coord.

Replacing the PoC's CLI-side `Macaroon::attenuate` with an
auth-service round-trip is the audit point: the auth service is the
only thing that can produce a narrowing, so its log records every
operator action centrally.

### How verification ties them together

When coord receives an operator IPC:

1. Coord walks its **stored primary macaroon** with `K_coord`,
   computing successive auth values.
2. At the third-party caveat, coord recovers `K_vid_org` from the
   caveat's `vid` field (the chain auth value at that point is the
   decryption key — standard macaroon TPC mechanic).
3. Coord verifies the **per-op discharge**'s MAC chain with
   `K_vid_org` as root.
4. Coord checks every first-party caveat: `CoordId` matches its own
   ULID, `OrgId` matches its enrolled OrgId, `Op` matches the
   dispatched verb, `Volume` matches the target, `NotAfter` is in
   the future.
5. If all pass, dispatch. If any fail, reject.

The key property: coord never needed the auth service's signing
authority directly. The auth service's discharge key (`K_vid_org`)
reaches coord through the primary's `vid` field, which only the
primary's chain holder can decrypt.

## Identity and policy

The per-op discharge carries three identity claims:

- **OrgId is mandatory and enforced.** Set by the auth service from
  the org selected at login. Coord and mint reject any discharge
  whose `OrgId` doesn't match their enrolled OrgId. This is the
  protocol's primary multi-tenant isolation boundary — see
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

## Cadence

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
"op caveat must match the entry-point" rule from
[`design-auth-model.md`](design-auth-model.md#typed-operation-surface).
Once coord has dispatched and (for writes) mint has issued a
write-capable cred, the cred's own short lifetime bounds the
in-flight work.

**Replay window.** Within its 60s NotAfter a discharge is theoretically
replayable. The initial design does not add nonce-caching at coord:

- Most operator IPC verbs are idempotent at the coord layer.
- The audit signal is preserved — every reuse leaves a coord-side
  verify entry, divergent from the auth-service issuance count.
- If a specific verb turns out to be non-idempotent and
  replay-sensitive, the discharge can carry a per-request nonce caveat
  as a per-verb addition.

## Audit anchors

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
| absent | present | Should be impossible — `K_vid_org` has leaked, or coord's primary embeds the wrong vid |

The "should be impossible" row is the security-relevant one. If it
ever fires, `K_vid_org` has leaked — either at the auth service, at
mint, or at a coord whose primary's `vid` field was extracted.

## Verification: two enforcement points, one auth service

Coord and mint **both verify the bundle independently** on the paths
they sit on. Mint does not trust coord's check — it re-runs the
verification from scratch. This is defense in depth: a compromised
coord can still make `/v1/assume-role` calls, but cannot bypass
mint's check by claiming "I already verified."

- **Coordinator** verifies the bundle on every operator IPC verb.
  Walks its stored primary with `K_coord`, recovers `K_vid_org` from
  the primary's TPC `vid` field, verifies the per-op discharge with
  `K_vid_org`, then checks every first-party caveat. No round-trip
  to mint or the auth service on verify; pull-on-fail refresh of the
  primary if `K_vid_org` has rotated (see *Tenancy and enrollment*
  above).
- **Mint** verifies on every `assume-role` call that issues
  write-capable creds. Re-derives `K_coord` from its root + the
  `CoordId` caveat on the presented primary, walks the primary,
  recovers (and cross-checks against state) `K_vid_org`, verifies
  the discharge, checks the same caveats. This is the architectural
  chokepoint from
  [`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-s3-writes-not-verbs);
  the third-party-caveat anchor sits on the primary mint issued at
  coord enrollment.

### What each verifier checks

| Check | Coord | Mint |
|---|---|---|
| Primary MAC | uses stored `K_coord` | re-derives `K_coord` from `K_M + coord_ulid` (extracts `coord_ulid` from the `CoordId` caveat) |
| Recover `K_vid_org` from primary's TPC vid | via primary's chain auth value | same — and cross-checks against `K_vid_org` already in mint state |
| Discharge MAC under `K_vid_org` | yes | yes |
| Discharge first-party caveats (`Op`, `Volume`, `NotAfter`) | matches the dispatched IPC verb | matches the `assume-role` request shape |
| `OrgId` matches enrolled org | matches coord's enrolled OrgId | matches mint's OrgId (must be the same — coord is enrolled to this mint) |
| `CoordId` on the primary | matches coord's own ULID | used to derive `K_coord`, and used to scope what the call may authorise (mint only grants `volume-rw` for volumes this coord owns, `coord-names` only within this coord's authority, etc.) |

### Which ops reach mint

Not every operator IPC verb passes through `/v1/assume-role`. Mint's
verifier sees the bundle only on S3-write paths.

| IPC verb shape | Coord verifies | Mint verifies |
|---|---|---|
| Read-only at coord (`volume list`, `volume status` from local index) | yes | not reached |
| Local-state mutation only (`volume register`, local `volume remove`) | yes | not reached |
| S3 read needed | yes | `coord-ro` cred path (existing, no operator discharge) |
| S3 write needed (`volume claim`, `volume release`, `volume snapshot`, `volume create` writing `names/`) | yes | yes — coord forwards `(primary, discharge)` with the assume-role call |

### Caller authentication is separate

Mint's bundle verification proves the *operator* authorised this
specific op. It does not prove the *caller* is a legitimate coord.
Coord-to-mint caller authentication uses mint's existing
cred-issuance auth path (the volume-macaroon-keyed mechanism mint
already has — unchanged by this design). Both are required for mint
to issue write-capable creds: caller-auth proves it's a real coord,
the bundle proves a human authorised the op.

Both verifiers trust the **same** auth service via `K_vid_org`.
Removing one enforcement point doesn't silently lose the other.

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
{ "session_discharge": "<macaroon>", "expires_at": "...", "org_id": "org_..." }
```

Response 400 with body `{ "error": "authorization_pending" | "slow_down" |
"expired_token" | "access_denied" }` (RFC 8628 vocabulary).

`POST /v1/login/api-key` (Bearer API key in `Authorization` header) —
non-interactive session exchange. Response shape matches
`/login/poll` success. 401 invalid, 403 disabled.

`POST /v1/discharge` (session discharge in `Authorization: Bearer
<session>` header) — issue per-op discharge. Request:

```json
{ "op": "Release", "volume": "myvm", "ttl_seconds": 60 }
```

Response 200:

```json
{ "discharge": "<macaroon>", "expires_at": "..." }
```

The returned `discharge` is a macaroon MAC'd under `K_vid_org` with
caveats `(Subject, OrgId, Op, Volume, NotAfter)`. 401 session
expired, 403 policy denies, 422 unknown op.

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
  "k_vid_org": "<base64 32-byte symmetric key>"
}
```

400 invalid / expired / already-used token. `k_vid_org` is the
per-org symmetric key used as the third-party-caveat vid: mint
embeds it in every coord's primary macaroon, and the auth service
MACs every discharge for org X with it. The auth service may rotate
`k_vid_org` (see *Tenancy and enrollment*).

`GET /v1/mint/k-vid` (mint-authenticated; mint presents its
own-issued bearer credential established at enrollment) — fetches
the current `K_vid_org` after rotation.

```json
{ "k_vid_org": "<base64>" }
```

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
  "k_coord": "<base64 32-byte symmetric key>",
  "primary_macaroon": "<base64 macaroon>",
  "org_id": "org_7vh3...",
  "auth_service_url": "https://auth.elide.example/"
}
```

`k_coord = HKDF(K_M, coord_ulid)`. The `primary_macaroon` carries
caveats `(CoordId, OrgId)` plus a third-party caveat
`(location=<auth_service_url>, caveat_id="discharge/<OrgId>",
vid=K_vid_org)`. Coord persists the full response in `data_dir`.
Mint stays stateless (re-derives `k_coord` on demand from its root +
`coord_ulid`).

`GET /v1/coord/primary` (coord-authenticated via the cred-issuance
path) — fetches a fresh primary embedding the current `K_vid_org`.
Used by coord on pull-on-verify-fail.

```json
{ "primary_macaroon": "<base64 macaroon>" }
```

Mint's existing cred-issuance endpoints (`assume-role` and friends)
are unchanged in shape but now additionally accept and verify a
`(primary_macaroon, per-op discharge)` bundle for ops that require
operator authorisation.

## Config

Coord and mint hold different config surfaces because the auth-service
binding reaches coord transitively through mint.

`coordinator.toml` points at mint for enrollment; it carries no
auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint URL, OrgId, auth-service URL, `K_coord`, and the primary
macaroon all land in the coord's `data_dir` at `elide-coordinator
setup` time and are not human-edited thereafter.

Mint's config carries the `[auth]` block pointing at the auth
service:

```toml
[auth]
endpoint = "https://auth.elide.example/"
```

Mint persists its OrgId, `K_vid_org`, and the auth-service URL to
its own state at `elide-mint setup --enrollment-token` time.
`K_vid_org` is refreshed via auth-service rotation, after which mint
re-issues fresh primary macaroons to coords on demand (see
*Tenancy and enrollment* above).

## Mint as auth (demo only)

For dev, test, and demo deployments, mint can mount the auth route
handlers itself:

```toml
# mint config
[auth]
demo-enabled = false   # default
```

When `true`, mint serves `/v1/login/*` and `/v1/discharge` alongside
its cred-issuance routes, rubber-stamping every request — no browser,
no real authentication. Mint generates a `K_vid_org` for itself at
demo startup (no auth-service round-trip), embeds it in every
primary macaroon it issues, and signs all discharges with the same
key. The coord codepath is identical to prod: verify primary with
`K_coord`, recover `K_vid_org` from the primary's vid, verify
discharge with `K_vid_org`. Enrollment tokens are also
rubber-stamped: a coord can enroll with any token (or none) and is
assigned `OrgId=demo`.

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

## Deployment shapes

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

## Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange, so
requiring the auth service reachable adds no new failure mode. There
is no offline escape hatch for operator login. The deployment story
is "online or not running."

## Wide discharges (deferred)

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

## Per-coord scoping within an org (deferred)

The primary macaroon already carries `CoordId`, so each verification
is naturally scoped to the verifying coord. What's deferred is
**auth-service-side per-coord narrowing of discharges**: an operator
who admins many coords in one org but wants per-coord blast-radius
limits would benefit from sessions that only authorise ops against
specific coords (e.g. session valid only for `CoordId ∈ {A, B}`).
The macaroon construction accommodates it cleanly (a discharge
caveat `AllowedCoords=[A, B]` plus a verifier check that the
verifying coord's ULID is in the list); the auth service would need
a per-coord policy surface. Out of scope for the initial design.

## Migration from PoC

Clean break. The PoC operator-token surface has already been removed
from the codebase (`~/.elide/tokens.toml`, `Request::MintOperatorToken`,
the `OperatorOp` / `verify_operator` plumbing, the `elide token`
subcommands). Operator IPC verbs are currently ungated; the central
auth service will re-gate them uniformly when it lands.

No compatibility shim. Operators with stale `~/.elide/tokens.toml`
files must remove them manually. Coords that were stood up under the
PoC must be re-enrolled via `elide-coordinator setup
--enrollment-token` after their org has been activated (mint
enrollment). No migration tooling ships.
