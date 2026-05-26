# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
sessions and per-coord discharges. It builds on the principle
established in
[`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-s3-writes-not-verbs)
— **every S3 mutation requires operator authorisation** — and is the
concrete shape of the *third-party-caveat discharge* anchor mint
requires for write-capable cred issuance.

**Status: proposed. Not yet implemented.**

## Principle

Every operator IPC verb requires a CLI-attenuated discharge,
presented alongside coord's mint-issued primary macaroon. All three
artefacts (session, primary, discharge) use the same
chained-keyed-BLAKE3 construction as volume macaroons — one
primitive end to end, with NotAfter and other narrowings expressed
as caveats throughout.

The design rests on three structural properties:

- **Mint is the sole holder of `K_M`** (the primary chain root).
  Mint mints one primary per coord at enrollment; coord receives
  `K_coord = HKDF(K_M, coord_ulid)` so it can verify its own primary
  locally. Mint stays stateless across coords.
- **Auth is the sole holder of `K_disch`** (the discharge MAC root).
  Auth mints all discharges; nobody else can produce one. Coord and
  mint hold *no* discharge verification key — they trust discharges
  on receipt from auth (via mint at enrollment-time vouch, via cache
  at runtime).
- **The primary's third-party caveat is woven into the chain MAC.**
  Stripping the discharge requirement requires `K_M` (mint-only);
  satisfying it requires a discharge with the right `CoordId`
  caveat. The TPC binding is therefore non-bypassable by any party
  who cannot mint primaries.

Operator IPC verbs are currently ungated; this design re-gates them.
Volume↔coord IPC (PID-bound volume macaroons) is unchanged.

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

The keys established across the system are:

- `K_M` — mint's root MAC key. Generated at mint setup, never leaves
  mint. Used to derive per-coord primary chain keys via HKDF.
- `K_disch` — auth's root MAC key for discharges. Generated at
  auth-service setup, never leaves the auth service. Auth uses it
  (or a per-org/per-coord HKDF derivation, internal to auth) when
  signing every discharge.
- `K_session` — auth-service-only root key for sessions. Never
  leaves the auth service.
- `K_coord = HKDF(K_M, coord_ulid)` — per-coord primary chain key.
  Mint re-derives on demand; coord receives a copy at enrollment.

**Mint ↔ auth service** — once per org lifetime plus occasional
rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, NotAfter=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint POSTs `<auth>/v1/mint/enroll` with the token.
5. Auth verifies the token, records org X as activated, provisions
   mint with a bearer credential for subsequent auth calls, returns
   `(OrgId, auth-service URL, mint bearer)`.
6. Mint persists.

No symmetric MAC key is shared between mint and auth. Mint's
outbound calls to auth use its bearer credential; auth uses it to
identify which mint (and therefore which org) is calling.

**Coord ↔ mint** — per-coord deployment cadence. Mint also brokers
a coord-to-auth bearer credential as part of this flow, so coord can
call auth directly at runtime.

1. Mint admin generates a one-shot coord-enrollment token signed by
   mint: `OrgId=X, Purpose=CoordEnroll, NotAfter=now+15m`.
2. Coord admin runs `elide-coordinator setup --enrollment-token <token>`.
3. Coord POSTs to mint with the token.
4. Mint verifies the token, allocates `coord_ulid`, derives
   `K_coord = HKDF(K_M, coord_ulid)`, mints a primary macaroon:
   - First-party caveats: `CoordId=<coord_ulid>, OrgId=X`
   - Third-party caveat: `(location=<auth-url>, caveat_id)` where
     `caveat_id` is an opaque routing blob carrying `CoordId, OrgId`
     so auth knows what discharge to mint. The TPC has no `vid`
     field — coord doesn't need to recover any discharge key from
     the primary (it doesn't verify discharge MACs at all).
   - Chain MAC'd with `K_coord`
5. Mint forwards a coord-provisioning request to auth using its own
   bearer credential. Auth issues a per-coord bearer (`coord-X`
   identifies as coord `<coord_ulid>` of org X) and returns it to
   mint.
6. Mint returns to coord: `coord_ulid`, `K_coord`, the primary, the
   auth-service URL, `OrgId`, and the coord-to-auth bearer.
7. Coord persists all of the above in its `data_dir`.

After enrollment coord has everything it needs to verify primaries
locally and to call auth directly when it needs to verify a
discharge it hasn't yet cached.

## Macaroons in this design

Same chained-keyed-BLAKE3 construction as volume macaroons in
`architecture.md` — per-token nonce, AND-of-predicates evaluation.
Three artefacts.

**1. Session.** Auth-issued, CLI-held. One per operator login, ~7d
lifetime. Caveats `(Subject, OrgId, NotAfter)`. Chain-MAC'd under
`K_session`. Used only on the CLI ↔ auth channel; coord and mint
never see it.

**2. Primary macaroon.** Mint-issued, coord-held. One per coord,
minted at coord enrollment. Caveats `(CoordId, OrgId)` plus a TPC
`(location=<auth-url>, caveat_id=<CoordId,OrgId>)`. Chain-MAC'd
under `K_coord`. Long-lived (re-issued only on `K_M` rotation or
re-enrollment).

**3. Discharge.** Auth-issued, CLI-held + coord-cached. One per
`(session, coord)` pair, ~5min lifetime. Caveats `(Subject, OrgId,
CoordId, NotAfter)`. Chain-MAC'd under `K_disch`. The discharge is
*wide* — it attests "operator authorised on this coord for the next
5 min," without binding to a specific op or volume. Per-op narrowing
happens via CLI attenuation per IPC (see *Per-IPC flow*).

## Per-IPC flow

The CLI fetches a wide discharge once per `(session, coord)` pair
and re-uses it across many operator IPC verbs by attenuating it per
call.

### Fetching the wide discharge

When the CLI is about to call coord-X for an operator IPC and
doesn't have a cached non-expired discharge for `(session, coord-X)`:

1. CLI POSTs `<auth>/v1/discharge` with the session in
   `Authorization: Bearer`, body `{coord_id: "<coord_ulid>"}`.
2. Auth verifies the session under `K_session`, applies its policy
   ("may this Subject operate on this coord at all?"), and mints a
   discharge with caveats `(Subject, OrgId, CoordId,
   NotAfter=now+5min)` chain-MAC'd under `K_disch`.
3. CLI stores the discharge in memory, keyed by `(session, coord-X)`.

The discharge is "wide": no `Op` or `Volume` caveats, no per-IPC
narrowing baked in.

### Attenuating per IPC

For each operator IPC verb, CLI appends caveats to the cached wide
discharge before sending. Standard macaroon bearer-attenuation: the
holder of the trailing MAC can extend the chain with new caveats
without holding the root key.

```
attenuation caveats per IPC:
  Op       = "snapshot"
  Volume   = "myvm"
  NotAfter = now + 5s        (tight per-IPC bound)
  Nonce    = <random 16B>    (optional, for replay-sensitive verbs)
```

CLI sends `(attenuated_discharge, IPC body)` to coord.

### Coord verification

For each operator IPC, coord:

1. **Verify the primary.** Walk the stored primary's chain with
   `K_coord`. Reject on MAC mismatch.
2. **Locate the discharge.** The IPC bundle includes an attenuated
   discharge. Split it into `(wide_bytes, attenuation_chain)` at the
   wide discharge's published trailing tag.
3. **Validate the wide bytes.** Look up `wide_bytes` in the local
   discharge cache.
   - **Cache hit:** the wide bytes were vouched by auth at some
     earlier moment; trust them until their cached `NotAfter`.
   - **Cache miss:** POST `wide_bytes` to `<auth>/v1/discharge/verify`
     using coord's per-coord bearer. Auth verifies the MAC under
     `K_disch`, returns `{valid: true, expires_at: <NotAfter>}` or
     `{valid: false, ...}`. On valid, cache `(wide_bytes →
     expires_at)`. On invalid, reject the IPC.
4. **Verify the attenuation chain.** Walk the attenuation chain
   forward from the wide discharge's trailing tag (no key needed
   for chain extension). Reject on MAC mismatch.
5. **AND-evaluate every caveat** across the primary, wide
   discharge, and attenuation:
   - `CoordId` (in primary + wide discharge + TPC routing blob)
     matches coord's own ULID
   - `OrgId` matches coord's enrolled OrgId
   - `Subject` from the wide discharge is logged (no per-Subject
     policy at coord in the initial design)
   - `Op` (from attenuation) matches the dispatched verb
   - `Volume` (from attenuation) matches the IPC's target
   - all `NotAfter` values are in the future
   - `Nonce` (if present) hasn't been seen recently (per-verb,
     per-volume nonce cache)
6. If all pass, dispatch. If any fail, reject.

The discharge MAC is verified *once per cache entry*, at auth, on
the cache miss that introduced the entry. After that coord holds the
wide bytes as a trusted-on-receipt artefact (mint's vouch via
enrollment established the trust channel; auth's `/discharge/verify`
response is the per-discharge vouch within that channel). Attenuation
verification is local-only and doesn't require any auth-held key.

### Mint verification (assume-role)

Mint independently verifies on every `/v1/assume-role` call that
issues write-capable creds. Identical pattern, independent cache:

1. Verify the primary's chain with `K_M` (re-derives `K_coord` on
   demand from `coord_ulid`).
2. Cache lookup on `wide_bytes`; on miss call `<auth>/v1/discharge/verify`
   using mint's own bearer.
3. Walk the attenuation chain forward from the wide's trailing tag.
4. AND-evaluate caveats against the assume-role request shape.

Mint does not trust coord's vouch — it re-verifies. Defense in depth:
a compromised coord can still make assume-role calls but cannot
bypass mint's gate.

## Verification: what each verifier checks

| Check | Coord | Mint |
|---|---|---|
| Primary MAC | uses stored `K_coord` | re-derives `K_coord` from `K_M + coord_ulid` |
| Wide discharge MAC | not verified locally — trusted via cache (one-shot auth verify on miss) | same — independent cache, independent miss path |
| Attenuation chain MAC | walked forward from wide's trailing tag (no key) | same |
| `Op`, `Volume`, `NotAfter` caveats | matches the dispatched IPC verb | matches the assume-role request shape |
| `OrgId` matches enrolled org | matches coord's enrolled OrgId | matches mint's OrgId |
| `CoordId` on primary + discharge | matches coord's own ULID | used to derive `K_coord` and scope the call |
| `Nonce` (if present) | not in coord's recent-nonce cache | not in mint's recent-nonce cache |

### Which ops reach mint

Not every operator IPC verb passes through `/v1/assume-role`. Mint's
verifier sees the bundle only on S3-write paths.

| IPC verb shape | Coord verifies | Mint verifies |
|---|---|---|
| Read-only at coord (`volume list`, `volume status` from local index) | yes | not reached |
| Local-state mutation only (`volume register`, local `volume remove`) | yes | not reached |
| S3 read needed | yes | `coord-ro` cred path (existing, no operator discharge) |
| S3 write needed (`volume claim`, `volume release`, `volume snapshot`, `volume create` writing `names/`) | yes | yes — coord forwards `(primary, attenuated discharge)` with the assume-role call |

### Caller authentication is separate

Mint's bundle verification proves the *operator* authorised this
specific op. It does not prove the *caller* is a legitimate coord.
Coord-to-mint caller authentication uses mint's existing
cred-issuance auth path (the volume-macaroon-keyed mechanism mint
already has — unchanged by this design). Both are required for mint
to issue write-capable creds: caller-auth proves it's a real coord,
the bundle proves a human authorised the op.

## Forgery model

`K_disch` lives only at auth; coord and mint never hold any
discharge-verification key. The consequences:

- **Coord and mint cannot synthesise discharges.** Without `K_disch`
  they can't produce a MAC chain auth would accept.
- **Coord and mint cannot synthesise primaries.** Without `K_M` they
  can't produce primaries either.
- **A rooted coord can bypass its own local gate** — it controls
  the verifier code path, so it can accept anything. But auth has
  no verification record for the "accepted" discharge, and the
  audit-anchor divergence (see *Audit anchors*) surfaces this.
- **A rooted coord can replay cached discharges within their
  NotAfter.** Bounded by the wide discharge's 5min lifetime. After
  expiry, coord must call auth again, and a compromised
  coord-to-auth bearer is the only remaining attack surface.

Forgery requires `K_disch` or `K_M`, neither of which lives outside
auth and mint respectively. Audit divergence detects unauthorised
acceptance.

## Audit anchors

The design produces two correlated audit streams:

- **Auth service log** — every `/v1/discharge` issuance and every
  `/v1/discharge/verify` response (subject, coord, expires_at).
- **Coordinator / mint log** — every operator IPC accepted (op,
  volume, subject, attenuation nonce if any).

The invariant: every accepted IPC at coord must trace back to a
`/discharge/verify` call at auth within the wide discharge's
`NotAfter` window. Divergences:

| Auth `verify` log | Coord/mint accept log | Meaning |
|---|---|---|
| present | present | Normal |
| present | absent | Verified but not used — CLI cancelled before IPC, network drop |
| absent | present | Acceptance with no upstream verification — either `K_disch` leakage or coord lying about cache hits |

The `absent / present` row is unambiguous: it can only arise from
`K_disch` leakage at auth, or from a compromised verifier (coord or
mint) accepting un-vouched bytes. Either is a high-severity event.

## Caching

Each verifier holds two caches.

### Wide-discharge vouch cache

Key: `wide_discharge_bytes` (or hash). Value: `expires_at` (the
`NotAfter` returned by auth's `/discharge/verify`). TTL: until
`expires_at`.

Populated on cache miss via a one-shot auth round-trip. Once
populated, all IPCs that present the same wide discharge bypass the
auth round-trip until expiry.

Cache size is bounded by (active sessions) × (coords per session) ×
(turnover within NotAfter window). For typical operator load this is
a handful of entries per coord.

### Nonce cache (optional, per-verb)

Key: `(volume, op, nonce)`. Value: presence. TTL: matches the
attenuation `NotAfter` plus a small jitter.

Populated when a verb is configured to require freshness. Used to
reject replays within the attenuation window. Most IPC verbs are
idempotent at the coord layer and do not need a nonce cache; this is
opt-in per verb.

## Login flow

`elide operator login` supports two modes. The CLI selects mode by
whether `ELIDE_OPERATOR_API_KEY` is set; both end at the same
artefact — a session macaroon stored once, per-user, in a file under
`~/.elide/`. Structurally it's a macaroon under `K_session` with
caveats `(Subject, OrgId, NotAfter=login_time+7d)`. The session is a
CLI ↔ auth-service credential only — coord and mint never see it.

The stored session is org-scoped (mandatory `OrgId` caveat) and
covers every coordinator within that org. Operators in multiple orgs
need separate sessions per org.

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
4. `/v1/login/poll` returns the session; CLI stores it.

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
   session, stores it.

The key is read from the environment, never accepted on argv (would
appear in `ps`). The auth service typically issues shorter-lived
sessions for API-key logins than for interactive ones, and may set a
`MachineAccount=true` field on issued discharges so audit can
distinguish automated from human actions.

## Identity and policy

The wide discharge carries three identity claims:

- **OrgId is mandatory and enforced.** Set by the auth service from
  the org selected at login. Coord and mint reject any discharge
  whose `OrgId` doesn't match their enrolled OrgId.
- **Subject is mandatory and opaque.** A stable identifier (UUID,
  OIDC `sub`, opaque token) chosen by the auth service. Not a
  username or email — those change. The auth service is responsible
  for keeping `Subject` stable for a given human across renames and
  IdP changes.
- **CoordId is mandatory and scoped.** The discharge verifies only
  at the named coord.

Per-op and per-volume narrowing is **not** in the initial protocol
caveats (see *Deferred* below). For now: a Subject authorised on
coord X can do any operator op on any volume managed by coord X
within the wide discharge's 5min window, subject to the CLI's
attenuation (`Op`, `Volume`) being honoured by coord. The CLI
attenuation is *the* per-op binding in the initial design.

Beyond OrgId and CoordId enforcement, coord performs no
subject-keyed policy. All access control — allow-listing, RBAC —
lives at the auth service and is exercised at `/v1/discharge`
issuance time.

Coord log shape:

```
INFO operator_token::authn event=accept op=snapshot volume=myvm
  org=org_7vh3... subject=usr_2k9q... coord=01HXY...
  wide_expires_at=2026-05-26T14:28:00Z
```

## Cadence

Three lifetimes, three refresh rhythms.

**Sessions: ~7 days, refreshed only by re-running `elide operator
login`.** Default lifetime is auth-service policy. There is no
sliding renewal — when the session expires, the next IPC call fails
with a clear error and the operator runs `login` again.
Non-interactive (API-key) sessions are typically shorter (e.g. 1
hour); the API key is the long-lived credential and the session is
its derived form.

**Wide discharges: ~5 minutes, fetched per `(session, coord)` pair
on cache miss.** CLI caches in memory. After expiry, the next
operator IPC triggers a fresh fetch.

**Attenuations: per IPC, ~5s NotAfter, tight enough to bound replay
within the wide discharge's window.** Built by the CLI before
sending each IPC; not cached.

**Replay window.** Within the attenuation `NotAfter` a specific
attenuated discharge is theoretically replayable on coord. Most
operator IPC verbs are idempotent at the coord layer. For
replay-sensitive verbs the attenuation carries a `Nonce` field that
coord caches and rejects on replay.

## Reachability

The auth service must be reachable from three places:

- **Mint** — at enrollment, for `K_disch` rotation discovery, and
  for `/v1/discharge/verify` calls on cache miss during assume-role
  verification.
- **Coord** — for `/v1/discharge/verify` calls on cache miss during
  operator IPC verification. Coord uses the per-coord bearer mint
  brokered at enrollment.
- **The operator's CLI machine** — for `elide operator login` and
  per-`(session, coord)` `/v1/discharge` issuance. The interactive
  flow also needs the auth service reachable from the operator's
  laptop browser.

In a hosted deployment this is one public URL. In self-hosted prod
the same URL must be reachable from operator workstations and from
each coord+mint that need to verify discharges.

Verification at coord and mint is cached but **not offline**: a
cache miss requires an auth round-trip. If the auth service is
unreachable when a cache miss occurs, that IPC fails. The cache TTL
(5 min) is the bound on how long operator IPC can continue on a
specific cached discharge during an auth-service outage.

## Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange. Auth
reachability is in addition to those — operator IPC can ride a
cached wide discharge for up to 5 min through a transient outage,
but no longer. There is no offline escape hatch for operator login.

## Key rotation

Three keys can be rotated.

### `K_disch` rotation (auth-only)

Triggered by routine rotation or suspected compromise. Auth runs
with both `K_disch_old` and `K_disch_new` during an overlap window:

- New discharges minted under `K_disch_new` from rotation+1 onward.
- `/v1/discharge/verify` accepts MACs under either key during the
  overlap; after overlap, drops `K_disch_old`.
- Coord and mint experience this as transparent — they don't hold
  either key.

A leak of `K_disch` is the worst case: an attacker holding it can
forge any discharge for any coord. Emergency rotation drops the
overlap to zero and invalidates all in-flight cached wide discharges
(by having `/v1/discharge/verify` refuse all MACs under the old key).

### `K_M` rotation (mint's root)

The heaviest event in the system. Triggered by routine mint-root
rotation (annual/biennial) or if `K_M` is suspected compromised.

When `K_M` rotates, every `K_coord = HKDF(K_M, coord_ulid)` changes.
Mint runs with both `K_M_old` and `K_M_new` during a grace window:

1. Mint generates `K_M_new`, retains `K_M_old` for the window.
2. During the window, mint verifies presented primaries with both
   keys.
3. Each coord, on its next mint interaction (assume-role, primary
   refresh, proactive heartbeat), is re-issued a fresh primary
   under `K_M_new` and a fresh `K_coord_new`.
4. Coord swaps both atomically in `data_dir`.
5. After the grace window, mint drops `K_M_old`.

Coord's local verification path is unaffected throughout — the
stored primary and `K_coord` stay consistent because they were issued
together.

### `K_session` rotation (auth-only)

Trivial: only the auth service holds `K_session`. Rotation
invalidates all existing sessions; operators re-run `login`. Grace
window optional — auth can keep `K_session_old` to honour in-flight
sessions until their `NotAfter` expiry, then drop it.

### Summary

| Key | Affects | Coord/mint impact |
|---|---|---|
| `K_disch` | Discharge verification at auth | None — coord/mint don't hold this key |
| `K_M` | Per-coord `K_coord` and primary chain | Both stored `K_coord` and primary need refresh from mint |
| `K_session` | Sessions invalidated | None |

## API surface

Concrete HTTP endpoints. All requests and responses JSON; all
endpoints versioned under `/v1/`.

### Auth service — operator-facing

`POST /v1/login/start` (anonymous) — initiate device-code flow.

```json
request:  { "client_id": "elide-cli", "client_version": "1.2.3" }
response: {
  "device_code": "<opaque>",
  "user_code": "ABCD-WXYZ",
  "verification_uri": "https://auth.elide.example/device",
  "verification_uri_complete": "...?user_code=ABCD-WXYZ",
  "expires_in": 600,
  "interval": 5
}
```

`POST /v1/login/poll` (anonymous; `device_code` is the proof) — poll
for completion.

```json
request:  { "device_code": "<opaque>" }
response: { "session": "<base64 macaroon>", "expires_at": "...", "org_id": "org_..." }
```

Response 400 with body `{ "error": "authorization_pending" | "slow_down" |
"expired_token" | "access_denied" }` (RFC 8628 vocabulary).

`POST /v1/login/api-key` (Bearer API key in `Authorization` header) —
non-interactive session exchange. Response shape matches
`/login/poll` success. 401 invalid, 403 disabled.

`POST /v1/discharge` (Bearer session) — issue a wide discharge.

```json
request:  { "coord_id": "01HXY..." }
response: { "discharge": "<base64 macaroon>", "expires_at": "..." }
```

The returned discharge has caveats `(Subject, OrgId, CoordId,
NotAfter)` and is MAC'd under `K_disch`. 401 session expired, 403
policy denies operating on this coord.

### Auth service — verifier-facing

`POST /v1/discharge/verify` (Bearer per-coord or mint credential) —
one-shot verification of a wide discharge.

```json
request:  { "discharge": "<base64 macaroon>" }
response: { "valid": true, "expires_at": "...", "subject": "usr_...", "org_id": "...", "coord_id": "..." }
       or { "valid": false, "reason": "expired" | "mac_mismatch" | "unknown_coord" | ... }
```

The verifier presents the wide discharge bytes; auth verifies the
MAC under `K_disch` and returns the validated payload (so the
verifier can log the Subject without re-parsing). 401 caller-auth
failed, 429 rate-limited.

### Auth service — mint-facing

`POST /v1/mint/enroll` (anonymous; enrollment token is the proof) —
one-shot mint enrollment.

```json
request:  { "enrollment_token": "<opaque>" }
response: { "org_id": "org_7vh3...", "mint_bearer": "<opaque>" }
```

400 invalid / expired / already-used token.

`POST /v1/coord/provision` (mint bearer) — issue a per-coord bearer
that coord uses to call `/v1/discharge/verify`. Called by mint
during coord enrollment, returns the bearer to mint which relays it
to coord.

```json
request:  { "coord_id": "01HXY..." }
response: { "coord_bearer": "<opaque>", "expires_at": "..." }
```

### Mint — coord-facing

`POST /v1/coord/enroll` (anonymous; mint-signed token is the proof) —
one-shot coord enrollment.

```json
request:  { "enrollment_token": "<mint-signed opaque>" }
response: {
  "coord_ulid": "01HXY...",
  "k_coord": "<base64 32-byte symmetric key>",
  "primary_macaroon": "<base64 macaroon>",
  "org_id": "org_7vh3...",
  "auth_service_url": "https://auth.elide.example/",
  "coord_bearer": "<opaque>"
}
```

`k_coord = HKDF(K_M, coord_ulid)`. The `primary_macaroon` carries
caveats `(CoordId, OrgId)` plus a TPC `(location=<auth_service_url>,
caveat_id=<routing blob>)`. Coord persists the full response in
`data_dir`. Mint stays stateless (re-derives `k_coord` on demand).

Mint's existing cred-issuance endpoints (`assume-role` and friends)
are unchanged in shape but now additionally accept and verify a
`(primary, attenuated discharge)` bundle for ops that require
operator authorisation.

## Config

`coordinator.toml` points at mint for enrollment; it carries no
auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint URL, OrgId, auth-service URL, `K_coord`, primary macaroon, and
the coord-to-auth bearer all land in the coord's `data_dir` at
`elide-coordinator setup` time and are not human-edited thereafter.

Mint's config carries the `[auth]` block pointing at the auth
service:

```toml
[auth]
endpoint = "https://auth.elide.example/"
```

Mint persists its OrgId, mint bearer credential, and the auth-service
URL to its own state at `elide-mint setup --enrollment-token` time.

## Mint as auth (demo only)

For dev, test, and demo deployments, mint can mount the auth route
handlers itself:

```toml
# mint config
[auth]
demo-enabled = false   # default
```

When `true`, mint serves `/v1/login/*`, `/v1/discharge`, and
`/v1/discharge/verify` alongside its cred-issuance routes,
rubber-stamping every request — no browser, no real authentication.
Mint generates `K_disch` and `K_session` for itself at demo startup
(no auth-service round-trip), signs discharges under `K_disch`, and
verifies them on demand. The coord codepath is identical to prod:
cache lookup → on miss, call `/discharge/verify` → cache verdict.
Enrollment tokens are also rubber-stamped: a coord can enroll with
any token (or none) and is assigned `OrgId=demo`.

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

## Deferred: per-op and per-volume narrowing in caveats

The initial design's wide discharge attests "Subject S authorised on
CoordId C until NotAfter." Per-op (`Op=snapshot`) and per-volume
(`Volume=myvm`) narrowing happens via **CLI-added attenuations**,
not via caveats baked in by auth at issuance time.

Adding auth-side per-op or per-volume policy later is purely
additive:

- Auth bakes `AllowedOps=[...]` and/or `AllowedVolumes=[...]` (or
  group equivalents) into the discharge as additional first-party
  caveats at issuance time.
- Coord and mint pick up two extra AND clauses on `Op` and `Volume`
  evaluation.
- The wire format extends; existing caveat handling doesn't change.
- The caching model is unaffected — the wider discharge bytes
  change, but the cache key is still the discharge bytes and the
  TTL is still `NotAfter`.

What this gains: per-op revocation latency bounded by the wide
discharge `NotAfter` (5min) instead of being unbounded; finer-grained
audit at the auth-issuance layer; the ability to express "Alice can
manage volume A but not B on the same coord."

Reasonable to add when the deployment grows multi-team workloads on
shared coords or when finer policy is requested. Not in the initial
shape.

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
