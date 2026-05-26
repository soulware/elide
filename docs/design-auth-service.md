# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
sessions and wide discharges, and the coord/mint verification chain
that consumes them. It builds on the principle established in
[`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-s3-writes-not-verbs)
— **every S3 mutation requires operator authorisation** — and is the
concrete shape of the *third-party-caveat discharge* anchor mint
requires for write-capable cred issuance.

**Status: proposed. Not yet implemented.**

## Principle

Every operator IPC verb requires a CLI-attenuated discharge alongside
coord's mint-issued primary macaroon. All three artefacts (session,
primary, discharge) are chained-keyed-BLAKE3 macaroons — the same
construction as volume macaroons in `architecture.md`. One primitive
end to end.

The design follows the canonical [Fly.io
macaroon](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md)
shape: third-party caveats with `VID`/`CID` for distributing the
discharge HMAC key, [Fly's
verify/clear split](https://fly.io/blog/macaroons-escalated-quickly/)
for separating cryptographic verification from caveat-predicate
evaluation, and isolated verification at a trusted service.

Three structural properties hold:

- **Mint is the sole holder of `K_M`** (primary chain root key). It
  derives `K_coord = HKDF(K_M, coord_ulid)` on demand at coord
  enrollment to chain the primary; it can re-derive at any time to
  walk the chain on verification calls.
- **Mint and auth share `K_M-A`** (per-org wrapping key for
  third-party-caveat `CID`s). Established at mint enrollment.
- **Verification is centralised at mint**, the way Fly centralises
  signature verification at `tkdb`. Coord holds no chain key, no
  discharge key; it cannot verify anything cryptographically. Coord
  forwards bundles to mint for verification and caches the resulting
  verdict.

The **trust circle for discharge minting and verification is
`{auth, mint}`**. Auth issues discharges (legitimate path). Mint
verifies them. Coord neither issues nor verifies — it forwards and
clears.

The TPC binding is woven into the primary's chain MAC, so the
discharge requirement cannot be stripped by any party who cannot
mint primaries. Auth's role as legitimate issuer is anchored
operationally (it's the only party an unprivileged CLI can ask) and
in audit (every legitimate discharge has an auth-side issuance log
entry).

Operator IPC verbs are currently ungated; this design re-gates them.
Volume↔coord IPC (PID-bound volume macaroons) is unchanged.

### Verify and clear

Following [Fly's
formulation](https://fly.io/blog/macaroons-escalated-quickly/):

- **Verification** = HMAC checking. Pure crypto, stable for given
  bytes, cacheable. Runs at the holder of the relevant key
  material. In this design, that's mint.
- **Clearing** = caveat predicate evaluation against live request
  context. Cannot be cached (the context changes per request).
  Runs at the verifier that has the context. In this design,
  that's coord (which knows the IPC verb, the target volume, and
  the current time).

The split places coord and mint cleanly: mint verifies bytes; coord
clears predicates. Auth participates in verification only at
discharge-issuance time — it doesn't sit on the verification path
at runtime.

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
  mint. Derives per-coord primary chain keys via HKDF.
- `K_M-A` — per-org AEAD key shared between mint and auth. Used to
  encrypt and decrypt the `CID` field of each coord's TPC, so auth
  can recover per-coord ephemeral `r` keys on demand without holding
  per-coord state.
- `K_session` — auth-service-only root for sessions. Never leaves
  auth.
- `K_coord = HKDF(K_M, coord_ulid)` — per-coord primary chain key.
  Mint re-derives on demand. **Coord does not hold this key.**
- `r` — per-coord ephemeral key. Auth uses it (recovered from `CID`)
  as the HMAC root when minting discharges; mint recovers it from
  either `CID` or by walking the primary chain to its `VID`. Lives
  for the primary's lifetime.

### Mint ↔ auth enrollment

Slow cadence — once per org lifetime plus occasional rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, NotAfter=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint POSTs `<auth>/v1/mint/enroll` with the token.
5. Auth verifies the token, records org X as activated, generates
   `K_M-A`, returns `(OrgId, K_M-A, auth-service URL, mint bearer)`.
6. Mint persists. The mint bearer is for subsequent auth calls
   (e.g., enrolment-side rotation flows). `K_M-A` is the AEAD key
   for `CID` construction and decryption.

### Coord ↔ mint enrollment

Per-coord deployment cadence. Mint generates the per-coord ephemeral
`r` here and embeds it into the primary's TPC, then discards it.

1. Mint admin generates a one-shot coord-enrollment token signed by
   mint: `OrgId=X, Purpose=CoordEnroll, NotAfter=now+15m`.
2. Coord admin runs `elide-coordinator setup --enrollment-token
   <token>`.
3. Coord POSTs to mint with the token.
4. Mint verifies the token, allocates `coord_ulid`, derives
   `K_coord = HKDF(K_M, coord_ulid)`, generates fresh `r`, and mints
   a **primary macaroon** for this coord:
   - First-party caveats: `CoordId=<coord_ulid>, OrgId=X`
   - Third-party caveat: `(location=<auth-url>, VID, CID)`
     - `VID = AEAD-encrypt(T_n, r)` — where `T_n` is the chain tag
       at the TPC position. Decryptable by anyone who can walk the
       primary chain (i.e., mint).
     - `CID = AEAD-encrypt(K_M-A, r ‖ CoordId ‖ OrgId)` —
       decryptable by mint and auth (both hold `K_M-A`).
   - Chain MAC'd with `K_coord`.
5. Mint discards `r` and `K_coord`. Both are re-derivable on demand
   from `K_M + coord_ulid` (for `K_coord`) and from chain-walk +
   `VID` or from `CID` + `K_M-A` (for `r`).
6. Mint returns to coord: `coord_ulid`, the primary macaroon,
   auth-service URL, `OrgId`.
7. Coord persists the response in its `data_dir`. **Coord does not
   receive `K_coord`.** Coord stores the primary bytes only.

After enrollment coord has the primary as a static bearer artefact
and the auth-service URL for the CLI to use. It holds no key
material it can use to verify primaries or discharges.

## Macaroons in this design

Three artefacts, same chained-keyed-BLAKE3 construction.

**1. Session.** Auth-issued, CLI-held. One per operator login, ~7d
lifetime. Caveats `(Subject, OrgId, NotAfter)`. Chain-MAC'd under
`K_session`. Used only on the CLI ↔ auth channel; coord and mint
never see it.

**2. Primary macaroon.** Mint-issued, coord-held. One per coord,
minted at coord enrollment. Caveats `(CoordId, OrgId)` plus a TPC
`(location, VID, CID)`. Chain-MAC'd under `K_coord`. Long-lived
(re-issued only on `K_M` rotation or coord re-enrollment).

**3. Wide discharge.** Auth-issued, CLI-held + coord-cached
(as a verification verdict). One per `(session, coord)` pair, ~5min
lifetime. Caveats `(Subject, OrgId, CoordId, NotAfter)`. Chain-MAC'd
under `r` (the per-coord ephemeral key, recovered by auth from
`CID`). Nonce equals `CID` — this is the binding mechanism between
the discharge and a specific primary's TPC (per Fly's mechanism: a
discharge for primary A's TPC has `CID_A` as its nonce, and won't
match primary B's TPC where the verifier looks for `CID_B`).

The discharge is "wide" — it attests "operator authorised on this
coord for the next 5 min," without binding to a specific op or
volume. Per-op narrowing happens via CLI attenuation per IPC (see
*Per-IPC flow*).

## Per-IPC flow

### Fetching the wide discharge

When the CLI is about to call coord-X for an operator IPC and
doesn't have a cached non-expired wide discharge for `(session,
coord-X)`:

1. CLI fetches coord-X's `CID` once (it's the routing blob from the
   primary's TPC; coord exposes it via a local read endpoint — the
   value isn't secret, it's only useful when paired with `K_M-A`
   which only mint and auth hold).
2. CLI POSTs `<auth>/v1/discharge` with the session in
   `Authorization: Bearer`, body `{cid: "<base64>"}`.
3. Auth verifies the session under `K_session`, AEAD-decrypts `CID`
   with `K_M-A` → recovers `(r, CoordId, OrgId)`. Cross-checks the
   decoded `OrgId` against the session's `OrgId`. Applies its policy
   ("may this Subject operate on this coord at all?"). Mints a
   discharge:
   - Caveats `(Subject, OrgId, CoordId, NotAfter=now+5min)`.
   - Chain-MAC'd under `r`.
   - Nonce equals `CID`.
4. CLI stores the discharge in memory, keyed by `(session, coord-X)`.

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

### Coord: forward and clear

Coord receives `(attenuated_discharge, IPC body)`. It pulls its
stored primary out of `data_dir` and runs the following.

1. **Split the attenuated discharge** into `(wide_bytes,
   attenuation_chain)` at the wide discharge's trailing tag.
2. **Cache lookup on `wide_bytes`** in coord's verification cache.
   - **Cache hit**: the wide bytes have already been verified by
     mint within their `NotAfter` window. Skip to step 4.
   - **Cache miss**: forward `(primary, wide_bytes)` to mint at
     `<mint>/v1/discharge/verify`. Mint returns `{valid: true,
     expires_at: <NotAfter>, caveats: {...}}` or `{valid: false,
     reason: "..."}`. On valid, cache `(wide_bytes → expires_at,
     caveats)`. On invalid, reject the IPC.
3. **Clear every caveat** across the primary (which coord can read
   without verifying), the wide discharge (caveats returned by
   mint), and the attenuation chain (which coord can read directly
   from `attenuation_chain` — chain extension is keyless, so coord
   can also walk the attenuation chain to confirm the trailing MAC
   is consistent with the wide's trailing tag). AND-evaluate against
   the live IPC context:
   - `CoordId` (in primary + wide discharge) matches coord's own
     ULID.
   - `OrgId` matches coord's enrolled OrgId.
   - `Subject` from the wide discharge is logged (no per-Subject
     policy at coord in the initial design).
   - `Op` (from attenuation) matches the dispatched verb.
   - `Volume` (from attenuation) matches the IPC's target.
   - all `NotAfter` values are still in the future.
   - `Nonce` (if present) hasn't been seen recently (per-verb,
     per-volume nonce cache at coord).
4. If all caveats clear, dispatch. If any fails, reject. Clearing
   results are never cached — the context changes every IPC.

Coord does **not** verify the primary's chain MAC, the wide
discharge's MAC, or recover `r` from `VID`. It holds no key material
that would let it do so. All cryptographic verification happens at
mint (or, transitively, was done by mint and cached).

### Mint: verification on `/v1/discharge/verify` and on assume-role

Mint exposes two endpoints that handle bundle verification:

- `/v1/discharge/verify` — called by coord when coord has a cache
  miss on a wide discharge. Returns the verification verdict.
- `/v1/assume-role` (existing) — called by coord when it needs
  write-capable S3 creds. Mint re-verifies the bundle from scratch
  (defense in depth) before issuing creds.

Both endpoints share a single verification routine:

1. Walk the primary's chain with `K_coord` (re-derived from `K_M +
   coord_ulid`, extracted from the primary's first-party `CoordId`
   caveat). Confirm the trailing MAC. At the TPC, hold `T_n`.
2. Decrypt `VID` with `T_n` → recover `r`. (Or, equivalently, decrypt
   `CID` with `K_M-A` — both paths yield the same `r`. Mint uses
   whichever it has cached or finds convenient.)
3. Verify the wide discharge's MAC chain under `r`. Confirm the
   nonce equals the primary's `CID` (the binding check).
4. (Verify endpoint) Return verdict + wide discharge's caveats to
   coord.
5. (Assume-role endpoint) Walk the attenuation chain forward from
   the wide's trailing tag, verify the trailing MAC, AND-evaluate
   all caveats against the assume-role request shape, then issue
   creds.

Mint holds its own verification cache keyed by wide-discharge bytes
so a coord's `/discharge/verify` call followed by an `/assume-role`
call within the same window doesn't repeat the chain walk
unnecessarily.

## Caching

Verification results are cacheable; clearing results are not. The
former is a function of (bytes, key) and is stable for the
discharge's lifetime; the latter is a function of (caveat, live
context) and changes every IPC. Each verifier holds two caches —
one for the cacheable side of verification, one for nonce-based
replay defence during clearing.

### Wide-discharge verification cache (coord-side)

Key: `wide_discharge_bytes` (or hash). Value: `(expires_at,
caveats)`. TTL: until `expires_at`.

Populated on cache miss via a one-shot mint round-trip (`/discharge/verify`).
Once populated, all subsequent IPCs that present the same wide
discharge skip the mint round-trip until expiry. Same bytes, same
verification verdict — the MAC over a fixed byte sequence is
deterministic and mint's verdict over fixed bytes doesn't change
between calls.

Cache size is bounded by (active sessions) × (coords per session) ×
(turnover within `NotAfter` window). For typical operator load this
is a handful of entries per coord.

### Wide-discharge verification cache (mint-side)

Same shape as coord's cache. Lets mint skip redundant chain walks
when coord's `/discharge/verify` call is followed by an
`/assume-role` call within the same window.

### Nonce cache (optional, per-verb, at coord)

Key: `(volume, op, nonce)`. Value: presence. TTL: matches the
attenuation `NotAfter` plus a small jitter.

Populated during clearing when a verb is configured to require
freshness. Used to reject replays within the attenuation window.
Most IPC verbs are idempotent at the coord layer and do not need a
nonce cache; this is opt-in per verb. Not a cache of clearing
results — it's a small store the freshness predicate consults to
clear the `Nonce` caveat.

## Forgery model

The trust circle for discharge minting and verification is `{auth,
mint}`. Coord is outside it.

What each party can do under compromise:

- **Coord rooted**: no key material. Cannot synthesise primaries
  (needs `K_M`), cannot synthesise discharges (needs `r` or
  `K_M-A`), cannot decrypt `VID` (no `K_coord`), cannot decrypt
  `CID` (no `K_M-A`). The only attack surface is *lying about
  clearing* (accepting an IPC that should have been rejected) or
  *lying about cache hits* (skipping the mint forward for unseen
  bytes). Both are detectable at audit: every accepted IPC at coord
  should trace through `/discharge/verify` at mint (which has its
  own log) which should trace to `/v1/discharge` at auth.
- **Mint rooted**: holds `K_M` (can derive any `K_coord`, can walk
  any primary's chain, can recover any `r` from `VID`) and `K_M-A`
  (can decrypt any `CID` to recover any `r`). Can forge any
  discharge for any coord. This is the trust-circle property:
  mint is fundamentally trusted because we've placed it inside the
  circle. Audit-anchor divergence at auth still detects forgery if
  done post-hoc (forged discharges have no auth-side issuance
  record).
- **Auth rooted**: holds `K_M-A` and `K_session`. Can mint
  discharges for any coord (decrypts any `CID`, recovers `r`, signs
  discharges). Same trust-circle property. Auth-side audit is
  self-attesting in this case — but mint's `/discharge/verify` log
  is a secondary signal.

Forgery requires `K_M`, `K_M-A`, or being mint/auth itself. None of
these lives at coord.

## Audit anchors

The design produces three correlated audit streams:

- **Auth log**: every `/v1/discharge` issuance (subject, coord_id
  via decoded CID, expires_at).
- **Mint log**: every `/v1/discharge/verify` and every assume-role
  verification (coord_id from primary, discharge nonce = CID,
  expires_at).
- **Coord log**: every operator IPC accepted (op, volume, subject,
  attenuation nonce if any).

The audit invariant: every accepted IPC at coord must trace through
a `/discharge/verify` (or `/assume-role` verification) at mint,
which must trace to a `/v1/discharge` issuance at auth, all within
the wide discharge's `NotAfter` window.

| Auth issuance | Mint verify | Coord accept | Meaning |
|---|---|---|---|
| present | present | present | Normal |
| present | present | absent | Verified but never accepted — CLI cancelled, network drop |
| present | absent | absent | Issued but never reached mint — CLI cancelled before any IPC |
| absent | present | present | Mint verified without an upstream issuance — `K_M-A` leak at mint or auth-issuance bypass |
| absent | absent | present | Coord accepted without an upstream verification — coord lying about cache hits |

The two `present accept` divergence rows are unambiguous forgery
signals. The first (`absent issuance, present verify`) indicates
`K_M-A` or `K_M` leakage. The second (`absent verify, present
accept`) indicates a compromised coord skipping the mint forward.

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
operator IPC triggers a fresh fetch from auth.

**Attenuations: per IPC, ~5s NotAfter, tight enough to bound replay
within the wide discharge's window.** Built by the CLI before
sending each IPC; not cached.

**Replay window.** Within the attenuation `NotAfter` a specific
attenuated discharge is theoretically replayable on coord. Most
operator IPC verbs are idempotent at the coord layer. For
replay-sensitive verbs the attenuation carries a `Nonce` field that
coord caches and rejects on replay.

## Reachability

The auth service must be reachable from two places:

- **The operator's CLI machine** — for `elide operator login` and
  per-`(session, coord)` `/v1/discharge` issuance. The interactive
  flow also needs the auth service reachable from the operator's
  laptop browser.
- **Mint** — at enrollment, for `K_M-A` rotation discovery, and (as
  a Bearer-cred client) for any future auth-side flows.

The auth service is **not** reachable from coord at runtime. Coord
talks only to mint for verification; mint verifies offline once
enrollment has completed.

If the auth service is unreachable, CLI cannot fetch fresh
discharges. Operator IPC can ride a cached wide discharge for up to
5 min through a transient outage, but no longer. There is no offline
escape hatch for operator login.

## Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange.
Operator IPC additionally requires auth reachable from the CLI for
discharge issuance. Mint↔coord verification is offline once
enrollment completes; only the CLI→auth path is online at runtime.

## Key rotation

Four keys/values can be rotated.

### `K_M-A` rotation (mint ↔ auth wrapping key)

Triggered by routine auth-service-side rotation, or if `K_M-A` is
suspected compromised. Auth runs with both `K_M-A_old` and
`K_M-A_new` during a grace window. When `K_M-A` rotates, every
existing primary's `CID` becomes undecodable by the new key — auth
can no longer recover `r` from those `CID`s, so fresh discharges
can't be issued against old primaries.

Resolution is pull-on-verify-fail: when the CLI's `/v1/discharge`
call fails with a CID-decode error, the CLI signals coord to
refresh. Coord fetches a fresh primary from mint via
`GET /v1/coord/primary`. Mint re-issues with a fresh `r`, fresh
`VID` (under the new chain tag), and fresh `CID` (encrypted under
the new `K_M-A`). Coord swaps the stored primary. The CLI fetches
the new `CID` from coord and retries the discharge request. Bounded
by one retry per in-flight verification.

### `K_M` rotation (mint's root)

The heaviest event in the system. Triggered by routine mint-root
rotation (annual/biennial) or if `K_M` is suspected compromised.

When `K_M` rotates, every `K_coord = HKDF(K_M, coord_ulid)` changes,
and therefore every primary's chain MAC becomes verifiable only
under the new `K_coord`. Mint runs with both `K_M_old` and `K_M_new`
during a grace window:

1. Mint generates `K_M_new`, retains `K_M_old` for the window.
2. During the window, mint verifies presented primaries by trying
   `K_coord_new` first then falling back to `K_coord_old`.
3. Each coord, on its next mint interaction (verification call,
   assume-role, or a proactive primary refresh), is re-issued a
   fresh primary under `K_M_new`. The fresh primary has a new `r`
   (so `VID` and `CID` are fresh too).
4. Coord swaps the stored primary atomically in `data_dir`.
5. After the grace window, mint drops `K_M_old`.

### `r` rotation (per-coord)

`r` is rotated whenever the primary is reissued — `K_M` rotation,
`K_M-A` rotation, or a deliberate primary refresh. Lifetime is tied
to the primary's lifetime.

### `K_session` rotation (auth-only)

Trivial: only the auth service holds `K_session`. Rotation
invalidates all existing sessions; operators re-run `login`. Grace
window optional — auth can keep `K_session_old` to honour in-flight
sessions until their `NotAfter` expiry, then drop it.

### Summary

| Key | Affects | Resolution path |
|---|---|---|
| `K_M-A` | `CID` undecodable; discharges can't be issued against old primary | CLI signals coord; coord refreshes primary; CLI retries `/v1/discharge` |
| `K_M` | Per-coord `K_coord` changes; primaries need re-issue | Mint re-issues primaries on next interaction; grace window covers in-flight |
| `r` | Per-coord; rotated with primary | Automatic on primary re-issue |
| `K_session` | Sessions invalidated | Operators re-run `login` |

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

`POST /v1/login/poll` (anonymous; `device_code` is the proof).

```json
request:  { "device_code": "<opaque>" }
response: { "session": "<base64 macaroon>", "expires_at": "...", "org_id": "org_..." }
```

`POST /v1/login/api-key` (Bearer API key) — non-interactive session
exchange. Response shape matches `/login/poll` success.

`POST /v1/discharge` (Bearer session) — issue a wide discharge.

```json
request:  { "cid": "<base64>" }
response: { "discharge": "<base64 macaroon>", "expires_at": "..." }
```

The returned discharge has caveats `(Subject, OrgId, CoordId,
NotAfter)`, is chain-MAC'd under `r` (recovered from `CID`), and has
nonce equal to `CID`. 401 session expired, 403 policy denies, 422
`CID` decode failure (signals `K_M-A` rotation).

### Auth service — mint-facing

`POST /v1/mint/enroll` (anonymous; enrollment token is the proof) —
one-shot mint enrollment.

```json
request:  { "enrollment_token": "<opaque>" }
response: {
  "org_id": "org_7vh3...",
  "k_m_a": "<base64 32-byte AEAD key>",
  "mint_bearer": "<opaque>"
}
```

`GET /v1/mint/k-m-a` (mint bearer) — fetch current `K_M-A` after
rotation.

### Mint — coord-facing

`POST /v1/coord/enroll` (anonymous; mint-signed token is the proof)
— one-shot coord enrollment.

```json
request:  { "enrollment_token": "<mint-signed opaque>" }
response: {
  "coord_ulid": "01HXY...",
  "primary_macaroon": "<base64 macaroon>",
  "org_id": "org_7vh3...",
  "auth_service_url": "https://auth.elide.example/"
}
```

The `primary_macaroon` carries caveats `(CoordId, OrgId)` plus a TPC
`(location, VID, CID)`. Coord persists the response in `data_dir`.
Mint stays stateless across coords (re-derives `K_coord` and `r` on
demand).

`GET /v1/coord/primary` (coord-authenticated via the cred-issuance
path) — fetches a fresh primary embedding new `VID`/`CID`. Used by
coord on pull-on-verify-fail after `K_M-A` rotation.

```json
response: { "primary_macaroon": "<base64 macaroon>" }
```

`POST /v1/discharge/verify` (coord-authenticated) — verify a wide
discharge. Coord forwards the primary and wide discharge bytes; mint
runs the verification routine described in *Mint: verification* and
returns the verdict + caveats.

```json
request:  {
  "primary": "<base64 macaroon>",
  "wide_discharge": "<base64 macaroon>"
}
response: {
  "valid": true,
  "expires_at": "...",
  "caveats": {
    "subject": "usr_2k9q...",
    "org_id": "org_7vh3...",
    "coord_id": "01HXY...",
    "not_after": "..."
  }
}
```

Or 200 with `{"valid": false, "reason": "expired" | "mac_mismatch" |
"unknown_coord" | ...}`.

Mint's existing cred-issuance endpoints (`/v1/assume-role` and
friends) are unchanged in shape but now additionally accept and
verify a `(primary, attenuated discharge)` bundle for ops that
require operator authorisation.

### Coord — CLI-facing

`GET /v1/coord/cid` (local socket; anonymous within the host's IPC
trust boundary) — exposes the `CID` from coord's stored primary's
TPC. Not secret; just routing metadata for the CLI to include in its
`/v1/discharge` request.

```json
response: { "cid": "<base64>" }
```

## Config

`coordinator.toml` points at mint for enrollment; it carries no
auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint URL, OrgId, auth-service URL, and the primary macaroon all
land in the coord's `data_dir` at `elide-coordinator setup` time and
are not human-edited thereafter.

Mint's config carries the `[auth]` block pointing at the auth
service:

```toml
[auth]
endpoint = "https://auth.elide.example/"
```

Mint persists its OrgId, `K_M-A`, mint bearer, and the auth-service
URL to its own state at `elide-mint setup --enrollment-token` time.

## Mint as auth (demo only)

For dev, test, and demo deployments, mint can mount the auth route
handlers itself:

```toml
# mint config
[auth]
demo-enabled = false   # default
```

When `true`, mint serves `/v1/login/*` and `/v1/discharge` alongside
its cred-issuance and verification routes, rubber-stamping every
login — no browser, no real authentication. Mint generates `K_M-A`
and `K_session` for itself at demo startup (no auth-service
round-trip). Enrollment tokens are also rubber-stamped: a coord can
enroll with any token (or none) and is assigned `OrgId=demo`. The
coord codepath is identical to prod: forward bundle to mint for
verification, cache verdict, clear caveats.

Two startup-time safety checks when `demo-enabled = true`:

- Mint refuses to start unless bound to loopback / UDS.
- Mint logs `WARN auth=demo: all operator sessions are unauthenticated`
  at startup and per issued session.

Both are config-time checks, not per-request branches — the verifier
in coord and mint stays unconditional. The mint binary has no
webauthn / OIDC / SAML code; production auth implementations live in
the separate auth service binary only.

The canonical test-fixture pattern is **demo mint + non-interactive
login**: a single mint process with `demo-enabled = true` bound to a
UDS, plus `ELIDE_OPERATOR_API_KEY=test` on the harness. The full
wire flow runs end-to-end with no browser and no `#[cfg(test)]`
shortcuts anywhere.

## Deployment shapes

| Deployment | Auth packaging | Auth backend |
|---|---|---|
| Dev / test / demo | mint serves auth routes (`demo-enabled = true`) | rubber-stamp, instant session |
| Single-tenant self-hosted prod | separate auth service binary | real (webauthn / OIDC / …) |
| Multi-tenant hosted | separate auth service binary | real, full SSO |

Mint-as-auth is fine as long as there is **one identity authority**
(single mint or HA replicas of one logical mint with a shared key).
With multiple distinct mints — sharded by tenant / region — one
would have to be nominated as the auth-primary, which is effectively
a separate logical auth service in shared packaging. At that point
splitting the binaries is cleaner.

## Deferred: per-op and per-volume narrowing in caveats

The initial design's wide discharge attests "Subject S authorised on
CoordId C until NotAfter." Per-op (`Op=snapshot`) and per-volume
(`Volume=myvm`) narrowing happens via CLI-added attenuations, not
via caveats baked in by auth at issuance time.

Adding auth-side per-op or per-volume policy later is purely
additive:

- Auth bakes `AllowedOps=[...]` and/or `AllowedVolumes=[...]` (or
  group equivalents) into the discharge as additional first-party
  caveats at issuance time.
- Coord picks up two extra AND clauses on `Op` and `Volume`
  clearing.
- The wire format extends; existing caveat handling doesn't change.
- The caching model is unaffected — the wider discharge bytes
  change, but the cache key is still the discharge bytes and the
  TTL is still `NotAfter`.

What this gains: per-op revocation latency bounded by the wide
discharge `NotAfter` (5 min) instead of being unbounded; finer
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
