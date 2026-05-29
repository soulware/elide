# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
sessions and wide discharges, and the coord/mint verification chain
that consumes them. It builds on the principle established in
[`design-auth-model.md`](design-auth-model.md#proposed-operator-tokens-gate-operator-initiated-s3-writes)
— **every operator-initiated S3 mutation requires operator
authorisation** — and is the concrete shape of the
*third-party-caveat discharge* anchor mint requires for
operator-attested cred issuance.

**Status: partially implemented.** Mint's verification routine
(`/v1/verify` plus the assume-role bundle check) and the demo discharge
issuer (mint-as-auth `/v1/discharge`, operator-write CID arm) are built
and exercised end-to-end by the mint CLI as the first client — `mint
client assume-role` on a TPC-bearing role fetches a discharge and
presents the bundle (see
[`design-mint.md`](design-mint.md#reference-client--demo)). The
standalone auth-service binary — which owns operator sessions and
login — plus the coord-side forward-and-clear and the verification
caches remain proposed. (Sessions and login are an auth-service
concern only; mint-as-auth never grows them.)

## Terminology

The operator-authorisation surface attaches a third-party caveat to
two of the role credentials mint already issues at coord enrollment
(see [`design-mint.md`](design-mint.md)). Throughout this doc:

- **Primary** — any TPC-bearing role credential. At enrollment a
  coord receives six role credentials; the two operator-write ones
  (`coord-rw`, `volume-rw`) carry a TPC and are therefore primaries
  in this sense. The other four (`coord-ro`, `volume-ro`,
  `coord-rw-background`, `volume-rw-background`) carry no TPC and
  are not primaries.
- **Discharge anchor** — the specific primary coord nominates when
  it forwards a bundle on `/v1/verify`. Every primary
  shares the same `r` and `CID` (see *Keys* below), so the choice
  is arbitrary; coord uses `coord-rw` by convention because every
  coord holds it.

There is no separate operator-auth primary artefact distinct from
the role credentials.

## Principle

Every operator IPC verb that initiates an S3 mutation requires a
CLI-attenuated discharge alongside one of coord's TPC-bearing role
credentials. Sessions, primaries, and discharges are
chained-keyed-BLAKE3 macaroons — the same construction as volume
macaroons in `architecture.md`. One primitive end to end.

The design follows the canonical [Fly.io
macaroon](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md)
shape: third-party caveats with `VID`/`CID` for distributing the
discharge HMAC key, [Fly's
verify/clear split](https://fly.io/blog/macaroons-escalated-quickly/)
for separating cryptographic verification from caveat-predicate
evaluation, and isolated verification at a trusted service.

Three structural properties hold:

- **Mint is the sole holder of `K_M`** (role-credential chain root
  key). It derives `K_coord = HKDF(K_M, coord_ulid)` on demand at
  coord enrollment to chain every role credential mint issues for
  that coord; it can re-derive at any time to walk the chain on
  verification calls.
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

The TPC binding is woven into each primary's chain MAC, so the
discharge requirement cannot be stripped by any party who cannot
mint primaries. Auth's role as legitimate issuer is anchored
operationally (it's the only party an unprivileged CLI can ask) and
in audit (every legitimate discharge has an auth-side issuance log
entry).

Operator IPC verbs are currently ungated; this design re-gates
those that initiate S3 mutations. Background coord work (GC, drain,
reaper, startup reconciliation) is coord-attested and uses the
`-background` role credentials; it requires no discharge.
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
  mint. Derives the per-coord chain key shared across all of a
  coord's role credentials.
- `K_M-A` — per-org AEAD key shared between mint and auth. Used to
  encrypt and decrypt the `CID` field on each primary's TPC, so
  auth can recover per-coord `r` keys on demand without holding
  per-coord state.
- `K_session` — auth-service-only root for sessions. Never leaves
  auth.
- `K_coord = HKDF(K_M, coord_ulid)` — per-coord role-credential
  chain key. Mint re-derives on demand. Used to chain every role
  credential mint issues for this coord — read, operator-write, and
  background-write alike. **Coord does not hold this key.**
- `r = HKDF(K_M, "r-coord-" || coord_ulid || r_epoch)` — per-coord
  primary-discharge key, **deterministically derived** by mint on
  demand. Mint never persists `r`; it re-derives it at every
  exchange and every verification. Both operator-write primaries
  for a given coord see the same `r` because the derivation depends
  only on `(K_M, coord_ulid, r_epoch)`, none of which differ between
  the two exchanges. The TPC `(VID, CID)` on both operator-write
  primaries is therefore identical at the `CID` (same plaintext)
  and differs at the `VID` (different chain tags). Auth uses `r`
  (recovered from any of the coord's `CID`s) as the HMAC root when
  minting discharges; mint recovers it from either `CID` or by
  walking a primary's chain to its `VID`. `r_epoch` is bumped only
  at deliberate `r` rotation (see *Key rotation*); one `r` per
  `(coord, epoch)` ⇒ one discharge serves every operator-write
  primary issued in that epoch.

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

Per-coord deployment cadence. Coord enrollment follows the existing
mint enrollment flow ([`design-mint.md`](design-mint.md) §
*Enrollment*): invite → `/v1/enroll` → operator approval →
`/v1/enroll-exchange` per role. The exchange fan-out produces **six
role credentials** instead of four; the two new entries are the
operator-write/background-write split. Each operator-write exchange
re-derives `r = HKDF(K_M, "r-coord-" || coord_ulid || r_epoch)` on
demand and embeds the resulting TPC into that role's credential.
The exchanges are independent — they can run in any order, days
apart, or one at a time — and still produce identical `CID`s, so
neither mint nor coord needs to hold transient state between them.

Role inventory (six):

| Role | TPC | Bundle required at assume-role |
|---|---|---|
| `coord-ro` | no | no |
| `coord-rw` (operator-initiated) | yes | yes |
| `coord-rw-background` | no | no |
| `volume-ro` | no | no |
| `volume-rw` (operator-initiated) | yes | yes |
| `volume-rw-background` | no | no |

At each `/v1/enroll-exchange` for an operator-write role, mint
mints the credential like every other role (first-party
`(sub=coord_ulid, cnf, aud=mint, role, op=assume-role)` caveats,
chain-MAC'd under `K_coord`) and additionally appends the TPC:

- Third-party caveat: `(location=<auth-url>, VID, CID)`
  - `VID = AEAD-encrypt(T_n, r)` — where `T_n` is the chain tag at
    the TPC position. Different for each operator-write credential
    (different chains, different `T_n`); decryptable by anyone who
    can walk the credential's chain (i.e., mint).
  - `CID = AEAD-encrypt(K_M-A, r ‖ CoordId ‖ OrgId)` — does not
    depend on the chain; identical across both operator-write
    credentials for this coord. Decryptable by mint and auth (both
    hold `K_M-A`).

Mint stays stateless across coords: `K_coord` and `r` are both
re-derivable on demand (`K_coord` from `K_M + coord_ulid`; `r` from
chain-walk + `VID`, or from `CID` + `K_M-A`).

After enrollment coord holds the six credentials under
`<data_dir>/credentials/<role>` plus the auth-service URL and OrgId
in its `data_dir`. It holds no key material it can use to verify
primaries or discharges.

## Macaroons in this design

Three classes of artefact, same chained-keyed-BLAKE3 construction.

**1. Session.** Auth-issued, CLI-held. One per operator login, ~7d
lifetime. Caveats `(Subject, OrgId, NotAfter)`. Chain-MAC'd under
`K_session`. Used only on the CLI ↔ auth channel; coord and mint
never see it.

**2. Primaries** (TPC-bearing role credentials). Mint-issued,
coord-held. Two per coord (`coord-rw`, `volume-rw`), minted at coord
enrollment as part of the standard six-role fan-out. Each carries
its role's first-party caveats (`sub=coord_ulid, cnf, aud=mint,
role, op=assume-role`) plus a TPC `(location, VID, CID)` where the
two CIDs are identical for a given coord (same `r`, same plaintext)
and the VIDs differ (different chains, different `T_n`). Chain-MAC'd
under `K_coord`. Long-lived (re-issued only on `K_M` rotation or
coord re-enrollment). The other four role credentials (`coord-ro`,
`volume-ro`, `coord-rw-background`, `volume-rw-background`) are not
primaries — they carry no TPC and require no discharge.

**3. Wide discharge.** Auth-issued, CLI-held + coord-cached
(as a verification verdict). One per `(session, coord)` pair, ~5min
lifetime. Caveats `(Subject, OrgId, CoordId, NotAfter)`. Chain-MAC'd
under `r` (the per-coord deterministic-derived key, recovered by
auth from any of the coord's `CID`s). Nonce equals the coord's
`CID` — this is
the binding mechanism between the discharge and the coord. A single
discharge satisfies the TPC on **either** of the coord's primaries
because both primaries' TPCs carry the same `CID` and the same
recovered `r`.

The discharge is "wide" — it attests "operator authorised on this
coord for the next 5 min," without binding to a specific op or
volume. Per-op narrowing happens via CLI attenuation per IPC (see
*Per-IPC flow*).

The initial design has exactly one TPC per primary (pointing to
auth) and therefore one wide discharge per bundle. The construction
admits multiple TPCs on a primary (each adding an independent
discharge requirement) and nested TPCs (a discharge that itself
carries a TPC, requiring its own discharge); the verifier and the
wire shape are built for either. See *Extensibility: multiple and
nested TPCs* below.

## Per-IPC flow

### Fetching the wide discharge

The CLI learns coord-X's `CID` lazily, via a challenge response on
the operator IPC itself. There is no separate discovery endpoint —
the IPC carries the discovery.

When the CLI is about to call coord-X for an operator IPC:

1. If the CLI has no cached non-expired wide discharge for
   `(session, coord-X)`, it issues the IPC without a discharge.
   Coord responds `401 { cid: "<base64>", auth_url: "..." }` where
   `cid` is the `CID` from coord's primary's TPC. (Coord 401s the
   same way for a presented discharge whose nonce doesn't match
   coord's current `CID` — see *Coord: forward and clear*.)
2. CLI POSTs `<auth>/v1/discharge` with the session in
   `Authorization: Bearer`, body `{cid: "<base64>"}` using the
   `cid` from the challenge.
3. Auth verifies the session under `K_session`, AEAD-decrypts `CID`
   with `K_M-A` → recovers `(r, CoordId, OrgId)`. Cross-checks the
   decoded `OrgId` against the session's `OrgId`. Applies its policy
   ("may this Subject operate on this coord at all?"). Mints a
   discharge:
   - Caveats `(Subject, OrgId, CoordId, NotAfter=now+5min)`.
   - Chain-MAC'd under `r`.
   - Nonce equals `CID`.
4. CLI stores the discharge in memory, keyed by `(session, coord-X)`,
   and caches the `CID` keyed by `coord-X` so subsequent first-IPCs
   to the same coord can skip the challenge by attaching the
   already-fetched discharge directly.
5. CLI retries the IPC with the attenuated discharge.

Subsequent IPCs within the discharge's lifetime go direct: the CLI
attaches the still-valid attenuated discharge and the IPC succeeds
without a challenge. The 401 path runs once per coord per
discharge lifetime, plus once on `K_M-A` rotation (see *Key
rotation*).

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
```

CLI sends `(attenuated_discharge, IPC body)` to coord. The tight
`NotAfter` bounds the per-IPC bundle's replay window; operator IPC
verbs are idempotent at the coord layer, so this is the only
replay defence needed.

### Coord: forward and clear

Coord receives `(attenuated_discharge, IPC body)`. It loads its
nominated discharge-anchor primary (`coord-rw` by convention) from
`data_dir` and runs the following.

1. **Challenge if missing or wrong-CID.** Coord reads the nominated
   primary's `CID` from the TPC and the presented discharge's
   nonce (both are plain byte reads — no key needed). If the IPC
   carries no discharge, or the discharge's nonce does not equal
   coord's `CID`, respond `401 { cid: <primary CID>, auth_url }`
   and stop. The CLI fetches a fresh discharge against that `CID`
   and retries. No mint round-trip on this path.
2. **Split the attenuated discharge** into `(wide_bytes,
   attenuation_chain)` at the wide discharge's trailing tag.
3. **Cache lookup on `wide_bytes`** in coord's verification cache.
   - **Cache hit**: the wide bytes have already been verified by
     mint within their `NotAfter` window. Skip to step 5.
   - **Cache miss**: coord first attenuates its nominated primary
     with a freshness `NotAfter` (see *Coord attenuates the primary*
     below), then forwards `(attenuated_primary, [wide_bytes])` to
     mint at `<mint>/v1/verify`. The discharge list is a
     flat bag — length 1 in the initial design. Mint returns
     `{valid: true, expires_at: <NotAfter>, caveats: {...}}` or
     `{valid: false, reason: "..."}`. On valid, cache `(wide_bytes
     → expires_at, caveats)`. On invalid, reject the IPC (do not
     401 — invalid means the CID matched but the discharge MAC
     didn't, which is not a routine miss).
4. **Clear every caveat** across the primary (which coord can read
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
5. If all caveats clear, dispatch. If any fails, reject. Clearing
   results are never cached — the context changes every IPC.

Coord does **not** verify the primary's chain MAC, the wide
discharge's MAC, or recover `r` from `VID`. It holds no key material
that would let it do so. All cryptographic verification happens at
mint (or, transitively, was done by mint and cached).

### Coord attenuates the primary before forwarding to mint

The stored primaries are long-lived. To avoid forwarding a
long-lived credential unattenuated, coord attaches a fresh
per-forward `NotAfter` caveat to the chain of whichever primary it
is forwarding before any call to mint (both `/v1/verify`
with the nominated discharge-anchor and `/v1/assume-role` with the
role-specific credential):

```
primary-attenuation per forward:
  NotAfter = now + 5s
```

Chain extension is keyless — coord can append to its primary's
trailing tag without holding `K_coord`. Mint walks the (slightly
longer) primary chain and clears the per-forward `NotAfter` as part
of its normal caveat AND-evaluation.

This is good macaroon discipline: every macaroon leaving coord is
attenuated as tightly as the use case allows. The bundle's
effective lifetime is already bounded by the discharge attenuation's
`NotAfter`, so this doesn't enable a new security property — but it
keeps the rule "always attenuate tightly" honest at both layers and
gives mint's audit log a per-forward freshness marker.

### Mint: verification on `/v1/verify` and on assume-role

Mint exposes two endpoints that handle bundle verification:

- `/v1/verify` — called by coord when coord has a cache
  miss on a wide discharge. Returns the verification verdict.
- `/v1/assume-role` (existing) — called by coord when it needs
  write-capable S3 creds. Mint re-verifies the bundle from scratch
  (defense in depth) before issuing creds.

Both endpoints share a single verification routine. It is written
as a queue walk so it handles multiple TPCs on the primary and
nested TPCs inside discharges without special-casing — the initial
single-TPC shape is the N=1 case.

1. Walk the primary's chain with `K_coord` (re-derived from `K_M +
   coord_ulid`, extracted from the credential's first-party `sub`
   caveat — see [`design-mint.md`](design-mint.md) for the caveat
   vocabulary). The chain now includes coord's per-forward
   `NotAfter` attenuation; confirm the trailing MAC and that the
   per-forward `NotAfter` is still in the future. For each TPC
   encountered, queue `(T_n, CID_n, location_n)`.
2. For each queued TPC, find a discharge in the request's
   `discharges` bundle whose nonce equals `CID_n`. Recover `r_n` by
   decrypting `VID_n` with `T_n` (or, equivalently, decrypting
   `CID_n` with `K_M-A` — both paths yield the same `r_n`; mint
   uses whichever it has cached or finds convenient).
3. Verify the matched discharge's MAC chain under `r_n`. If the
   discharge's own chain contains further TPCs, queue them and
   continue. Recurse to fixpoint.
4. Confirm every queued TPC matched a discharge and every MAC
   verified. Any unmatched TPC or failed MAC → return `{valid:
   false, reason}`.
5. (Verify endpoint) Aggregate caveats across the primary and every
   verified discharge. Return verdict + aggregated caveats + the
   minimum `NotAfter` across all macaroons.
6. (Assume-role endpoint) For each discharge that carries a CLI
   attenuation chain, walk the attenuation forward from the
   discharge's trailing tag, verify the trailing MAC, and
   AND-evaluate the attenuation caveats against the assume-role
   request shape. Then issue creds. The initial design attenuates
   only the single auth discharge; with multiple TPCs the CLI may
   attenuate each independently.

Mint holds its own verification cache keyed by wide-discharge bytes
so a coord's `/verify` call followed by an `/assume-role`
call within the same window doesn't repeat the chain walk
unnecessarily.

## Caching

Verification results are cacheable; clearing results are not. The
former is a function of (bytes, key) and is stable for the
discharge's lifetime; the latter is a function of (caveat, live
context) and changes every IPC.

### Wide-discharge verification cache (coord-side)

Key: `wide_discharge_bytes` (or hash). Value: `(expires_at,
caveats)`. TTL: until `expires_at`.

Populated on cache miss via a one-shot mint round-trip (`/verify`).
Once populated, all subsequent IPCs that present the same wide
discharge skip the mint round-trip until expiry. Same bytes, same
verification verdict — the MAC over a fixed byte sequence is
deterministic and mint's verdict over fixed bytes doesn't change
between calls.

The cache is keyed on the *wide* bytes only, not the attenuation.
Each IPC has a fresh attenuation, but the wide bytes are stable
across IPCs within the wide discharge's lifetime, so cache hits
dominate.

Cache size is bounded by (active sessions) × (coords per session) ×
(turnover within `NotAfter` window). For typical operator load this
is a handful of entries per coord.

### Wide-discharge verification cache (mint-side)

Same shape as coord's cache. Lets mint skip redundant chain walks
when coord's `/verify` call is followed by an
`/assume-role` call within the same window. Keyed on wide bytes
only — coord's per-forward primary attenuation changes the primary
chain per call, but mint walks the (short) attenuation suffix
locally and re-uses the cached `r` recovered from the underlying
primary's `VID`.

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
  should trace through `/verify` at mint (which has its
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
  self-attesting in this case — but mint's `/verify` log
  is a secondary signal.

Forgery requires `K_M`, `K_M-A`, or being mint/auth itself. None of
these lives at coord.

## Audit anchors

The design produces three correlated audit streams:

- **Auth log**: every `/v1/discharge` issuance (subject, coord_id
  via decoded CID, expires_at).
- **Mint log**: every `/v1/verify` and every assume-role
  verification (coord_id from primary, discharge nonce = CID,
  expires_at).
- **Coord log**: every operator IPC accepted (op, volume, subject,
  wide discharge nonce `= CID`).

The audit invariant: every accepted IPC at coord must trace through
a `/verify` (or `/assume-role` verification) at mint,
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

## Extensibility: multiple and nested TPCs

The macaroon construction admits two natural extensions to the
single-TPC shape used today. Both are supported by the verification
routine and the wire surface as designed; they are listed here so
the initial implementation doesn't accidentally close the door.

**Multiple flat TPCs on the primary.** Mint can enrol a primary
with more than one TPC, each pointing at a different third party
and each carrying its own `(VID_n, CID_n)` with its own ephemeral
`r_n`. Every TPC must be discharged for the bundle to verify; the
bundle's `discharges` list grows to one entry per TPC.

Use cases this opens up:
- A second TPC pointing to a per-org compliance / audit service
  (every operator IPC requires both auth-service approval and a
  compliance discharge).
- Step-up auth for high-privilege ops (primary requires a base
  discharge plus a step-up discharge from a distinct flow).
- A break-glass TPC for emergency ops, discharged by a separate
  service.

**Nested TPCs.** A discharge is itself a macaroon, so it can carry
its own TPC pointing at a further third party. The verifier walks
the discharge's chain just as it walks the primary's chain; when
it encounters a TPC inside the discharge, it queues `(T_n, CID_n,
location_n)` and looks for a matching nested discharge in the same
flat `discharges` bag.

Use cases this opens up:
- Auth-service mints a discharge whose own TPC requires a
  passkey-service discharge (auth + passkey, without auth needing
  to integrate passkey directly).
- Delegated discharge: auth-service's discharge requires a
  discharge from a customer-controlled service before it is
  valid.

The cryptography is just recursion of the basic TPC mechanism — no
new primitives. The API shape (flat `discharges` list, matched by
nonce) accommodates either extension without a wire change. The
verifier's queue walk handles either without a routine change.

Out of scope for the initial implementation: caching shape for
multi-discharge bundles (each discharge could in principle be
cached independently by its bytes; today we cache the single
discharge whole), per-TPC CLI attenuation ergonomics, and the
specifics of any second issuer's wire protocol.

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

Four lifetimes, four refresh rhythms.

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

**CLI discharge attenuations: per IPC, ~5s NotAfter.** Built by the
CLI before sending each IPC; not cached. Carries `Op`, `Volume`,
and `NotAfter`.

**Coord primary attenuations: per forward to mint, ~5s NotAfter.**
Built by coord before each `/v1/verify` or
`/v1/assume-role` call; not cached. Carries just `NotAfter`. Keeps
the primary tight on the wire even though the underlying primary
in `data_dir` is long-lived.

**Replay window.** Within the attenuation `NotAfter` a specific
attenuated discharge is theoretically replayable on coord. Operator
IPC verbs are idempotent at the coord layer (`/v1/verify`
returns the same yes/no for the same bytes; `/v1/assume-role`
returns equivalent short-lived creds), so the 5s replay window
doesn't grant additional authority. No nonce caching is needed at
coord or mint in the initial design. If a future non-idempotent op
appears that's replay-sensitive, a `Nonce` caveat plus a
recent-nonce store at the relevant verifier can be added per verb
without changing the surrounding design.

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

Resolution is pull-on-verify-fail. The cascade:

1. CLI's `/v1/discharge` call to auth fails with `422 CID decode
   error` — auth recognises the `CID` was AEAD'd under the old
   `K_M-A`.
2. CLI signals coord to refresh its primaries (a local IPC,
   separate from the operator IPCs). Coord re-exchanges its
   credential ticket against the existing `/v1/enroll-exchange`
   endpoint for each operator-write role. Mint re-mints each
   credential with a fresh `r` (shared across the pair), fresh
   per-credential `VID`s (under the new chain tags), and a fresh
   shared `CID` (encrypted under the new `K_M-A`). Coord
   atomically swaps the stored credentials.
3. CLI retries the operator IPC. With no valid discharge cached
   (the old one's nonce is the old `CID`), coord 401s with the
   new `CID`. CLI fetches a fresh discharge against the new
   `CID` and retries the IPC.

Bounded by one refresh + one challenge round per in-flight IPC
during the rotation grace window. The challenge flow makes the
post-refresh CID re-discovery free — it is the same 401 path used
on first contact.

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
   assume-role, or a proactive primary refresh), is re-issued
   fresh operator-write primaries under `K_M_new`. The fresh
   primaries derive `r` under `K_M_new` (so `VID` and `CID` are
   fresh too).
4. Coord swaps the stored credentials atomically in `data_dir`.
5. After the grace window, mint drops `K_M_old`.

### `r` rotation (per-coord)

`r` is bumped by incrementing the coord's `r_epoch`. Mint stores
`r_epoch` as a small integer in `_mint/approved/<sub>` (the only
mint-side state tied to `r`); it defaults to `0` at approval time.
A bump invalidates `r` under the old epoch — fresh exchanges
derive a new `r` and produce new `(VID, CID)`. Lifetime is
operator-driven, not tied to credential lifetime: a deliberate
rotation, a `K_M` or `K_M-A` rotation cascading through, or a
suspected-compromise response all bump the epoch and trigger the
same coord-side refresh cascade as `K_M-A` rotation.

### `K_session` rotation (auth-only)

Trivial: only the auth service holds `K_session`. Rotation
invalidates all existing sessions; operators re-run `login`. Grace
window optional — auth can keep `K_session_old` to honour in-flight
sessions until their `NotAfter` expiry, then drop it.

### Summary

| Key | Affects | Resolution path |
|---|---|---|
| `K_M-A` | `CID` undecodable; discharges can't be issued against old primary | CLI signals coord; coord refreshes primary; CLI retries IPC and gets a 401 with the new `CID` |
| `K_M` | Per-coord `K_coord` changes; primaries need re-issue | Mint re-issues primaries on next interaction; grace window covers in-flight |
| `r` | Per-coord; derived from `(K_M, coord_ulid, r_epoch)` | Operator bumps `r_epoch` in `_mint/approved/<sub>`; refresh cascade rerolls primaries |
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

Coord enrollment reuses the existing mint enrollment flow
([`design-mint.md`](design-mint.md) § *Enrollment*): `POST
/v1/enroll` (with invite + `sub`/`cnf` + PoP) yields a credential
ticket; `POST /v1/enroll-exchange` per role yields the six role
credentials. No `/v1/coord/enroll` endpoint distinct from the
credential-plane enrollment exists. Operator-write role exchanges
additionally embed a TPC in the issued credential (see *Coord ↔
mint enrollment* above); the OrgId and auth-service URL are
returned alongside the first operator-write credential mint issues
in the fan-out.

Refreshing a primary after `K_M-A` rotation is also done via
`/v1/enroll-exchange` (the ticket flow is the only path that mints
a fresh credential under a fresh TPC). No dedicated
`/v1/coord/primary` endpoint exists.

`POST /v1/verify` (coord-authenticated) — verify a bundle.
Coord forwards a per-forward-attenuated primary (its nominated
discharge-anchor) and the list of discharge bytes; mint runs the
verification routine described in *Mint: verification* and returns
the verdict + aggregated caveats.

```json
request:  {
  "primary": "<base64 macaroon, attenuated by coord with per-forward NotAfter>",
  "discharges": [
    "<base64 macaroon>"
  ]
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

The `discharges` list is a flat bag — verification matches by
nonce, so order does not matter and nesting (a TPC inside a
discharge) is handled by the verifier's queue walk, not by the
wire shape. Length is 1 in the initial design.

Or 200 with `{"valid": false, "reason": "expired" | "mac_mismatch" |
"unknown_coord" | "tpc_undischarged" | ...}`.

Mint's existing `/v1/assume-role` endpoint is unchanged in wire
shape. Whether a bundle is required is determined structurally by
the presented role credential: when its chain carries a TPC (i.e.
the role is a primary — `coord-rw` or `volume-rw`), mint's
verification routine requires a matching discharge and fails the
chain walk if absent (`tpc_undischarged`). When the chain carries
no TPC (`coord-ro`, `volume-ro`, `coord-rw-background`,
`volume-rw-background`), there is nothing to discharge and the
routine returns valid on a successful chain walk. Coord constructs
its assume-role request as `(per-forward-attenuated role credential,
discharges)` where `discharges` is empty for non-primary roles and
length-1 for primaries.

### Coord — CLI-facing

Operator IPC verbs (local socket) — coord's existing surface. Every
verb gets the same auth shape: a `(wide_discharge, attenuation)`
bundle is expected in the request; on missing or wrong-`CID`
discharge, coord responds:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Macaroon
Content-Type: application/json

{ "cid": "<base64>", "auth_url": "https://auth.elide.example/" }
```

The CLI uses the `cid` from the challenge to fetch a wide discharge
from `auth_url` (see *Per-IPC flow*), then retries the IPC. The
discharge's nonce equals the challenge's `cid`, so this is also the
binding check on the retry. There is no separate `/v1/coord/cid`
endpoint — the IPC carries the discovery.

`POST /v1/coord/refresh-primaries` (local socket; operator-signal
shape, not gated by a wide discharge — it carries no authority
itself, it just tells coord its `CID` is stale). Used by the CLI
when its `/v1/discharge` call fails with a `CID` decode error
after `K_M-A` rotation. Coord re-runs the credential-ticket
enrollment fast path (`_mint/approved/<sub>` makes this
non-interactive) and re-exchanges its operator-write role
credentials via `/v1/enroll-exchange`; both new credentials carry
the new shared `CID`. Coord swaps atomically; the next operator
IPC's 401 carries the new `CID`.

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

When `true`, mint serves `/v1/discharge` on its own UDS alongside its
cred-issuance and verification routes, and generates `K_M-A` for itself
at demo startup (no auth-service round-trip). **There is no session or
login layer on mint-as-auth — not deferred, never.** Operator sessions,
`/v1/login/*`, and `K_session` belong exclusively to the standalone
auth-service binary; the demo discharge endpoint authenticates nothing,
so the CID in the request body is its only input. Enrollment tokens are
likewise rubber-stamped: a coord can enroll with any token (or none) and
is assigned `OrgId=demo`. The coord codepath is identical to prod:
forward bundle to mint for verification, cache verdict, clear caveats.

Two startup-time safety checks when `demo-enabled = true`:

- Mint refuses to start unless bound to loopback / UDS.
- Mint logs `WARN auth=demo: discharges are issued without operator
  authentication` at startup and per issued discharge.

Both are config-time checks, not per-request branches — the verifier
in coord and mint stays unconditional. The mint binary has no
webauthn / OIDC / SAML / session code; production auth implementations
live in the separate auth service binary only.

The canonical test-fixture pattern is a single mint process with
`demo-enabled = true` bound to a UDS; the client fetches a discharge
against a TPC's CID with no session in the request. The full wire flow
runs end-to-end with no browser, no API key, and no `#[cfg(test)]`
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
