# Central auth service: operator sessions and discharges

This doc describes the central auth service that issues operator
**sessions** and **discharges**, and the two third-party caveats those
discharges satisfy. It builds on the principle in
[`design-auth-model.md`](design-auth-model.md) — **operator authority is
proven by a third-party-caveat discharge from a logged-in operator** —
and is the concrete shape of the discharge anchors mint relies on.

Operator authority is exercised at **three points, all at the mint
boundary**, never on a runtime data path:

- **Enroll** — the invite macaroon carries a TPC, so a
  coordinator can only attempt `/v1/enroll` when a logged-in operator
  has discharged it (the *enrolling* operator; see
  [`design-mint.md`](design-mint.md) § *Enrollment*).
- **Exchange** — the credential ticket returned by
  `/v1/enroll` carries its own TPC, so a coordinator can only pull its
  role credentials at `/v1/enroll-exchange` when a logged-in operator
  discharges it (the *exchanging* operator).
- **Mint admin plane** (where *approve* lives) — the admin service token carries a TPC, so every
  `/v1/admin/*` verb (invite management, enrollment approval) requires a
  fresh operator discharge (the *approving* operator and other admins;
  see [`design-mint.md`](design-mint.md) § *Operator authorization*).

Credentials themselves carry **no TPC**: once a coordinator is enrolled,
its role credentials are long-lived service tokens and `assume-role` is
app-driven, never operator-gated. There is no per-IPC operator discharge
and no coord-side verification chain.

**Status: partially implemented.** Mint's verification routine and the
demo discharge issuer (mint-as-auth `/v1/discharge`) are built and
exercised end-to-end by the mint CLI as the first client — `mint client
enroll` discharges the invite's TPC against the demo auth socket (see
[`design-mint.md`](design-mint.md#reference-client--demo)). The
standalone auth-service binary — which owns operator sessions and login —
remains proposed. (Sessions and login are an auth-service concern only;
mint-as-auth never grows them.)

## Terminology

There is no separate operator-auth credential artefact. Operator
authority rides two third-party caveats already present in the system:

- **Invite TPC** — the third-party caveat on the shared invite macaroon
  (one per mint/org). Discharged by the *enrolling* operator at
  `/v1/enroll`.
- **Ticket TPC** — the third-party caveat on the credential ticket mint
  returns from `/v1/enroll`. Discharged by the *exchanging* operator
  at `/v1/enroll-exchange`.
- **Admin-token TPC** — the third-party caveat on the mint admin service
  token. Discharged by an operator on each `/v1/admin/*` call.
- **Discharge** — an auth-issued macaroon that satisfies one of those
  TPCs. Carries `(aud, sub, scope, exp)` — attesting *who* authorised
  (`sub`), at what tier (`scope`), for *how long* (`exp`), scoped to mint
  (`aud`) — and is verified at mint, which holds the chain root. The org
  is bound in the TPC `CID` (`org_id`), checked at issuance, not a caveat.

## Principle

Operator authority is proven by a discharge from a logged-in operator,
satisfying a third-party caveat at the **mint boundary** — never on a
runtime data path. Sessions, the invite, the admin service token, and
discharges are all chained-keyed-BLAKE3 macaroons — the same
construction as volume macaroons in `architecture.md`. One primitive end
to end.

The design follows the canonical [Fly.io
macaroon](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md)
shape: third-party caveats with `VID`/`CID` for distributing the
discharge HMAC key, [Fly's
verify/clear split](https://fly.io/blog/macaroons-escalated-quickly/)
for separating cryptographic verification from caveat-predicate
evaluation, and isolated verification at a trusted service.

Three structural properties hold:

- **Mint is the sole holder of `K_M`** (its macaroon root). It chains
  the invite and the admin service token under `K_M` and verifies any
  bundle presented to it (`/v1/enroll`, the admin endpoints) by walking
  that chain.
- **Mint and auth share `K_M-A`** (per-org wrapping key for
  third-party-caveat `CID`s). Established at mint enrollment. It lets
  auth recover a TPC's discharge key from its `CID` on demand, holding
  no per-TPC state.
- **Verification is centralised at mint**, the way Fly centralises
  signature verification at `tkdb`. The discharge is presented to mint
  alongside the macaroon it discharges — the invite at `/v1/enroll`, the
  service token at `/v1/admin/*`; mint verifies both. No third party
  holds a chain key or a discharge key.

The **trust circle for discharge minting and verification is
`{auth, mint}`**. Auth issues discharges (legitimate path). Mint
verifies them.

The TPC binding is woven into the invite's and the service token's chain
MAC, so the discharge requirement cannot be stripped by any party who
cannot mint them. Auth's role as legitimate issuer is anchored
operationally (it's the only party an unprivileged CLI can ask) and in
audit (every legitimate discharge has an auth-side issuance log entry).

A coordinator's runtime S3 access — `assume-role` and the writes it
enables, including background work like GC, drain, and reaper — is
app-driven service-token authority granted once at enrollment; it
carries no TPC and requires no discharge. Volume↔coord IPC (PID-bound
volume macaroons) is unchanged.

### Verify and clear

Following [Fly's
formulation](https://fly.io/blog/macaroons-escalated-quickly/):

- **Verification** = HMAC checking. Pure crypto, stable for given
  bytes, cacheable. Runs at the holder of the relevant key material —
  mint.
- **Clearing** = caveat predicate evaluation against live request
  context (the operator `sub`, the admin verb, the current time).
  Cannot be cached. Runs at mint, which has the request context at the
  point the discharge is presented.

Auth participates in verification only at discharge-issuance time — it
applies its policy ("may this sub do this?") when it mints the
discharge, and does not sit on any later path.

## Tenancy and enrollment

The auth service is multi-tenant; coordinators and operators belong
to organisations. **Org-scoping is the primary isolation boundary**
and is enforced by construction — the org rides each TPC's `CID`
(`org_id`) and is checked when auth mints the discharge, before the
discharge exists — not by an `OrgId` caveat mint clears, and not by ACL.

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
  mint. Chains the invite macaroon, the admin service token, and (via
  `K_coord`) every role credential.
- `K_M-A` — per-org AEAD key shared between mint and auth. Used to
  encrypt and decrypt the `CID` field on each third-party caveat (the
  invite's and the admin service token's), so auth can recover that TPC's
  discharge key on demand without holding any per-TPC state.
- `K_session` — auth-service-only root for sessions. Never leaves auth.
- `K_coord = HKDF(K_M, coord_ulid)` — per-coord credential chain key.
  Mint re-derives on demand to chain the four role credentials it issues
  for a coord. **Coord does not hold this key.** No role credential
  carries a third-party caveat.
- `r_tpc` — a per-TPC discharge key, drawn fresh (random) at the moment
  the caveat is attached: the invite (`r_inv`), the credential ticket
  (`r_xchg`), and the admin service token (`r_adm`) each seal their own.
  `CID = AEAD-encrypt(K_M-A, r_tpc ‖ OrgId)`, so mint and auth both
  recover `r_tpc` from the `CID`; mint can also recover it by walking
  the anchor macaroon's chain to the TPC's `VID`. `r_tpc` exists
  nowhere outside its caveat — there is no derivation to replay — so a
  discharge is MAC-valid against exactly the caveat it was minted for.
  Auth uses `r_tpc` as the HMAC root when minting a discharge for that
  caveat; the discharge's nonce is random — its audit identity, while
  the binding to the caveat is `r_tpc` itself. The
  *authorization* dimension — which operator may obtain which
  discharge — rides a `scope` caveat, not the key (§ *Discharge flows*,
  § *Scope tier*). Rotated by re-minting the anchor macaroon — a fresh
  invite, a fresh ticket, or `mint admin-service rotate`; see *Key
  rotation*.

The **`AEAD(k, p)` seal** — here and in the sibling docs
([`design-mint.md`](design-mint.md),
[`design-mint-volume-attestation.md`](design-mint-volume-attestation.md))
— is ChaCha20-Poly1305 (RFC 8439). Each seal draws a fresh random
12-byte nonce; the sealed bytes are `nonce ‖ ciphertext`, and unseal
splits the leading 12 bytes back off. Nonce uniqueness under a reused
key (`K_M-A`, `K_M-B`) is the construction's one requirement, and the
per-seal random draw carries it.

### Mint ↔ auth enrollment

Slow cadence — once per org lifetime plus occasional rotation.

1. Org admin signs up at the auth service's web UI (out of band).
2. Org admin generates a one-shot mint-enrollment token in the auth
   service UI: `OrgId=X, Purpose=MintEnroll, exp=now+24h`.
3. Mint admin runs `elide-mint setup --enrollment-token <token>`.
4. Mint POSTs `<auth>/v1/mint/enroll` with the token.
5. Auth verifies the token, records org X as activated, generates
   `K_M-A`, returns `(OrgId, K_M-A, auth-service URL, mint bearer)`.
6. Mint persists. The mint bearer is for subsequent auth calls
   (e.g., enrolment-side rotation flows). `K_M-A` is the AEAD key
   for `CID` construction and decryption.

### Coord ↔ mint enrollment

Per-coord deployment cadence, following the mint enrollment flow
([`design-mint.md`](design-mint.md) § *Enrollment*): the *enrolling*
operator discharges the invite's TPC and the coordinator self-asserts
`sub`/`cnf` at `/v1/enroll`, which returns a short-lived **credential
ticket** carrying its own TPC; the *approving* operator approves; then
the *exchanging* operator discharges the ticket's TPC and the
coordinator presents `[ticket, discharge]` at `/v1/enroll-exchange`,
which — checking mint's approved registry — issues each role credential.
The exchange produces **four role credentials**, none of which carries a
third-party caveat:

| Role | Scope |
|---|---|
| `coord-ro` | coordinator-wide read |
| `coord-rw` | coordinator-wide write |
| `volume-ro` | per-volume lineage read |
| `volume-rw` | per-volume read+write |

Each is minted under `K_coord` with first-party caveats only
(`sub=coord_ulid, cnf, aud=mint, role, op=assume-role`); mint stays
stateless across coords (`K_coord` re-derives from `K_M + coord_ulid`).

Two TPCs gate enrollment — both on macaroons the coordinator carries,
neither on a credential, each `(location=<auth-url>, VID, CID)` with
`VID = AEAD(T, r)` and `CID = AEAD(K_M-A, r ‖ OrgId)`:

- The **invite's** TPC wraps `r_inv`. The invite is shared, so its `CID`
  is the same for every coordinator; one enroll-gate discharge can bring
  in any number of coordinators in its window.
- The **ticket's** TPC wraps `r_xchg` (a distinct per-org key, so a
  distinct `CID` auth can police separately). The ticket is
  per-coordinator (carries its own `sub`/`cnf`), but its `CID` is
  org-wide, so one exchange-gate discharge can exchange every role — and
  serve several coordinators — within its window.

Both discharges attest an org-wide operator authorisation, not a
coord-specific one; the specific coordinator is pinned by its `sub`/`cnf`
+ PoP and by the approving operator's fingerprint check.

After enrollment coord holds the four credentials under
`<data_dir>/credentials/<role>` plus the auth-service URL and OrgId in
its `data_dir`. It holds no key material and verifies nothing; its
credentials are inert service tokens it presents at `assume-role`.

## Macaroons in this design

Same chained-keyed-BLAKE3 construction throughout.

**1. Session.** Auth-issued, CLI-held. One per operator login, ~7d
lifetime. Caveats `(sub, exp)`. Chain-MAC'd under
`K_session`. Used only on the CLI ↔ auth channel; coord and mint never
see it.

**2. Invite.** Mint-issued, distributed out-of-band, one per mint/org,
non-expiring. First-party `(op=enroll, aud=mint, invite=<nonce>)` plus a
TPC `(location, VID, CID)` whose `CID` wraps `r_inv` (§ *Coord ↔ mint
enrollment*). Chain-MAC'd under `K_M`. Discharged by the enrolling
operator at `/v1/enroll`.

**3. Credential ticket.** Mint-issued at `/v1/enroll`, coord-held in
memory across the wait for approval. Short-lived. First-party
`(op=enroll-exchange, sub, cnf, aud=mint, exp)` plus a TPC whose `CID`
wraps `r_xchg`. Chain-MAC'd under `K_M`. Discharged by the exchanging
operator at `/v1/enroll-exchange`, where it is also PoP-bound to the
coordinator's `cnf` and checked against the approved registry.

**4. admin service token.** Mint-issued, held by the local mint CLI, one
per mint deployment. First-party `(aud=mint, cnf)` plus a TPC whose
`CID` wraps `r_adm` (see [`design-mint.md`](design-mint.md) § *Operator
authorization*). Chain-MAC'd under `K_M`. The operator attenuates
`op=admin:<verb>` per call; discharged on every `/v1/admin/*` call.

**5. Discharge.** Auth-issued, CLI-held. Short-lived (~5 min). Caveats
`(aud, sub, scope, exp)` — the `scope` first-party caveat
names the authority class auth authorised (`mint:enroll`,
`mint:exchange`, or `mint:admin`), and is what the gate clears against.
Chain-MAC'd under the `r_tpc` recovered from the target `CID`, with a
random nonce. One discharge satisfies one TPC. The operator may
attenuate it before use (e.g. the admin CLI appends `op=admin:<verb>`).

**Role credentials carry no TPC** and so are not discharge anchors —
they are plain key-bound service tokens (`design-mint.md` § *Credential
macaroon & lifecycle*).

The initial design has exactly one TPC per anchor. The construction
admits multiple TPCs (each an independent discharge requirement) and
nested TPCs (a discharge that itself carries a TPC); the verifier and
the wire shape are built for either. See *Extensibility: multiple and
nested TPCs* below.

## Discharge flows

All three discharge consumers follow the same shape: the operator's CLI
fetches a discharge from auth against a `CID`, **naming the scope it
needs**, then presents it to mint alongside the macaroon it discharges.
Auth issues only if the operator's session grants that scope, and stamps
it as a `scope` first-party caveat; mint clears that caveat against the
scope the gate requires. Mint verifies inline. No coordinator sits on the
verification path, and there is nothing to cache between calls.

### Enroll-gate discharge

When the enrolling operator brings a coordinator in:

1. The operator's CLI POSTs `<auth>/v1/discharge` with the session in
   `Authorization: Bearer`, body `{cid: "<base64>", scope:
   "mint:enroll"}`, where `cid` is the invite's `CID` (fixed for the
   org; it travels with the invite).
2. Auth verifies the session under `K_session`, AEAD-decrypts `CID` with
   `K_M-A` → recovers `(r_inv, OrgId)`, cross-checks the decoded `OrgId`
   against the session's, requires `mint:enroll ∈ session.scopes`,
   and mints a discharge: caveats `(sub, scope=mint:enroll,
   exp=now+5min)`, chain-MAC'd under `r_inv`. A
   session lacking the scope → `403`.
3. The operator conveys the discharge to the coordinator (inert bytes).
   The coordinator presents `[invite ⊕ sub/cnf, coordinator PoP,
   discharge]` at `/v1/enroll`.
4. Mint walks the invite's chain under `K_M`, recovers `r_inv` from the
   TPC's `VID` (or from the `CID` under `K_M-A`), verifies the
   discharge's MAC under `r_inv`, and clears its caveats (`scope` is
   `mint:enroll`, `exp` in the future; the org was already checked
   against the `CID` when auth minted the discharge). It
   records `requested_by = sub` on the pending enrollment.

One discharge serves any number of `/v1/enroll` calls in its window — it
is org-wide, not coord-bound.

### Exchange-gate discharge

When the exchanging operator brings an approved coordinator online:

1. The CLI fetches a discharge against the **ticket's** `CID` (the
   coordinator's ticket carries it), `scope: "mint:exchange"` — auth
   recovers `r_xchg`, requires `mint:exchange ∈ session.scopes`, and
   mints `(sub, scope=mint:exchange, exp)`.
2. The operator conveys the discharge to the coordinator. The
   coordinator presents `[ticket, discharge]` + PoP at
   `/v1/enroll-exchange`, once per role.
3. Mint walks the ticket's chain under `K_M`, verifies the discharge
   under `r_xchg`, clears its `scope` against `mint:exchange`,
   verifies the PoP against the ticket's `cnf`, requires
   `_mint/clients/enrolled/<sub>` to match, and mints the TPC-free role
   credential. One discharge covers every role exchanged in its window.

### Admin-plane discharge

When an operator runs `mint enroll approve` (or any other `/v1/admin/*`
verb):

1. The CLI fetches a discharge against the admin service token's `CID`,
   `scope: "mint:admin"` — auth recovers `r_adm`, requires `admin ∈
   session.scopes`, mints `(sub, scope=mint:admin, exp)`. One
   fetch covers every admin verb in the window; the
   verb is bound per call by the attenuation below, not by the discharge.
2. The CLI attenuates `op=admin:<verb>` onto the service token, bundles
   `[service token, discharge]`, PoP-signs the attenuated tail with the
   machine key, and calls the admin endpoint.
3. Mint walks the service token's chain under `K_M`, verifies the
   discharge under `r_adm`, clears `(sub, scope=mint:admin,
   exp, op)` against the dispatched verb and the current time, and —
   for `enroll approve` — records `approved_by = sub` on the approval
   entry.

The admin service token, its machine key, and the `op=admin:<verb>`
attenuation are specified in [`design-mint.md`](design-mint.md) §
*Operator authorization*.

### No runtime discharge, no verification cache

Role credentials carry no TPC, so the runtime data path — `assume-role`
and the S3 writes it enables — presents no discharge and makes no
verification round-trip. Operator authority is verified inline at the
two enrollment/admin moments above and nowhere else, so there is no
coord-side or mint-side discharge cache to maintain. (Discharge
verification is pure HMAC over fixed bytes and would be cacheable in
principle; at the volume these two flows run at, mint just verifies each
inline.)

## Forgery model

The trust circle for discharge minting and verification is `{auth,
mint}`. No other party holds key material.

What each party can do under compromise:

- **Operator CLI rooted**: holds a session and any discharge it has
  fetched. Can replay a still-valid discharge within its short
  `exp`, bounded by the session's lifetime and auth's policy.
  Cannot synthesise a discharge for a TPC it has no session-authorised
  access to (needs `r_tpc`), and cannot mint an invite, service token,
  or credential (needs `K_M`). Its reach is exactly the operator
  authority auth granted it.
- **Mint rooted**: holds `K_M` (can mint invites, service tokens, and
  credentials; can walk any chain and recover any `r_tpc` from a `VID`)
  and `K_M-A` (can decrypt any `CID` to recover any `r_tpc`). Can forge
  any discharge. This is the trust-circle property: mint is
  fundamentally trusted. Auth-side issuance logs still detect post-hoc
  forgery — a forged discharge has no auth issuance record.
- **Auth rooted**: holds `K_M-A` and `K_session`. Can mint discharges
  for any TPC (decrypts any `CID`, recovers `r_tpc`, signs) and any
  session. Same trust-circle property.

Forgery requires `K_M`, `K_M-A`, or being mint/auth itself. A
coordinator holds none of these and is not on the discharge path at all.

## Audit anchors

The design produces two correlated audit streams:

- **Auth log**: every `/v1/discharge` issuance (sub, target `CID`,
  OrgId, expires_at).
- **Mint log**: every discharge verified at the boundary — at
  `/v1/enroll` (the invite TPC, stamped `requested_by`), at
  `/v1/enroll-exchange` (the ticket TPC, stamped the exchanging
  `sub`), and at each `/v1/admin/*` call (the service-token TPC,
  stamped the operator `sub`, e.g. `approved_by` on `enroll
  approve`).

The audit invariant: every operator-authorised action at mint must
trace to a `/v1/discharge` issuance at auth within the discharge's
`exp` window. A mint-side verification with no matching auth
issuance (`absent issuance, present verify`) is the one unambiguous
forgery signal — it indicates `K_M-A`/`K_M` leakage or an auth-issuance
bypass.

## Extensibility: multiple and nested TPCs

The macaroon construction admits two natural extensions to the
single-TPC shape used today. Both are supported by the verification
routine and the wire surface as designed; they are listed here so
the initial implementation doesn't accidentally close the door.

**Multiple flat TPCs on an anchor.** Mint can stamp the invite or the
service token with more than one TPC, each pointing at a different third
party and each carrying its own `(VID_n, CID_n)` with its own ephemeral
`r_n`. Every TPC must be discharged for the bundle to verify; the
bundle's `discharges` list grows to one entry per TPC.

Use cases this opens up:
- A second TPC on the invite pointing to a per-org compliance / audit
  service (every enrollment requires both auth-service approval and a
  compliance discharge).
- Step-up auth for high-privilege admin verbs (the service token
  requires a base discharge plus a step-up discharge from a distinct
  flow).
- A break-glass TPC, discharged by a separate service.

**Nested TPCs.** A discharge is itself a macaroon, so it can carry
its own TPC pointing at a further third party. The verifier walks
the discharge's chain just as it walks the anchor's chain; when
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
new primitives. The API shape (flat `discharges` list, matched
positionally to the chain's TPCs) accommodates either extension
without a wire change. The verifier's queue walk handles either
without a routine change.

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
caveats `(sub, exp=login_time+7d)`. The session is a
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

A discharge attests two claims; the org is bound separately:

- **The org is mandatory and enforced — via the `CID`, not a caveat.**
  It rides each TPC's `CID` (`org_id`), set by the auth service from the
  org selected at login. Auth checks it before minting the discharge
  (it must match the org the role serves), so a wrong-org discharge is
  never issued — there is no `OrgId` caveat for mint to clear.
- **`sub` is mandatory and opaque.** A stable identifier (UUID,
  OIDC `sub`, opaque token) chosen by the auth service. Not a
  username or email — those change. The auth service is responsible
  for keeping `sub` stable for a given human across renames and
  IdP changes. It is what mint records as `requested_by` / `approved_by`.
- **Scope is the authority class auth granted** — `mint:enroll`,
  `mint:exchange`, or `mint:admin`. Auth issues it only if the session
  carries it; mint clears it against the scope each gate requires. This
  is the dimension that lets "may exchange but not administer" be
  expressed (§ *Scope tier*).

The discharge carries no per-op or per-volume narrowing in the initial
protocol caveats (see *Deferred* below). The admin plane binds the verb
via the CLI's `op=admin:<verb>` attenuation, cleared at mint; the
enroll-gate and exchange-gate discharges are org-wide
(coord-specificity comes from the macaroon's `sub`/`cnf` + PoP). All
access control — allow-listing, RBAC, which sub may enroll,
exchange, or administer — lives at the auth service and is exercised
at `/v1/discharge` issuance time.

Mint log shape (admin verb):

```
INFO mint::authn event=accept op=admin:enroll-approve
  org=org_7vh3... subject=usr_2k9q... discharge_cid=...
  expires_at=2026-05-26T14:28:00Z
```

## Cadence

Three lifetimes, three refresh rhythms.

**Sessions: ~7 days, refreshed only by re-running `elide operator
login`.** Default lifetime is auth-service policy. There is no
sliding renewal — when the session expires, the next call fails
with a clear error and the operator runs `login` again.
Non-interactive (API-key) sessions are typically shorter (e.g. 1
hour); the API key is the long-lived credential and the session is
its derived form.

**Discharges: ~5 minutes, fetched per enroll / exchange / admin
call.** The CLI caches a discharge in memory for the window; within it,
an operator may enroll or exchange several coordinators, or run
several admin verbs, without re-fetching. After expiry, the next call
triggers a fresh fetch
from auth.

**Admin attenuations: per call, ~5s exp.** Built by the admin CLI
before each `/v1/admin/*` call; not cached. Carries `op=admin:<verb>`
and `exp`.

**Replay window.** Within the attenuation `exp` a specific
attenuated discharge is theoretically replayable at the mint boundary.
Admin verbs are idempotent (`enroll approve` of an already-approved sub
is a no-op), so the short replay window grants no additional authority.
If a future non-idempotent verb appears that's replay-sensitive, a
`Nonce` caveat plus a recent-nonce store at mint can be added per verb
without changing the surrounding design.

## Reachability

The auth service must be reachable from two places:

- **The operator's CLI machine** — for `elide operator login` and
  `/v1/discharge` issuance (enrollment requests and admin verbs). The
  interactive flow also needs the auth service reachable from the
  operator's laptop browser.
- **Mint** — at enrollment, for `K_M-A` rotation discovery, and (as
  a Bearer-cred client) for any future auth-side flows.

The auth service is **not** reachable from coord, and is off the runtime
data path entirely: once a coordinator is enrolled, `assume-role` and
its S3 access never touch auth.

If the auth service is unreachable, the CLI cannot fetch fresh
discharges, so enrollment and admin verbs stall (a cached discharge
covers a transient outage for up to 5 min); already-enrolled
coordinators are unaffected. There is no offline escape hatch for
operator login.

## Offline / air-gapped

Not supported. The coordinator already requires S3 reachable for
segment GET, manifest writes, and mint-issued cred exchange.
Enrollment and admin verbs additionally require auth reachable from the
CLI for discharge issuance; an already-enrolled coordinator needs no
auth contact at all, and mint↔coord exchange is offline once enrollment
completes.

## Key rotation

Three keys plus the per-anchor discharge keys can be rotated.

### `K_M-A` rotation (mint ↔ auth wrapping key)

Triggered by routine auth-service-side rotation, or if `K_M-A` is
suspected compromised. Auth runs with both `K_M-A_old` and `K_M-A_new`
during a grace window. When `K_M-A` rotates, the `CID` on the invite and
on the admin service token becomes undecodable by the new key — auth can no
longer recover `r_tpc` from those `CID`s, so fresh discharges can't be
issued against the old anchors.

Resolution: mint re-mints the affected anchors under the new key. The
invite is re-minted (`mint invite --rotate` draws a fresh `r_inv` and a
fresh `CID` under `K_M-A_new`) and redistributed; the admin service token
is re-minted by `mint admin-service rotate`. A discharge request against an
old `CID` fails with `422 CID decode error`, signalling the operator to
pick up the fresh invite (or the CLI to re-read the rotated service
token) and retry. Coordinator credentials carry no `CID` and are
unaffected.

### `K_M` rotation (mint's root)

The heaviest event in the system. Triggered by routine mint-root
rotation (annual/biennial) or if `K_M` is suspected compromised. When
`K_M` rotates, the invite, the admin service token, and every `K_coord =
HKDF(K_M, coord_ulid)` change, so every chain MAC mint issued becomes
verifiable only under the new root. Mint runs with both `K_M_old` and
`K_M_new` during a grace window, verifying under the new root first and
falling back to the old; it re-mints the invite and the admin service
token immediately, and re-mints each coord's role credentials on that
coord's next interaction (a credential collection or `assume-role`),
which the coord swaps atomically in `data_dir`. After the grace window
mint drops `K_M_old`. (Mint's keyring already supports this additive
rotation — see [`design-mint.md`](design-mint.md) § *Root-key
rotation*.)

### `r_tpc` rotation (per-anchor)

`r_inv` and `r_adm` are not rotated independently of their anchors:
re-minting the invite (`mint invite --rotate`) or running `mint
admin-service rotate` draws a fresh `r_tpc` as a side effect. There is no
per-coord discharge key to rotate — discharges anchor on the invite and
the service token, never on a credential.

### `K_session` rotation (auth-only)

Trivial: only the auth service holds `K_session`. Rotation
invalidates all existing sessions; operators re-run `login`. Grace
window optional — auth can keep `K_session_old` to honour in-flight
sessions until their `exp` expiry, then drop it.

### Summary

| Key | Affects | Resolution path |
|---|---|---|
| `K_M-A` | `CID` on invite + service token undecodable; discharges can't be issued | Mint re-mints the invite and service token under the new key; CLI picks up the fresh anchors |
| `K_M` | Invite, service token, and every `K_coord` change; all chains re-issue | Mint re-mints invite + service token immediately, credentials on next interaction; grace window covers in-flight |
| `r_tpc` | Discharges against the old `CID` fail | Re-mint the anchor (`invite --rotate` / `admin-service rotate`); no standalone rotation |
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

`POST /v1/discharge` (Bearer session) — issue a discharge for a TPC.

```json
request:  { "cid": "<base64>", "scope": "mint:enroll" }
response: { "discharge": "<base64 macaroon>", "expires_at": "..." }
```

The `cid` is the invite's, the ticket's, or the admin service token's
`CID`; `scope` is the authority class requested (`mint:enroll`,
`mint:exchange`, or `mint:admin`). Auth requires `scope ∈ session.scopes`
and stamps it as a `scope` caveat on the returned discharge, which is
otherwise `(sub, exp)`, chain-MAC'd under the `r_tpc`
recovered from `CID`. `401` session expired, `403` session
lacks the scope, `422` `CID` decode failure (signals `K_M-A` rotation).

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

Coord enrollment reuses the mint enrollment flow
([`design-mint.md`](design-mint.md) § *Enrollment*): `POST /v1/enroll`
(invite ⊕ `sub`/`cnf` + PoP + the enrolling operator's discharge)
records a pending enrollment and returns a **credential ticket** carrying
its own TPC; after operator approval, `POST /v1/enroll-exchange`
(`[ticket, exchanging-operator discharge]` + PoP + `{ts, role}`,
checked against the approved registry) yields each of the four role
credentials. None of the credentials embeds a TPC. The OrgId and
auth-service URL are returned alongside the first credential mint issues.

`POST /v1/assume-role` is unchanged in wire shape and carries **no
discharge**: role credentials have no TPC, so the verification routine
returns valid on a successful chain + PoP walk, with nothing to
discharge. There is no coord-facing discharge-forwarding endpoint and no
`/v1/coord/*` refresh endpoint — the three operator discharges are
presented to mint at `/v1/enroll` (invite TPC), `/v1/enroll-exchange`
(ticket TPC), and the admin endpoints (service-token TPC), never
forwarded by coord.

### Coord — CLI-facing

There is no coord-facing operator-auth surface. A coordinator's operator
IPC verbs are **not** discharge-gated: operator authority is established
once, at enrollment, and a coordinator's runtime authority is the
service credentials it was issued there. The CLI ↔ auth interactions
(`login`, `/v1/discharge`) feed the enrollment request and the mint
admin plane, not coord.

## Config

`coordinator.toml` points at mint for enrollment; it carries no
auth-service config:

```toml
[mint]
endpoint = "https://mint.acme.elide.example/"
```

Mint URL, OrgId, auth-service URL, and the role credentials all
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
is assigned `OrgId=demo`. The codepath is identical to prod: an operator
fetches a discharge for the invite's `CID` (presented at `/v1/enroll`)
and for the ticket's `CID` (presented at `/v1/enroll-exchange`), and mint
verifies each inline.

Two startup-time safety checks when `demo-enabled = true`:

- Mint refuses to start unless bound to loopback / UDS.
- Mint logs `WARN auth=demo: discharges are issued without operator
  authentication` at startup and per issued discharge.

Both are config-time checks, not per-request branches — the verifier
in mint stays unconditional. The mint binary has no
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

## Deferred: finer narrowing in caveats

Operator authority today is coarse: a valid session authorizes any
enrollment request or admin verb its scope permits (see *Scope tier*
below), and the admin verb is bound per call by the CLI's
`op=admin:<verb>` attenuation. There is **no per-volume operator
narrowing**, because there is no runtime operator authority over volumes
to narrow — a coordinator's volume writes are app-driven service-token
authority, not operator-gated.

Finer auth-side policy on *which* admin verbs or enrollments a sub
may authorize is the Scope tier below; an even finer explicit
`AllowedOps=[...]` list baked into the discharge at issuance is a purely
additive extension on top of it (extra first-party caveats, one extra
AND clause at the mint clear, no wire change). Reasonable to add when
admin delegation grows multi-team; not in the initial shape.

## Scope tier on sessions and discharges

The scope mechanism is **core** (§ *Discharge flows*): every session
carries a granted scope set, every `/v1/discharge` names a scope auth
checks against it, and every gate clears the discharge's `scope` caveat.
Three baseline scopes ship — `mint:enroll`, `mint:exchange`,
`mint:admin` — one per gate. A *finer* vocabulary on the same mechanism is
proposed below.

### Mechanism (core)

A **scope** is a named class of authority. It is a first-party caveat,
granted at login, checked at issuance, cleared at verify:

1. **Granted at login, carried on the session.** Login is the trust
   source for what a human may authorize, so the session carries its
   granted scope set as a **single** canonical `scope` caveat — the
   scope names sorted and space-joined into one value — alongside
   `(sub, exp)`. One caveat, not one per scope: a holder cannot append a
   `scope` caveat to widen the grant, because two `scope` caveats resolve
   to `Unsatisfiable` (→ empty grant), the same append-only-narrows rule
   that protects every scalar caveat (`docs/finding-membership-caveat-read.md`).
   Auth-side policy decides the grant; the demo grants all scopes to every
   subject — login stays wide-open, but the grant is *explicit* on the
   session.

2. **Checked at `/v1/discharge`.** The request names the scope it needs;
   auth requires `requested ∈ session.scope` and mints the discharge
   carrying that one `scope`. A session lacking it is refused (`403`) —
   the authorization decision `/v1/discharge` makes, distinct from the
   liveness gate.

3. **Cleared at verify.** Each gate knows the scope it requires and
   clears the discharge's `scope` against it (`/v1/enroll` →
   `mint:enroll`, `/v1/enroll-exchange` → `mint:exchange`,
   `/v1/admin/*` → `mint:admin`). A per-request predicate, never cached,
   joining the existing `aud`/`op`/`exp`/PoP clears.

### Proposed: finer vocabulary

The baseline `mint:admin` scope covers every `/v1/admin/*` verb, so "may
approve enrollments but not seal" cannot yet be expressed. Splitting
`mint:admin` into per-area scopes (e.g. `mint:admin:approve`,
`mint:admin:seal`) — and deciding whether scopes are flat or
hierarchical — is purely additive on the mechanism above: more `scope`
names, and a gate that requires the
finer one. An even finer explicit `AllowedOps=[...]` list baked into the
discharge at issuance composes on top (a specific list *within* a scope;
`AllowedOps` is the unit of *per-call narrowing*, scope the unit of
*human grant*).

### Fail-closed mapping

Where a gate maps a finer `op`/verb to a required scope, that map is a
correctness surface: total and closed — an `op` with no scope is
unauthorizable, never silently wide. Where the map (or any hierarchy) is
defined and how it is integrity-protected is TBD; that it fails closed is
not.

### Open

- The finer partition: which admin verbs group into which scope, and
  whether scopes are flat or hierarchical (`mint:admin ⊃ mint:admin:approve`?).
- Where the verb→scope map lives and how it is integrity-protected.
- The `AllowedOps` wire shape, if/when per-call narrowing is wanted.

## Migration from PoC

Clean break. The PoC operator-token surface has already been removed
from the codebase (`~/.elide/tokens.toml`, `Request::MintOperatorToken`,
the `OperatorOp` / `verify_operator` plumbing, the `elide token`
subcommands). Operator IPC verbs are ungated and remain so — operator
authority is established at enrollment, not per runtime IPC, so the auth
service gates enrollment and the mint admin plane rather than the coord
data plane.

No compatibility shim. Operators with stale `~/.elide/tokens.toml`
files must remove them manually. Coords that were stood up under the
PoC must be re-enrolled via `elide-coordinator setup
--enrollment-token` after their org has been activated (mint
enrollment). No migration tooling ships.
