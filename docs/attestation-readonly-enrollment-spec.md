# Hand-off: attestation-kind (read-only) enrollment (mint repo)

**Status: cross-repo interface spec for the `soulware/mint` session.**
The reference record of the mint ↔ coordinator contract for scoping an
enrollment's granted role set. References to `soulware/mint@main`. The
elide-side design is `docs/design/mint-volume-attestation.md` §
*Attestation-kind enrollment* and § *A dedicated attestation instance*.

## Goal

Let an enrollee declare, at `/v1/enroll`, a **kind** that bounds the set
of roles its `Enrolled` record may later exchange. A `coordinator`
enrollment grants the four roles it grants today; an `attestation`
enrollment grants `{coord-ro}` and nothing else. `enroll-exchange`
refuses any role outside the record's granted set.

This is the gate for the dedicated attestation instance
(`elide-coordinator attest`): coord B holds only `coord-ro`, so its
read-only, `by_id/`-free property must be **mint-enforced**, not left to
the coordinator's good behaviour.

## Why

Enrollment today grants every approved `sub` the full coordinator role
set — the `Enrolled` record carries no role constraint, and the role
list is coordinator-side convention. A coordinator that should only ever
read (the attestation discharge authority) can today exchange
`coord-rw`, `volume-rw`, `volume-ro` just by asking. By Elide's
*no-optional-path-for-a-correctness-invariant* rule, "the attestation
authority is read-only" only holds if mint refuses to vend it anything
else. So the grant must become explicit, typed, and enforced.

## Scope: enrollment grant only — no discharge/CID change

The attested-TPC `cid` seal, the discharge MAC, the `mint-macaroon-v6`
domain, `K_M-B`, and `testdata/mint-discharge-vectors.json` are all
**unchanged**. This spec touches only how an `Enrolled` record's
permitted role set is set and enforced. No DOMAIN bump, no vector
regeneration.

## The contract

### 1. `/v1/enroll` carries a `kind`

The request body gains a `kind` field, a string enum:

```
{ "ts": <unix-seconds>, "kind": "coordinator" | "attestation" }
```

- The field is **required and fails closed** — a request with no `kind`
  (or an unrecognised value) is rejected (`400`). A missing kind must
  never default to `coordinator`: defaulting to the wider grant would let
  a dropped field silently over-privilege an attestation instance, which
  is exactly the failure this work prevents.
- `kind` rides the PoP-signed body (the coordinator already signs the
  enroll body — `{ts}` today), so it is bound to the enrollee and not
  forgeable in transit.
- The enrollee *declares* the kind; mint owns what each kind grants (next
  point), so the enrollee cannot request an arbitrary role subset.

### 2. mint maps `kind` → granted role set (mint-owned)

| `kind` | granted role set |
|---|---|
| `coordinator` | `coord-ro`, `coord-rw`, `volume-rw`, `volume-ro` (today's set) |
| `attestation` | `coord-ro` |

The mapping lives in mint. Adding a kind never means trusting a
client-supplied role list.

### 3. The `Enrolled` record stores the granted set, MAC-covered

The resolved role set (or the `kind` it derives from) is recorded on the
pending/`Enrolled` record and **covered by the record's body MAC**, so it
cannot be tampered after approval. This is the durable entitlement
`enroll-exchange` checks against.

### 4. The operator ratifies the kind at approval

`mint enroll list` (and whatever the operator reads before
`mint enroll approve <sub>`) **displays the kind / granted role set**
alongside the `cnf` fingerprint. The operator already matches the
fingerprint out of band; ratifying the privilege class at that same
checkpoint is the trust act. `approve` takes no new flag — it ratifies
the kind the enrollee declared and the operator sees.

### 5. `enroll-exchange` enforces role ∈ grant

When an `enroll-exchange` requests a `role` not in the record's granted
set, mint **refuses with a status distinct from `401`/`403`** — suggest
`422 Unprocessable Entity` — with a clear message.

> **Why not `403`.** The coordinator's exchange client treats
> `403` as *awaiting approval* and `401` as *ticket expired*
> (`elide-coordinator/src/enroll.rs`, `exchange_request`), and will poll
> on `403`. A role-outside-grant denial reusing `403` would make a
> misconfigured client poll forever instead of failing loudly. Any status
> outside `{200, 401, 403}` is surfaced as a hard error by that client,
> which is the behaviour wanted here.

A legitimate client never hits this — an `attestation` enrollee only ever
asks for `coord-ro`. It is the enforcement backstop against a buggy or
compromised coordinator reaching past its grant.

## Clean break (no compat default)

Existing `coordinator` enrollment must now send `kind: "coordinator"`
explicitly (point 1 fails closed on absence). mint and the coordinator
deploy in lockstep via `MINT_REF`, so this is a clean break, not a
compatibility path — consistent with Elide's *no-backward-compat-by-
default* rule. After mint ships this, bump `MINT_REF` in
`deploy/mint/Dockerfile` and `elide-coordinator/src/mint_attested_e2e.rs`
to a commit carrying it.

## Elide-side follow-up (lands with the `MINT_REF` bump)

- `/v1/enroll` request gains `kind` (`elide-coordinator/src/enroll.rs`,
  `enroll_request` — the body is `{"ts":…}` today).
- The role fan-out (`ENROLL_ROLES` / `assert_enrolled`) becomes
  kind-parametric: a `coordinator` enroll fans out all four roles; an
  `attestation` enroll fans out `{coord-ro}` only.
- The new `elide-coordinator attest` subcommand enrolls with
  `kind=attestation`, assumes `coord-ro`, and serves only the discharge
  listener (§ *A dedicated attestation instance*, shape 2).
