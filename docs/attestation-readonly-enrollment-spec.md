# Enrollment profiles (read-only attestation enrollment)

**Status: the mint ↔ coordinator contract for scoping an enrollment's
granted role set.** Implemented mint-side in `soulware/mint#50` (its
reference is `docs/enroll-profiles.md`) and coordinator-side in
`elide-coordinator/src/enroll.rs` (`EnrollProfile`). The elide-side design
is `docs/design/mint-volume-attestation.md` § *Attestation-profile
enrollment* and § *A dedicated attestation instance*.

## Goal

Let an enrollee declare, at `/v1/enroll`, a **profile** that bounds the set
of roles its `Enrolled` record may later exchange. A `coordinator`
enrollment grants the four roles it grants today; an `attestation`
enrollment grants `{coord-ro}` and nothing else. `enroll-exchange` refuses
any role outside the record's granted set.

This is the gate for the dedicated attestation instance
(`elide-coordinator attest`): coord B holds only `coord-ro`, so its
read-only, `by_id/`-free property must be **mint-enforced**, not left to the
coordinator's good behaviour.

## Why

Enrollment once granted every approved `sub` the full coordinator role set —
the `Enrolled` record carried no role constraint, and the role list was
coordinator-side convention. A coordinator that should only ever read (the
attestation discharge authority) could then exchange `coord-rw`,
`volume-rw`, `volume-ro` just by asking. By Elide's
*no-optional-path-for-a-correctness-invariant* rule, "the attestation
authority is read-only" only holds if mint refuses to vend it anything else.
So the grant is explicit, typed, and enforced.

## Scope: enrollment grant only — no discharge/CID change

The attested-TPC `cid` seal, the discharge MAC, the `mint-macaroon-v6`
domain, `K_M-B`, and `testdata/mint-discharge-vectors.json` are all
**unchanged**. This contract touches only how an `Enrolled` record's
permitted role set is set and enforced. No DOMAIN bump, no vector
regeneration.

## The contract

### 1. `/v1/enroll` carries a `profile`

The request body carries a `profile` field, a string naming a configured
profile:

```
{ "ts": <unix-seconds>, "profile": "coordinator" | "attestation" }
```

- The field is **required and fails closed** — a request with no `profile`
  (or an unrecognised name) is rejected (`400`). A missing profile never
  defaults to `coordinator`: defaulting to the wider grant would let a
  dropped field silently over-privilege an attestation instance, which is
  exactly the failure this prevents.
- `profile` rides the PoP-signed body (the coordinator signs `{ts, profile}`),
  so it is bound to the enrollee and not forgeable in transit.
- The enrollee *declares* the profile; mint owns what each profile grants
  (next point), so the enrollee cannot request an arbitrary role subset.

### 2. mint maps `profile` → granted role set (config-owned)

mint holds the mapping as a top-level `[[profile]]` catalog, a sibling to
`[[role]]`, each entry a `name` and the `roles` it grants. For Elide:

| profile | granted role set |
|---|---|
| `coordinator` | `coord-ro`, `coord-rw`, `volume-rw`, `volume-ro` |
| `attestation` | `coord-ro` |

At least one `[[profile]]` is required and the catalog is validated at
config load (unique names; every granted role is a configured `[[role]]`).
The catalog may live inline or in a separate file referenced by
`catalog_file`; Elide's deployment uses the latter (`deploy/mint/`). Adding
a profile never means trusting a client-supplied role list.

### 3. The `Enrolled` record stores the grant, MAC-covered

The declared profile is recorded on the pending/`Enrolled` record and
**covered by the record's body MAC**, so it cannot be tampered after
approval. This is the durable entitlement `enroll-exchange` checks against.

### 4. The operator ratifies the profile at approval

`mint enroll list` (and whatever the operator reads before
`mint enroll approve <sub>`) **displays the profile / granted role set**
alongside the `cnf` fingerprint. The operator already matches the
fingerprint out of band; ratifying the privilege class at that same
checkpoint is the trust act. `approve` takes no new flag — it ratifies the
profile the enrollee declared and the operator sees.

### 5. `enroll-exchange` enforces role ∈ grant

When an `enroll-exchange` requests a `role` not in the record's granted set,
mint **refuses with `422`** — a status distinct from `401`/`403` — with a
clear message.

> **Why not `403`.** The coordinator's exchange client treats `403` as
> *awaiting approval* and `401` as *ticket expired*
> (`elide-coordinator/src/enroll.rs`, `exchange_request`), and will poll on
> `403`. A role-outside-grant denial reusing `403` would make a
> misconfigured client poll forever instead of failing loudly. Any status
> outside `{200, 401, 403}` is surfaced as a hard error by that client,
> which is the behaviour wanted here.

A legitimate client never hits this — an `attestation` enrollee only ever
asks for `coord-ro`. It is the enforcement backstop against a buggy or
compromised coordinator reaching past its grant.

## Clean break (no compat default)

Every `/v1/enroll` now sends a `profile` (point 1 fails closed on absence),
and every mint config declares at least one `[[profile]]`. mint and the
coordinator deploy in lockstep via `MINT_REF`, so this is a clean break, not
a compatibility path — consistent with Elide's *no-backward-compat-by-
default* rule. Once mint ships a release carrying `#50`, bump `MINT_REF` in
`deploy/mint/Dockerfile` and `elide-coordinator/src/mint_attested_e2e.rs` to
it.

## Elide side (landed)

- `/v1/enroll` sends `profile` (`enroll.rs`, `enroll_request`).
- The role fan-out is profile-parametric: `EnrollProfile::Coordinator` fans
  out all four roles, `EnrollProfile::Attestation` fans out `{coord-ro}`
  (`enroll.rs`, `assert_enrolled`).
- `elide-coordinator attest` enrols `profile=attestation`, assumes
  `coord-ro`, and serves only the discharge listener (§ *A dedicated
  attestation instance*, shape 2).
- `deploy/mint/` declares the `[[role]]` + `[[profile]]` catalog in a
  `catalog_file`.
