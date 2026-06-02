# Auth model: principles and isolation

This doc captures the coordinator's auth principles and the isolation
guarantees the macaroon scheme does and does not provide on a
shared-uid host.

The underlying macaroon construction — chained keyed-BLAKE3 MAC,
per-token struct-level nonce, AND-of-predicates caveat evaluation —
is documented in
[`architecture.md`](architecture.md#proposed-s3-credential-distribution-via-macaroons).
Two distinct auth surfaces layer on that foundation:

- **Volume macaroons** — minted by the coordinator on `register`,
  PID-bound, scope-bound. Used by volume processes to request
  short-lived read-only S3 credentials. Implemented. Construction
  and registration flow live in `architecture.md`.
- **Operator authorisation** — gates coordinator **enrollment** and the
  **mint admin plane**, not runtime S3 writes. Operator authority is
  established at enrollment via three TPC gates, each discharged by a
  logged-in operator: a TPC on the shared invite (the *requesting*
  operator, at `/v1/enroll`), a TPC on the credential ticket mint returns
  (the *initializing* operator, at `/v1/enroll-exchange`), and the
  *approving* operator's confirmation of the coordinator's key in
  between. The role credentials mint then issues carry **no** TPC — they
  are long-lived service tokens, and `assume-role` is app-driven. The
  same discharge mechanism gates each `/v1/admin/*` verb on mint (a TPC
  on the CLI service token). Design lives in [`design-mint.md`](design-mint.md)
  (the enrollment flow and admin plane) and
  [`design-auth-service.md`](design-auth-service.md) (the
  session/discharge issuer). Mint's verification routine and the demo
  discharge issuer are implemented and exercised by the mint CLI as
  mint's first client; the standalone auth service is not yet built.

The remaining sections cover the isolation model that frames what
either surface can and cannot enforce, and the principle that operator
authority is an *enrollment-time* attestation — not a runtime gate on
every S3 write.

## Two surfaces, two trust sources

The two surfaces have different issuers because they attest different
kinds of claim. The organising principle is: **the issuer of an
attestation is whoever is the trust source for the claim being
attested.**

- A volume macaroon attests "this PID is volume V on this
  coordinator, scoped to S, valid until T." Every component of that
  claim is coord-local: coord spawned the process, owns the IPC
  socket (SO_PEERCRED is the live check), and owns the volume
  registration table. Coord is the trust source, so coord is the
  issuer. A compromised coord could "forge" a volume macaroon, but
  that is indistinguishable from coord lying about its own state —
  there is no upstream party whose attestation is being faked.
- An operator discharge attests "a human authorised this — an
  enrollment, or an admin verb." The trust source is the human's
  identity provider, not coord. Coord must not be able to forge that
  claim, so coord is excluded from issuance and from verification: mint
  stamps the third-party caveats (on the invite and the CLI service
  token) and verifies them — it holds `K_M` to walk the chain and can
  recover the discharge HMAC key from the TPC's `VID` or `CID` — and the
  auth service issues the discharges (it is the human-identity
  authority). The discharge is presented to mint alongside the macaroon
  it discharges — at `/v1/enroll` and at the admin endpoints — never
  forwarded by coord. Coord holds no key material and is not on the
  discharge path.

The trust circle for discharge minting and verification is
`{auth, mint}`. Coord is outside it. The mint-and-auth-service split
for the operator chain is therefore specific to that chain. It is
not a general "centralise all macaroon issuance" principle.

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

**What operator authorisation provides — audit + ceremony at
enrollment, not runtime access control.** Operator authority is an
enrollment-time attestation: bringing a coordinator into the fleet
requires a *requesting* operator's discharge, an *approving* operator's
confirmation, and an *initializing* operator's discharge when the
coordinator first pulls its credentials — all three attributed to humans
in the audit trail (`requested_by`, `approved_by`, and the initializing
`Subject`); each mint admin verb requires a fresh operator discharge. This raises the bar over bare socket access and
produces a centralised audit trail anchored at the auth service. It does
not gate a coordinator's runtime S3 writes — those run on the
service-token authority granted at enrollment — and it does not prevent
a compromised local process from manipulating a volume dir directly
(`rm -rf` needs no coordinator). The value is auditable, ceremony-gated
*enrollment and administration* — not a hard security boundary against a
local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Coordinator enrollment + mint admin verbs | Operator discharge on the invite / ticket / CLI service token (planned) | mint + auth service, once the central auth service lands |
| Coordinator S3 mutations (all) | Role credential alone (no discharge) | mint, via the assume-role gate on the role |

## Operator authority is established at enrollment

**Status: proposed. Not yet implemented. Motivates the central auth
service in [`design-auth-service.md`](design-auth-service.md) and the
[`mint`](design-mint.md) enrollment flow.**

### The principle

Operator authority is proven **at the boundaries where a human decision
belongs** — bringing a coordinator into the fleet, and administering the
mint — not on every S3 write a coordinator subsequently makes. An
earlier framing gated "every operator-initiated S3 mutation" at runtime,
splitting role credentials into operator-write and background-write
variants; that was the wrong abstraction. A coordinator that has been
enrolled is a trusted service: its writes — operator-initiated and
background alike — run on the long-lived role credentials it was issued,
and require no per-write human attestation.

The places a human decision is required:

- **Enrollment** — three gates, each a TPC discharged by a logged-in
  operator, none of them on a credential. A *requesting* operator
  authorises a coordinator to attempt enrollment (a TPC on the shared
  invite); an *approving* operator — possibly a different human —
  confirms the coordinator's key (an admin-plane discharge); an
  *initializing* operator is present when the coordinator first pulls its
  credentials (a TPC on the credential ticket, at `/v1/enroll-exchange`).
  All three identities are recorded. After that the coordinator holds
  TPC-free service credentials.
- **Mint administration.** Each `/v1/admin/*` verb (invite management,
  enrollment approval) requires a fresh operator discharge satisfying a
  TPC on the mint CLI service token.

### Why this is structural under mint

Today the coordinator holds IAM admin and writes S3 directly. `mint`
(see [`design-mint.md`](design-mint.md)) removes that: to mutate S3 a
coordinator must call `mint /v1/assume-role` with a role credential and
obtain a scoped, short-lived keypair. That chokepoint is what makes
*enrollment* the right place for operator authority — a coordinator
cannot obtain any credential without having been enrolled, and
enrollment is exactly the human-gated ceremony. Gating every runtime
write instead would put a non-bypassable human round-trip on the hot
path of GC, drain, and reaper — ceremony with no commensurate security
gain, since an enrolled coordinator is already trusted within its scope.

### Issuer and the human-authorisation point

Following the [canonical macaroon
shape](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md):

- **Mint** holds `K_M` and shares `K_M-A` with auth (per-org wrapping
  key for third-party-caveat `CID`s). It stamps the TPCs on the invite,
  the credential ticket, and the CLI service token, issues the four
  TPC-free role credentials at enrollment, and **verifies** every
  discharge presented to it (it holds `K_M` to walk the chain and
  `K_M-A` to recover the discharge key from a `CID`). Verification at
  mint is offline.
- **The auth service** holds `K_M-A` (shared with mint) and `K_session`.
  It issues operator sessions at login and mints short-lived discharges
  against a TPC's `CID`. It does not sit on any verification path at
  runtime.

**Coord holds no chain key and no discharge key, and is not on the
discharge path.** The discharge is presented to mint by the party
holding it — the coordinator at `/v1/enroll` and `/v1/enroll-exchange`
(the requesting and initializing operators' discharges, conveyed to it),
the mint CLI at the admin endpoints. The TPC binding is woven into the
invite's, the ticket's, and the service token's HMAC chains, so the
discharge requirement cannot be stripped by any party who cannot mint
them; combined with the `{auth, mint}` trust circle, the auth-service
round-trip is a **non-bypassable property of enrollment and of every
admin verb**, enforced by the math (the TPC is in the chain;
verification requires `K_M` and `K_M-A`) and by audit (every accepted
discharge traces to an auth issuance).

The concrete shape of that auth service — login flow, session and
discharge protocol, multi-tenancy, enrollment, API surface — lives
in [`design-auth-service.md`](design-auth-service.md).

## Future directions

These do not affect the design above; they describe extensions that slot
in cleanly when the threat model or deployment shape warrants them.
- **Root key in a separate signing process.** Today the coordinator
  holds the volume-macaroon root key in memory. Splitting it into a
  standalone signing service reduces blast radius (coordinator
  compromise can no longer forge volume macaroons across the fleet)
  and enables TPM/HSM backing. Volume `credentials` verification is
  hot, so the likely shape is per-coordinator derived keys (signing
  service issues an HKDF-derived sub-key the coordinator uses to
  verify locally) rather than RPC-on-verify. Worth doing when there
  is more than one coordinator host, or when the coordinator's trust
  level is bounded below the key's.
