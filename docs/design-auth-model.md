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
- **Operator authorisation** — gates every operator IPC verb that
  initiates an S3 mutation. Mint issues role credentials at coord
  enrollment; the **operator-write** variants (`coord-rw`,
  `volume-rw`) carry a third-party caveat (TPC) requiring an
  auth-service-issued wide discharge. The CLI fetches one discharge
  per `(session, coord)` and attenuates it per IPC for `(Op,
  Volume)` binding. Coord holds no chain key and no discharge key:
  it forwards bundles to mint for cryptographic verification, caches
  mint's verdict for the discharge's NotAfter, and clears caveats
  against the live IPC context. Design lives in
  [`design-auth-service.md`](design-auth-service.md); not yet
  implemented. Operator IPC verbs are ungated in the codebase today.

The remaining sections cover the isolation model that frames what
either surface can and cannot enforce, and the settled principle
that operator authorisation gates S3 *writes* — not a hand-enumerated
verb list — once the central auth service lands.

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
- An operator discharge attests "a human authorised this op against
  this coordinator." The trust source is the human's identity
  provider, not coord. Coord must not be able to forge that claim,
  so coord is excluded from issuance and from verification: mint
  issues primaries (mint is the org's identity hub) and the auth
  service issues discharges (the auth service is the human-identity
  authority). Mint is also the verifier — it holds the chain key
  and can recover the discharge HMAC key from the TPC's `VID` or
  `CID`. Coord holds no key material; it forwards bundles to mint
  for verification, caches the verdict, and clears caveats locally.

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

**What operator authorisation will provide — audit + ceremony, not
access control.** Once the central auth service lands, operator IPC
verbs that initiate S3 mutations will require a mint-issued
TPC-bearing role credential (held by coord) plus an
auth-service-issued discharge (vouched at auth on first sight,
cached at coord), attenuated by the CLI per IPC. This raises the
bar over bare socket access and produces a centralised audit trail
anchored at the auth service. It does not prevent a compromised
local process from achieving the same effect via direct filesystem
manipulation (`rm -rf` on the volume dir achieves `remove` without
going through the coordinator). The value is auditability, forced
ceremony for operator-initiated S3 mutations, and per-IPC CLI
attenuation — not a hard security boundary against a local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Operator-initiated coordinator mutations | TPC-bearing role credential + cached auth-service discharge (planned) | Coordinator + mint, once the central auth service lands |
| Background coordinator mutations | Role credential alone (no discharge) | mint, via assume-role gate on the background role |

## Proposed: operator tokens gate operator-initiated S3 writes

**Status: proposed. Not yet implemented. Documents the settled
principle that motivates the central auth service design in
[`design-auth-service.md`](design-auth-service.md) and the
[`mint`](design-mint.md) cutover.**

### The principle

Operator authorisation is not about "gating destructive verbs." It
is: **every operator-initiated S3 mutation must be authorised.**
Three framings were considered and rejected as the organising axis:

- *Destructive verbs* — `remove`'s default form is a reversible local
  cache drop; the destructive/reversible line does not fall on verb
  boundaries.
- *`--force` flags* — narrows the gate to irreversibility escape
  hatches, but says nothing about the routine S3 writes that are the
  actual point.
- *Ownership ops only* — closer (`claim` / `release` do write shared
  S3 state), but still an enumeration, not the principle.

The principle is operator-initiated vs background **against S3**:
read paths are an unauthorised baseline; background coord work
(GC, drain, reaper, startup reconciliation) is coord-attested and
runs on coord's own role credentials; an operator-initiated mutation
requires the operator's discharge in addition to coord's role
credential.

Background work is not "ungated" — it still goes through mint's
assume-role and gets a credential scoped to coord's role. What it
does not require is a *human* attestation: the audit trail records
the mutation as coord-attested, distinct from operator-attested
mutations. That distinction is structural at the role level (next
section), not a per-call flag.

### Why this cannot be expressed today, and becomes structural under mint

Today the coordinator holds IAM admin and writes S3 directly.
Enforcing "every operator-initiated S3 mutation is authorised" in
that architecture means intercepting every code path that touches
the bucket from an IPC handler and bolting a token check onto each
— a leaky enumeration and exactly the "optional path for a
correctness property" this project rejects. There is no chokepoint,
so per-verb gating can never be more than a proof of concept.

`mint` (see [`design-mint.md`](design-mint.md)) creates the chokepoint.
Once mint is split out, the coordinator cannot write S3 with ambient
admin creds: to mutate it must call `mint /v1/assume-role` with a
role credential and obtain a write-capable keypair. The role
inventory splits operator-write from background-write at this point:
mint configures the operator-write roles (`coord-rw`, `volume-rw`)
to require an additional discharge at assume-role time (because their
credentials carry a TPC), and the background-write roles
(`coord-rw-background`, `volume-rw-background`) to require none.
"Operator-initiated mutations are operator-attested" then holds
*architecturally* — enforced by mint's chain walk at the single
point write credentials are acquired — rather than by scattered
in-coordinator checks or caller-declared flags.

### Issuer and the human-authorisation point

Following the [canonical macaroon
shape](https://github.com/superfly/macaroon/blob/main/macaroon-thought.md):

- **Mint** holds `K_M`, the role-credential MAC root, and shares
  `K_M-A` with auth (per-org wrapping key for third-party-caveat
  `CID`s). At coord enrollment mint issues a role credential per
  role; the operator-write credentials carry a TPC `(location, VID,
  CID)`, all using the same per-coord ephemeral `r`. **Mint is
  also the verifier** — it holds `K_M` (derives `K_coord` on demand
  to walk any of the credential's chains) and `K_M-A` (decrypts
  `CID` to recover `r`). Verification at mint is offline.
- **The auth service** holds `K_M-A` (shared with mint) and
  `K_session`. Auth mints wide discharges (one per `(session,
  coord)`, ~5 min) by decrypting any of the coord's TPC `CID`s with
  `K_M-A` to recover `r`, then MACs the discharge under `r`. Auth
  does not sit on the verification path at runtime. One discharge
  serves every operator-write credential for that coord because
  they share `r`.

**Coord holds no chain key, no discharge key.** It receives the
role credentials at enrollment and stores the bytes. On each
operator IPC, coord forwards the bundle (the role credential it
nominates as the discharge anchor, plus the attenuated discharge)
to mint for verification via `/v1/verify`, caches mint's
verdict for the wide discharge's NotAfter, and clears caveats
locally against the live IPC context.

The TPC binding is woven into the operator-write credentials' HMAC
chains, so the discharge requirement cannot be stripped by any
party who cannot mint credentials. Combined with the trust circle
for discharge mint/verify being `{auth, mint}`, this makes the
auth-service round-trip a **non-bypassable property of every
accepted operator IPC**, enforced by the math (the TPC is in the
chain; verification requires `K_M` and `K_M-A`) and by audit
(every accepted IPC must trace through mint's verification log to
auth's issuance log within the cache TTL).

The CLI narrows the wide discharge per IPC by appending
bearer-attenuation caveats (`Op`, `Volume`, tight `NotAfter`). Coord
attenuates the role credential it forwards with a per-forward
`NotAfter` before every call to mint, on the same "always attenuate
tightly" principle. Coord and mint clear both attenuations against
their respective request contexts.

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
