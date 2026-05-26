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
- **Operator authorisation** — gates every operator IPC verb via a
  mint-issued primary macaroon (one per coord, cached at coord) and
  an auth-service-issued wide discharge (one per `(session, coord)`,
  vouched on cache miss via `/v1/discharge/verify`), with the CLI
  attenuating the wide discharge per IPC for `(Op, Volume)` binding.
  Design lives in
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
  so coord is excluded from issuance entirely: mint issues primaries
  (mint is the org's identity hub) and the auth service issues
  discharges (the auth service is the human-identity authority).
  Coord and mint trust discharges *on receipt* — coord via the
  cached vouch obtained from `/v1/discharge/verify` at auth, mint
  via the same mechanism on its assume-role path. Neither holds any
  discharge-MAC key.

The mint-and-auth-service split for the operator chain is therefore
specific to that chain. It is not a general "centralise all macaroon
issuance" principle.

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
verbs will require a mint-issued primary (held by coord) plus an
auth-service-issued discharge (vouched at auth on first sight,
cached at coord), attenuated by the CLI per IPC. This raises the
bar over bare socket access and produces a centralised audit trail
anchored at the auth service. It does not prevent a compromised
local process from achieving the same effect via direct filesystem
manipulation (`rm -rf` on the volume dir achieves `remove` without
going through the coordinator). The value is auditability, forced
ceremony for S3 mutations, and per-IPC CLI attenuation — not a hard
security boundary against a local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Coordinator mutations | Operator primary + cached auth-service discharge (planned) | Coordinator + mint, once the central auth service lands |

## Proposed: operator tokens gate S3 writes, not verbs

**Status: proposed. Not yet implemented. Documents the settled
principle that motivates the central auth service design in
[`design-auth-service.md`](design-auth-service.md) and the
[`mint`](design-mint.md) cutover.**

### The principle

Operator authorisation is not about "gating destructive verbs." It
is: **any operation that mutates S3 state must be authorised.** Three
framings were considered and rejected as the organising axis:

- *Destructive verbs* — `remove`'s default form is a reversible local
  cache drop; the destructive/reversible line does not fall on verb
  boundaries.
- *`--force` flags* — narrows the gate to irreversibility escape
  hatches, but says nothing about the routine S3 writes that are the
  actual point.
- *Ownership ops only* — closer (`claim` / `release` do write shared
  S3 state), but still an enumeration, not the principle.

The principle is read-vs-write **against S3**: read paths are an
unauthorised baseline; every S3 mutation requires operator
authorisation.

### Why this cannot be expressed today, and becomes structural under mint

Today the coordinator holds IAM admin and writes S3 directly.
Enforcing "every S3 mutation is authorised" in that architecture
means intercepting every code path that touches the bucket
(breadcrumb writes, snapshot uploads, `names/` flips, IAM teardown)
and bolting a token check onto each — a leaky enumeration and exactly
the "optional path for a correctness property" this project rejects.
There is no chokepoint, so per-verb gating can never be more than a
proof of concept.

`mint` (see [`design-mint.md`](design-mint.md)) creates the chokepoint.
Once mint is split out, the coordinator cannot write S3 with ambient
admin creds: to mutate it must call `mint /v1/assume-role` with a
macaroon and obtain a write-capable keypair (`volume-rw`, `coord-names`,
the Split-A writer roles). Reads need only `coord-ro`, the read-only
baseline every coordinator already holds. "Every S3 mutation is
authorised" then holds *architecturally* — enforced by IAM at the single
point write credentials are acquired — rather than by scattered
in-coordinator checks.

### Issuer and the human-authorisation point

Two issuers, separated by capability:

- **Mint** holds `K_M`, the primary-macaroon MAC root. Mint mints
  one primary per coord at enrollment; the primary carries a
  third-party caveat naming the auth service. Coord receives
  `K_coord = HKDF(K_M, coord_ulid)` so it can verify its own
  primary's chain locally.
- **The auth service** holds `K_disch`, the discharge MAC root.
  Auth mints wide discharges (one per `(session, coord)`, ~5 min)
  and verifies them on demand via `/v1/discharge/verify`. Coord and
  mint hold no discharge-MAC key — they trust discharges *on
  receipt* via the cached vouch.

The TPC binding is woven into the primary's HMAC chain, so the
discharge requirement cannot be stripped by any party who cannot
mint primaries. Combined with `K_disch` living only at auth, this
makes the auth-service round-trip a **non-bypassable property of
every accepted operator IPC**, enforced by the math (the TPC is in
the chain; the discharge MAC is only verifiable by auth) and by
audit (every accepted bundle must trace to a `/discharge/verify`
call at auth within the cache TTL).

The CLI further narrows the wide discharge per IPC by appending
bearer-attenuation caveats (`Op`, `Volume`, tight `NotAfter`,
optional `Nonce`). Coord verifies the attenuation chain locally
from the cached wide's trailing tag — no auth round-trip per IPC.

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
