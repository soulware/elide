# Auth model: principles and isolation

This doc captures the coordinator's auth principles and the isolation
guarantees the macaroon scheme does and does not provide on a
shared-uid host.

The underlying macaroon construction — chained keyed-BLAKE3 MAC,
per-token struct-level nonce, AND-of-predicates caveat evaluation —
is documented in
[`architecture.md`](architecture.md#proposed-s3-credential-distribution-via-macaroons).
Two macaroon classes layer on that foundation:

- **Volume macaroons** — minted on `register`, PID-bound, scope-bound.
  Used by volume processes to request short-lived read-only S3
  credentials. Implemented. Construction and registration flow live in
  `architecture.md`.
- **Operator session and discharge macaroons** — issued by a central
  auth service, not the coordinator. Gate every operator IPC verb via
  a session + per-op discharge. Design lives in
  [`design-auth-service.md`](design-auth-service.md); not yet
  implemented. Operator IPC verbs are ungated in the codebase today.

The remaining sections cover the isolation model that frames what
either macaroon class can and cannot enforce, and the settled
principle that operator authorisation gates S3 *writes* — not a
hand-enumerated verb list — once the central auth service lands.

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

**What operator macaroons will provide — audit + ceremony, not access
control.** Once the central auth service lands, operator IPC verbs
will require a session + per-op discharge. This raises the bar over
bare socket access and provides an audit trail centred on the auth
service. It does not prevent a compromised local process from
achieving the same effect via direct filesystem manipulation (`rm
-rf` on the volume dir achieves `remove` without going through the
coordinator). The value is auditability, forced ceremony for S3
mutations, and per-request attenuation — not a hard security boundary
against a local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Coordinator mutations | Operator session + discharge (planned) | Coordinator + mint, once the central auth service lands |

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

The mint cutover settles the issuer: mint is the sole issuer and
verifier, with a single root that never leaves it (`design-mint.md` §
*Trust model*). Human authorisation does not enter by *which authority
issues* — it enters as a **third-party-caveat discharge**: the
coordinator holds a primary macaroon; a write window additionally
requires a discharge from an identity authority (the managed `elide
operator login` service) attesting a human authorised it. The concrete
shape of that auth service — login flow, session/discharge macaroons,
multi-tenancy, enrollment, API surface — lives in
[`design-auth-service.md`](design-auth-service.md).

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
