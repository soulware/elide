# mint (prototype)

Macaroon-authenticated scoped-credential vending for Tigris. Tracks
[`docs/design-mint.md`](../docs/design-mint.md).

This is an implementation tracking the settled design — a runnable
vertical slice, not v1. It lives in the elide workspace during the
design phase and is deliberately free of `elide-*` dependencies; it is
destined to become a standalone OSS project.

## Caveat vocabulary

Borrowed verbatim from the RFCs (`docs/design-mint.md` § *Standard
caveats*): `aud` (RFC 7519), `exp` (RFC 7519), `sub` (RFC 7519 — the
opaque principal; Elide puts a coordinator ULID here), `cnf` (RFC 7800
holder-of-key, scalar-encoded `ed25519:<pub>`). Coined, mint-specific:
`op` (endpoint partition — positively required at every endpoint, never
absence-tested), `role`, `bootstrap` (the rotation nonce). Elide's only
namespaced caveat is `elide:Volume`.

## Flow

**Enrollment** (`docs/design-mint.md` § *Enrollment*):

```
mint bootstrap             -> reusable non-expiring bootstrap macaroon
                              (op=enroll, aud, current bootstrap nonce)
client attenuates sub+cnf, PoP
  POST /v1/enroll          -> pending record (keyed by sub) + short
                              intermediate (op=enroll-exchange)
operator: mint enroll list / approve <sub>   (verify cnf fingerprint
                              out of band — the client prints its own)
  POST /v1/enroll-exchange -> 403 until approved, then re-mint the
                              non-expiring primary from root
                              (op=assume-role); pending record consumed
```

**Vending**: the client attenuates the held primary (`exp`,
`elide:Volume`, …) and `POST /v1/assume-role` + PoP → role gate →
policy render → Tigris keypair.

`mint bootstrap rotate` draws a new nonce and cancels in-flight
enrollments; outstanding primaries are unaffected.

## Modules

- `caveat` / `macaroon` — named **scalar** caveats, chained-BLAKE3 MAC,
  base64 wire. `EffectiveCaveats` resolves a name tri-state — `Absent`
  / `Value` / `Unsatisfiable` — ≥2 disagreeing occurrences are
  `Unsatisfiable` (fail closed, the append-a-contradictory-copy
  defence). `caveat::name` / `caveat::op` are the canonical constants.
- `pop` — the `cnf` holder-of-key gate. Ed25519 over
  `tail ‖ BLAKE3(raw-body)`; freshness `ts` rides in the body. Required
  on all three operations in the Elide path.
- `issuance` — `mint_bootstrap` / `mint_intermediate` / `mint_primary`
  (each a fresh chain from root) + `bound_identity`.
- `state` — persisted bootstrap nonce + transient pending table, a
  directory of files (`bootstrap`, `pending/<sub>.json`,
  `approved/<sub>`) so the lifecycle is `ls`-inspectable. Idempotent
  same-`(sub,pub)`, conflict on a different key, GC of stale unapproved,
  consume-on-exchange.
- `config` — TOML: audience, trust root, `state_dir`, tenant, roles.
  Admin credential from `AWS_*`, never the TOML.
- `role` / `template` / `audit` / `http` — role gate, handlebars policy
  render, JSON audit line, axum endpoints.
- `iam` — `KeypairMinter` trait; `FakeMinter` for tests.

## Run it

```sh
mint bootstrap            mint/examples/demo.toml   # print the bootstrap macaroon
mint enroll list          mint/examples/demo.toml
mint enroll approve       mint/examples/demo.toml <sub>
mint serve                mint/examples/demo.toml 127.0.0.1:8085
```

**Interim:** until the live Tigris SigV4 minter lands, `serve` wires
`FakeMinter` and warns loudly on every start — the enroll/exchange flow
is real, but `assume-role` returns a deterministic placeholder keypair.
This is an explicit, temporary deviation from the design's "no stub
backend", removed when the real minter is wired.

## Staged tail

The networked `mint client enroll|exchange|assume-role` and the live
Tigris IAM SigV4 minter (the one production-coupled module, isolated
behind `KeypairMinter`) are the next stage. Also out of scope here: TLS,
multi-root / root rotation, multi-tenancy, `ListRoles`/`GetRole`,
third-party-caveat discharge for a central identity authority
(`docs/design-mint.md` § *Open questions* #14/#15). `trust_root_hex`
straight from TOML remains the OQ#14 shortcut.
