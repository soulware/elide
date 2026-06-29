# Mint template seal

The template seal — the signed `seal.json` over role blocks and
policy-template hashes that pins what a `mint serve` host will render, the
dormant-until-sealed startup state, the authenticated `POST /v1/admin/seal`
authoring call, and the local sealed cache — is **mint's mechanism, owned by
the mint repository**
([`github.com/soulware/mint`](https://github.com/soulware/mint): `src/seal.rs`,
`src/sealed_cache.rs`, `src/admin.rs`, and mint's own
`docs/design/mint-template-seal.md`). It moved out of Elide when mint became a
separate project, and the always-attest work (mint's
`docs/design-always-attest.md`) reshaped the sealed surface — a single
`ttl_seconds` per role, and caveat provenance *derived* from the policy
template rather than a declared `[role.template]` / `[role.attestation]`
contract — so this Elide copy is no longer maintained.

What Elide owns is the **input** to the seal: the role policy templates and the
`mint-elide.toml` inventory in `deploy/mint/` (`deploy/mint/README.md` is the
run-book), sealed by `mint seal` at deploy time. How Elide consumes the result
is `docs/design/mint.md`; the per-volume attestation that rides the sealed
templates is `docs/design/mint-volume-attestation.md`.
