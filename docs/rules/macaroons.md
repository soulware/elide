# Macaroon design

Macaroons in this project follow the canonical design from Fly.io's ["Macaroons Escalated Quickly"](https://fly.io/blog/macaroons-escalated-quickly/). Two examples in tree: volume macaroons (coord-issued, PID-bound — see `docs/architecture.md`) and the operator-authorisation chain (mint primaries + auth-issued discharges, see `docs/design/auth-service.md`).

**Stay aligned with the canonical model.**

- **Symmetric MAC only.** A macaroon's chain is keyed-BLAKE3 (or keyed-HMAC) MAC. If a proposal reaches for asymmetric crypto inside something it still calls a macaroon, that's drift — rename it and design it as a separate artefact, or rework to symmetric.
- **Don't distribute the root key.** Verification of MAC tags happens at the service that holds the root key. Other services POST bytes to that service and cache the yes/no answer. The root never leaves its home.
- **Don't distribute HKDF-derived per-scope keys to verifiers either.** Anyone who can verify with a key can also forge with it. Distributing per-coord/per-window/per-anything MAC keys to verifiers gives them forgery capability for that scope. Use the verification-service pattern instead.
- **Verify ≠ clear.** Verification = HMAC tag check (pure crypto, cacheable, same bytes → same answer). Clearing = caveat predicate evaluation against live request context (per-request, never cacheable). Caches are for verification results, never for clearing results.
- **Service tokens at the trust source.** The issuer of a token is whoever is the trust source for the claim being attested. Volume tokens attest "this PID is volume V on this host" — coord is the trust source, so coord issues. Operator authorisation attests "a human authorised this op" — mint and auth are the trust sources, so they issue.
- **Third-party caveats + discharges, not handrolled asymmetric signatures,** when composing trust across services with independent root keys. The TPC mechanism is what's in the macaroon paper; if you find yourself reaching for Ed25519 to "compose" two signing parties, you're rebuilding TPCs poorly.

When in doubt, re-read the Fly.io blog before proposing changes to anything macaroon-shaped.
