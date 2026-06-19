# Mint change spec — durable, further-exchangeable role tokens

> Hand-off spec for a change in the **mint** repo (`github.com/soulware/mint`).
> This fixes the *behavioral contract* only — the config key, the wire
> representation, and the rest of the implementation are the mint session's to
> choose. Move/delete this file once the change lands.

## Goal

elide needs a role whose exchange yields a **durable, further-exchangeable
token** — minted once at enrollment (operator-gated) and held for the
coordinator's whole lifetime, then finalized repeatedly (once per volume) with
no further operator interaction.

This is what lets a long-running coordinator daemon provision per-volume
credentials **unattended** (GC reading ancestors, first drain, demand-fetch)
for volumes it may never have created — even though `enroll-exchange` is
operator-gated and no operator is present at 3am. The operator gate is paid
once, at enrollment, for the durable parent; per-volume finalize needs only the
attestation authority (coord B).

## The change

Today, exchanging a role at `/v1/enroll-exchange` yields either a
directly-usable credential, or — for a role that requires a further attestation
step — a short-lived token that must be finalized promptly. elide needs the
exchange to instead yield a **durable** token it can hold and finalize many
times over its lifetime.

Make this an **explicit, opt-in property declared on the role in config.** A
role states that its exchange produces a durable, further-exchangeable parent
rather than an ephemeral or final credential.

**This is orthogonal to `[role.attestation]` — do not gate it on the presence
of an attestation contract.** A role may be attested without being durable, or
durable without being attested. elide's volume roles happen to be *both*
(durable parents that finalize under a coord-B attestation), but mint should let
the two be declared independently rather than inferring one from the other.

How the token's durability is represented, and the name/shape of the config
property, are the mint session's call — this doc does not prescribe them.

## Contract elide relies on

- Exchanging a durable-parent role at `/v1/enroll-exchange` (operator-gated)
  returns a token elide **stores and reuses indefinitely**.
- That token is presented to `/v1/exchange-finalize` **repeatedly — once per
  volume, with a fresh coord-B discharge each time** — with no further operator
  interaction. Each finalize yields the usable per-volume credential, which
  `assume-role` then renders.
- The token carries **nothing volume-specific**, so a single parent finalizes
  for any number of distinct volumes (the volume is supplied per-finalize, from
  the discharge — see below).
- `exchange-finalize` continues to bake the attested value(s) **from the
  authority's discharge**, not from the request body, and to re-check the
  enrolled record so a revoke still bites. (elide depends on this existing
  behavior; the durability change must not alter it.)

## Properties to preserve / verify

The durable parent must keep every security property the short-lived token
already has, now over an indefinite lifetime:

1. **Non-bearer.** Holder-of-key bound; only the enrolled coordinator can
   present it. A leaked parent is inert without the coordinator's key.
2. **Not usable on its own.** It is not an `assume-role` credential and cannot
   be rendered directly — it only finalizes.
3. **Revocable.** An operator revoke of the enrollment must invalidate the
   parent (pending finalizes) and the per-volume credentials finalized from it.
   This is the property most worth a dedicated test, since the parent now lives
   indefinitely rather than briefly.
4. **One parent → many volumes** (for elide's attested volume roles). A single
   durable parent finalizes for arbitrarily many volumes; per-volume authority
   comes solely from coord B's discharge, never from the coordinator's
   assertion. Add/extend a test.
5. **Attestation-key rotation.** A rotation of the attestation root makes
   outstanding parents undischargeable; the coordinator re-enrolls to mint fresh
   ones. Acceptable; note it.

## Compatibility note (merge order is free)

elide's side is already merged and works against **current `mint@main`**: it
fetches the parent at enrollment and finalizes promptly in the e2e (sub-second),
so today's short-lived token suffices for CI. The durability change matters only
for the **production daemon**, which finalizes new volumes minutes-to-days after
enrollment — there, a short-lived parent expires and the daemon cannot onboard
new volumes. So CI is unaffected by merge order; production per-volume
provisioning depends on this change.
