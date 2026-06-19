# Mint change spec — durable volume-parametric token

> Hand-off spec for a change in the **mint** repo (`github.com/soulware/mint`).
> Written from elide's side; elide is wired to consume it. Move/delete this
> file once the mint change lands.

## Goal

Let an enrolled coordinator hold a **durable, volume-parametric capability**
per attested role (`volume-rw`, `volume-ro`): minted **once at enrollment**
(operator-gated) and finalized **autonomously per volume** (coord-B-attested)
for the coordinator's whole lifetime. This removes the human operator from the
per-volume credential path, which a long-running coordinator daemon traverses
unattended (GC reading ancestors, first drain, demand-fetch) for volumes it may
never have "created".

The capability is exactly today's `op=exchange-finalize` intermediate — it
carries `(role, sub, cnf, attestation-TPC)` and **nothing volume-specific** —
made durable instead of 600s-ephemeral. Its volume requirement is already
declared by the role contract (`[role.attestation].attested = ["volume"]` plus
the `{{caveat.volume}}` template); the token is the unfulfilled, must-be-attested
form, finalized per volume.

## The change

At `POST /v1/enroll-exchange`, when the resolved role declares
`[role.attestation]`, mint the returned `op=exchange-finalize` intermediate
**durable (no `exp` caveat)** instead of stamping `now + INTERMEDIATE_TTL_SECONDS`.

Touchpoints (paths as of `main`):
- `issuance::mint_intermediate` — currently appends `Caveat::scalar(name::EXP, exp_unix)`.
  Drop the `exp` for the durable form (or add a durable variant / `Option<exp>`).
- `http::enroll_exchange` — the caller passes `now_unix.saturating_add(issuance::INTERMEDIATE_TTL_SECONDS)`; stop passing an expiry.
- `INTERMEDIATE_TTL_SECONDS` — retire, unless a transient intermediate path remains for some other caller.

That is the whole protocol change. Everything below is already correct and
should **not** move.

## Unchanged (already correct)

- `/v1/enroll-exchange` stays **operator-gated** (`mint:exchange` discharge).
  This is the once-per-coordinator gate, exercised while the operator is present
  at enrollment. The operator authorizes *that this coordinator may provision
  volume credentials at all* — not each volume.
- `/v1/exchange-finalize` stays **coord-B-gated**; it bakes `caveat.volume`
  **from the discharge's caveats** (`cleared.discharge_caveats`), never from the
  request body; re-reads the enrolled record and stamps the current `rev_epoch`;
  and mints the non-expiring `op=assume-role` credential. A no-`exp` parent
  already verifies and clears cleanly here (`exp` is a bound, not required).
- `assume-role` over the finalized per-volume credential is a pure render —
  unchanged.

## Properties to preserve / verify

1. **Non-bearer.** The durable parent is `cnf`-bound; only the holding
   coordinator (PoP by `coordinator.key`) can finalize it. Already enforced —
   finalize requires the PoP.
2. **Not directly usable.** The parent carries `op=exchange-finalize` and no
   `caveat.volume`, so `assume-role` must reject it (wrong `op`, and the policy
   template has no `volume` to substitute). Worth an explicit test now that the
   token is long-lived.
3. **Per-volume authority is coord B's, not the coordinator's.** The baked
   `volume` derives solely from coord B's discharge; the coordinator cannot
   self-assert it. Already true; keep it.
4. **Revocable.** An operator revoke (`rev_epoch` bump on the enrolled record)
   must invalidate both *pending* finalizes (finalize re-reads the record) and
   *already-finalized* per-volume credentials (the `assume-role` `rev_epoch`
   check). This is the property most worth a dedicated test, since the parent
   now lives indefinitely rather than 600s.
5. **One parent → many volumes.** A single durable intermediate must finalize
   for arbitrarily many distinct volumes (it carries no volume; each finalize
   supplies its own via the discharge). Add/extend a test asserting this.
6. **K_M-B rotation.** The parent's attestation TPC is bound to the current
   K_M-B. After a K_M-B rotation, outstanding parents become undischargeable and
   the coordinator re-enrolls to mint fresh ones. Acceptable; note it.

## Contract elide relies on

The `/v1/enroll-exchange` response for an attested role is a **durable token**
that the coordinator stores and presents to `/v1/exchange-finalize` repeatedly —
once per volume, with a fresh coord-B discharge each time — indefinitely, with no
further operator interaction.

## Compatibility note (no elide-side dependency for CI)

The elide wiring works against **both** the current 600s intermediate and the
durable form: elide fetches the parent at enrollment and finalizes promptly in
the e2e (sub-second), so the attested-e2e stays green before this change lands.
The durability change matters only for the **production daemon**, which finalizes
new volumes minutes-to-days after enrollment — with the 600s form those parents
expire and production cannot onboard new volumes. So: CI is unaffected by merge
order; production per-volume provisioning requires this change.
