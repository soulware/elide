//! Macaroon issuance (`docs/design-mint.md` § *Credential macaroon &
//! lifecycle*, § *Enrollment*).
//!
//! Every macaroon mint here is a fresh chain **from the root** (only
//! the root holder can mint; a client can only attenuate). Three
//! mint points, each stamped with its own positively-required `op`:
//!
//! 1. [`mint_invite`] — `op=enroll`, the reusable non-expiring
//!    participation gate. No principal identity; carries the current
//!    `invite` nonce.
//! 2. [`mint_credential_ticket`] — `op=enroll-exchange`, short-lived,
//!    minted at `POST /v1/enroll` once the presented (client-
//!    attenuated) invite has verified and a pending record exists.
//!    Carries the self-asserted `sub`/`cnf` forward.
//! 3. [`mint_credential`] — `op=assume-role`, non-expiring, minted at
//!    `POST /v1/enroll-exchange` after operator approval. Same
//!    `sub`/`cnf`; no `exp`.
//!
//! MAC verification, the `op`/`aud`/`invite` gates, the holder-of-key
//! PoP and the pending/approval lookup are the HTTP layer's job (they
//! need the root, config and the state store). The functions here are
//! pure given an already-authenticated macaroon.

use crate::caveat::{Caveat, EffectiveCaveats, Resolved, name, op};
use crate::keyring::Keyring;
use crate::macaroon::{self, Macaroon};
use crate::pop;

/// Why extracting the bound identity from a verified macaroon failed.
/// The HTTP layer collapses every variant to the same opaque `401`
/// (don't help an attacker distinguish causes); the variant is for the
/// audit log and tests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrollError {
    /// `cnf` is not a well-formed `ed25519:<b64 pub>`.
    #[error("malformed cnf")]
    BadCnf,
    /// No `sub` (the macaroon is not principal-scoped).
    #[error("missing sub")]
    MissingSub,
    /// No `cnf` (not key-bound — a bearer cannot enrol).
    #[error("missing cnf")]
    MissingCnf,
    /// A binding caveat resolved `Unsatisfiable` (≥2 disagreeing
    /// occurrences — the append-a-contradictory-copy downgrade; fail
    /// closed, never read as absent).
    #[error("contradictory binding caveat")]
    Unsatisfiable,
}

/// Fixed `client_id` bound into the **invite's** third-party caveat (the
/// enroll gate). The invite is shared org-wide, so its `r`-cluster is a
/// single fixed scope — one org, one enroll gate — and its `CID` is the
/// same for every enrolling coordinator, so one enroll-gate discharge can
/// bring in any number of them (`docs/design-auth-service.md` § *Coord ↔
/// mint enrollment*).
pub const INVITE_CLIENT_ID: &str = "invite";

/// Fixed `client_id` bound into the **credential ticket's** third-party
/// caveat (the exchange gate). Distinct from [`INVITE_CLIENT_ID`] so the
/// two gates derive distinct keys (`r_inv` ≠ `r_xchg`) — a discharge for
/// one anchor is not MAC-valid against the other. Still org-wide (not
/// per-coordinator): one exchange-gate discharge exchanges every role for
/// every approved coordinator in its window.
pub const TICKET_CLIENT_ID: &str = "ticket";

/// The enroll-gate and exchange-gate `r` epochs. Fixed at 0; rotation
/// re-mints the anchor (`mint invite --rotate` / a fresh ticket) and
/// draws a fresh `r` from a fresh keyring generation, so no per-epoch
/// bump is needed here.
const ANCHOR_R_EPOCH: u32 = 0;

/// The reusable invite macaroon: root attenuated with `op=enroll`,
/// `aud`, the current `invite` nonce, **and the enroll-gate third-party
/// caveat** at `location`. Non-expiring, carries no principal identity —
/// a pure participation gate, distributed out-of-band and reusable for
/// every enrolling client. The TPC is what makes it a *gate* rather than
/// a free pass: it is inert without a fresh enrolling-operator discharge
/// (`docs/design-mint.md` § *Enrollment*).
pub fn mint_invite(
    keyring: &Keyring,
    k_m_a: &[u8; 32],
    audience: &str,
    invite_nonce: &str,
    org_id: &str,
    location: &str,
) -> Macaroon {
    let base = macaroon::mint(
        keyring,
        vec![
            Caveat::scalar(name::OP, op::ENROLL),
            Caveat::scalar(name::AUD, audience),
            Caveat::scalar(name::INVITE, invite_nonce),
        ],
    );
    let r = crate::tpc::derive_r(keyring.current_key(), INVITE_CLIENT_ID, ANCHOR_R_EPOCH);
    let tpc = crate::tpc::build_caveat(base.tail(), &r, k_m_a, INVITE_CLIENT_ID, org_id, location);
    base.attenuate(tpc)
}

/// The short-lived credential ticket handed back from `POST /v1/enroll`:
/// `op=enroll-exchange`, `aud`, the self-asserted `sub`/`cnf`, an `exp`,
/// **and the exchange-gate third-party caveat** at `location` (a distinct
/// `CID` from the invite's). The TPC is the exchange gate: the ticket is
/// inert without a fresh exchanging-operator discharge
/// (`docs/design-mint.md` § *Enrollment* (3)).
#[allow(clippy::too_many_arguments)]
pub fn mint_credential_ticket(
    keyring: &Keyring,
    k_m_a: &[u8; 32],
    audience: &str,
    sub: &str,
    cnf: &str,
    exp_unix: u64,
    org_id: &str,
    location: &str,
) -> Macaroon {
    let base = macaroon::mint(
        keyring,
        vec![
            Caveat::scalar(name::OP, op::ENROLL_EXCHANGE),
            Caveat::scalar(name::AUD, audience),
            Caveat::scalar(name::SUB, sub),
            Caveat::scalar(name::CNF, cnf),
            Caveat::scalar(name::EXP, exp_unix.to_string()),
        ],
    );
    let r = crate::tpc::derive_r(keyring.current_key(), TICKET_CLIENT_ID, ANCHOR_R_EPOCH);
    let tpc = crate::tpc::build_caveat(base.tail(), &r, k_m_a, TICKET_CLIENT_ID, org_id, location);
    base.attenuate(tpc)
}

/// The attested third-party caveat to stamp onto a credential whose role
/// declares `[role.attestation]` (`docs/design-mint-volume-attestation.md`).
/// `mode` is opaque to mint, carried verbatim into the CID for the
/// discharging authority at `location`; the CID is sealed under `K_M-B`
/// and `r` derives from the credential's own `sub`, so the discharge
/// binds to this coordinator.
pub struct AttestedTpc<'a> {
    pub k_m_b: &'a [u8; 32],
    pub org_id: &'a str,
    pub mode: &'a str,
    pub location: &'a str,
}

/// The non-expiring credential, re-minted from root at a successful
/// exchange: `op=assume-role`, `aud`, the same `sub`/`cnf`, the
/// `role` it was authorized for, the enrolled record's `rev_epoch` as
/// an `epoch` caveat, **no** `exp`. A fresh chain, not an attenuation
/// of the credential ticket (only the root holder can do this). One
/// credential carries exactly one role — a client exchanges once per
/// role it needs (`docs/design-mint.md` § *Credential macaroon &
/// lifecycle*).
///
/// `rev_epoch` is the revocation generation `assume-role` later clears
/// the credential against (`docs/design-mint.md` § *Revocation*): a
/// revoke bumps the enrolled record's epoch, so a credential minted
/// before it carries a now-stale value and can never clear again.
///
/// `attested` is `Some` exactly for a role declaring `[role.attestation]`:
/// the credential then carries a static attested third-party caveat that
/// the attestation authority discharges at `assume-role`. Most roles pass
/// `None` and get the uniform key-bound credential.
pub fn mint_credential(
    keyring: &Keyring,
    audience: &str,
    sub: &str,
    cnf: &str,
    role: &str,
    rev_epoch: u64,
    attested: Option<AttestedTpc<'_>>,
) -> Macaroon {
    let base = macaroon::mint(
        keyring,
        vec![
            Caveat::scalar(name::OP, op::ASSUME_ROLE),
            Caveat::scalar(name::AUD, audience),
            Caveat::scalar(name::SUB, sub),
            Caveat::scalar(name::CNF, cnf),
            Caveat::scalar(name::ROLE, role),
            Caveat::scalar(name::EPOCH, rev_epoch.to_string()),
        ],
    );
    match attested {
        None => base,
        Some(a) => {
            // `r` derives from the credential's own `sub`, so the TPC is
            // per-coordinator; the holder cannot recover it (it has
            // neither `K_M-B` nor the chain tag at the TPC position).
            let r = crate::tpc::derive_r(keyring.current_key(), sub, ANCHOR_R_EPOCH);
            let tpc = crate::tpc::build_caveat_attested(
                base.tail(),
                &r,
                a.k_m_b,
                sub,
                a.org_id,
                a.mode,
                a.location,
            );
            base.attenuate(tpc)
        }
    }
}

/// Fixed `client_id` bound into the admin service token's third-party
/// caveat. The admin-service is the deployment's admin-plane primary, not
/// a per-operator credential, so its `r`-cluster is a single fixed
/// scope — one deployment, one admin plane
/// (`docs/design-mint.md` § *Admin service token*).
pub const ADMIN_SERVICE_CLIENT_ID: &str = "admin-service";

/// The admin-service's TPC `r` epoch. Fixed at 0; rotation (which would
/// bump it to invalidate outstanding discharges) is deferred.
const ADMIN_SERVICE_R_EPOCH: u32 = 0;

/// Mint the **admin service token** — the deployment's admin-plane
/// primary (`docs/design-mint.md` § *Admin service token*). A mint-issued
/// chain carrying `aud` and `cnf` (the mint-generated machine key the
/// operator CLI signs PoP with), plus a single third-party caveat at
/// `location` that the auth service discharges.
///
/// No `op` and no `exp` on the base token: the operator attenuates
/// `op=admin:<verb>` per call (so the op binds to that call's PoP over
/// the attenuated tail), and per-call freshness rides on the discharge.
/// The token is inert without a fresh discharge satisfying the TPC.
///
/// `r` for the TPC is `derive_r(K_M, "admin-service", 0)`; the verifier
/// recovers it from the TPC's `VID` (chain-tag-keyed), the auth service
/// from the `CID` (`K_M-A`-keyed) — both yield this same `r`.
pub fn mint_admin_service_token(
    keyring: &Keyring,
    k_m_a: &[u8; 32],
    audience: &str,
    cnf: &str,
    org_id: &str,
    location: &str,
) -> Macaroon {
    let base = macaroon::mint(
        keyring,
        vec![
            Caveat::scalar(name::AUD, audience),
            Caveat::scalar(name::CNF, cnf),
        ],
    );
    let r = crate::tpc::derive_r(
        keyring.current_key(),
        ADMIN_SERVICE_CLIENT_ID,
        ADMIN_SERVICE_R_EPOCH,
    );
    let tpc = crate::tpc::build_caveat(
        base.tail(),
        &r,
        k_m_a,
        ADMIN_SERVICE_CLIENT_ID,
        org_id,
        location,
    );
    base.attenuate(tpc)
}

/// Extract the bound `(sub, cnf)` from an already-MAC-verified
/// macaroon, tri-state-safe: a contradictory copy of either fails
/// closed (never silently read as the first value), and `cnf` is
/// validated as a usable Ed25519 key here so a malformed one is
/// refused at enrollment rather than opaquely at first `assume-role`.
pub fn bound_identity(token: &Macaroon) -> Result<(String, String), EnrollError> {
    let eff = EffectiveCaveats::new(token.caveats());
    let sub = match eff.resolve(name::SUB) {
        Resolved::Value(v) => v,
        Resolved::Unsatisfiable => return Err(EnrollError::Unsatisfiable),
        Resolved::Absent => return Err(EnrollError::MissingSub),
    };
    let cnf = match eff.resolve(name::CNF) {
        Resolved::Value(v) => v,
        Resolved::Unsatisfiable => return Err(EnrollError::Unsatisfiable),
        Resolved::Absent => return Err(EnrollError::MissingCnf),
    };
    pop::validate_cnf(&cnf).map_err(|_| EnrollError::BadCnf)?;
    Ok((sub, cnf))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn ring() -> Keyring {
        Keyring::single([7u8; 32])
    }

    fn cnf() -> String {
        pop::cnf_value(&[3u8; 32])
    }

    const K_M_A: [u8; 32] = [42u8; 32];
    const LOCATION: &str = "https://auth.example/v1/discharge";

    /// Count the third-party caveats on a macaroon — the enroll/exchange
    /// gate lands as exactly one.
    fn tpc_count(m: &Macaroon) -> usize {
        m.caveats()
            .iter()
            .filter(|c| matches!(c, Caveat::ThirdParty { .. }))
            .count()
    }

    #[test]
    fn invite_is_enroll_op_no_identity_with_gate_tpc() {
        let kr = ring();
        let b = mint_invite(&kr, &K_M_A, "mint", "nonceXYZ", "org_demo", LOCATION);
        assert!(b.verify(&kr));
        let eff = EffectiveCaveats::new(b.caveats());
        assert_eq!(eff.resolve(name::OP), Resolved::Value(op::ENROLL.into()));
        assert_eq!(eff.resolve(name::AUD), Resolved::Value("mint".into()));
        assert_eq!(
            eff.resolve(name::INVITE),
            Resolved::Value("nonceXYZ".into())
        );
        assert_eq!(eff.resolve(name::SUB), Resolved::Absent);
        assert_eq!(eff.resolve(name::CNF), Resolved::Absent);
        // The enroll gate: exactly one third-party caveat.
        assert_eq!(tpc_count(&b), 1);
    }

    #[test]
    fn ticket_then_credential_carry_identity_with_distinct_ops() {
        let kr = ring();
        let ticket = mint_credential_ticket(
            &kr,
            &K_M_A,
            "mint",
            SUB,
            &cnf(),
            1_700_000_000,
            "org_demo",
            LOCATION,
        );
        assert!(ticket.verify(&kr));
        let ie = EffectiveCaveats::new(ticket.caveats());
        assert_eq!(
            ie.resolve(name::OP),
            Resolved::Value(op::ENROLL_EXCHANGE.into())
        );
        assert_eq!(ie.min_bound(name::EXP), Some(1_700_000_000));
        // The exchange gate: the ticket carries its own TPC.
        assert_eq!(tpc_count(&ticket), 1);

        let cred = mint_credential(&kr, "mint", SUB, &cnf(), "volume-ro", 7, None);
        assert!(cred.verify(&kr));
        let pe = EffectiveCaveats::new(cred.caveats());
        assert_eq!(
            pe.resolve(name::OP),
            Resolved::Value(op::ASSUME_ROLE.into())
        );
        assert_eq!(pe.resolve(name::SUB), Resolved::Value(SUB.into()));
        assert_eq!(pe.resolve(name::CNF), Resolved::Value(cnf()));
        assert_eq!(pe.resolve(name::ROLE), Resolved::Value("volume-ro".into()));
        // The credential carries the revocation epoch it was minted at.
        assert_eq!(pe.resolve(name::EPOCH), Resolved::Value("7".into()));
        // The credential does not expire.
        assert_eq!(pe.min_bound(name::EXP), None);
        // A credential carries no third-party caveat — operator authority
        // lives entirely at the enroll/exchange gates, not at assume-role.
        assert_eq!(tpc_count(&cred), 0);
        // Fresh chain, not an attenuation of the credential ticket.
        assert_ne!(cred.nonce(), ticket.nonce());
    }

    #[test]
    fn attested_role_credential_carries_a_discharging_tpc() {
        const K_M_B: [u8; 32] = [9u8; 32];
        const ATT_LOCATION: &str = "https://coord-b.example/v1/discharge";
        let kr = ring();
        let cred = mint_credential(
            &kr,
            "mint",
            SUB,
            &cnf(),
            "volume-ro",
            7,
            Some(AttestedTpc {
                k_m_b: &K_M_B,
                org_id: "org_demo",
                mode: "volume-ro",
                location: ATT_LOCATION,
            }),
        );
        assert!(cred.verify(&kr));
        // Identity caveats are exactly the plain credential's.
        let pe = EffectiveCaveats::new(cred.caveats());
        assert_eq!(pe.resolve(name::ROLE), Resolved::Value("volume-ro".into()));
        assert_eq!(pe.resolve(name::SUB), Resolved::Value(SUB.into()));
        // Plus exactly one third-party caveat, naming the authority.
        assert_eq!(tpc_count(&cred), 1);
        let (location, cid) = cred
            .caveats()
            .iter()
            .find_map(|c| match c {
                Caveat::ThirdParty { location, cid, .. } => {
                    Some((location.as_str(), cid.as_slice()))
                }
                _ => None,
            })
            .expect("a third-party caveat");
        assert_eq!(location, ATT_LOCATION);
        // The CID seals (sub, org, mode) under K_M-B. `mode` round-trips
        // verbatim — mint transported it without interpretation.
        let pt = crate::tpc::decrypt_cid_attested(&K_M_B, cid).expect("decrypt cid");
        assert_eq!(pt.client_id, SUB);
        assert_eq!(pt.org_id, "org_demo");
        assert_eq!(pt.mode, "volume-ro");
        // `r` is per-coordinator — derived from the credential's own `sub`.
        assert_eq!(
            pt.r,
            crate::tpc::derive_r(kr.current_key(), SUB, ANCHOR_R_EPOCH)
        );
    }

    #[test]
    fn bound_identity_extracts_sub_and_cnf() {
        let m = macaroon::mint(
            &ring(),
            vec![
                Caveat::scalar(name::SUB, SUB),
                Caveat::scalar(name::CNF, cnf()),
            ],
        );
        assert_eq!(bound_identity(&m), Ok((SUB.to_string(), cnf())));
    }

    #[test]
    fn missing_or_bad_identity_refused() {
        let kr = ring();
        let no_cnf = macaroon::mint(&kr, vec![Caveat::scalar(name::SUB, SUB)]);
        assert_eq!(bound_identity(&no_cnf), Err(EnrollError::MissingCnf));

        let no_sub = macaroon::mint(&kr, vec![Caveat::scalar(name::CNF, cnf())]);
        assert_eq!(bound_identity(&no_sub), Err(EnrollError::MissingSub));

        let bad_cnf = macaroon::mint(
            &kr,
            vec![
                Caveat::scalar(name::SUB, SUB),
                Caveat::scalar(name::CNF, "ed25519:not-base64!!"),
            ],
        );
        assert_eq!(bound_identity(&bad_cnf), Err(EnrollError::BadCnf));
    }

    #[test]
    fn contradictory_binding_fails_closed() {
        // Appended second, disagreeing sub (only the trailing MAC is
        // needed to append). Must be Unsatisfiable, never the first value.
        let m = macaroon::mint(
            &ring(),
            vec![
                Caveat::scalar(name::SUB, SUB),
                Caveat::scalar(name::CNF, cnf()),
            ],
        )
        .attenuate(Caveat::scalar(name::SUB, "01EVIL"));
        assert_eq!(bound_identity(&m), Err(EnrollError::Unsatisfiable));
    }
}
