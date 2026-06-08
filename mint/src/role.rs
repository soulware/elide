//! Role gating and TTL computation (`docs/design-mint.md`
//! § *Role configuration*, § *TTL bounds*).
//!
//! Given a *verified* macaroon's caveats, a requested role, and a
//! requested TTL, decide whether the role may be assumed and for how
//! long. This module does **not** verify the MAC — that already
//! happened — it only evaluates caveat *values*.

use crate::caveat::{EffectiveCaveats, Resolved, name};
use crate::sealed_cache::ServedSurface;

const SUBJECT_CAVEAT: &str = name::SUB;
const AUDIENCE_CAVEAT: &str = name::AUD;
const EXP_CAVEAT: &str = name::EXP;
const ROLE_CAVEAT: &str = name::ROLE;

/// Caveats every assume-role credential must carry, enforced for
/// presence only and identically for every role — `sub` (principal),
/// `aud` (audience), `exp` (expiry). Hard-coded, not role-configurable:
/// these are universal invariants of a mint-issued credential, not a
/// per-role policy knob. `aud` and `exp` additionally have their *values*
/// checked below; `sub` is presence-only (its value is MAC-authentic and
/// its holder is proven by the `cnf`+PoP gate at the HTTP layer).
const REQUIRED_CAVEATS: [&str; 3] = [SUBJECT_CAVEAT, AUDIENCE_CAVEAT, EXP_CAVEAT];

/// Why an assume-role request was refused. Mapped to coarse HTTP
/// statuses by the caller; never surfaced verbatim to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Role name not in mint config.
    UnknownRole,
    /// `Audience` caveat missing or != configured audience.
    WrongAudience,
    /// A `Role` caveat is present and does not permit this role.
    RoleNotPermitted,
    /// A universally-required caveat ([`REQUIRED_CAVEATS`]) is absent.
    MissingRequiredCaveat(String),
    /// A required caveat is present but its occurrences contradict
    /// (unsatisfiable) — fail closed, never treat as absent.
    UnsatisfiableCaveat(String),
    /// Macaroon carries no usable `exp`, or it is already past.
    Expired,
    /// Requested TTL below the role's `min_ttl_seconds`.
    TtlTooShort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    /// The granted role's name. The policy bytes to render are looked up
    /// from the served surface by this name.
    pub role_name: String,
    /// Effective lifetime in seconds after clamping.
    pub ttl_seconds: u64,
}

/// Evaluate an assume-role request against the **sealed** surface, not
/// the live config: the TTL bounds and the audience are the values the
/// operator sealed, so a drifted `roles_dir/` or `mint.toml` cannot widen
/// them at render time. Caveat presence ([`REQUIRED_CAVEATS`]) is a fixed
/// invariant, not part of the sealed surface.
///
/// `requested_ttl` is the caller's `ttl_seconds` body field (already
/// defaulted to the role's `default_ttl_seconds` by the caller if the
/// field was absent). `now_unix` is the current time.
pub fn authorize(
    surface: &ServedSurface,
    caveats: &[crate::caveat::Caveat],
    requested_role: &str,
    requested_ttl: u64,
    now_unix: u64,
) -> Result<Granted, Denied> {
    let role = surface.role(requested_role).ok_or(Denied::UnknownRole)?;

    let eff = EffectiveCaveats::new(caveats);

    // Required caveats: every credential must carry `sub`/`aud`/`exp`,
    // present *and* satisfiable. An unsatisfiable required caveat is a
    // distinct denial, never collapsed to "missing". This is the
    // hard-coded universal gate; `aud` and `exp` have their values
    // checked below, `sub` is presence-only.
    for req in REQUIRED_CAVEATS {
        match eff.resolve(req) {
            Resolved::Value(_) => {}
            Resolved::Absent => return Err(Denied::MissingRequiredCaveat(req.to_string())),
            Resolved::Unsatisfiable => {
                return Err(Denied::UnsatisfiableCaveat(req.to_string()));
            }
        }
    }

    // Audience: cross-service replay defence. Must resolve to a single
    // value equal to the sealed name; absent or unsatisfiable both fail
    // closed.
    match eff.resolve(AUDIENCE_CAVEAT) {
        Resolved::Value(a) if a == surface.audience() => {}
        _ => return Err(Denied::WrongAudience),
    }

    // The Role caveat is the single role this credential carries
    // (mint-stamped at the enrollment exchange). It must be present and
    // equal the asserted `requested_role` — `req.role` is the
    // caller's independent statement of intent, so a mismatch means the
    // wrong per-role credential was loaded: fail closed. There is no
    // role-less ("omnibus") credential — absent is also a denial, never
    // read as unrestricted; unsatisfiable likewise.
    match eff.resolve(ROLE_CAVEAT) {
        Resolved::Value(s) if s == requested_role => {}
        Resolved::Value(_) | Resolved::Absent | Resolved::Unsatisfiable => {
            return Err(Denied::RoleNotPermitted);
        }
    }

    // TTL: granted = min(requested_or_default, role.max, exp - now).
    let exp = eff.min_bound(EXP_CAVEAT).ok_or(Denied::Expired)?;
    let remaining = exp.checked_sub(now_unix).ok_or(Denied::Expired)?;
    if remaining == 0 {
        return Err(Denied::Expired);
    }
    if requested_ttl < role.min_ttl_seconds {
        return Err(Denied::TtlTooShort);
    }
    let ttl_seconds = requested_ttl.min(role.max_ttl_seconds).min(remaining);

    Ok(Granted {
        role_name: requested_role.to_string(),
        ttl_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveat::Caveat;
    use crate::keyring::Keyring;

    /// The sealed surface authorize evaluates against — built from a
    /// config exactly as startup's adopt path does. The keyring is
    /// arbitrary; serving reads only audience + the sealed role fields.
    fn surface() -> ServedSurface {
        let cfg = crate::config::parse_for_test(
            r#"
audience = "mint"
[store]
bucket = "b"
[[role]]
name = "volume-ro"
min_ttl_seconds = 60
max_ttl_seconds = 1000
default_ttl_seconds = 800
policy_file = "volume-ro.json"
"#,
            &[("volume-ro.json", "{}")],
        )
        .expect("cfg");
        ServedSurface::from_config(&cfg, &Keyring::single([7u8; 32]), "t")
    }

    fn good_caveats(exp: u64) -> Vec<Caveat> {
        // `aud` and `role` stay at indices 0 and 1 — some tests mutate
        // them positionally.
        vec![
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::ROLE, "volume-ro"),
            Caveat::scalar("elide:Volume", "01ARZ"),
            Caveat::scalar(name::EXP, exp.to_string()),
            Caveat::scalar(name::SUB, "alice"),
        ]
    }

    #[test]
    fn happy_path_clamps_to_max() {
        let g = authorize(
            &surface(),
            &good_caveats(1_000_000),
            "volume-ro",
            5000,
            1000,
        )
        .unwrap();
        assert_eq!(g.ttl_seconds, 1000); // role max
    }

    #[test]
    fn ttl_capped_by_exp() {
        let g = authorize(&surface(), &good_caveats(1300), "volume-ro", 900, 1000).unwrap();
        assert_eq!(g.ttl_seconds, 300); // exp - now
    }

    #[test]
    fn wrong_audience_denied() {
        let mut cv = good_caveats(1_000_000);
        cv[0] = Caveat::scalar(name::AUD, "other");
        assert_eq!(
            authorize(&surface(), &cv, "volume-ro", 800, 1000),
            Err(Denied::WrongAudience)
        );
    }

    #[test]
    fn missing_required_caveat_denied() {
        // `sub` is universally required (presence-only); a credential
        // lacking it is denied before any role-specific check.
        let cv = vec![
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::ROLE, "volume-ro"),
            Caveat::scalar("elide:Volume", "01ARZ"),
            Caveat::scalar(name::EXP, "1000000"),
        ];
        assert_eq!(
            authorize(&surface(), &cv, "volume-ro", 800, 1000),
            Err(Denied::MissingRequiredCaveat("sub".into()))
        );
    }

    #[test]
    fn expired_macaroon_denied() {
        assert_eq!(
            authorize(&surface(), &good_caveats(500), "volume-ro", 800, 1000),
            Err(Denied::Expired)
        );
    }

    #[test]
    fn unknown_role_denied() {
        assert_eq!(
            authorize(&surface(), &good_caveats(1_000_000), "nope", 800, 1000),
            Err(Denied::UnknownRole)
        );
    }

    #[test]
    fn role_caveat_must_equal_requested() {
        // Credential carries role=volume-ro; caller asserts a different
        // role (wrong per-role credential loaded) → fail closed.
        let cv = good_caveats(1_000_000);
        assert_eq!(
            authorize(&surface(), &cv, "coord-names", 800, 1000),
            Err(Denied::UnknownRole),
            "coord-names isn't configured here, so UnknownRole comes first"
        );
        // With the role configured, the role-caveat mismatch is what
        // denies. Re-point the caveat, keep the request at volume-ro.
        let mut cv = good_caveats(1_000_000);
        cv[1] = Caveat::scalar(name::ROLE, "coord-names");
        assert_eq!(
            authorize(&surface(), &cv, "volume-ro", 800, 1000),
            Err(Denied::RoleNotPermitted)
        );
    }

    #[test]
    fn absent_role_caveat_denied_no_omnibus() {
        let cv = vec![
            Caveat::scalar(name::SUB, "alice"),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar("elide:Volume", "01ARZ"),
            Caveat::scalar(name::EXP, "1000000"),
        ];
        assert_eq!(
            authorize(&surface(), &cv, "volume-ro", 800, 1000),
            Err(Denied::RoleNotPermitted),
            "a credential with no role caveat is not an omnibus pass"
        );
    }
}
