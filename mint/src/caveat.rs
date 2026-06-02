//! Caveats: first-party scalar and third-party.
//!
//! The mint is caveat-vocabulary-agnostic (see `docs/design-mint.md`
//! § *Macaroon caveat conventions*): it does not hard-code which
//! first-party caveat names are meaningful. A first-party caveat is a
//! `(name, value)` pair; **every first-party caveat is scalar**. There
//! is no list-valued caveat type — the only list-shaped input a role
//! ever needed (the `volume-ro` ancestor set) rides the PoP-signed
//! request body as `request.ancestors`, not the caveat chain
//! (design-mint.md § *All caveats are scalar*).
//!
//! Third-party caveats carry `(location, VID, CID)` and discharge
//! verification (`docs/design-auth-service.md`); they're not scalar
//! and don't participate in name-based resolution. Mint appends them
//! at issuance when the role sets `[role.tpc]`; they ride
//! in the same chain as first-party caveats but the wire format
//! distinguishes them with a per-step type byte.

use std::collections::BTreeSet;

/// Canonical caveat names (`docs/design-mint.md` § *Standard caveats*).
/// **Borrowed** names reuse a registered claim verbatim (RFC 7519 /
/// RFC 7800) — the abbreviation *is* the standard. **Coined** names are
/// mint-specific, readable lowercase, deliberately *not* in the
/// registered-claim style.
pub mod name {
    // Borrowed (RFC 7519 / RFC 7800).
    /// RFC 7519 audience — the service this macaroon is for.
    pub const AUD: &str = "aud";
    /// RFC 7519 expiry, unix seconds; multiple narrow to the minimum.
    pub const EXP: &str = "exp";
    /// RFC 7519 subject — the opaque principal the credential is bound
    /// to (typically a stable identifier of the client — e.g. a ULID).
    pub const SUB: &str = "sub";
    /// RFC 7800 confirmation — the holder-of-key, scalar-encoded
    /// `ed25519:<pub>` (not the JWT `cnf` JSON object).
    pub const CNF: &str = "cnf";
    // Coined (mint-specific; no registered equivalent).
    /// Endpoint partition: `enroll` / `enroll-exchange` / `assume-role`.
    pub const OP: &str = "op";
    /// Restricts the assumable role. Optional.
    pub const ROLE: &str = "role";
    /// Carried only by the invite macaroon; the current nonce.
    pub const INVITE: &str = "invite";
    /// Discharge / attenuation deadline, unix seconds; multiple narrow
    /// to the minimum. Distinct from `exp`: borne by auth-issued
    /// discharges and by per-IPC / per-forward chain attenuations,
    /// where the holder bounds a bearer chain it cannot re-key.
    pub const NOT_AFTER: &str = "NotAfter";
    /// Authority class a discharge attests, named at `/v1/discharge` and
    /// cleared by the gate that consumes the discharge
    /// (`docs/design-auth-service.md` § *Scope tier*). Carried as a
    /// granted set on a session (membership-checked at issuance) and as a
    /// single value on a discharge (scalar-cleared at the gate).
    pub const SCOPE: &str = "Scope";
}

/// `Scope` caveat values — the authority classes auth grants and each
/// gate clears (`docs/design-auth-service.md` § *Scope tier*). One per
/// enrollment gate; namespaced under `mint:` so a session's scope set can
/// span services.
pub mod scope {
    /// The enroll gate — discharges the invite's TPC at `/v1/enroll`.
    pub const MINT_ENROLL: &str = "mint:enroll";
    /// The exchange gate — discharges the ticket's TPC at
    /// `/v1/enroll-exchange`.
    pub const MINT_EXCHANGE: &str = "mint:exchange";
    /// The admin plane — discharges the cli-token's TPC at every
    /// `/v1/admin/*` verb.
    pub const MINT_ADMIN: &str = "mint:admin";
}

/// `op` caveat values. Mint stamps one at every point it mints; each
/// endpoint **positively requires** its own (never tests absence).
pub mod op {
    pub const ENROLL: &str = "enroll";
    pub const ENROLL_EXCHANGE: &str = "enroll-exchange";
    pub const ASSUME_ROLE: &str = "assume-role";
    /// Demo auth-role session (`docs/design-auth-service.md` § *Login
    /// flow*). MAC'd under `K_session`, never `K_M`; partitions the
    /// CLI ↔ auth session credential from every mint-issued chain.
    /// Verified only by the colocated demo auth role at
    /// `/v1/discharge`, never by mint proper.
    pub const SESSION: &str = "session";
}

/// One step in a macaroon's caveat chain. A chain interleaves
/// first-party scalar caveats (the common case) and third-party
/// caveats (issued by mint when a role sets `[role.tpc]`).
/// Position in the chain matters for third-party caveats: the
/// verifier uses the chain tag *before* the TPC step to recover the
/// discharge key, so re-ordering would break verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    /// `(name, value)` scalar caveat. Name-based resolution and
    /// attenuation semantics live in [`EffectiveCaveats`].
    FirstParty { name: String, value: String },
    /// Third-party caveat: requires a discharge MAC'd under the key
    /// `r` recoverable from `vid` (and from `cid` by an authority
    /// holding `K_M-A` — see [`docs/design-auth-service.md`]). Carries
    /// `location` for the client to know which authority to ask.
    ThirdParty {
        location: String,
        vid: Vec<u8>,
        cid: Vec<u8>,
    },
}

impl Caveat {
    /// Construct a first-party scalar caveat. The naming carries
    /// over from when `Caveat` itself was the scalar type.
    pub fn scalar(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::FirstParty {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Construct a third-party caveat. The issuer is mint; no other
    /// code path constructs one (callers can only attenuate with
    /// first-party caveats via the trailing MAC).
    pub fn third_party(
        location: impl Into<String>,
        vid: impl Into<Vec<u8>>,
        cid: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ThirdParty {
            location: location.into(),
            vid: vid.into(),
            cid: cid.into(),
        }
    }

    /// First-party name, or `None` for a third-party caveat. Used by
    /// audit/display callers that present caveats by name.
    pub fn first_party_name(&self) -> Option<&str> {
        match self {
            Self::FirstParty { name, .. } => Some(name),
            Self::ThirdParty { .. } => None,
        }
    }

    /// First-party value, or `None` for a third-party caveat.
    pub fn first_party_value(&self) -> Option<&str> {
        match self {
            Self::FirstParty { value, .. } => Some(value),
            Self::ThirdParty { .. } => None,
        }
    }
}

/// The resolution of one caveat name against the chain under AND
/// (attenuation) semantics. A macaroon attenuates by *appending*, so N
/// occurrences of a name are AND-ed. The three outcomes are **not**
/// collapsible to `Option`: conflating "absent" with "present but
/// unsatisfiable" is a downgrade footgun — a gate keyed on the former
/// would skip for the latter, and a holder can append a contradictory
/// copy of a binding caveat using only the trailing MAC. Every
/// consumer must handle all three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// No occurrence of this name — genuinely unconstrained.
    Absent,
    /// Present and satisfiable: every occurrence agreed on this value.
    Value(String),
    /// Present but ≥2 occurrences disagree: the AND is empty. Must
    /// deny in **every** consumer — never silently read as `Absent`.
    Unsatisfiable,
}

/// The effective view of a caveat chain. The one place "what does this
/// caveat mean" is decided, shared by the gate ([`crate::role`]), the
/// policy renderer ([`crate::template`]), and the holder-of-key check
/// ([`crate::pop`]). Every first-party caveat is scalar: repeated
/// occurrences must agree (→ `Value`); ≥2 distinct → `Unsatisfiable`.
/// Third-party caveats are skipped by every method here — they don't
/// carry a name/value and don't participate in name-based resolution
/// (their semantic is "discharge required", verified separately).
pub struct EffectiveCaveats<'a> {
    caveats: &'a [Caveat],
}

impl<'a> EffectiveCaveats<'a> {
    pub fn new(caveats: &'a [Caveat]) -> Self {
        Self { caveats }
    }

    /// Resolve `name` against the chain under AND semantics. The single
    /// definition of the caveat's effective meaning; tri-state so no
    /// consumer can collapse "absent" into "unsatisfiable" (see
    /// [`Resolved`]). Third-party caveats are skipped.
    pub fn resolve(&self, name: &str) -> Resolved {
        let mut occ = self.caveats.iter().filter_map(|c| match c {
            Caveat::FirstParty { name: n, value } if n == name => Some(value.as_str()),
            _ => None,
        });
        let Some(first) = occ.next() else {
            return Resolved::Absent;
        };
        if occ.all(|v| v == first) {
            Resolved::Value(first.to_string())
        } else {
            Resolved::Unsatisfiable
        }
    }

    /// Whether any occurrence of `name` equals `value` — membership, not
    /// the scalar-AND of [`Self::resolve`]. A caveat carrying a *set*
    /// (the granted `Scope` list on a session) has multiple disagreeing
    /// occurrences by design, so `resolve` would read it `Unsatisfiable`;
    /// this asks the set-membership question instead.
    pub fn contains(&self, name: &str, value: &str) -> bool {
        self.caveats.iter().any(
            |c| matches!(c, Caveat::FirstParty { name: n, value: v } if n == name && v == value),
        )
    }

    /// Distinct first-party caveat names in first-occurrence order.
    pub fn names(&self) -> Vec<&'a str> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for c in self.caveats {
            if let Caveat::FirstParty { name, .. } = c
                && seen.insert(name.as_str())
            {
                out.push(name.as_str());
            }
        }
        out
    }

    /// Minimum `NotAfter` (unix seconds) across all `NotAfter` caveats,
    /// or `None` if the macaroon carries no parseable `NotAfter`. This
    /// is a numeric intersection (the minimum binds), distinct from the
    /// scalar-agreement resolution of [`Self::resolve`].
    pub fn not_after(&self, name: &str) -> Option<u64> {
        self.caveats
            .iter()
            .filter_map(|c| match c {
                Caveat::FirstParty { name: n, value } if n == name => value.parse::<u64>().ok(),
                _ => None,
            })
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cv(pairs: &[(&str, &str)]) -> Vec<Caveat> {
        pairs.iter().map(|(n, v)| Caveat::scalar(*n, *v)).collect()
    }

    #[test]
    fn absent_when_no_occurrence() {
        let c = cv(&[("Audience", "mint")]);
        assert_eq!(
            EffectiveCaveats::new(&c).resolve("elide:Volume"),
            Resolved::Absent
        );
    }

    #[test]
    fn single_and_agreeing_occurrences_resolve_to_value() {
        let c = cv(&[("elide:Volume", "V1"), ("elide:Volume", "V1")]);
        assert_eq!(
            EffectiveCaveats::new(&c).resolve("elide:Volume"),
            Resolved::Value("V1".into())
        );
    }

    #[test]
    fn disagreeing_occurrences_are_unsatisfiable_not_absent() {
        // The downgrade footgun: an appended contradictory copy must
        // resolve to Unsatisfiable, never Absent.
        let c = cv(&[
            ("elide:CoordKey", "ed25519:A"),
            ("elide:CoordKey", "ed25519:B"),
        ]);
        assert_eq!(
            EffectiveCaveats::new(&c).resolve("elide:CoordKey"),
            Resolved::Unsatisfiable
        );
    }

    #[test]
    fn not_after_takes_the_minimum() {
        let c = cv(&[
            ("NotAfter", "5000"),
            ("NotAfter", "3000"),
            ("NotAfter", "9000"),
        ]);
        assert_eq!(EffectiveCaveats::new(&c).not_after("NotAfter"), Some(3000));
    }
}
