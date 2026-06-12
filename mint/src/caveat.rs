//! Caveats: first-party scalar and third-party.
//!
//! The mint is caveat-vocabulary-agnostic (see `docs/design-mint.md`
//! § *Macaroon caveat conventions*): it does not hard-code which
//! first-party caveat names are meaningful. A first-party caveat is a
//! `(name, value)` pair; **every first-party caveat is scalar**. There
//! is no list-valued caveat type (design-mint.md § *All caveats are
//! scalar*).
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
    /// RFC 7519 expiry, unix seconds; the sole deadline caveat. Multiple
    /// occurrences narrow to the minimum, so every party binds time the
    /// same way: the issuer's lifetime on a primary, an authority's bound
    /// on a discharge, and a key-less holder's per-IPC / per-forward
    /// attenuation all append `exp` and the tightest wins.
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
    /// Per-coordinator revocation epoch. Stamped on a credential at
    /// `enroll-exchange` from the enrolled record's `rev_epoch`, then
    /// cleared at `assume-role`: the credential's value must equal the
    /// enrolled record's current `rev_epoch` or the credential is dead
    /// (`docs/design-mint.md` § *Revocation*).
    pub const EPOCH: &str = "epoch";
    /// Carried only by the invite macaroon; the current nonce.
    pub const INVITE: &str = "invite";
    /// Authority class a discharge attests, named at `/v1/discharge` and
    /// cleared by the gate that consumes the discharge
    /// (`docs/design-auth-service.md` § *Scope tier*). Carried as a
    /// granted set on a session (membership-checked at issuance) and as a
    /// single value on a discharge (scalar-cleared at the gate). Coined,
    /// so lowercase like the other coined names (`op`/`role`/`invite`).
    pub const SCOPE: &str = "scope";

    /// Every reserved control-caveat name. A role's declared `attested`
    /// contract must be disjoint from this set (enforced at seal
    /// authoring), so an attested name can never shadow a primary's
    /// MAC-bound control caveat.
    pub const RESERVED: &[&str] = &[AUD, EXP, SUB, CNF, OP, ROLE, EPOCH, INVITE, SCOPE];
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
    /// The admin plane — discharges the admin-service's TPC at every
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

    /// Minimum value (unix seconds) across all caveats named `name`, or
    /// `None` if the macaroon carries no parseable occurrence. The field
    /// is read as a numeric narrowing bound — the minimum binds — which
    /// is how the `exp` deadline is cleared, distinct from the
    /// scalar-agreement resolution of [`Self::resolve`].
    pub fn min_bound(&self, name: &str) -> Option<u64> {
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
    fn min_bound_takes_the_minimum() {
        let c = cv(&[("exp", "5000"), ("exp", "3000"), ("exp", "9000")]);
        assert_eq!(EffectiveCaveats::new(&c).min_bound("exp"), Some(3000));
    }
}

/// Property-based tests for caveat resolution. The example tests above
/// pin specific scenarios; these assert the same invariants hold for
/// *every* chain a holder could assemble. The chain alphabet is small
/// on purpose — a handful of names and values — so agreement,
/// disagreement, and absence all occur densely rather than every
/// generated caveat being unique.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// The names queried by every property. `resolve` is checked against
    /// each, so absent and present cases are both exercised per run.
    const NAMES: &[&str] = &["a", "b", "c", "exp", "sub"];

    fn fp_name() -> impl Strategy<Value = String> {
        prop_oneof![Just("a"), Just("b"), Just("c"), Just("exp"), Just("sub"),]
            .prop_map(String::from)
    }

    /// Small token values plus a numeric range — the tokens drive
    /// agreement/disagreement, the numbers exercise `min_bound`.
    fn fp_value() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("x".to_string()),
            Just("y".to_string()),
            Just("z".to_string()),
            (0u64..10_000).prop_map(|n| n.to_string()),
        ]
    }

    /// A chain step: mostly first-party scalars, occasionally a
    /// third-party caveat (which name-based resolution must ignore).
    fn any_caveat() -> impl Strategy<Value = Caveat> {
        prop_oneof![
            9 => (fp_name(), fp_value()).prop_map(|(n, v)| Caveat::scalar(n, v)),
            1 => (vec(any::<u8>(), 0..6), vec(any::<u8>(), 0..6))
                .prop_map(|(vid, cid)| Caveat::third_party("auth", vid, cid)),
        ]
    }

    fn chain() -> impl Strategy<Value = Vec<Caveat>> {
        vec(any_caveat(), 0..16)
    }

    /// First-party values for `name`, in chain order — the raw material
    /// every oracle below recomputes from.
    fn fp_values<'a>(chain: &'a [Caveat], name: &str) -> Vec<&'a str> {
        chain
            .iter()
            .filter_map(|c| match c {
                Caveat::FirstParty { name: n, value } if n == name => Some(value.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Independent oracle for `resolve`, formulated by distinct-value
    /// *cardinality* rather than the implementation's sequential
    /// all-equal scan — so agreement of the two is a real cross-check.
    fn oracle_resolve(chain: &[Caveat], name: &str) -> Resolved {
        let distinct: BTreeSet<&str> = fp_values(chain, name).into_iter().collect();
        match distinct.len() {
            0 => Resolved::Absent,
            1 => Resolved::Value(distinct.into_iter().next().unwrap_or_default().to_string()),
            _ => Resolved::Unsatisfiable,
        }
    }

    proptest! {
        /// `resolve` agrees with the cardinality oracle for every name.
        #[test]
        fn resolve_matches_oracle(chain in chain()) {
            let eff = EffectiveCaveats::new(&chain);
            for &name in NAMES {
                prop_assert_eq!(eff.resolve(name), oracle_resolve(&chain, name));
            }
        }

        /// The tri-state characterisation — and the downgrade footgun it
        /// guards: disagreement resolves `Unsatisfiable`, never `Absent`.
        /// Absent ⟺ no occurrence; Value(v) ⟺ exactly one distinct value;
        /// Unsatisfiable ⟺ ≥2 distinct values.
        #[test]
        fn resolve_tristate_characterisation(chain in chain()) {
            let eff = EffectiveCaveats::new(&chain);
            for &name in NAMES {
                let distinct: BTreeSet<&str> = fp_values(&chain, name).into_iter().collect();
                match eff.resolve(name) {
                    Resolved::Absent => prop_assert!(distinct.is_empty()),
                    Resolved::Value(v) => {
                        prop_assert_eq!(distinct.len(), 1);
                        prop_assert_eq!(Some(v.as_str()), distinct.into_iter().next());
                    }
                    Resolved::Unsatisfiable => prop_assert!(distinct.len() >= 2),
                }
            }
        }

        /// Attenuation only narrows. Appending one more occurrence of a
        /// name — the only move a key-less holder has via the trailing
        /// MAC — can keep `Value` (agreeing copy) or collapse it to
        /// `Unsatisfiable` (contradicting copy), but never re-widens.
        #[test]
        fn appending_only_narrows(
            chain in vec(any_caveat(), 0..12),
            name in fp_name(),
            extra in fp_value(),
        ) {
            let before = EffectiveCaveats::new(&chain).resolve(&name);
            let mut narrowed = chain.clone();
            narrowed.push(Caveat::scalar(name.clone(), extra.clone()));
            let after = EffectiveCaveats::new(&narrowed).resolve(&name);
            match before {
                Resolved::Absent => prop_assert_eq!(after, Resolved::Value(extra)),
                Resolved::Value(v) => {
                    if v == extra {
                        prop_assert_eq!(after, Resolved::Value(v));
                    } else {
                        prop_assert_eq!(after, Resolved::Unsatisfiable);
                    }
                }
                Resolved::Unsatisfiable => prop_assert_eq!(after, Resolved::Unsatisfiable),
            }
        }

        /// `min_bound` is the minimum over parseable-u64 occurrences,
        /// silently skipping non-numeric values, `None` if none parse.
        #[test]
        fn min_bound_matches_oracle(chain in chain()) {
            let eff = EffectiveCaveats::new(&chain);
            for &name in NAMES {
                let oracle = fp_values(&chain, name)
                    .into_iter()
                    .filter_map(|v| v.parse::<u64>().ok())
                    .min();
                prop_assert_eq!(eff.min_bound(name), oracle);
            }
        }

        /// Third-party caveats are inert to name-based resolution:
        /// scattering arbitrary TPCs through a chain changes nothing
        /// `resolve`, `min_bound`, or `names` reports.
        #[test]
        fn third_party_caveats_are_inert(
            pairs in vec((fp_name(), fp_value()), 0..12),
            tpcs in vec((vec(any::<u8>(), 0..6), vec(any::<u8>(), 0..6)), 0..4),
        ) {
            let only_fp: Vec<Caveat> =
                pairs.iter().map(|(n, v)| Caveat::scalar(n.clone(), v.clone())).collect();
            let mut mixed = only_fp.clone();
            for (i, (vid, cid)) in tpcs.into_iter().enumerate() {
                let pos = (i * 2 + 1).min(mixed.len());
                mixed.insert(pos, Caveat::third_party("auth", vid, cid));
            }
            let plain = EffectiveCaveats::new(&only_fp);
            let with_tpcs = EffectiveCaveats::new(&mixed);
            for &name in NAMES {
                prop_assert_eq!(plain.resolve(name), with_tpcs.resolve(name));
                prop_assert_eq!(plain.min_bound(name), with_tpcs.min_bound(name));
            }
            prop_assert_eq!(plain.names(), with_tpcs.names());
        }

        /// `names` lists distinct first-party names in first-occurrence
        /// order, with third-party caveats excluded.
        #[test]
        fn names_are_distinct_first_occurrence(chain in chain()) {
            let names = EffectiveCaveats::new(&chain).names();

            let mut expected = Vec::new();
            let mut seen = BTreeSet::new();
            for c in &chain {
                if let Some(n) = c.first_party_name()
                    && seen.insert(n)
                {
                    expected.push(n);
                }
            }
            prop_assert_eq!(names, expected);
        }
    }
}
