//! Policy-template rendering (`docs/design-mint.md` § *Templating*).
//!
//! A role's policy template is **JSON** carrying `{{ ns.key }}` scalar
//! substitution tokens, each token sitting inside a JSON *string value*.
//! Four namespaces, each a flat scalar lookup — **every one MAC-verified
//! or server-side, none self-asserted** (`docs/design-mint-volume-attestation.md`
//! § *Every template value is MAC-verified or server-side*):
//!
//! - `{{env.X}}`      — sealed server-side config (the `[env]` table).
//! - `{{attested.X}}` — values attested by a discharge authority, carried
//!   on the discharge and MAC'd under its `r` (e.g. `attested.volume`).
//!   Restricted to the closed [`ATTESTABLE`] registry.
//! - `{{mint.X}}`     — mint-computed (`mint.expiry`).
//! - `{{caveat.X}}`   — MAC-verified caveat values on the primary (e.g.
//!   `caveat.sub`).
//!
//! Rendering parses the template as JSON, substitutes into the string
//! leaves, and re-serialises. Two security properties fall out of that
//! shape rather than from a bespoke check:
//!
//! - **Injection-proof.** A substituted value is placed into an
//!   already-parsed JSON string and the document is re-serialised, so
//!   serde escapes any `"`/`\` it contains — a value can never break out
//!   of its slot, whatever its content. The output is valid JSON by
//!   construction.
//! - **Substitution is string-positioned, structurally.** A `{{…}}` token
//!   anywhere but inside a string value (array element, object key, bare)
//!   makes the template invalid JSON, rejected when it is parsed (at seal
//!   authoring, then again here). JSON validity *is* the "token sits in a
//!   safe position" assertion — there is no separate positional check.
//!
//! Substitution is scalar-only: no list iteration, conditionals, helpers,
//! or path navigation. Mint ships no policy DSL.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::caveat::{Caveat, EffectiveCaveats, Resolved};

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// The policy template is not valid JSON. A `{{…}}` token that escaped
    /// a string value (array, key, or bare position) lands here, as does a
    /// genuinely malformed document.
    #[error("policy template for role {role:?} is not valid JSON: {source}")]
    NotJson {
        role: String,
        source: serde_json::Error,
    },
    /// A `{{…}}` token names a field absent from the render data. Strict:
    /// a missing `req`/`env`/`mint`/`caveat` value fails the render closed,
    /// never a silent empty string.
    #[error("policy for role {role:?} references unknown field '{field}'")]
    UnknownField { role: String, field: String },
    /// A `{{…}}` token is not a `namespace.key` scalar path (an unknown
    /// namespace, an empty key, embedded whitespace, an unterminated `{{`,
    /// or a leftover handlebars-ism such as `#each`).
    #[error("policy for role {role:?} has a malformed substitution '{token}'")]
    MalformedToken { role: String, token: String },
    /// Re-serialising the substituted document failed. Not reachable for a
    /// `serde_json::Value` in practice; surfaced rather than unwrapped.
    #[error("serialise rendered policy for role {role:?}: {source}")]
    Serialize {
        role: String,
        source: serde_json::Error,
    },
}

/// The outcome of resolving one `{{…}}` token against the render data.
enum Resolution {
    /// A `namespace.key` path that resolved to a scalar string.
    Value(String),
    /// A well-formed path whose value is absent (strict → `UnknownField`).
    Absent,
    /// Not a `namespace.key` scalar path (→ `MalformedToken`).
    Malformed,
}

/// The complete set of `mint.*` keys the renderer computes — currently
/// just the credential's expiry. The seal-time surface check
/// ([`crate::config::Config::validate_policy_surface`]) rejects a template
/// referencing any `mint.X` outside this set, so an unknown mint key fails
/// at publish, not at first render. Keep in sync with the `mint` arm of
/// [`render_policy`]'s resolver, which is the matching value source.
pub const MINT_KEYS: &[&str] = &["expiry"];

/// Parse a token's trimmed interior into `(namespace, key)`, or `None` if
/// it is not a well-formed `namespace.key` scalar path — an unknown
/// namespace, a missing or empty key, or embedded whitespace (which
/// catches engine-isms like `#each items`). The single definition of
/// token *shape*, shared by the renderer, the surface scanner, and the
/// seal-time lint so all three agree on what is valid.
fn classify_token(inner: &str) -> Option<(&str, &str)> {
    if inner.is_empty() || inner.contains(char::is_whitespace) {
        return None;
    }
    let (ns, key) = inner.split_once('.')?;
    if key.is_empty() {
        return None;
    }
    matches!(ns, "env" | "mint" | "attested" | "caveat").then_some((ns, key))
}

/// The closed set of attestable names — the only keys `{{attested.X}}`
/// may reference and the only names mint reads off a discharge's attested
/// context. mint pulls attested values **by name from this set**, never
/// "whatever the discharge carries", so a discharge can fill only the
/// protocol's attestable slots. Disjoint from the reserved control caveat
/// names by construction (asserted in tests), so `attested.*` can never
/// shadow a primary's MAC-bound control caveat
/// (`docs/design-mint-volume-attestation.md` § *Decided*).
pub const ATTESTABLE: &[&str] = &["volume"];

/// Render `policy_template` into a concrete IAM policy JSON string.
///
/// The template is parsed as JSON; substitution happens only into string
/// leaves; the result is re-serialised, so it is valid JSON by
/// construction and no value can break out of its string slot.
///
/// `discharge_caveats` are the **MAC-verified** caveats from the bundle's
/// discharges (the `discharge_caveats` set `verify_and_clear` returns,
/// each MAC'd under its discharge's `r` and attributable to the issuing
/// authority); they are the `attested.*` namespace. Only the names in the
/// closed [`ATTESTABLE`] registry are exposed — a discharge cannot fill an
/// arbitrary or reserved slot, and the attested context is never flattened
/// into `caveat.*`, so a discharge value can never shadow the primary's
/// MAC-bound `caveat.*`.
///
/// `caveats` is the **MAC-verified** caveat chain of the primary; it is
/// the `caveat.*` namespace. Only caveats that resolve to a single
/// [`Resolved::Value`] are exposed — a contradictory (`Unsatisfiable`)
/// occurrence is omitted, so a holder cannot smuggle a forged value past
/// the renderer by appending a contradictory copy under the trailing MAC.
///
/// Each class has a distinct, explicit trust provenance, **none
/// self-asserted**: `attested.*` discharge-MAC'd, `env.*` config,
/// `mint.*` mint-computed, `caveat.*` primary-MAC'd.
pub fn render_policy(
    policy_template: &str,
    env: &BTreeMap<String, String>,
    discharge_caveats: &[Caveat],
    caveats: &[Caveat],
    expiry: &str,
    role: &str,
) -> Result<String, TemplateError> {
    let mut doc: Value =
        serde_json::from_str(policy_template).map_err(|source| TemplateError::NotJson {
            role: role.to_string(),
            source,
        })?;

    // Verified caveats, by name. Resolution is the same scalar-AND the
    // gate uses: an `Unsatisfiable` name is dropped, never exposed — a
    // `{{caveat.X}}` over it then fails the render closed rather than
    // silently substituting one of the disagreeing occurrences.
    let eff = EffectiveCaveats::new(caveats);
    let mut caveat_map: BTreeMap<&str, String> = BTreeMap::new();
    for name in eff.names() {
        if let Resolved::Value(v) = eff.resolve(name) {
            caveat_map.insert(name, v);
        }
    }

    // Attested values, pulled **by name from the closed registry** out of
    // the discharge context — never "whatever the discharge carries". A
    // discharge caveat outside [`ATTESTABLE`] (or a reserved name) is not
    // exposed here, so it cannot reach a policy slot.
    let dis = EffectiveCaveats::new(discharge_caveats);
    let mut attested_map: BTreeMap<&str, String> = BTreeMap::new();
    for &name in ATTESTABLE {
        if let Resolved::Value(v) = dis.resolve(name) {
            attested_map.insert(name, v);
        }
    }

    let resolve = |inner: &str| -> Resolution {
        let Some((ns, key)) = classify_token(inner) else {
            return Resolution::Malformed;
        };
        let value = match ns {
            "env" => env.get(key).cloned(),
            "mint" => (key == "expiry").then(|| expiry.to_string()),
            "caveat" => caveat_map.get(key).cloned(),
            "attested" => attested_map.get(key).cloned(),
            // `classify_token` already rejected unknown namespaces.
            _ => return Resolution::Malformed,
        };
        match value {
            Some(v) => Resolution::Value(v),
            None => Resolution::Absent,
        }
    };

    substitute_value(&mut doc, role, &resolve)?;
    serde_json::to_string(&doc).map_err(|source| TemplateError::Serialize {
        role: role.to_string(),
        source,
    })
}

/// Recurse the parsed template, substituting tokens into every string
/// leaf. Numbers, bools, and null carry no tokens; object **keys** are
/// left verbatim (no role templates a key).
fn substitute_value(
    value: &mut Value,
    role: &str,
    resolve: &dyn Fn(&str) -> Resolution,
) -> Result<(), TemplateError> {
    match value {
        Value::String(s) => {
            if s.contains("{{") {
                *s = substitute_string(s, role, resolve)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                substitute_value(item, role, resolve)?;
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                substitute_value(val, role, resolve)?;
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
    Ok(())
}

/// Replace every `{{ ns.key }}` token in one string leaf. A substituted
/// value is emitted verbatim and never re-scanned, so a value that itself
/// contains `{{…}}` is inert text, not a template.
fn substitute_string(
    s: &str,
    role: &str,
    resolve: &dyn Fn(&str) -> Resolution,
) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // Unterminated `{{` — `{{` is reserved token syntax, so this is
            // a template error, not literal text.
            return Err(TemplateError::MalformedToken {
                role: role.to_string(),
                token: rest[open..].to_string(),
            });
        };
        let inner = after[..close].trim();
        match resolve(inner) {
            Resolution::Value(v) => out.push_str(&v),
            Resolution::Absent => {
                return Err(TemplateError::UnknownField {
                    role: role.to_string(),
                    field: inner.to_string(),
                });
            }
            Resolution::Malformed => {
                return Err(TemplateError::MalformedToken {
                    role: role.to_string(),
                    token: inner.to_string(),
                });
            }
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The substitution surface a policy template references, grouped by
/// trust provenance (`docs/design-mint.md` § *Templating*): `attested`
/// discharge-MAC'd, `env` config, `mint` mint-computed, `caveat`
/// primary-MAC'd. Each list is sorted and de-duplicated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemplateSurface {
    pub env: Vec<String>,
    pub mint: Vec<String>,
    pub attested: Vec<String>,
    pub caveat: Vec<String>,
}

/// Extract the [`TemplateSurface`] of a policy template by scanning its
/// `{{ ns.key }}` tokens. Lets `mint role inspect` state what a role's
/// policy depends on without rendering it: rendering needs a live
/// verified request body, so there is no static "what this grants" to
/// show. Best-effort — a malformed token contributes nothing (the
/// renderer rejects it).
pub fn template_surface(template: &str) -> TemplateSurface {
    let mut s = TemplateSurface::default();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            break;
        };
        let inner = after[..close].trim();
        rest = &after[close + 2..];
        if let Some((ns, _key)) = classify_token(inner) {
            let bucket = match ns {
                "env" => &mut s.env,
                "mint" => &mut s.mint,
                "attested" => &mut s.attested,
                "caveat" => &mut s.caveat,
                _ => continue,
            };
            bucket.push(inner.to_string());
        }
    }
    for v in [&mut s.env, &mut s.mint, &mut s.attested, &mut s.caveat] {
        v.sort();
        v.dedup();
    }
    s
}

/// Report every `{{…}}` token in the parsed template's string leaves that
/// the renderer would reject as malformed — an unknown namespace, a
/// missing or empty key, embedded whitespace, an unterminated `{{`, or a
/// leftover engine-ism like `{{#each}}`. Seal authoring
/// (`Config::validate_policy_surface`) refuses a template carrying any, so
/// such a template fails at publish rather than at first render. This is a
/// *shape* check only: an absent value (a `req`/`caveat`/`mint` field not
/// known until a request) is not malformed and is not reported here.
pub fn malformed_tokens(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_malformed(doc, &mut out);
    out
}

fn collect_malformed(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => collect_malformed_in_str(s, out),
        Value::Array(items) => {
            for item in items {
                collect_malformed(item, out);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                collect_malformed(val, out);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

fn collect_malformed_in_str(s: &str, out: &mut Vec<String>) {
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // Unterminated `{{` — `{{` is reserved token syntax.
            out.push(rest[open..].to_string());
            return;
        };
        if classify_token(after[..close].trim()).is_none() {
            out.push(rest[open..open + 2 + close + 2].to_string());
        }
        rest = &after[close + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BTreeMap<String, String> {
        BTreeMap::from([("bucket".to_string(), "demo".to_string())])
    }

    const TPL: &str = r#"{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::{{env.bucket}}/by_id/{{attested.volume}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}"#;

    /// Discharge caveats carrying an attested `volume`, as the attestation
    /// authority would stamp them.
    fn dis(volume: &str) -> Vec<Caveat> {
        vec![Caveat::scalar("volume", volume)]
    }

    fn cv(pairs: &[(&str, &str)]) -> Vec<Caveat> {
        pairs.iter().map(|(n, v)| Caveat::scalar(*n, *v)).collect()
    }

    #[test]
    fn attestable_is_disjoint_from_reserved_control_names() {
        // The fencing invariant: no attestable name is also a reserved
        // control caveat, so `attested.X` can never name (and thus never
        // shadow) a primary's MAC-bound control caveat.
        use crate::caveat::name;
        let reserved = [
            name::AUD,
            name::EXP,
            name::SUB,
            name::CNF,
            name::OP,
            name::ROLE,
            name::EPOCH,
            name::INVITE,
            name::SCOPE,
        ];
        for a in ATTESTABLE {
            assert!(
                !reserved.contains(a),
                "attestable name {a:?} collides with a reserved control caveat"
            );
        }
    }

    #[test]
    fn renders_env_attested_scalar_and_mint() {
        let out = render_policy(
            TPL,
            &env(),
            &dis("VOL1"),
            &[],
            "2026-05-15T14:30:00Z",
            "volume-ro",
        )
        .unwrap();
        assert!(out.contains("demo/by_id/VOL1/*"));
        assert!(out.contains("2026-05-15T14:30:00Z"));
        serde_json::from_str::<Value>(&out).expect("valid json");
    }

    #[test]
    fn caveat_sub_comes_from_the_primary_not_the_discharge() {
        // `{{caveat.sub}}` substitutes the MAC-verified principal —
        // sourced from the primary's caveat chain, never the discharge.
        // A discharge caveat also named `sub` must not bleed into
        // `caveat.*` (the attested context is never flattened in), and in
        // any case `sub` is not in ATTESTABLE so it is never exposed.
        const TPL_SUB: &str = r#"{"Resource":["arn:aws:s3:::b/coordinators/{{caveat.sub}}/*"]}"#;
        let out = render_policy(
            TPL_SUB,
            &env(),
            &cv(&[("sub", "FORGED")]),
            &cv(&[("sub", "COORD1"), ("aud", "mint")]),
            "t",
            "coord-rw",
        )
        .unwrap();
        assert!(out.contains("coordinators/COORD1/*"), "got: {out}");
        assert!(
            !out.contains("FORGED"),
            "discharge sub bled into caveat.sub: {out}"
        );
    }

    #[test]
    fn unsatisfiable_caveat_is_omitted_and_fails_closed() {
        // Two disagreeing `sub` occurrences resolve Unsatisfiable; the
        // renderer omits the name rather than picking one, so a
        // `{{caveat.sub}}` over it fails the render closed — no forged
        // value can ride a contradictory appended copy.
        const TPL_SUB: &str = r#"{"Resource":["{{caveat.sub}}"]}"#;
        let err = render_policy(
            TPL_SUB,
            &env(),
            &[],
            &cv(&[("sub", "REAL"), ("sub", "FORGED")]),
            "t",
            "coord-rw",
        );
        assert!(
            matches!(err, Err(TemplateError::UnknownField { .. })),
            "{err:?}"
        );
    }

    #[test]
    fn missing_attested_field_fails_closed() {
        // A template referencing attested.volume with no discharge
        // carrying it must fail the render, not mint an unscoped
        // credential.
        let err = render_policy(TPL, &env(), &[], &[], "t", "r");
        assert!(
            matches!(err, Err(TemplateError::UnknownField { .. })),
            "{err:?}"
        );
    }

    #[test]
    fn attested_name_outside_registry_fails_closed() {
        // A discharge caveat whose name is not in ATTESTABLE is never
        // exposed, so a policy referencing it fails closed — a discharge
        // cannot fill an arbitrary slot.
        const TPL_R: &str = r#"{"Resource":["{{attested.region}}"]}"#;
        let err = render_policy(
            TPL_R,
            &env(),
            &cv(&[("region", "eu-west")]),
            &[],
            "t",
            "volume-ro",
        );
        assert!(
            matches!(err, Err(TemplateError::UnknownField { .. })),
            "{err:?}"
        );
    }

    #[test]
    fn token_outside_a_string_makes_the_template_non_json() {
        // The structural injection defense: a token in array position is
        // not valid JSON, so the template is rejected — there is no
        // unsafe non-string substitution position to reach.
        const TPL_BAD: &str = r#"{"Resource":[{{attested.volume}}]}"#;
        let err = render_policy(TPL_BAD, &env(), &dis("V"), &[], "t", "volume-ro");
        assert!(matches!(err, Err(TemplateError::NotJson { .. })), "{err:?}");
    }

    #[test]
    fn metacharacters_in_a_value_cannot_inject_structure() {
        // A value full of JSON metacharacters is escaped into its string
        // slot, never parsed as policy structure.
        const TPL_R: &str =
            r#"{"Statement":[{"Effect":"Allow","Resource":["arn:{{attested.volume}}"]}]}"#;
        let evil = r#"x","Effect":"Deny"},{"Resource":"*"#;
        let out = render_policy(TPL_R, &env(), &dis(evil), &[], "t", "volume-ro").unwrap();
        let v: Value = serde_json::from_str(&out).expect("output is valid json");
        let stmts = v["Statement"].as_array().expect("statement array");
        assert_eq!(stmts.len(), 1, "value injected a statement: {out}");
        assert_eq!(stmts[0]["Effect"], "Allow");
        assert_eq!(
            stmts[0]["Resource"][0].as_str().unwrap(),
            format!("arn:{evil}"),
            "value not held intact in its slot: {out}"
        );
    }

    #[test]
    fn malformed_token_fails_closed() {
        // A leftover handlebars-ism and a namespace-less token are both
        // rejected, not rendered as empty.
        for bad in [r#"{"x":"{{#each items}}"}"#, r#"{"x":"{{volume}}"}"#] {
            let err = render_policy(bad, &env(), &dis("V"), &[], "t", "r");
            assert!(
                matches!(err, Err(TemplateError::MalformedToken { .. })),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn render_error_names_the_role() {
        // Operator-facing: the error must point at the role.
        let err = render_policy(
            r#"{"x":"{{attested.volume}}"}"#,
            &env(),
            &[],
            &[],
            "t",
            "read",
        )
        .expect_err("missing attested.volume must fail closed");
        assert!(
            err.to_string().contains("\"read\""),
            "message should name the role: {err}"
        );
    }

    #[test]
    fn malformed_tokens_flags_shape_errors_not_absent_values() {
        // Shape errors are reported (the seal-time lint); well-formed
        // tokens — even ones whose value is absent until a request — are
        // not, because absence is a render-time data concern, not a
        // template defect.
        let doc = serde_json::json!({
            "ok": "arn:{{env.bucket}}/{{attested.volume}}",
            "engineism": "{{#each items}}",
            "no_namespace": "{{volume}}",
            "absent_but_well_formed": "{{attested.nonesuch}}",
            "nested": ["{{caveat.sub}}", "{{ bad token }}"],
        });
        let bad = malformed_tokens(&doc);
        assert!(bad.contains(&"{{#each items}}".to_string()), "{bad:?}");
        assert!(bad.contains(&"{{volume}}".to_string()), "{bad:?}");
        assert!(bad.contains(&"{{ bad token }}".to_string()), "{bad:?}");
        assert!(
            !bad.iter().any(|t| t.contains("env.bucket")
                || t.contains("attested.volume")
                || t.contains("attested.nonesuch")
                || t.contains("caveat.sub")),
            "well-formed token reported as malformed: {bad:?}"
        );
    }

    #[test]
    fn malformed_tokens_flags_unterminated() {
        let doc = serde_json::json!({ "x": "arn:{{attested.volume" });
        assert_eq!(
            malformed_tokens(&doc),
            vec!["{{attested.volume".to_string()]
        );
    }

    #[test]
    fn surface_groups_refs_by_provenance() {
        // TPL references one of each non-primary namespace.
        let s = template_surface(TPL);
        assert_eq!(s.env, vec!["env.bucket"]);
        assert_eq!(s.mint, vec!["mint.expiry"]);
        assert_eq!(s.attested, vec!["attested.volume"]);
        assert!(s.caveat.is_empty());

        // The primary MAC-verified namespace is scanned too.
        let cav = template_surface("{{caveat.sub}}");
        assert_eq!(cav.caveat, vec!["caveat.sub"]);

        // Tokens that aren't `namespace.key` scalar paths contribute
        // nothing — an unknown namespace, whitespace, a bare name.
        let noise = template_surface("{{../env.region}} {{ a b }}{{volume}}");
        assert!(
            noise.env.is_empty()
                && noise.mint.is_empty()
                && noise.attested.is_empty()
                && noise.caveat.is_empty()
        );
    }
}

/// Property-based tests for the renderer's injection-proofness. The
/// example tests above pin one hand-built malicious value; these assert
/// the guarantee over *every* value a namespace source could carry: a
/// substituted value always lands intact in its string slot, never alters
/// the document's structure, and is never re-scanned as a second template.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn env_one(key: &str, val: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(key.to_string(), val.to_string())])
    }

    fn dis(volume: &str) -> Vec<Caveat> {
        vec![Caveat::scalar("volume", volume)]
    }

    /// An adversarial value: a run of fragments biased towards the
    /// characters and substrings that could break a naïve string-splice
    /// renderer — JSON metacharacters, control bytes, token-looking
    /// `{{…}}` text, and arbitrary Unicode scalars.
    fn evil_value() -> impl Strategy<Value = String> {
        let fragment = prop_oneof![
            Just("\"".to_string()),
            Just("\\".to_string()),
            Just("{".to_string()),
            Just("}".to_string()),
            Just("[".to_string()),
            Just("]".to_string()),
            Just(",".to_string()),
            Just(":".to_string()),
            Just("\n".to_string()),
            Just("\u{0}".to_string()),
            Just("{{env.bucket}}".to_string()),
            Just("{{attested.volume}}".to_string()),
            "[a-z0-9/_-]{0,5}".prop_map(String::from),
            any::<char>().prop_map(|c| c.to_string()),
        ];
        proptest::collection::vec(fragment, 0..12).prop_map(|frags| frags.concat())
    }

    proptest! {
        /// Whatever a substituted value contains, the output is valid JSON
        /// and the value reappears byte-for-byte in its slot — serde
        /// escapes it into the string on the way out.
        #[test]
        fn value_lands_intact_and_output_is_valid_json(value in evil_value()) {
            const TPL: &str = r#"{"Resource":["arn:aws:s3:::{{attested.volume}}/*"]}"#;
            let out = render_policy(TPL, &env_one("bucket", "demo"), &dis(&value), &[], "t", "r")
                .expect("render must succeed for a well-formed, present token");
            let v: Value = serde_json::from_str(&out).expect("output is valid json");
            let expected = format!("arn:aws:s3:::{value}/*");
            prop_assert_eq!(v["Resource"][0].as_str(), Some(expected.as_str()));
        }

        /// A value can never inject structure: regardless of content, the
        /// rendered document has the same shape as a benign render — one
        /// statement, `Effect: Allow`, a single `Resource` element — with
        /// the value confined to that one leaf.
        #[test]
        fn value_cannot_alter_structure(value in evil_value()) {
            const TPL: &str =
                r#"{"Statement":[{"Effect":"Allow","Resource":["arn:{{attested.volume}}"]}]}"#;
            let out = render_policy(TPL, &env_one("bucket", "demo"), &dis(&value), &[], "t", "r")
                .expect("render ok");
            let v: Value = serde_json::from_str(&out).expect("valid json");
            let stmts = v["Statement"].as_array().expect("statement array");
            prop_assert_eq!(stmts.len(), 1);
            prop_assert_eq!(stmts[0]["Effect"].as_str(), Some("Allow"));
            let res = stmts[0]["Resource"].as_array().expect("resource array");
            prop_assert_eq!(res.len(), 1);
            let expected = format!("arn:{value}");
            prop_assert_eq!(res[0].as_str(), Some(expected.as_str()));
        }

        /// Three namespaces resolved in one render each land in their own
        /// slot, intact and independent — no value bleeds across slots.
        #[test]
        fn every_namespace_value_lands_in_its_own_slot(
            e in evil_value(),
            a in evil_value(),
            c in evil_value(),
        ) {
            const TPL: &str = r#"{"e":"{{env.x}}","a":"{{attested.volume}}","c":"{{caveat.sub}}"}"#;
            let out = render_policy(
                TPL,
                &env_one("x", &e),
                &dis(&a),
                &[Caveat::scalar("sub", &c)],
                "t",
                "r",
            )
            .expect("render ok");
            let v: Value = serde_json::from_str(&out).expect("valid json");
            prop_assert_eq!(v["e"].as_str(), Some(e.as_str()));
            prop_assert_eq!(v["a"].as_str(), Some(a.as_str()));
            prop_assert_eq!(v["c"].as_str(), Some(c.as_str()));
        }

        /// A substituted value is emitted verbatim and never re-scanned: a
        /// value that itself contains `{{env.bucket}}` stays literal text,
        /// so the (differently-valued) real `env.bucket` never appears.
        #[test]
        fn substituted_values_are_not_rescanned(suffix in evil_value()) {
            let value = format!("{{{{env.bucket}}}}{suffix}"); // literal "{{env.bucket}}" + suffix
            const TPL: &str = r#"{"r":["{{attested.volume}}"]}"#;
            let out = render_policy(
                TPL,
                &env_one("bucket", "SHOULD_NOT_APPEAR"),
                &dis(&value),
                &[],
                "t",
                "r",
            )
            .expect("render ok");
            let v: Value = serde_json::from_str(&out).expect("valid json");
            prop_assert_eq!(v["r"][0].as_str(), Some(value.as_str()));
            prop_assert!(!out.contains("SHOULD_NOT_APPEAR"));
        }
    }
}
