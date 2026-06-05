//! Policy-template rendering (`docs/design-mint.md` § *Templating*).
//!
//! Four substitution classes are exposed to a role's policy template,
//! each a plain handlebars data path:
//!
//! - `{{env.X}}`     — server-side config (the `[env]` table).
//! - `{{req.X}}`     — PoP-verified request-body fields, the channel the
//!   coordinator uses to convey scoping data such as the target volume
//!   (`req.volume`).
//! - `{{mint.X}}`    — mint-computed (`mint.expiry`).
//! - `{{caveat.X}}`  — MAC-verified caveat values from the presented
//!   macaroon, e.g. `caveat.sub` (the enrolment-immutable principal). The
//!   value is sourced from the verified chain, never echoed through the
//!   request body, so it cannot be forged: a contradictory occurrence
//!   resolves [`Resolved::Unsatisfiable`] and is *omitted*, and a
//!   reference to an absent caveat fails the render closed (strict mode).
//!
//! The surface is exactly these plain scalar paths — mint ships no
//! policy DSL, and there is no arbitrary data-graph traversal. Each
//! class has a distinct, explicit trust provenance: `env.*` config,
//! `req.*` PoP-bound, `mint.*` mint-computed, `caveat.*` MAC-verified.

use std::collections::BTreeMap;

use handlebars::Handlebars;
use serde_json::{Map, Value};

use crate::caveat::{Caveat, EffectiveCaveats, Resolved};

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("render policy: {0}")]
    Render(#[from] handlebars::RenderError),
    #[error("compile policy template: {0}")]
    Compile(#[from] handlebars::TemplateError),
    #[error("rendered policy is not valid JSON: {0}")]
    NotJson(serde_json::Error),
}

/// Render `policy_template` into a concrete IAM policy JSON string.
///
/// `request` is the **PoP-verified** request body (its provenance is
/// the client's identity key, bound to this macaroon and moment —
/// see [`crate::pop`]); it is exposed as the `req.*` namespace.
/// The caller must verify the PoP signature *before* passing the
/// body here.
///
/// `caveats` is the **MAC-verified** caveat chain (the aggregated set
/// `verify_and_clear` returns); it is exposed as the `caveat.*`
/// namespace. Only caveats that resolve to a single [`Resolved::Value`]
/// are exposed — a contradictory (`Unsatisfiable`) occurrence is
/// omitted, so a holder cannot smuggle a forged value past the renderer
/// by appending a contradictory copy under the trailing MAC.
///
/// Each substitution class has a distinct, explicit trust provenance:
/// `req.*` PoP-bound, `env.*` config, `mint.*` mint-computed,
/// `caveat.*` MAC-verified.
pub fn render_policy(
    policy_template: &str,
    env: &BTreeMap<String, String>,
    request: &Value,
    caveats: &[Caveat],
    expiry: &str,
    role: &str,
) -> Result<String, TemplateError> {
    let mut reg = Handlebars::new();
    // Policies are JSON, not HTML — disable entity escaping.
    reg.register_escape_fn(handlebars::no_escape);
    // A missing variable is a misconfigured role, not an empty string.
    reg.set_strict_mode(true);

    let mut env_map = Map::new();
    for (k, v) in env {
        env_map.insert(k.clone(), Value::String(v.clone()));
    }

    let mut mint_map = Map::new();
    mint_map.insert("expiry".into(), Value::String(expiry.to_string()));

    // Verified caveats, by name. Resolution is the same scalar-AND the
    // gate uses: an `Unsatisfiable` name is dropped, never exposed — a
    // `{{caveat.X}}` over it then fails the render closed under strict
    // mode rather than silently substituting one of the disagreeing
    // occurrences.
    let eff = EffectiveCaveats::new(caveats);
    let mut caveat_map = Map::new();
    for name in eff.names() {
        if let Resolved::Value(v) = eff.resolve(name) {
            caveat_map.insert(name.to_string(), Value::String(v));
        }
    }

    let mut data = Map::new();
    data.insert("env".into(), Value::Object(env_map));
    data.insert("mint".into(), Value::Object(mint_map));
    data.insert("req".into(), request.clone());
    data.insert("caveat".into(), Value::Object(caveat_map));

    // Register under the role name so handlebars error messages name
    // the role ("...rendering \"read\"...") instead of the opaque
    // "Unnamed template" that render_template's anonymous path emits.
    reg.register_template_string(role, policy_template)?;
    let rendered = reg.render(role, &Value::Object(data))?;
    serde_json::from_str::<Value>(&rendered).map_err(TemplateError::NotJson)?;
    Ok(rendered)
}

/// The substitution surface a policy template references, grouped by
/// trust provenance (`docs/design-mint.md` § *Templating*): `req`
/// PoP-bound, `env` config, `mint` mint-computed, `caveat` MAC-verified.
/// Each list is sorted and de-duplicated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemplateSurface {
    pub env: Vec<String>,
    pub mint: Vec<String>,
    pub req: Vec<String>,
    pub caveat: Vec<String>,
}

/// Extract the [`TemplateSurface`] of a policy template by scanning the
/// four documented token shapes — `{{env.*}}`, `{{mint.*}}`, `{{req.*}}`,
/// `{{caveat.*}}` (with optional `../`/`./` scope prefixes). Lets `mint
/// role inspect` state what a role's policy depends on without rendering
/// it: rendering needs a live verified request body, so there is no
/// static "what this grants" to show.
pub fn template_surface(template: &str) -> TemplateSurface {
    let mut s = TemplateSurface::default();
    let mut i = 0;
    while let Some(open) = template[i..].find("{{") {
        let start = i + open + 2;
        let Some(rel_close) = template[start..].find("}}") else {
            break;
        };
        let end = start + rel_close;
        // Inner span; trim mustache modifiers (block #, close /, raw {,
        // unescape ~) and whitespace at the edges.
        let inner = template[start..end]
            .trim_matches(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '#' | '~'));
        i = end + 2;
        if inner.starts_with('/') || inner.starts_with('!') || inner.starts_with('>') {
            continue; // block close, comment, partial — no data refs
        }
        for tok in inner.split_whitespace() {
            // A plain path: strip a leading `(`, any number of `../`
            // and a `./` scope prefix, and a trailing `)`.
            let mut p = tok.trim_start_matches('(').trim_end_matches(')');
            while let Some(rest) = p.strip_prefix("../") {
                p = rest;
            }
            p = p.strip_prefix("./").unwrap_or(p);
            let bucket = if p == "env" || p.starts_with("env.") {
                Some(&mut s.env)
            } else if p == "mint" || p.starts_with("mint.") {
                Some(&mut s.mint)
            } else if p == "req" || p.starts_with("req.") {
                Some(&mut s.req)
            } else if p == "caveat" || p.starts_with("caveat.") {
                Some(&mut s.caveat)
            } else {
                None
            };
            if let Some(v) = bucket {
                v.push(p.to_string());
            }
        }
    }
    for v in [&mut s.env, &mut s.mint, &mut s.req, &mut s.caveat] {
        v.sort();
        v.dedup();
    }
    s
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
    "Resource": ["arn:aws:s3:::{{env.bucket}}/by_id/{{req.volume}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}"#;

    fn req(volume: &str) -> Value {
        serde_json::json!({ "volume": volume })
    }

    fn cv(pairs: &[(&str, &str)]) -> Vec<Caveat> {
        pairs.iter().map(|(n, v)| Caveat::scalar(*n, *v)).collect()
    }

    #[test]
    fn renders_env_req_scalar_and_mint() {
        let out = render_policy(
            TPL,
            &env(),
            &req("VOL1"),
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
    fn caveat_sub_comes_from_the_chain_not_the_body() {
        // `{{caveat.sub}}` substitutes the MAC-verified principal —
        // sourced from the caveat chain, never the request body. A body
        // field also named `sub` lands in the `req` namespace and must
        // not bleed into `caveat.*`: a forged body value cannot displace
        // the MAC-bound one.
        const TPL_SUB: &str = r#"{"Resource":["arn:aws:s3:::b/coordinators/{{caveat.sub}}/*"]}"#;
        let out = render_policy(
            TPL_SUB,
            &env(),
            &serde_json::json!({ "sub": "FORGED" }),
            &cv(&[("sub", "COORD1"), ("aud", "mint")]),
            "t",
            "coord-rw",
        )
        .unwrap();
        assert!(out.contains("coordinators/COORD1/*"), "got: {out}");
        assert!(
            !out.contains("FORGED"),
            "body sub bled into caveat.sub: {out}"
        );
    }

    #[test]
    fn unsatisfiable_caveat_is_omitted_and_fails_closed() {
        // Two disagreeing `sub` occurrences resolve Unsatisfiable; the
        // renderer omits the name rather than picking one, so a
        // `{{caveat.sub}}` over it fails the render closed (strict mode)
        // — no forged value can ride a contradictory appended copy.
        const TPL_SUB: &str = r#"{"Resource":["{{caveat.sub}}"]}"#;
        let err = render_policy(
            TPL_SUB,
            &env(),
            &serde_json::json!({}),
            &cv(&[("sub", "REAL"), ("sub", "FORGED")]),
            "t",
            "coord-rw",
        );
        assert!(matches!(err, Err(TemplateError::Render(_))));
    }

    #[test]
    fn missing_request_field_fails_closed() {
        // Strict mode: a template referencing req.volume when the signed
        // body omitted it must fail the render, not mint.
        let err = render_policy(TPL, &env(), &serde_json::json!({}), &[], "t", "r");
        assert!(matches!(err, Err(TemplateError::Render(_))));
    }

    #[test]
    fn render_error_names_the_role_not_unnamed_template() {
        // Operator-facing: the handlebars message must point at the
        // role, not the opaque "Unnamed template".
        let err = render_policy(
            "{{req.prefix}}",
            &env(),
            &serde_json::json!({}),
            &[],
            "t",
            "read",
        )
        .expect_err("missing req.prefix must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("\"read\""),
            "message should name the role: {msg}"
        );
        assert!(
            !msg.contains("Unnamed template"),
            "message still anonymous: {msg}"
        );
    }

    #[test]
    fn surface_groups_refs_by_provenance() {
        // TPL references one of each request-side namespace: `env.bucket`,
        // `req.volume`, `mint.expiry`.
        let s = template_surface(TPL);
        assert_eq!(s.env, vec!["env.bucket"]);
        assert_eq!(s.mint, vec!["mint.expiry"]);
        assert_eq!(s.req, vec!["req.volume"]);
        assert!(s.caveat.is_empty());

        // The MAC-verified namespace is scanned too.
        let cav = template_surface("{{caveat.sub}}");
        assert_eq!(cav.caveat, vec!["caveat.sub"]);

        // `../` scope prefixes fold to the base namespace; comments and
        // partials contribute nothing.
        let scoped = template_surface("{{../env.region}} {{! a comment }}{{> partial}}");
        assert_eq!(scoped.env, vec!["env.region"]);
        assert!(scoped.mint.is_empty() && scoped.req.is_empty() && scoped.caveat.is_empty());
    }
}
