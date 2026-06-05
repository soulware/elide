//! Policy-template rendering (`docs/design-mint.md` § *Templating*).
//!
//! Three substitution classes are exposed to a role's policy template:
//!
//! - `{{env.X}}`               — server-side config (the `[env]` table).
//! - `{{caveat "elide:X"}}`    — verified-macaroon caveat, looked up
//!   through a registered `caveat` helper. Scalars render directly;
//!   list caveats iterate as `{{#each (caveat "elide:X")}}`.
//! - `{{mint.X}}`              — mint-computed (`mint.expiry`).
//!
//! Caveats are reached through the `caveat` *helper* — not a
//! `{{caveat.X}}` data path — for two reasons:
//!
//! 1. The design doc namespaces caveats with `:` (`elide:Volume`),
//!    which is not a legal handlebars path segment. The helper takes
//!    the name as a string argument, so the doc's `:` convention is
//!    preserved unchanged (no issuer-side rename).
//! 2. It tightens the "mint ships no policy DSL" property: the only
//!    template surface is `{{env.*}}` / `{{mint.*}}` plain paths,
//!    one `caveat` lookup helper, and the built-in `{{#each}}`. There
//!    is no arbitrary data-graph traversal.
//!
//! The helper resolves names against the **effective** caveat set
//! ([`crate::caveat::EffectiveCaveats::effective`]) — list caveats are
//! intersected, scalars must agree — so the minted policy reflects
//! exactly the authority the gate evaluated, never a broader
//! last-occurrence view.

use std::collections::BTreeMap;

use handlebars::{
    Context, Handlebars, Helper, HelperDef, RenderContext, RenderError, RenderErrorReason,
    ScopedJson,
};
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
    #[error("substitution `{0}` is not inside a JSON string literal")]
    NonStringSubstitution(String),
    #[error("raw (unescaped) substitution `{0}` is not allowed")]
    RawSubstitution(String),
}

/// The `caveat` scalar lookup helper. Holds the resolved-caveat map;
/// `{{caveat "name"}}` resolves against it. A name that is absent **or
/// unsatisfiable** is a hard render error (fail closed): a role
/// template referencing a caveat the macaroon doesn't carry — or whose
/// occurrences contradict — must never mint an unscoped or downgraded
/// credential. All caveats are scalar; there is no `{{#each}}` over a
/// caveat (ancestor-style lists are PoP-signed `req.*` data).
struct CaveatHelper {
    resolved: BTreeMap<String, String>,
}

impl HelperDef for CaveatHelper {
    fn call_inner<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'rc>,
        _: &'reg Handlebars<'reg>,
        _: &'rc Context,
        _: &mut RenderContext<'reg, 'rc>,
    ) -> Result<ScopedJson<'rc>, RenderError> {
        let name = h
            .param(0)
            .and_then(|p| p.value().as_str())
            .ok_or(RenderErrorReason::ParamNotFoundForIndex("caveat", 0))?;
        let value = self.resolved.get(name).ok_or_else(|| {
            RenderErrorReason::Other(format!("caveat not present or unsatisfiable: {name}"))
        })?;
        Ok(ScopedJson::Derived(Value::String(value.clone())))
    }
}

/// Build the resolved-caveat map: one entry per distinct caveat name
/// whose chain occurrences resolve to a single agreed value. `Absent`
/// and `Unsatisfiable` names are omitted, so a template referencing
/// either fails the render closed.
fn resolved_map(caveats: &[Caveat]) -> BTreeMap<String, String> {
    let eff = EffectiveCaveats::new(caveats);
    let mut map = BTreeMap::new();
    for name in eff.names() {
        if let Resolved::Value(v) = eff.resolve(name) {
            map.insert(name.to_string(), v);
        }
    }
    map
}

/// Escape `s` for embedding inside a JSON string literal. Substituted
/// values are caller-influenced (`req.*` is honest-but-unverified, an
/// appended `caveat` is holder-chosen), so without escaping a value
/// carrying `"`/`\` could close its string and restructure the policy
/// while staying valid JSON — escalating a scoped credential to a
/// broader grant. serde_json's encoder produces a fully-escaped quoted
/// string; the template already supplies the surrounding quotes, so the
/// outer pair is dropped. This is the handlebars escape function, so it
/// applies uniformly to every `{{…}}` value (`env`, `caveat`, `req`,
/// `mint`). It is a no-op on injection-free values.
fn escape_json_string(s: &str) -> String {
    match serde_json::to_string(s) {
        // Quotes are single ASCII bytes, so [1..len-1] is on char
        // boundaries.
        Ok(quoted) if quoted.len() >= 2 => quoted[1..quoted.len() - 1].to_string(),
        // Serialising a `&str` is infallible; an empty render (`""`) on
        // the impossible error path fails safe — never a breakout.
        _ => String::new(),
    }
}

/// Verify the template is safe to render under [`escape_json_string`]:
/// every **value-emitting** `{{…}}` must sit inside a JSON string
/// literal, and no raw (`{{{…}}}` / `{{& …}}`) substitution may appear.
///
/// The escape only neutralises breakout for a value placed *inside* a
/// string — it escapes `"`/`\`/control chars, not the structural
/// `,{}[]`. A value hole in a bare JSON position, or a raw stache that
/// bypasses the escape, could still restructure the policy, so both are
/// rejected before any rendering. Section/block tokens (`{{#each}}`,
/// `{{/each}}`, inverted `{{^}}`, `{{else}}`, comments, partials) emit
/// no value of their own and may sit anywhere — only value expressions
/// are constrained, which is what lets `{{#each req.ancestors}}` wrap a
/// string-positioned `{{this}}`.
pub(crate) fn validate_substitutions(template: &str) -> Result<(), TemplateError> {
    let b = template.as_bytes();
    let mut in_string = false;
    let mut escaped = false; // prev byte was a backslash inside a string
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' && i + 1 < b.len() && b[i + 1] == b'{' {
            let triple = i + 2 < b.len() && b[i + 2] == b'{';
            let close_pat = if triple { "}}}" } else { "}}" };
            let open = i + 2;
            let Some(rel) = template[open..].find(close_pat) else {
                break; // unterminated — handlebars compile will report it
            };
            let end = open + rel;
            let inner = template[open..end]
                .trim_matches(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '~'));
            let amp = inner.starts_with('&');
            let token = inner.trim_start_matches('&').trim_start();
            // Section/block/comment/partial tokens emit no value.
            let is_control = token.is_empty()
                || token.starts_with('#')
                || token.starts_with('/')
                || token.starts_with('^')
                || token.starts_with('!')
                || token.starts_with('>')
                || token == "else";
            if !is_control {
                if triple || amp {
                    return Err(TemplateError::RawSubstitution(token.to_string()));
                }
                if !in_string {
                    return Err(TemplateError::NonStringSubstitution(token.to_string()));
                }
            }
            i = end + close_pat.len();
            continue;
        }
        // Plain JSON text — track string state. `{{…}}` spans are skipped
        // above, so quotes inside helper arguments never toggle it.
        let c = b[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        }
        i += 1;
    }
    Ok(())
}

/// Render `policy_template` into a concrete IAM policy JSON string.
///
/// `request` is the **PoP-verified** request body (its provenance is
/// the client's identity key, bound to this macaroon and moment —
/// see [`crate::pop`]); it is exposed as the `req.*` namespace.
/// The caller must verify the PoP signature *before* passing the
/// body here.
/// Each substitution class has a distinct, explicit trust provenance:
/// `caveat.*` MAC-bound, `req.*` PoP-bound, `env.*` config,
/// `mint.*` mint-computed.
pub fn render_policy(
    policy_template: &str,
    env: &BTreeMap<String, String>,
    caveats: &[Caveat],
    request: &Value,
    expiry: &str,
    role: &str,
) -> Result<String, TemplateError> {
    // Reject any value hole outside a JSON string, or any raw stache,
    // before rendering — those are the shapes the escape below cannot
    // make safe.
    validate_substitutions(policy_template)?;

    let mut reg = Handlebars::new();
    // Policies are JSON: escape substituted values for a JSON *string*
    // context (not HTML), so a caller-influenced value can never break
    // out of its string and restructure the policy.
    reg.register_escape_fn(escape_json_string);
    // A missing variable is a misconfigured role, not an empty string.
    reg.set_strict_mode(true);
    reg.register_helper(
        "caveat",
        Box::new(CaveatHelper {
            resolved: resolved_map(caveats),
        }),
    );

    let mut env_map = Map::new();
    for (k, v) in env {
        env_map.insert(k.clone(), Value::String(v.clone()));
    }

    let mut mint_map = Map::new();
    mint_map.insert("expiry".into(), Value::String(expiry.to_string()));

    let mut data = Map::new();
    data.insert("env".into(), Value::Object(env_map));
    data.insert("mint".into(), Value::Object(mint_map));
    data.insert("req".into(), request.clone());

    // Register under the role name so handlebars error messages name
    // the role ("...rendering \"read\"...") instead of the opaque
    // "Unnamed template" that render_template's anonymous path emits.
    reg.register_template_string(role, policy_template)?;
    let rendered = reg.render(role, &Value::Object(data))?;
    serde_json::from_str::<Value>(&rendered).map_err(TemplateError::NotJson)?;
    Ok(rendered)
}

/// The substitution surface a policy template references, grouped by
/// trust provenance (`docs/design-mint.md` § *Templating*): `caveats`
/// MAC-bound, `req` PoP-bound, `env` config, `mint`
/// mint-computed. Each list is sorted and de-duplicated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TemplateSurface {
    pub caveats: Vec<String>,
    pub env: Vec<String>,
    pub mint: Vec<String>,
    pub req: Vec<String>,
}

/// Extract the [`TemplateSurface`] of a policy template by scanning the
/// four documented token shapes — `{{caveat "name"}}`, `{{env.*}}`,
/// `{{mint.*}}`, `{{req.*}}` (with optional `../`/`./` scope
/// prefixes and `(…)` subexpression wrapping). Lets `mint role inspect`
/// state what a role's policy depends on without rendering it:
/// rendering needs a live verified request and fails closed on any
/// absent caveat, so there is no static "what this grants" to show.
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
        let mut tokens = inner.split_whitespace().peekable();
        while let Some(tok) = tokens.next() {
            // `caveat "name"` / `(caveat "name")` — the name is the
            // next token, quote- and paren-stripped (caveat names carry
            // `:`, so only trim wrapping punctuation).
            if tok.trim_start_matches('(') == "caveat" {
                if let Some(arg) = tokens.peek() {
                    let name = arg.trim_matches(|c: char| matches!(c, '(' | ')' | '"' | '\''));
                    if !name.is_empty() {
                        s.caveats.push(name.to_string());
                    }
                }
                continue;
            }
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
            } else {
                None
            };
            if let Some(v) = bucket {
                v.push(p.to_string());
            }
        }
    }
    for v in [&mut s.caveats, &mut s.env, &mut s.mint, &mut s.req] {
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
    "Resource": [
      "arn:aws:s3:::{{env.bucket}}/by_id/{{caveat "elide:Volume"}}/*"
      {{#each req.ancestors}},
      "arn:aws:s3:::{{../env.bucket}}/by_id/{{this}}/*"
      {{/each}}
    ],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}"#;

    fn req(ancestors: &[&str]) -> Value {
        serde_json::json!({ "ancestors": ancestors })
    }

    #[test]
    fn renders_scalar_caveat_signed_request_list_and_mint() {
        let caveats = vec![Caveat::scalar("elide:Volume", "VOL1")];
        let out = render_policy(
            TPL,
            &env(),
            &caveats,
            &req(&["ANC1", "ANC2"]),
            "2026-05-15T14:30:00Z",
            "volume-ro",
        )
        .unwrap();
        assert!(out.contains("demo/by_id/VOL1/*"));
        assert!(out.contains("by_id/ANC1/*"));
        assert!(out.contains("by_id/ANC2/*"));
        assert!(out.contains("2026-05-15T14:30:00Z"));
        serde_json::from_str::<Value>(&out).expect("valid json");
    }

    #[test]
    fn empty_request_ancestors_renders_self_only() {
        // Maximal narrowing — zero ancestors is a coherent grant, not
        // an error: the {{#each}} simply emits nothing.
        let caveats = vec![Caveat::scalar("elide:Volume", "VOL1")];
        let out = render_policy(TPL, &env(), &caveats, &req(&[]), "t", "volume-ro").unwrap();
        assert!(out.contains("by_id/VOL1/*"));
        assert!(!out.contains("by_id//*"));
        serde_json::from_str::<Value>(&out).expect("valid json");
    }

    #[test]
    fn unknown_caveat_is_error() {
        let err = render_policy(
            r#"{"r": "{{caveat "nope"}}"}"#,
            &env(),
            &[],
            &req(&[]),
            "x",
            "r",
        );
        assert!(matches!(err, Err(TemplateError::Render(_))));
    }

    #[test]
    fn missing_request_field_fails_closed() {
        // Strict mode: a template referencing req.ancestors when
        // the signed body omitted it must fail the render, not mint.
        let caveats = vec![Caveat::scalar("elide:Volume", "VOL1")];
        let err = render_policy(TPL, &env(), &caveats, &serde_json::json!({}), "t", "r");
        assert!(matches!(err, Err(TemplateError::Render(_))));
    }

    #[test]
    fn render_error_names_the_role_not_unnamed_template() {
        // Operator-facing: the handlebars message must point at the
        // role, not the opaque "Unnamed template".
        let err = render_policy(
            r#"{"r": "{{req.prefix}}"}"#,
            &env(),
            &[],
            &serde_json::json!({}),
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
    fn contradictory_scalar_caveat_fails_closed() {
        // Two disagreeing scalar occurrences ⇒ Unsatisfiable ⇒ omitted
        // from the resolved map ⇒ template referencing it errors
        // rather than minting a downgraded credential.
        let caveats = vec![
            Caveat::scalar("elide:Volume", "VOL1"),
            Caveat::scalar("elide:Volume", "VOL2"),
        ];
        let err = render_policy(
            r#"{"r": "{{caveat "elide:Volume"}}"}"#,
            &env(),
            &caveats,
            &req(&[]),
            "x",
            "r",
        );
        assert!(matches!(err, Err(TemplateError::Render(_))));
    }

    #[test]
    fn surface_groups_refs_by_provenance_through_scopes_and_subexprs() {
        // TPL exercises every shape: a scalar caveat, a `../`-scoped
        // env ref inside an #each block, a req.* block path, and
        // a mint.* ref. `{{this}}` and the `each` helper are not data
        // refs and must not leak in.
        let s = template_surface(TPL);
        assert_eq!(s.caveats, vec!["elide:Volume"]);
        assert_eq!(s.env, vec!["env.bucket"]); // ../ scope folded
        assert_eq!(s.mint, vec!["mint.expiry"]);
        assert_eq!(s.req, vec!["req.ancestors"]);

        // Subexpression form `{{#each (caveat "elide:X")}}` and a bare
        // namespace token both resolve; duplicates collapse.
        let s = template_surface(
            r#"{{caveat "a"}} {{caveat "a"}} {{#each (caveat "b")}}{{env}}{{/each}}"#,
        );
        assert_eq!(s.caveats, vec!["a", "b"]);
        assert_eq!(s.env, vec!["env"]);
        assert!(s.mint.is_empty() && s.req.is_empty());

        // Comments/partials contribute nothing.
        assert_eq!(
            template_surface("{{! caveat \"x\" }}{{> partial}}"),
            TemplateSurface::default()
        );
    }

    #[test]
    fn req_value_breakout_attempt_is_escaped_not_structural() {
        // A malicious ancestor tries to close the Resource-array string,
        // close the array, and inject a second "Resource" key granting
        // `*`. With JSON-string escaping the `"`/`\` are inert, so it
        // stays a single (ugly) string element — no duplicate key, no
        // escalation.
        let evil = r#"*"],"Resource":["arn:aws:s3:::*"#;
        let caveats = vec![Caveat::scalar("elide:Volume", "VOL1")];
        let out = render_policy(
            TPL,
            &env(),
            &caveats,
            &req(&[evil]),
            "2026-05-15T14:30:00Z",
            "volume-ro",
        )
        .expect("escaped value renders to valid JSON");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        let res = v["Statement"][0]["Resource"]
            .as_array()
            .expect("Resource is an array");
        // Exactly the two intended entries — the scoped volume and the
        // single ancestor element (carrying the injection inertly).
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], "arn:aws:s3:::demo/by_id/VOL1/*");
        let injected = res[1].as_str().expect("ancestor renders as a string");
        assert!(injected.starts_with("arn:aws:s3:::demo/by_id/"));
        assert!(injected.ends_with("/*"));
        // The breakout payload survives only as inert string content.
        assert!(injected.contains(r#""],"Resource""#));
    }

    #[test]
    fn malicious_caveat_value_is_escaped() {
        // A holder-appended caveat the issuer never bound carries an
        // injection payload; escaping keeps it inside its string.
        let caveats = vec![Caveat::scalar("elide:Volume", r#"x","Resource":"*"#)];
        let out = render_policy(
            r#"{"Resource": "by_id/{{caveat "elide:Volume"}}/*"}"#,
            &env(),
            &caveats,
            &req(&[]),
            "t",
            "r",
        )
        .expect("escaped value renders to valid JSON");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        // One Resource key, value carries the payload as inert text.
        assert_eq!(
            v["Resource"],
            serde_json::json!(r#"by_id/x","Resource":"*/*"#)
        );
    }

    #[test]
    fn non_string_positioned_substitution_is_rejected() {
        // A value hole outside a JSON string — escaping `"`/`\` cannot
        // stop `,{}` breakout there, so the template is refused.
        let err = render_policy(
            r#"{"ttl": {{req.n}}}"#,
            &env(),
            &[],
            &serde_json::json!({"n": 5}),
            "t",
            "r",
        );
        assert!(matches!(err, Err(TemplateError::NonStringSubstitution(_))));
    }

    #[test]
    fn raw_stache_is_rejected() {
        // Triple-stache and `{{&}}` bypass the escape fn entirely.
        for tpl in [r#"{"r": "{{{req.x}}}"}"#, r#"{"r": "{{& req.x}}"}"#] {
            let err = render_policy(tpl, &env(), &[], &serde_json::json!({"x": "v"}), "t", "r");
            assert!(
                matches!(err, Err(TemplateError::RawSubstitution(_))),
                "expected RawSubstitution for {tpl}"
            );
        }
    }

    #[test]
    fn each_block_tokens_are_not_value_substitutions() {
        // The `{{#each}}`/`{{/each}}` tokens sit outside strings (between
        // array elements) yet the template validates: only the
        // string-positioned `{{this}}` inside is a value substitution.
        assert!(validate_substitutions(TPL).is_ok());
    }
}
