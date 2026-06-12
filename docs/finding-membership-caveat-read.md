# Finding: set-valued caveats read by membership can be appended upward by the holder

## Symptom

A macaroon's authority is supposed to be monotonically *narrowing*:
because chain extension is keyless, any holder can append a caveat, so
the system's safety rests on the rule that **appending a caveat can only
ever remove authority, never add it.** Every scalar caveat read honours
that rule via [`EffectiveCaveats::resolve`](../mint/src/caveat.rs)'s
tri-state AND semantics: two disagreeing occurrences of a name resolve to
`Unsatisfiable` and every consumer must deny.

Two reads in the mint crate broke the rule by treating a caveat *name* as
a **set** whose membership grants authority:

- `EffectiveCaveats::contains(name, value)` — returned true if *any*
  occurrence matched. No production caller; it existed only as a footgun
  (and one proptest).
- `verify_session` collected *all* `Scope` caveats into
  `SessionClaims.scopes: Vec<String>`, and `issue_discharge` authorised
  with `claims.scopes.iter().any(|s| s == &req.scope)` — `contains` by
  another name.

For a membership read, an appended occurrence *introduces* a value, so a
holder can append their way to more authority than they were granted —
the exact inverse of the attenuation invariant, and the same bug class as
the `r`-reuse transplant closed by #579 (holder leverages the trailing
MAC to exceed issuer intent).

## Exploit sequence

Latent in the demo because `mint_session` granted all three scopes to
every session and the session is MAC'd under `K_session`, held only by
the colocated demo auth role — there was nothing to escalate *to*. The
moment a real auth-service issued a **narrowed** session and kept the
`Scope`-as-set + `.any()` read, it became exploitable:

1. Operator logs in. Auth issues a session granting only
   `Scope=mint:enroll` (production auth-service grants per policy, not the
   demo's blanket grant). The session is a `mnt1_` macaroon MAC'd under
   `K_session`; the operator holds it.
2. Operator wants an admin discharge they were not granted. They take
   their own session and append one caveat with no key —
   `session.attenuate(Caveat::scalar("Scope", "mint:admin"))`. The
   trailing MAC needed to extend the chain is in the token they already
   hold; the result is a structurally valid session carrying
   `[Scope=mint:enroll, Scope=mint:admin, …]`.
3. Operator calls `POST /v1/discharge` with `{scope: "mint:admin", …}`
   and the doctored session in `Authorization: Bearer`.
4. `verify_session` MAC-verifies the session — it passes, because
   appending a caveat is a legal chain extension — then collects scopes:
   `["mint:enroll", "mint:admin"]`.
5. `issue_discharge` evaluates
   `claims.scopes.iter().any(|s| s == "mint:admin")` → **true**. A
   `mint:admin` discharge is issued. Privilege escalation.

Contrast the scalar path, which fails closed against the same move: the
admin plane (`admin.rs`) reads `resolve(name::SCOPE)`; the appended
second, distinct `Scope` makes that `Unsatisfiable`, and the
`Resolved::Value(v) if v == mint:admin` arm does not match → denied. The
vulnerability is purely the membership read, not the absence of a
proof/finalization step.

## Root cause

Elide macaroons have no superfly-style "proof" finalization (a sealed
tail that refuses further `Add`). The deliberate substitute is that
**every caveat read is append-safe by construction**: `resolve` (scalar
AND → `Unsatisfiable` on conflict) and `min_bound` (numeric minimum) both
have the property that an appended occurrence can only narrow or
contradict — never broaden. A membership read has the opposite
monotonicity, so it is the one read shape that is unsafe without
finalization, and it slipped in for the one caveat that was modelled as a
set (the session's granted scopes).

## Fix (implemented)

Principle, now explicit: **no caveat is ever read by membership.** A
capability is never expressed as "a set of occurrences, any of which
grants" — it is expressed so that *adding* a caveat can only subtract
capability. Every caveat read goes through `resolve` or `min_bound`.

1. **Deleted `EffectiveCaveats::contains`** and its
   `contains_is_membership` proptest (`caveat.rs`). The only membership
   read primitive is gone; nothing can call it.

2. **The session grant is a single scalar caveat**, not N `Scope`
   caveats. `mint_session` stamps one `scope` caveat whose value is the
   canonical (sorted, space-joined) grant set
   (`GrantedScopes::canonical`), e.g.
   `scope = "mint:admin mint:enroll mint:exchange"`. `verify_session`
   reads it with `resolve(name::SCOPE)`:
   - `Resolved::Value(s)` → `GrantedScopes::parse(s)` splits into the set.
   - `Resolved::Absent` / `Resolved::Unsatisfiable` → empty grant.

   `SessionClaims.scopes` is now a `GrantedScopes` newtype whose inner
   `BTreeSet` is **private**; the only question callers can ask is
   `grants(scope) -> bool`, answered against the value recovered from
   that one caveat. There is no longer a `Vec<String>` to `.iter().any()`
   over. `issue_discharge` calls `claims.scopes.grants(&req.scope)`. A
   holder appending a second `scope` caveat now yields two distinct
   values → `Unsatisfiable` → empty grant → denied, exactly like every
   other scalar. The legitimate narrowing direction (requesting *less*)
   already lives in `req.scope`, not in edits to the session, so
   collapsing the set to one immutable scalar costs nothing.

   This matches the pattern already used correctly when rendering
   attested scope values, which reads via `resolve` and joins.

3. **Regression test:** `auth::tests::appended_scope_caveat_cannot_widen_the_grant`
   mints a narrow (enroll-only) session, has the holder `attenuate` a
   `scope=mint:admin` caveat with only the trailing MAC, and asserts the
   re-verified session grants *nothing* (fail closed, never widen).

4. **Audit gate for the future:** any new set-valued caveat must use the
   single-canonical-scalar-value shape above. The invariant to preserve
   is monotone: *appending a caveat may only shrink the authorised set.*
   `contains`-shaped reads reintroduce the escalation and must not return.

## Status

Fixed on branch `mint-no-membership-reads` (off `origin/main`, post-#579).
The membership read was not reachable in the demo configuration; this is
a defence-in-depth fix that lands **before** any non-demo auth-service
issues narrowed sessions. Sibling of the `r`-reuse finding closed in #579.
