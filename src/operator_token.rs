// Operator-token resolution and attenuation, CLI side.
//
// The persistent operator token (`~/.elide/operator-token` or env / flag)
// is coordinator-wide: it carries `Role::Operator`, a nonce, and a long
// `NotAfter`, but no `Op` or `Volume`. Each gated CLI verb narrows the
// token at the moment of use by appending a typed `Op` caveat, a
// `Volume` caveat scoped to the verb's target, and a short additional
// `NotAfter`. The narrowed token is what crosses the IPC boundary; the
// persistent token never leaves the operator's machine.
//
// See docs/design-auth-model.md.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, io};

use elide_coordinator::macaroon::{Caveat, Macaroon, OperatorOp};

/// Environment variable consulted after `--token` and before
/// `~/.elide/operator-token`.
pub const TOKEN_ENV_VAR: &str = "ELIDE_OPERATOR_TOKEN";

/// On-wire expiry the CLI attaches at use time. Short by design: the
/// attenuated token only needs to outlive the IPC round-trip plus
/// modest clock skew.
pub const USE_EXPIRY_SECS: u64 = 60;

/// Where the operator token is stored on disk. Falls back to a hard
/// path under `$HOME` when `~` expansion is unavailable.
pub fn default_token_path() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push(".elide");
    p.push("operator-token");
    Some(p)
}

/// Resolve the persistent operator token: `--token` flag wins, then
/// `ELIDE_OPERATOR_TOKEN`, then `~/.elide/operator-token`. Trims
/// trailing whitespace. Returns `None` if no source has a non-empty
/// value.
pub fn resolve(token_flag: Option<&str>) -> io::Result<Option<String>> {
    if let Some(t) = token_flag {
        let t = t.trim();
        if !t.is_empty() {
            return Ok(Some(t.to_owned()));
        }
    }
    if let Ok(t) = env::var(TOKEN_ENV_VAR) {
        let t = t.trim();
        if !t.is_empty() {
            return Ok(Some(t.to_owned()));
        }
    }
    let Some(path) = default_token_path() else {
        return Ok(None);
    };
    match fs::read_to_string(&path) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                Ok(Some(t.to_owned()))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Diagnostic message for the "no token" case. Shared between CLI
/// verbs so the suggestion stays consistent.
pub fn missing_token_hint(op: OperatorOp) -> String {
    format!(
        "`elide volume {op_name}` requires an operator token.\n\
         Run `elide token create` and either:\n  \
         - pass --token <value>\n  \
         - set {env} in your environment\n  \
         - or save it to ~/.elide/operator-token",
        op_name = op.as_str(),
        env = TOKEN_ENV_VAR,
    )
}

/// Take a stored (coordinator-wide) operator token, append the
/// per-use caveats — `Op(op)`, `Volume(volume)`, short `NotAfter` —
/// and return the encoded wire token ready to hand to the
/// coordinator.
pub fn attenuate_for(stored: &str, op: OperatorOp, volume: &str) -> io::Result<String> {
    let m = Macaroon::parse(stored)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let wire = m.attenuate(vec![
        Caveat::Op(op),
        Caveat::Volume(volume.to_owned()),
        Caveat::NotAfter(now + USE_EXPIRY_SECS),
    ]);
    Ok(wire.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_coordinator::macaroon::{mint_operator, verify_operator};

    fn key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn attenuate_round_trips_and_verifies() {
        let root = mint_operator(&key(), 1_900_000_000);
        let wire = attenuate_for(&root.encode(), OperatorOp::Remove, "myvm").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let m = verify_operator(&key(), &wire, now, OperatorOp::Remove, "myvm").unwrap();
        assert_eq!(m.op(), Some(OperatorOp::Remove));
        assert_eq!(m.volume(), Some("myvm"));
    }

    #[test]
    fn attenuate_scopes_to_named_volume_only() {
        let root = mint_operator(&key(), 1_900_000_000);
        let wire = attenuate_for(&root.encode(), OperatorOp::Remove, "myvm").unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_operator(&key(), &wire, now, OperatorOp::Remove, "othervm").is_err());
    }

    #[test]
    fn resolve_prefers_flag_over_env() {
        // SAFETY: tests in this crate are single-threaded by default
        // and we restore the env after.
        unsafe { env::set_var(TOKEN_ENV_VAR, "from-env") };
        let got = resolve(Some("from-flag")).unwrap();
        unsafe { env::remove_var(TOKEN_ENV_VAR) };
        assert_eq!(got.as_deref(), Some("from-flag"));
    }

    #[test]
    fn resolve_falls_back_to_env_when_flag_empty() {
        unsafe { env::set_var(TOKEN_ENV_VAR, "from-env") };
        let got = resolve(Some("")).unwrap();
        unsafe { env::remove_var(TOKEN_ENV_VAR) };
        assert_eq!(got.as_deref(), Some("from-env"));
    }
}
