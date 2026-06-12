//! The per-user auth session, shared by the operator admin plane and the
//! reference client (`docs/design-auth-service.md` § *Login flow*). One
//! `mint login` serves both: it authenticates at the auth role and stores
//!
//! - `session` — the session bearer that gates `/v1/discharge`; ephemeral
//!   (cleared by `mint logout`, refreshed by the next login), and
//! - `auth-transport` — how to dial the auth role (`unix:<sock>` or
//!   `http(s)://host`); durable, overwritten only when a login resolves a
//!   new transport from `--url`/`--config`, and left in place by logout so
//!   a later bare `mint login` re-authenticates at the same place.
//!
//! Both live under `$XDG_CONFIG_HOME/mint` (else `$HOME/.config/mint`),
//! mode 0600 — per-user state, distinct from the daemon's `data_dir` and
//! the client's `client_dir`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::macaroon::Macaroon;

const SESSION_FILE: &str = "session";
const TRANSPORT_FILE: &str = "auth-transport";
const ATTEST_TRANSPORT_FILE: &str = "attest-transport";

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("io: {0}")]
    Io(String),
    #[error("no config home — set HOME or XDG_CONFIG_HOME")]
    NoHome,
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("not logged in (run `mint login`)")]
    NotLoggedIn,
    #[error("no auth transport known — run `mint login --url <auth-url>`")]
    NoTransport,
    #[error("no attestation transport known — run `mint login --config <mint.toml>`")]
    NoAttestTransport,
    #[error("login failed ({status}): {body}")]
    Login { status: u16, body: String },
}

/// The per-user mint config dir: `$XDG_CONFIG_HOME/mint`, else
/// `$HOME/.config/mint`. Strict XDG so it reads `~/.config/mint`
/// identically on every platform.
pub fn dir() -> Result<PathBuf, SessionError> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("mint"));
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".config").join("mint")),
        _ => Err(SessionError::NoHome),
    }
}

/// Persist `session` (validated as a decodable macaroon) and `transport`,
/// both mode 0600, creating the config dir if needed. Overwrites both —
/// one session and one transport at a time.
pub fn save(session: &str, transport: &str) -> Result<(), SessionError> {
    let session = session.trim();
    Macaroon::decode(session).map_err(|_| SessionError::Malformed("session"))?;
    let d = dir()?;
    std::fs::create_dir_all(&d).map_err(|e| SessionError::Io(e.to_string()))?;
    write_0600(&d.join(SESSION_FILE), session.as_bytes())?;
    write_0600(&d.join(TRANSPORT_FILE), transport.trim().as_bytes())?;
    Ok(())
}

/// Load the session bearer, validated as a decodable macaroon. Absent →
/// [`SessionError::NotLoggedIn`].
pub fn load_session() -> Result<String, SessionError> {
    let path = dir()?.join(SESSION_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SessionError::NotLoggedIn);
        }
        Err(e) => return Err(SessionError::Io(e.to_string())),
    };
    let trimmed = text.trim();
    Macaroon::decode(trimmed).map_err(|_| SessionError::Malformed("session"))?;
    Ok(trimmed.to_string())
}

/// Load the saved auth transport (`unix:<sock>` / `http(s)://host`).
/// Absent → [`SessionError::NoTransport`].
pub fn load_transport() -> Result<String, SessionError> {
    let path = dir()?.join(TRANSPORT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(t.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SessionError::NoTransport),
        Err(e) => Err(SessionError::Io(e.to_string())),
    }
}

/// Persist how to dial the attestation authority (`unix:<sock>` /
/// `http(s)://host`), mode 0600. Written by `mint login --config` when
/// the config colocates the demo attestation authority; durable like
/// `auth-transport`.
pub fn save_attest_transport(transport: &str) -> Result<(), SessionError> {
    let d = dir()?;
    std::fs::create_dir_all(&d).map_err(|e| SessionError::Io(e.to_string()))?;
    write_0600(&d.join(ATTEST_TRANSPORT_FILE), transport.trim().as_bytes())
}

/// Load the saved attestation transport. Absent →
/// [`SessionError::NoAttestTransport`].
pub fn load_attest_transport() -> Result<String, SessionError> {
    let path = dir()?.join(ATTEST_TRANSPORT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(t.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SessionError::NoAttestTransport),
        Err(e) => Err(SessionError::Io(e.to_string())),
    }
}

/// Remove the session, leaving `auth-transport` in place so a later bare
/// `mint login` re-authenticates at the same auth role. Returns whether a
/// session was present — a no-op logout is `Ok(false)`.
pub fn clear_session() -> Result<bool, SessionError> {
    let path = dir()?.join(SESSION_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(SessionError::Io(e.to_string())),
    }
}

/// `POST /v1/login` at `transport` and return the session bearer. The
/// demo auth role accepts any subject with no password; production
/// authenticates here for real and issues the same session shape.
pub async fn login(transport: &str, subject: &str) -> Result<String, SessionError> {
    let body = serde_json::json!({ "subject": subject }).to_string();
    let headers = [("content-type", "application/json".to_string())];
    let (status, text) = crate::transport::post(transport, "/v1/login", &headers, body)
        .await
        .map_err(SessionError::Io)?;
    if status != 200 {
        return Err(SessionError::Login { status, body: text });
    }
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("session")
                .and_then(|s| s.as_str())
                .map(str::to_string)
        })
        .ok_or(SessionError::Malformed("login response"))
}

fn write_0600(path: &std::path::Path, bytes: &[u8]) -> Result<(), SessionError> {
    std::fs::write(path, bytes).map_err(|e| SessionError::Io(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| SessionError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test points XDG_CONFIG_HOME at its own tempdir. The env is
    // process-global, so these are not run concurrently with each other
    // (serialised via the shared guard).
    use std::sync::Mutex;
    static ENV: Mutex<()> = Mutex::new(());

    fn sample_session() -> String {
        crate::macaroon::mint_under_key(
            &[1u8; 32],
            crate::macaroon::SESSION_KID,
            vec![crate::caveat::Caveat::scalar(
                crate::caveat::name::SUB,
                "alice",
            )],
        )
        .encode()
    }

    #[test]
    fn save_load_clear_round_trip_leaves_transport() {
        let _g = ENV.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: guarded by ENV; no other thread reads the env here.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };

        let s = sample_session();
        save(&s, "unix:/run/auth.sock").unwrap();
        assert_eq!(load_session().unwrap(), s);
        assert_eq!(load_transport().unwrap(), "unix:/run/auth.sock");

        // logout clears the session but keeps the transport pointer.
        assert!(clear_session().unwrap());
        assert!(matches!(load_session(), Err(SessionError::NotLoggedIn)));
        assert_eq!(load_transport().unwrap(), "unix:/run/auth.sock");
        // idempotent
        assert!(!clear_session().unwrap());

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn absent_session_and_transport_report_distinctly() {
        let _g = ENV.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", tmp.path()) };

        assert!(matches!(load_session(), Err(SessionError::NotLoggedIn)));
        assert!(matches!(load_transport(), Err(SessionError::NoTransport)));

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn dir_prefers_xdg_then_home() {
        let _g = ENV.lock().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", "/x/cfg") };
        assert_eq!(dir().unwrap(), PathBuf::from("/x/cfg/mint"));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        unsafe { std::env::set_var("HOME", "/home/bob") };
        assert_eq!(dir().unwrap(), PathBuf::from("/home/bob/.config/mint"));
    }
}
