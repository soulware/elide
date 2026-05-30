//! Operator-plane client identity and auth (`docs/design-mint.md`
//! § *CLI service token*).
//!
//! The operator runs `mint invite`, `mint enroll …` against the admin
//! surface. Its authority is the **cli-token** (the deployment's
//! machine primary, written by `mint serve` at first start) plus a
//! fresh auth-service discharge and a per-call proof-of-possession. Two
//! identities meet here:
//!
//! - the **machine key** — the cli-token's `cnf`, held in
//!   `<data_dir>/cli-token.key`, which signs every admin request's PoP;
//! - the **human session** — minted by `mint login` and held in
//!   `<data_dir>/cli-session`, which gates discharge issuance at the
//!   auth role.
//!
//! This module loads that identity, drives `login` / `fetch_discharge`
//! over the demo auth socket, and assembles the `(Authorization,
//! X-Mint-Pop)` header pair for a single admin call. The admin client
//! functions in [`crate::admin`] call [`Operator::authorize`] per
//! request; the verifier side is [`crate::http::verify_and_clear`].

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::caveat::{Caveat, name};
use crate::macaroon::Macaroon;
use crate::pop;

/// The cli-token (admin-plane primary) on disk.
pub const CLI_TOKEN_FILE: &str = "cli-token";
/// The cli-token's machine key seed (64 ASCII hex, mode 0600) — what
/// the operator CLI signs PoP with.
pub const CLI_TOKEN_KEY_FILE: &str = "cli-token.key";
/// The demo session minted by `mint login` (gates discharge issuance).
pub const SESSION_FILE: &str = "cli-session";

/// Why an operator-plane step failed. Coarse on purpose — the operator
/// CLI surfaces these to a human, not to a peer service.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error("{0}")]
    Io(String),
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("cli-token carries no third-party caveat to discharge")]
    NoTpc,
    #[error("transport: {0}")]
    Transport(String),
    #[error("auth service returned {status}: {body}")]
    Status { status: u16, body: String },
}

/// The operator's admin-plane identity: the cli-token and the machine
/// key seed it is PoP'd with. Loaded from `<data_dir>` on the host that
/// also runs `mint serve`.
pub struct Operator {
    cli_token: Macaroon,
    machine_seed: [u8; 32],
}

impl Operator {
    /// Load the cli-token and its machine key from `<data_dir>`. Both
    /// are written by `mint serve` at first start; a missing pair means
    /// either no auth service is configured or `serve` has not run.
    pub fn load(data_dir: &Path) -> Result<Operator, OperatorError> {
        let token_path = data_dir.join(CLI_TOKEN_FILE);
        let token_text = std::fs::read_to_string(&token_path).map_err(|e| {
            OperatorError::Io(format!(
                "{}: {e} (run `mint serve` once to mint the cli-token)",
                token_path.display()
            ))
        })?;
        let cli_token = Macaroon::decode(token_text.trim())
            .map_err(|_| OperatorError::Malformed("cli-token"))?;

        let key_path = data_dir.join(CLI_TOKEN_KEY_FILE);
        let key_hex = std::fs::read_to_string(&key_path)
            .map_err(|e| OperatorError::Io(format!("{}: {e}", key_path.display())))?;
        let machine_seed =
            unhex32(key_hex.trim()).ok_or(OperatorError::Malformed("cli-token.key"))?;

        Ok(Operator {
            cli_token,
            machine_seed,
        })
    }

    /// Base64 (standard) of the cli-token's third-party-caveat `CID` —
    /// the value POSTed to `/v1/discharge` so the auth role can recover
    /// the discharge key under `K_M-A`.
    pub fn cid_b64(&self) -> Result<String, OperatorError> {
        for c in self.cli_token.caveats() {
            if let Caveat::ThirdParty { cid, .. } = c {
                return Ok(BASE64.encode(cid));
            }
        }
        Err(OperatorError::NoTpc)
    }

    /// Build the `(Authorization, X-Mint-Pop)` headers for one admin
    /// call: attenuate `op=<op_value>` onto the cli-token (so the verb
    /// binds to this call's PoP over the attenuated tail), bundle it
    /// with the wide `discharge`, and sign `tail ‖ BLAKE3(body)` with
    /// the machine key. `body` must already carry the freshness `ts`.
    pub fn authorize(&self, discharge: &Macaroon, op_value: &str, body: &[u8]) -> (String, String) {
        let attenuated = self
            .cli_token
            .clone()
            .attenuate(Caveat::scalar(name::OP, op_value));
        let sig = pop::client_signature(&self.machine_seed, attenuated.tail(), body);
        let auth = format!("MintV1 {},{}", attenuated.encode(), discharge.encode());
        (auth, sig)
    }
}

/// Persist a session macaroon to `<data_dir>/cli-session` (mode 0600).
/// Parse-don't-validate: only a decodable macaroon is written.
pub fn save_session(data_dir: &Path, session: &str) -> Result<(), OperatorError> {
    Macaroon::decode(session.trim()).map_err(|_| OperatorError::Malformed("session"))?;
    write_0600(&data_dir.join(SESSION_FILE), session.trim().as_bytes())
        .map_err(|e| OperatorError::Io(e.to_string()))
}

/// Load the session from `<data_dir>/cli-session`, validated as a
/// decodable macaroon. A missing file points the operator at
/// `mint login`.
pub fn load_session(data_dir: &Path) -> Result<String, OperatorError> {
    let path = data_dir.join(SESSION_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| OperatorError::Io(format!("{}: {e} (run `mint login`)", path.display())))?;
    let trimmed = text.trim();
    Macaroon::decode(trimmed).map_err(|_| OperatorError::Malformed("session"))?;
    Ok(trimmed.to_string())
}

/// `mint login`: trivially authenticate at the demo auth role and
/// return the session bearer. The demo accepts any subject with no
/// password; production auth-service authenticates here for real and
/// issues the same session shape.
pub async fn login(auth_socket: &Path, subject: &str) -> Result<String, OperatorError> {
    let body = serde_json::json!({ "subject": subject }).to_string();
    let (status, text) = post_uds(auth_socket, "/v1/login", &[], body).await?;
    if status != 200 {
        return Err(OperatorError::Status { status, body: text });
    }
    json_field(&text, "session")
}

/// Fetch a wide discharge for the cli-token's CID from the demo auth
/// role, gated by the session bearer. One discharge satisfies every
/// admin verb (the verb is the operator's per-call attenuation onto the
/// cli-token), so the CLI fetches it once per invocation.
pub async fn fetch_discharge(
    auth_socket: &Path,
    session: &str,
    cid_b64: &str,
) -> Result<Macaroon, OperatorError> {
    let body = serde_json::json!({ "cid": cid_b64 }).to_string();
    let headers = [("authorization", format!("Bearer {session}"))];
    let (status, text) = post_uds(auth_socket, "/v1/discharge", &headers, body).await?;
    if status != 200 {
        return Err(OperatorError::Status { status, body: text });
    }
    let discharge = json_field(&text, "discharge")?;
    Macaroon::decode(&discharge).map_err(|_| OperatorError::Malformed("discharge"))
}

/// POST `body` to `<endpoint>` on the auth role's UDS with arbitrary
/// headers, returning `(status, text)`. `reqwest` has no UDS support,
/// so this dials the socket via `hyperlocal`'s `UnixConnector` — the
/// same leg the enrolling client uses for the mint socket.
async fn post_uds(
    socket: &Path,
    endpoint: &str,
    headers: &[(&str, String)],
    body: String,
) -> Result<(u16, String), OperatorError> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
    let uri: hyper::Uri = hyperlocal::Uri::new(socket, endpoint).into();
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, v);
    }
    let req = builder
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|e| OperatorError::Transport(e.to_string()))?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| OperatorError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| OperatorError::Transport(e.to_string()))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

fn json_field(body: &str, key: &'static str) -> Result<String, OperatorError> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_string))
        .ok_or(OperatorError::Malformed(key))
}

/// Parse 64 ASCII hex chars into a 32-byte key. `None` on any non-hex
/// byte or a wrong length.
fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Atomic 0600 write — tmp file, chmod, rename.
fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::Keyring;

    const ROOT: [u8; 32] = [42u8; 32];
    const K_M_A: [u8; 32] = [13u8; 32];
    const MACHINE_SEED: [u8; 32] = [55u8; 32];

    /// Write a cli-token + key pair into `dir` exactly as `mint serve`
    /// does, returning the minted token for cross-checking.
    fn seed_operator_files(dir: &Path) -> Macaroon {
        let kr = Keyring::single(ROOT);
        let cnf = pop::cnf_value(&MACHINE_SEED);
        let token =
            crate::issuance::mint_cli_token(&kr, &K_M_A, "mint", &cnf, "demo", "unix:/auth.sock");
        std::fs::write(dir.join(CLI_TOKEN_FILE), token.encode()).unwrap();
        let hex: String = MACHINE_SEED.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(CLI_TOKEN_KEY_FILE), hex).unwrap();
        token
    }

    #[test]
    fn load_round_trips_identity_and_extracts_cid() {
        let dir = tempfile::tempdir().unwrap();
        let token = seed_operator_files(dir.path());
        let op = Operator::load(dir.path()).expect("load");
        // The extracted CID matches the token's own TPC bytes.
        let expected = match token.caveats().iter().find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        }) {
            Some(cid) => BASE64.encode(cid),
            None => panic!("token has no TPC"),
        };
        assert_eq!(op.cid_b64().unwrap(), expected);
    }

    #[test]
    fn authorize_signs_attenuated_tail_under_machine_key() {
        let dir = tempfile::tempdir().unwrap();
        seed_operator_files(dir.path());
        let op = Operator::load(dir.path()).unwrap();
        let discharge = crate::macaroon::mint_under_key(
            &[7u8; 32],
            crate::macaroon::DISCHARGE_KID,
            vec![Caveat::scalar(name::SUB, "alice")],
        );
        let body = br#"{"ts":1700000000}"#;
        let (auth, sig) = op.authorize(&discharge, "admin:invite-read", body);
        assert!(auth.starts_with("MintV1 "));
        assert!(auth.contains(','), "bundle must carry the discharge too");
        // The PoP verifies against the attenuated cli-token tail under
        // the machine key bound in the token's cnf.
        let primary = auth
            .strip_prefix("MintV1 ")
            .and_then(|p| p.split(',').next())
            .and_then(|m| Macaroon::decode(m).ok())
            .expect("primary decodes");
        let proof = pop::Proof::from_b64(&sig).expect("proof");
        let cnf = vec![Caveat::scalar(name::CNF, pop::cnf_value(&MACHINE_SEED))];
        assert!(pop::check(&cnf, primary.tail(), body, Some(proof), 1700000000).is_ok());
    }

    #[test]
    fn session_save_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let session = crate::macaroon::mint_under_key(
            &[1u8; 32],
            crate::macaroon::SESSION_KID,
            vec![Caveat::scalar(name::SUB, "alice")],
        )
        .encode();
        save_session(dir.path(), &session).unwrap();
        assert_eq!(load_session(dir.path()).unwrap(), session);
    }

    #[test]
    fn load_session_absent_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_session(dir.path()),
            Err(OperatorError::Io(_))
        ));
    }

    #[test]
    fn unhex32_rejects_bad_input() {
        assert!(unhex32("xy").is_none());
        assert!(unhex32(&"0".repeat(63)).is_none());
        assert_eq!(unhex32(&"00".repeat(32)), Some([0u8; 32]));
    }
}
