//! Operator-plane client identity and auth (`docs/design-mint.md`
//! § *Admin service token*).
//!
//! The operator runs `mint invite`, `mint enroll …` against the admin
//! surface. Its authority is the **admin-service** (the deployment's
//! machine primary, written by `mint serve` at first start) plus a
//! fresh auth-service discharge and a per-call proof-of-possession. Two
//! identities meet here:
//!
//! - the **machine key** — the admin-service's `cnf`, held in
//!   `<data_dir>/admin-service.key`, which signs every admin request's PoP;
//! - the **human session** — minted by `mint login` and held per-user by
//!   [`crate::session`], which gates discharge issuance at the auth role.
//!
//! This module loads the machine identity, fetches a discharge over the
//! session's transport ([`Operator::fetch_discharge`]), and assembles the
//! `(Authorization, X-Mint-Pop)` header pair for a single admin call. The
//! admin client functions in [`crate::admin`] call [`Operator::authorize`]
//! per request; the verifier side is [`crate::http::verify_and_clear`].

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use ed25519_dalek::SigningKey;

use crate::caveat::{Caveat, name, scope};
use crate::macaroon::Macaroon;
use crate::pop;

/// The admin-service (admin-plane primary) on disk.
pub const ADMIN_SERVICE_FILE: &str = "admin-service";
/// The admin-service's machine key seed (64 ASCII hex, mode 0600) — what
/// the operator CLI signs PoP with.
pub const ADMIN_SERVICE_KEY_FILE: &str = "admin-service.key";

/// Why an operator-plane step failed. Coarse on purpose — the operator
/// CLI surfaces these to a human, not to a peer service.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error("{0}")]
    Io(String),
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("admin-service carries no third-party caveat to discharge")]
    NoTpc,
    #[error("transport: {0}")]
    Transport(String),
    #[error("auth service returned {status}: {body}")]
    Status { status: u16, body: String },
}

/// The operator's admin-plane identity: the admin-service and the machine
/// key it is PoP'd with. Loaded from `<data_dir>` on the host that
/// also runs `mint serve`.
pub struct Operator {
    admin_service: Macaroon,
    machine_key: SigningKey,
}

impl Operator {
    /// Load the admin-service and its machine key from `<data_dir>`. Both
    /// are written by `mint serve` at first start; a missing pair means
    /// either no auth service is configured or `serve` has not run.
    pub fn load(data_dir: &Path) -> Result<Operator, OperatorError> {
        let token_path = data_dir.join(ADMIN_SERVICE_FILE);
        let token_text = std::fs::read_to_string(&token_path).map_err(|e| {
            OperatorError::Io(format!(
                "{}: {e} (run `mint serve` once to mint the admin-service)",
                token_path.display()
            ))
        })?;
        let admin_service = Macaroon::decode(token_text.trim())
            .map_err(|_| OperatorError::Malformed("admin-service"))?;

        let key_path = data_dir.join(ADMIN_SERVICE_KEY_FILE);
        let key_hex = std::fs::read_to_string(&key_path)
            .map_err(|e| OperatorError::Io(format!("{}: {e}", key_path.display())))?;
        let machine_seed =
            unhex32(key_hex.trim()).ok_or(OperatorError::Malformed("admin-service.key"))?;

        Ok(Operator {
            admin_service,
            machine_key: SigningKey::from_bytes(&machine_seed),
        })
    }

    /// Base64 (standard) of the admin-service's third-party-caveat `CID` —
    /// the value POSTed to `/v1/discharge` so the auth role can recover
    /// the discharge key under `K_M-A`.
    pub fn cid_b64(&self) -> Result<String, OperatorError> {
        for c in self.admin_service.caveats() {
            if let Caveat::ThirdParty { cid, .. } = c {
                return Ok(BASE64.encode(cid));
            }
        }
        Err(OperatorError::NoTpc)
    }

    /// The request path of the admin-service's third-party-caveat
    /// `location` — where the operator fetches its discharge. Only the
    /// path is taken; a separately-supplied transport carries the
    /// connection, exactly as the enrolling client derives its discharge
    /// route from a credential's TPC location.
    fn discharge_path(&self) -> Result<String, OperatorError> {
        for c in self.admin_service.caveats() {
            if let Caveat::ThirdParty { location, .. } = c {
                return crate::tpc::location_path(location)
                    .ok_or(OperatorError::Malformed("tpc location"));
            }
        }
        Err(OperatorError::NoTpc)
    }

    /// Fetch a discharge for the admin-service's CID over `transport`, gated
    /// by the session bearer and scoped `mint:admin`. The discharge route
    /// is the path of the admin-service's own TPC location; `transport` is the
    /// connection to the auth role (the demo socket today). One discharge
    /// satisfies every admin verb — the verb is the operator's per-call
    /// attenuation onto the admin-service — so the CLI fetches it once per
    /// invocation.
    pub async fn fetch_discharge(
        &self,
        transport: &str,
        session: &str,
    ) -> Result<Macaroon, OperatorError> {
        let path = self.discharge_path()?;
        let body = self.discharge_request_body()?;
        let headers = [
            ("content-type", "application/json".to_string()),
            ("authorization", format!("Bearer {session}")),
        ];
        let (status, text) = crate::transport::post(transport, &path, &headers, body)
            .await
            .map_err(OperatorError::Transport)?;
        if status != 200 {
            return Err(OperatorError::Status { status, body: text });
        }
        let discharge = json_field(&text, "discharge")?;
        Macaroon::decode(&discharge).map_err(|_| OperatorError::Malformed("discharge"))
    }

    /// The `/v1/discharge` request body for the admin-service's CID at the
    /// admin scope. Built from the handler's own [`crate::auth::DischargeRequest`]
    /// so the field set the daemon expects cannot drift from what the CLI
    /// sends.
    fn discharge_request_body(&self) -> Result<String, OperatorError> {
        let req = crate::auth::DischargeRequest {
            cid: self.cid_b64()?,
            scope: scope::MINT_ADMIN.to_string(),
        };
        serde_json::to_string(&req).map_err(|_| OperatorError::Malformed("discharge request"))
    }

    /// Build the `(Authorization, X-Mint-Pop)` headers for one admin
    /// call: attenuate `op=<op_value>` onto the admin-service (so the verb
    /// binds to this call's PoP over the attenuated tail), bundle it
    /// with the wide `discharge`, and sign `tail ‖ BLAKE3(body)` with
    /// the machine key. `body` must already carry the freshness `ts`.
    pub fn authorize(&self, discharge: &Macaroon, op_value: &str, body: &[u8]) -> (String, String) {
        let attenuated = self
            .admin_service
            .clone()
            .attenuate(Caveat::scalar(name::OP, op_value));
        let sig = pop::client_signature(&self.machine_key, attenuated.tail(), body);
        let auth = format!("MintV1 {},{}", attenuated.encode(), discharge.encode());
        (auth, sig)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::Keyring;

    const ROOT: [u8; 32] = [42u8; 32];
    const K_M_A: [u8; 32] = [13u8; 32];
    const MACHINE_SEED: [u8; 32] = [55u8; 32];

    /// Write a admin-service + key pair into `dir` exactly as `mint serve`
    /// does, returning the minted token for cross-checking.
    fn seed_operator_files(dir: &Path) -> Macaroon {
        let kr = Keyring::single(ROOT);
        let cnf = pop::cnf_value(&SigningKey::from_bytes(&MACHINE_SEED));
        let token = crate::issuance::mint_admin_service_token(
            &kr,
            &K_M_A,
            "mint",
            &cnf,
            "demo",
            "https://auth.example/v1/discharge",
        );
        std::fs::write(dir.join(ADMIN_SERVICE_FILE), token.encode()).unwrap();
        let hex: String = MACHINE_SEED.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(ADMIN_SERVICE_KEY_FILE), hex).unwrap();
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
    fn discharge_path_derives_from_admin_service_tpc() {
        let dir = tempfile::tempdir().unwrap();
        seed_operator_files(dir.path());
        let op = Operator::load(dir.path()).unwrap();
        // The discharge route is the path of the admin-service's own TPC
        // location — the transport supplies the host.
        assert_eq!(op.discharge_path().unwrap(), "/v1/discharge");
    }

    #[test]
    fn discharge_request_body_carries_cid_and_admin_scope() {
        // Regression: the admin discharge fetch must POST the `mint:admin`
        // scope. An earlier cut sent only `cid`, so `/v1/discharge` (whose
        // DischargeRequest now requires `scope`) rejected every operator
        // admin verb with a 400 before it reached the gate. Deserialise
        // through the handler's own type so the field set is the one the
        // daemon expects.
        let dir = tempfile::tempdir().unwrap();
        seed_operator_files(dir.path());
        let op = Operator::load(dir.path()).unwrap();
        let body = op.discharge_request_body().expect("body");
        let req: crate::auth::DischargeRequest = serde_json::from_str(&body).expect("deserialise");
        assert_eq!(req.cid, op.cid_b64().unwrap());
        assert_eq!(req.scope, scope::MINT_ADMIN);
    }

    #[test]
    fn authorize_signs_attenuated_tail_under_machine_key() {
        let dir = tempfile::tempdir().unwrap();
        seed_operator_files(dir.path());
        let op = Operator::load(dir.path()).unwrap();
        let discharge = crate::macaroon::mint_under_key(
            &[7u8; 32],
            crate::macaroon::KeyRef::Discharge,
            vec![Caveat::scalar(name::SUB, "alice")],
        );
        let body = br#"{"ts":1700000000}"#;
        let (auth, sig) = op.authorize(&discharge, "admin:invite-read", body);
        assert!(auth.starts_with("MintV1 "));
        assert!(auth.contains(','), "bundle must carry the discharge too");
        // The PoP verifies against the attenuated admin-service tail under
        // the machine key bound in the token's cnf.
        let primary = auth
            .strip_prefix("MintV1 ")
            .and_then(|p| p.split(',').next())
            .and_then(|m| Macaroon::decode(m).ok())
            .expect("primary decodes");
        let proof = pop::Proof::from_b64(&sig).expect("proof");
        let cnf = vec![Caveat::scalar(
            name::CNF,
            pop::cnf_value(&SigningKey::from_bytes(&MACHINE_SEED)),
        )];
        assert!(pop::check(&cnf, primary.tail(), body, Some(proof), 1700000000).is_ok());
    }

    #[test]
    fn unhex32_rejects_bad_input() {
        assert!(unhex32("xy").is_none());
        assert!(unhex32(&"0".repeat(63)).is_none());
        assert_eq!(unhex32(&"00".repeat(32)), Some([0u8; 32]));
    }
}
