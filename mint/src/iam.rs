//! Keypair minting boundary.
//!
//! In production this is the `CreatePolicy` + `CreateAccessKey` +
//! `AttachUserPolicy` sequence against Tigris IAM (`docs/design-mint.md`
//! § *Open questions* #9). mint never deletes keys — they expire via the
//! policy's `DateLessThan` (§ *Cleanup*).
//!
//! The minter is behind a trait so the HTTP/macaroon/role shape can run
//! end-to-end without a live Tigris account. [`FakeMinter`] returns
//! deterministic keys and records every call for assertions;
//! [`crate::tigris::TigrisMinter`] is the real Tigris IAM Query-API
//! implementation (`serve --tigris`). The Tigris client is ported into
//! `mint/` rather than shared with `elide-tigris-iam` so the eventual
//! standalone project carries no `elide-*` dependency.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};

#[derive(Debug, Clone)]
pub struct MintedKeypair {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub expiration: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    /// Tigris-side transient failure (rate limit, quota, admin
    /// credential rejection). Maps to HTTP 503.
    #[error("backend unavailable: {0}")]
    Backend(String),
}

#[async_trait]
pub trait KeypairMinter: Send + Sync {
    /// Mint a keypair scoped by `policy_json`, expiring after `ttl`.
    /// `policy_name` is the IAM policy name to register the document
    /// under — operator-visible metadata, no security significance.
    /// Build it via [`policy_name`].
    async fn mint_keypair(
        &self,
        policy_name: &str,
        policy_json: &str,
        ttl: Duration,
    ) -> Result<MintedKeypair, MintError>;
}

/// Build a mint-issued IAM policy name.
///
/// Format: `mint_<role>_<scope>_<expiry>_<nonce>`
/// - `role`: the role slug.
/// - `scope`: the role's attested values joined by `-`, `global` for a
///   role that attests none.
/// - `expiry`: basic ISO 8601 UTC (`YYYYMMDDTHHMMSSZ`) of the policy's
///   `DateLessThan` — sorts lexically = chronologically in the Tigris
///   console.
/// - `nonce`: 32 bits of OS randomness as 8 lowercase hex chars; ensures
///   uniqueness within a single (role, scope, second) bucket.
///
/// All characters are in IAM's policy-name charset (`[\w+=,.@-]{1,128}`).
/// `_` separates fields; `-` only appears inside the role and scope
/// segments.
pub fn policy_name(role: &str, scope: Option<&str>, expiry: DateTime<Utc>) -> String {
    let scope = scope.unwrap_or("global");
    let expiry_compact = expiry.format("%Y%m%dT%H%M%SZ");
    let nonce: u32 = OsRng.next_u32();
    format!("mint_{role}_{scope}_{expiry_compact}_{nonce:08x}")
}

#[derive(Debug, Clone)]
pub struct RecordedMint {
    pub policy_name: String,
    pub policy_json: String,
    pub ttl: Duration,
    pub issued_key_id: String,
}

/// Deterministic in-memory minter for the prototype and tests.
pub struct FakeMinter {
    calls: Mutex<Vec<RecordedMint>>,
}

impl FakeMinter {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of every `mint_keypair` call so far.
    pub fn calls(&self) -> Vec<RecordedMint> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl Default for FakeMinter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeypairMinter for FakeMinter {
    async fn mint_keypair(
        &self,
        policy_name: &str,
        policy_json: &str,
        ttl: Duration,
    ) -> Result<MintedKeypair, MintError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| MintError::Backend("poisoned call log".into()))?;
        let n = calls.len();
        let key_id = format!("tid_fake_{n:08}");
        calls.push(RecordedMint {
            policy_name: policy_name.to_string(),
            policy_json: policy_json.to_string(),
            ttl,
            issued_key_id: key_id.clone(),
        });
        let expiration = Utc::now()
            + chrono::Duration::from_std(ttl)
                .map_err(|_| MintError::Backend("ttl out of range".into()))?;
        Ok(MintedKeypair {
            access_key_id: key_id,
            secret_access_key: format!("fakesecret{n:08}"),
            expiration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_minter_records_and_is_deterministic() {
        let m = FakeMinter::new();
        let k0 = m
            .mint_keypair(
                "mint_test_global_20260521T000000Z_00000000",
                "{}",
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let k1 = m
            .mint_keypair(
                "mint_test_global_20260521T000000Z_00000001",
                "{}",
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(k0.access_key_id, "tid_fake_00000000");
        assert_eq!(k1.access_key_id, "tid_fake_00000001");
        assert_eq!(m.calls().len(), 2);
    }

    #[test]
    fn policy_name_shape() {
        let expiry = "2026-05-21T14:30:00Z".parse::<DateTime<Utc>>().unwrap();
        let scoped = policy_name("volume-rw", Some("01JD8K3FQ9R0YHGWZV5XPMNTAB"), expiry);
        assert!(
            scoped.starts_with("mint_volume-rw_01JD8K3FQ9R0YHGWZV5XPMNTAB_20260521T143000Z_"),
            "got {scoped}"
        );
        // 4 (mint) + 1 + 9 (volume-rw) + 1 + 26 + 1 + 16 + 1 + 8 = 67
        assert_eq!(scoped.len(), 67);
        assert!(scoped.len() <= 128);

        let global = policy_name("coord-ro", None, expiry);
        assert!(global.starts_with("mint_coord-ro_global_20260521T143000Z_"));
    }
}
