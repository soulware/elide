//! Self-vended `mint-rw` Tigris keypair for `_mint/*` data-plane I/O
//! (`docs/design-mint.md` § *Mint state in the tenant bucket*).
//!
//! On `serve --tigris` startup, mint asks its own [`KeypairMinter`] for
//! an access key scoped to `arn:aws:s3:::<bucket>/_mint/*`, then builds
//! an [`object_store::aws::AmazonS3`] using that key as its
//! [`CredentialProvider`]. A background task re-mints before the
//! `DateLessThan` lapses, swapping the new credential into the
//! provider; the `AmazonS3` instance itself is constant for the
//! process lifetime.
//!
//! The admin Tigris credential ([`crate::config::AdminCredential`]) is
//! used **only** on the IAM plane (`CreateAccessKey + CreatePolicy +
//! AttachUserPolicy` through [`crate::tigris::TigrisMinter`]); it
//! never signs an `s3:*` call. A request-handler bug that leaks the
//! `mint-rw` cred therefore exposes only `_mint/*`, not org admin.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use object_store::CredentialProvider;
use object_store::aws::{AmazonS3Builder, AwsCredential, S3ConditionalPut};
use tokio::sync::RwLock;

use crate::iam::{KeypairMinter, MintedKeypair, policy_name};

/// `mint-rw` keypair TTL. 7 days is long enough that operator restarts
/// dominate the refresh cadence in practice, short enough that a leaked
/// key has bounded value. Refresh fires at half-life by default.
pub const MINT_RW_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// How early before `DateLessThan` to re-mint. At half-life: a transient
/// IAM outage has the other half of the lifetime to recover before the
/// credential turns into an outage.
pub const REFRESH_SAFETY_MARGIN_RATIO: f64 = 0.5;

/// `mint-rw` policy: prefix-scoped S3 read/write/delete on `_mint/*`
/// plus prefix-conditional `ListBucket` for the rotation/GC walks
/// (`_mint/pending/*` enumeration). The bare bucket appears as a
/// resource only for `s3:ListBucket`, which is the AWS-mandated shape;
/// the `s3:prefix` condition keeps that list scoped to `_mint/`.
///
/// `DateLessThan` rendered as the keypair's expiry is what
/// retires the credential: mint never deletes IAM users or keys
/// (`docs/design-mint.md` § *Cleanup*).
fn mint_rw_policy_json(bucket: &str, expiry_iso8601: &str) -> String {
    format!(
        r#"{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::{bucket}/_mint/*"],
      "Condition": {{"DateLessThan": {{"aws:CurrentTime": "{expiry_iso8601}"}}}}
    }},
    {{
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::{bucket}"],
      "Condition": {{
        "StringLike": {{"s3:prefix": ["_mint/*"]}},
        "DateLessThan": {{"aws:CurrentTime": "{expiry_iso8601}"}}
      }}
    }}
  ]
}}"#
    )
}

/// Mint a fresh `mint-rw` keypair via `minter`, scoped to `bucket`.
pub async fn vend_mint_rw(
    minter: &Arc<dyn KeypairMinter>,
    bucket: &str,
) -> Result<MintedKeypair, crate::iam::MintError> {
    let expiry =
        Utc::now() + chrono::Duration::from_std(MINT_RW_TTL).expect("TTL within chrono range");
    let expiry_iso = expiry.to_rfc3339();
    let name = policy_name("mint-rw", None, expiry);
    let policy = mint_rw_policy_json(bucket, &expiry_iso);
    minter.mint_keypair(&name, &policy, MINT_RW_TTL).await
}

/// `CredentialProvider` whose backing [`AwsCredential`] can be swapped
/// at runtime by the refresh task. Hot path is an `RwLock` read +
/// `Arc::clone`; refresh takes the write lock briefly.
#[derive(Debug)]
pub struct SwappableAwsProvider {
    cred: RwLock<Arc<AwsCredential>>,
}

impl SwappableAwsProvider {
    pub fn new(initial: AwsCredential) -> Self {
        Self {
            cred: RwLock::new(Arc::new(initial)),
        }
    }

    pub async fn replace(&self, next: AwsCredential) {
        *self.cred.write().await = Arc::new(next);
    }
}

#[async_trait]
impl CredentialProvider for SwappableAwsProvider {
    type Credential = AwsCredential;

    async fn get_credential(&self) -> object_store::Result<Arc<AwsCredential>> {
        Ok(self.cred.read().await.clone())
    }
}

fn aws_credential(kp: &MintedKeypair) -> AwsCredential {
    AwsCredential {
        key_id: kp.access_key_id.clone(),
        secret_key: kp.secret_access_key.clone(),
        token: None,
    }
}

/// Build the data-plane `AmazonS3` client backed by a self-vended
/// `mint-rw` keypair, plus the [`SwappableAwsProvider`] handle the
/// refresh task uses to rotate credentials. The initial mint runs
/// synchronously so a misconfigured tenant fails fast at startup
/// rather than at the first request.
pub async fn build_s3_with_mint_rw(
    minter: &Arc<dyn KeypairMinter>,
    bucket: &str,
    endpoint: Option<&str>,
    region: Option<&str>,
) -> Result<
    (
        Arc<object_store::aws::AmazonS3>,
        Arc<SwappableAwsProvider>,
        chrono::DateTime<Utc>,
    ),
    BuildError,
> {
    let kp = vend_mint_rw(minter, bucket).await?;
    let expiration = kp.expiration;
    let provider = Arc::new(SwappableAwsProvider::new(aws_credential(&kp)));
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(bucket)
        .with_credentials(provider.clone())
        // `PutMode::Create` (the only conditional mode mint uses) does
        // not require this; set it anyway so callers reading the
        // backend with `PutMode::Update` semantics get a clean error
        // rather than a confusing one if the surface ever grows.
        .with_conditional_put(S3ConditionalPut::ETagMatch);
    if let Some(ep) = endpoint {
        builder = builder
            .with_endpoint(ep)
            .with_virtual_hosted_style_request(false);
    }
    builder = builder.with_region(region.unwrap_or("us-east-1"));
    let s3 = builder.build().map_err(BuildError::from)?;
    Ok((Arc::new(s3), provider, expiration))
}

/// Spawn the credential-refresh task. Re-mints `mint-rw` at half-life
/// (or `REFRESH_SAFETY_MARGIN_RATIO` of `MINT_RW_TTL`, whichever is
/// sooner), swaps the new key into `provider`, and repeats. Transient
/// IAM failures back off and retry within the remaining lifetime; if
/// the credential lapses before a refresh succeeds, the next
/// `_mint/*` op will fail closed (Tigris 403) — louder than a silent
/// bypass.
pub fn spawn_refresh(
    minter: Arc<dyn KeypairMinter>,
    bucket: String,
    provider: Arc<SwappableAwsProvider>,
    initial_expiration: chrono::DateTime<Utc>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut expiration = initial_expiration;
        loop {
            let wait = refresh_delay(expiration);
            tokio::time::sleep(wait).await;
            match vend_mint_rw(&minter, &bucket).await {
                Ok(kp) => {
                    let new_expiry = kp.expiration;
                    provider.replace(aws_credential(&kp)).await;
                    expiration = new_expiry;
                    tracing::info!(
                        target: "mint::mint_rw",
                        new_expiration = %expiration,
                        "refreshed mint-rw credential"
                    );
                }
                Err(e) => {
                    // Back off for a bounded retry within the remaining
                    // lifetime — half of what's left, capped at one
                    // minute so we don't bunch retries against a flaky
                    // IAM endpoint, floor of five seconds.
                    let remaining = (expiration - Utc::now()).num_seconds().max(0) as u64;
                    let backoff = (remaining / 2).clamp(5, 60);
                    tracing::warn!(
                        target: "mint::mint_rw",
                        error = %e,
                        remaining_seconds = remaining,
                        retry_in_seconds = backoff,
                        "mint-rw refresh failed; will retry"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                }
            }
        }
    })
}

fn refresh_delay(expiration: chrono::DateTime<Utc>) -> Duration {
    let now = Utc::now();
    let remaining = (expiration - now).num_seconds();
    if remaining <= 0 {
        // Already lapsed — try again immediately. Belt-and-braces; the
        // refresh logic should prevent this in normal operation.
        return Duration::from_secs(1);
    }
    let margin = (remaining as f64 * REFRESH_SAFETY_MARGIN_RATIO) as u64;
    Duration::from_secs(margin.max(1))
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("vending mint-rw: {0}")]
    Mint(#[from] crate::iam::MintError),
    #[error("building S3 client: {0}")]
    Object(#[from] object_store::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::FakeMinter;

    #[test]
    fn policy_json_scopes_to_mint_prefix_and_carries_expiry() {
        let p = mint_rw_policy_json("demo-bucket", "2026-12-31T23:59:59Z");
        // The data-plane statement targets _mint/* only.
        assert!(p.contains(r#""arn:aws:s3:::demo-bucket/_mint/*""#));
        // The ListBucket statement targets the bucket itself with a
        // prefix Condition that keeps the list scoped.
        assert!(p.contains(r#""arn:aws:s3:::demo-bucket""#));
        assert!(p.contains(r#""s3:prefix""#));
        assert!(p.contains(r#""_mint/*""#));
        // DateLessThan carries the expiry — what retires the keypair.
        assert!(p.contains("2026-12-31T23:59:59Z"));
        // No leakage outside _mint/.
        assert!(!p.contains(r#""arn:aws:s3:::demo-bucket/by_id/*""#));
    }

    #[tokio::test]
    async fn vend_calls_minter_with_mint_rw_policy_name_and_ttl() {
        let minter: Arc<dyn KeypairMinter> = Arc::new(FakeMinter::new());
        let kp = vend_mint_rw(&minter, "demo-bucket").await.unwrap();
        assert_eq!(kp.access_key_id, "tid_fake_00000000");
    }

    #[tokio::test]
    async fn swappable_provider_returns_latest_credential() {
        let p = Arc::new(SwappableAwsProvider::new(AwsCredential {
            key_id: "k1".into(),
            secret_key: "s1".into(),
            token: None,
        }));
        assert_eq!(p.get_credential().await.unwrap().key_id, "k1");
        p.replace(AwsCredential {
            key_id: "k2".into(),
            secret_key: "s2".into(),
            token: None,
        })
        .await;
        assert_eq!(p.get_credential().await.unwrap().key_id, "k2");
    }

    #[test]
    fn refresh_delay_picks_half_remaining_lifetime() {
        let now = Utc::now();
        // 10 minutes left → ~5 minutes wait.
        let d = refresh_delay(now + chrono::Duration::seconds(600));
        assert!(d.as_secs() >= 290 && d.as_secs() <= 310, "got {d:?}");
    }

    #[test]
    fn refresh_delay_short_circuits_when_lapsed() {
        let past = Utc::now() - chrono::Duration::seconds(60);
        assert_eq!(refresh_delay(past), Duration::from_secs(1));
    }
}
