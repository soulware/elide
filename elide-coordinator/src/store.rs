// Store configuration and construction.
//
// Config is read from environment variables:
//   ELIDE_S3_BUCKET          — required; bucket to store segments in
//   AWS_ENDPOINT_URL         — optional; custom endpoint for MinIO/Tigris/etc.
//   AWS_ACCESS_KEY_ID        — standard AWS credential env var
//   AWS_SECRET_ACCESS_KEY    — standard AWS credential env var
//
// When AWS_ENDPOINT_URL is set, path-style requests are used (MinIO default).
// For Tigris (virtual-hosted-style), leave AWS_ENDPOINT_URL unset and configure
// the endpoint via AmazonS3Builder directly.

use anyhow::{Context, Result};
use object_store::ObjectStore;
use object_store::aws::AmazonS3Builder;
use std::sync::Arc;

pub struct StoreConfig {
    pub bucket: String,
    pub endpoint: Option<String>,
}

impl StoreConfig {
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("ELIDE_S3_BUCKET").context("ELIDE_S3_BUCKET not set")?;
        let endpoint = std::env::var("AWS_ENDPOINT_URL").ok();
        Ok(Self { bucket, endpoint })
    }

    pub fn build(&self) -> Result<Arc<dyn ObjectStore>> {
        let mut builder = AmazonS3Builder::from_env().with_bucket_name(&self.bucket);
        if let Some(endpoint) = &self.endpoint {
            // Path-style for custom endpoints (MinIO). Tigris requires virtual-hosted-style
            // and should not set AWS_ENDPOINT_URL — use the default S3 endpoint instead.
            builder = builder
                .with_endpoint(endpoint)
                .with_virtual_hosted_style_request(false);
        }
        Ok(Arc::new(builder.build().context("building S3 client")?))
    }
}
