//! Domain-typed handle over a single volume's `by_id/<vol>/…` objects.
//!
//! Third slice of the domain-typed store layer
//! (`docs/design-domain-store.md`). The `VolumeData` trait is the
//! per-volume handle; it carves the volume's `coord-data` prefix into
//! object-class sub-accessors that callers name explicitly. This PR
//! populates two of the four sub-accessors the design enumerates:
//!
//! * [`HeadView`] — the per-volume HEAD object
//!   (`by_id/<vol>/HEAD`, the post-snapshot delta from
//!   `docs/design-segment-index.md`). Single-writer, no CAS.
//! * [`MetadataView`] — the immutable trust artefacts
//!   `by_id/<vol>/volume.pub` and `by_id/<vol>/volume.provenance`.
//!
//! [`Segments`][1], [`Snapshots`][1], and [`Retention`][1] are listed
//! in the design doc and land in later slices. Until they do, the
//! [`VolumeData::data_store`] escape hatch returns the raw
//! `Arc<dyn ObjectStore>` so callers spanning multiple object classes
//! (`resolve_live_segments`, `prefetch`, the snapshot publish path)
//! can keep working unchanged.
//!
//! Sub-accessors are non-`async` zero-cost views that hold a `&self`
//! reference to the parent handle. The design choice is at the noun,
//! not the verb: a caller publishing a snapshot also writes a HEAD,
//! and we want those to land on one `VolumeData` handle.
//!
//! [1]: crate::stores::ScopedStores::volume_data

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use ulid::Ulid;

use elide_core::signing::VerifyingKey;

use crate::portable::MIME_TEXT;
use crate::segment_head::{self, ParseHeadError, SegmentHead};

/// Per-volume domain handle. Object class sub-accessors are vended
/// from the same handle so callers spanning HEAD + manifests + … only
/// hold one `Arc`.
///
/// Acquired via [`crate::stores::ScopedStores::volume_data`]. Backed
/// by the `coord-data` role for the named volume — every operation
/// the handle vends lands under `by_id/<vol>/`.
#[async_trait]
pub trait VolumeData: Send + Sync {
    /// The volume this handle is scoped to.
    fn vol_ulid(&self) -> Ulid;

    /// Escape hatch for object classes not yet covered by a
    /// sub-accessor (segments, snapshots, retention). Returns the raw
    /// `coord-data`-credentialled store. Removed as the remaining
    /// sub-accessors land (`docs/design-domain-store.md` § *Cascade
    /// containment*).
    fn data_store(&self) -> &Arc<dyn ObjectStore>;

    // ----- HEAD -----

    async fn read_head_inner(&self) -> Result<SegmentHead, HeadError>;
    async fn put_head_inner(&self, head: &SegmentHead) -> Result<(), HeadError>;
    async fn delete_head_inner(&self) -> Result<(), HeadError>;

    // ----- Metadata -----

    async fn read_pubkey_inner(&self) -> Result<VerifyingKey, MetadataError>;
    async fn read_pubkey_optional_inner(&self) -> Result<Option<VerifyingKey>, MetadataError>;
    async fn write_pubkey_bytes_inner(&self, bytes: &[u8]) -> Result<(), MetadataError>;
    async fn write_provenance_bytes_inner(&self, bytes: &[u8]) -> Result<(), MetadataError>;
}

/// Non-async, zero-cost view bundling the HEAD operations. Construct
/// via `vd.head()`.
pub struct HeadView<'a> {
    inner: &'a dyn VolumeData,
}

impl HeadView<'_> {
    /// GET `by_id/<vol>/HEAD`. Returns [`SegmentHead::empty`] when
    /// absent or unparseable — HEAD is derived state that self-heals
    /// on the next active tick.
    pub async fn read(&self) -> Result<SegmentHead, HeadError> {
        self.inner.read_head_inner().await
    }

    /// PUT `by_id/<vol>/HEAD` with the rendered body. Whole-object
    /// overwrite, no CAS — the per-volume tick loop is the sole
    /// writer (`docs/design-segment-index.md`).
    pub async fn put(&self, head: &SegmentHead) -> Result<(), HeadError> {
        self.inner.put_head_inner(head).await
    }

    /// DELETE `by_id/<vol>/HEAD`. Volume teardown only.
    pub async fn delete(&self) -> Result<(), HeadError> {
        self.inner.delete_head_inner().await
    }
}

/// Non-async, zero-cost view bundling the immutable metadata
/// operations (`volume.pub`, `volume.provenance`). Construct via
/// `vd.metadata()`.
pub struct MetadataView<'a> {
    inner: &'a dyn VolumeData,
}

impl MetadataView<'_> {
    /// GET `by_id/<vol>/volume.pub` and parse the hex-encoded body
    /// into an Ed25519 [`VerifyingKey`].
    pub async fn read_pubkey(&self) -> Result<VerifyingKey, MetadataError> {
        self.inner.read_pubkey_inner().await
    }

    /// Like [`Self::read_pubkey`] but returns `Ok(None)` when the
    /// object is absent. Used by `volume release --force` to recover
    /// the create-time window where `names/<name>` was published
    /// before `volume.pub`.
    pub async fn read_pubkey_optional(&self) -> Result<Option<VerifyingKey>, MetadataError> {
        self.inner.read_pubkey_optional_inner().await
    }

    /// PUT `by_id/<vol>/volume.pub` with the given hex-encoded body.
    /// Bytes are passed through verbatim — the on-disk format is
    /// `lowercase-hex(pub_bytes) + "\n"` and this method preserves it.
    pub async fn write_pubkey_bytes(&self, bytes: &[u8]) -> Result<(), MetadataError> {
        self.inner.write_pubkey_bytes_inner(bytes).await
    }

    /// PUT `by_id/<vol>/volume.provenance` with the given body.
    pub async fn write_provenance_bytes(&self, bytes: &[u8]) -> Result<(), MetadataError> {
        self.inner.write_provenance_bytes_inner(bytes).await
    }
}

impl dyn VolumeData + '_ {
    pub fn head(&self) -> HeadView<'_> {
        HeadView { inner: self }
    }
    pub fn metadata(&self) -> MetadataView<'_> {
        MetadataView { inner: self }
    }
}

/// Errors from [`HeadView`] operations.
#[derive(Debug)]
pub enum HeadError {
    Get(object_store::Error),
    Put(object_store::Error),
    Delete(object_store::Error),
    NotUtf8(std::str::Utf8Error),
    Parse(ParseHeadError),
}

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting HEAD: {e}"),
            Self::Put(e) => write!(f, "putting HEAD: {e}"),
            Self::Delete(e) => write!(f, "deleting HEAD: {e}"),
            Self::NotUtf8(e) => write!(f, "HEAD body not utf-8: {e}"),
            Self::Parse(e) => write!(f, "parsing HEAD: {e}"),
        }
    }
}

impl std::error::Error for HeadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) | Self::Delete(e) => Some(e),
            Self::NotUtf8(e) => Some(e),
            Self::Parse(e) => Some(e),
        }
    }
}

/// Errors from [`MetadataView`] operations.
#[derive(Debug)]
pub enum MetadataError {
    Get(object_store::Error),
    Put(object_store::Error),
    /// `volume.pub` body is not valid UTF-8.
    PubkeyNotUtf8(std::str::Utf8Error),
    /// `volume.pub` body did not parse as 64 hex chars + Ed25519 pub.
    InvalidPubkey(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting metadata: {e}"),
            Self::Put(e) => write!(f, "putting metadata: {e}"),
            Self::PubkeyNotUtf8(e) => write!(f, "volume.pub not utf-8: {e}"),
            Self::InvalidPubkey(s) => write!(f, "invalid volume.pub: {s}"),
        }
    }
}

impl std::error::Error for MetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) => Some(e),
            Self::PubkeyNotUtf8(e) => Some(e),
            Self::InvalidPubkey(_) => None,
        }
    }
}

fn pubkey_key(vol: Ulid) -> StorePath {
    StorePath::from(format!("by_id/{vol}/volume.pub"))
}

fn provenance_key(vol: Ulid) -> StorePath {
    StorePath::from(format!(
        "by_id/{vol}/{name}",
        name = elide_core::signing::VOLUME_PROVENANCE_FILE,
    ))
}

fn parse_hex_pubkey(hex: &str) -> Result<VerifyingKey, MetadataError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(MetadataError::InvalidPubkey(format!(
            "expected 64 hex chars for Ed25519 pubkey, got {}",
            hex.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            MetadataError::InvalidPubkey(format!("invalid hex at position {}", i * 2))
        })?;
    }
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| MetadataError::InvalidPubkey(format!("invalid Ed25519 pubkey: {e}")))
}

/// Concrete [`VolumeData`] over a single `coord-data` store handle.
pub struct BucketVolumeData {
    store: Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl BucketVolumeData {
    pub fn new(store: Arc<dyn ObjectStore>, vol_ulid: Ulid) -> Self {
        Self { store, vol_ulid }
    }
}

#[async_trait]
impl VolumeData for BucketVolumeData {
    fn vol_ulid(&self) -> Ulid {
        self.vol_ulid
    }

    fn data_store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    async fn read_head_inner(&self) -> Result<SegmentHead, HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        let bytes = match self.store.get(&key).await {
            Ok(g) => g.bytes().await.map_err(HeadError::Get)?,
            Err(object_store::Error::NotFound { .. }) => return Ok(SegmentHead::empty(None)),
            Err(e) => return Err(HeadError::Get(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(HeadError::NotUtf8)?;
        match segment_head::parse(text) {
            Ok(h) => Ok(h),
            Err(e) => {
                tracing::warn!(
                    "[volume_data] {key} unparseable ({e}); treating as empty (self-heals on next tick)"
                );
                Ok(SegmentHead::empty(None))
            }
        }
    }

    async fn put_head_inner(&self, head: &SegmentHead) -> Result<(), HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        let body = segment_head::render(head);
        crate::upload::put_with_content_type(
            &self.store,
            &key,
            Bytes::from(body.into_bytes()),
            MIME_TEXT,
        )
        .await
        .map_err(HeadError::Put)?;
        Ok(())
    }

    async fn delete_head_inner(&self) -> Result<(), HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        self.store.delete(&key).await.map_err(HeadError::Delete)
    }

    async fn read_pubkey_inner(&self) -> Result<VerifyingKey, MetadataError> {
        let key = pubkey_key(self.vol_ulid);
        let result = self.store.get(&key).await.map_err(MetadataError::Get)?;
        let bytes = result.bytes().await.map_err(MetadataError::Get)?;
        let hex = std::str::from_utf8(&bytes).map_err(MetadataError::PubkeyNotUtf8)?;
        parse_hex_pubkey(hex)
    }

    async fn read_pubkey_optional_inner(&self) -> Result<Option<VerifyingKey>, MetadataError> {
        let key = pubkey_key(self.vol_ulid);
        match self.store.get(&key).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(MetadataError::Get)?;
                let hex = std::str::from_utf8(&bytes).map_err(MetadataError::PubkeyNotUtf8)?;
                parse_hex_pubkey(hex).map(Some)
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(MetadataError::Get(e)),
        }
    }

    async fn write_pubkey_bytes_inner(&self, bytes: &[u8]) -> Result<(), MetadataError> {
        let key = pubkey_key(self.vol_ulid);
        crate::upload::put_with_content_type(
            &self.store,
            &key,
            Bytes::copy_from_slice(bytes),
            MIME_TEXT,
        )
        .await
        .map_err(MetadataError::Put)
    }

    async fn write_provenance_bytes_inner(&self, bytes: &[u8]) -> Result<(), MetadataError> {
        let key = provenance_key(self.vol_ulid);
        crate::upload::put_with_content_type(
            &self.store,
            &key,
            Bytes::copy_from_slice(bytes),
            MIME_TEXT,
        )
        .await
        .map_err(MetadataError::Put)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::ulid_mint::UlidMint;
    use object_store::memory::InMemory;

    fn vd() -> (Arc<dyn ObjectStore>, BucketVolumeData) {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let vol = Ulid::from_string("01J0000000000000000000000V").unwrap();
        (Arc::clone(&store), BucketVolumeData::new(store, vol))
    }

    fn mint() -> UlidMint {
        UlidMint::new(Ulid::nil())
    }

    #[tokio::test]
    async fn head_read_returns_empty_when_absent() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let h = vd.head().read().await.unwrap();
        assert_eq!(h, SegmentHead::empty(None));
    }

    #[tokio::test]
    async fn head_put_then_read_round_trips() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let mut m = mint();
        let mut head = SegmentHead::empty(Some(m.next()));
        head.added.insert(m.next());
        vd.head().put(&head).await.unwrap();
        let got = vd.head().read().await.unwrap();
        assert_eq!(got, head);
    }

    #[tokio::test]
    async fn head_delete_removes_object() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let mut h = SegmentHead::empty(None);
        h.added.insert(mint().next());
        vd.head().put(&h).await.unwrap();
        vd.head().delete().await.unwrap();
        // After delete a read sees the absent → empty path.
        assert_eq!(vd.head().read().await.unwrap(), SegmentHead::empty(None));
    }

    #[tokio::test]
    async fn metadata_pubkey_round_trip() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let (_signer, vk) = elide_core::signing::generate_ephemeral_signer();
        let hex = elide_core::signing::encode_hex(&vk.to_bytes()) + "\n";
        vd.metadata()
            .write_pubkey_bytes(hex.as_bytes())
            .await
            .unwrap();
        let got = vd.metadata().read_pubkey().await.unwrap();
        assert_eq!(got.to_bytes(), vk.to_bytes());
    }

    #[tokio::test]
    async fn metadata_pubkey_optional_absent_is_none() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let got = vd.metadata().read_pubkey_optional().await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn metadata_pubkey_optional_present_is_some() {
        let (_s, vd) = vd();
        let vd: &dyn VolumeData = &vd;
        let (_signer, vk) = elide_core::signing::generate_ephemeral_signer();
        let hex = elide_core::signing::encode_hex(&vk.to_bytes()) + "\n";
        vd.metadata()
            .write_pubkey_bytes(hex.as_bytes())
            .await
            .unwrap();
        let got = vd.metadata().read_pubkey_optional().await.unwrap();
        assert_eq!(got.expect("present").to_bytes(), vk.to_bytes());
    }

    #[tokio::test]
    async fn metadata_provenance_bytes_round_trip_via_store() {
        let (store, vd) = vd();
        let vd_dyn: &dyn VolumeData = &vd;
        let body = b"provenance body";
        vd_dyn
            .metadata()
            .write_provenance_bytes(body)
            .await
            .unwrap();
        let got = store.get(&provenance_key(vd.vol_ulid())).await.unwrap();
        assert_eq!(got.bytes().await.unwrap().as_ref(), body);
    }
}
