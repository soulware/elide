//! ObjectStore-backed ancestry walkers.
//!
//! Two consumers, one shared per-step verify and one shared driver:
//!
//! - [`walk_ancestry`] — the peer-fetch auth pipeline. Fork-parent chain
//!   only, read from the peer's *own local* `by_id/<vol>/volume.
//!   {provenance,pub}` (a `LocalFileSystem` rooted at the coordinator's
//!   `data_dir` — no S3 read, no credential; see
//!   docs/design-peer-segment-fetch.md § Peer verification, check 4). A
//!   fork the peer does not serve has no local provenance: the walk
//!   returns `NotFound` and the caller fails closed (declines; the
//!   requester falls back to S3). `extent_index` sources are *excluded* —
//!   peer-fetch authorisation matches what the S3 IAM layer enforces (the
//!   volume's own prefix and its fork-parent prefixes), a dedup-source
//!   relationship is not a "may read those segments" relationship.
//!
//! - [`walk_lineage_set`] — coord B's volume-attestation discharge
//!   (docs/design-mint-volume-attestation.md). Fork-parent chain **plus**
//!   every `extent_index` source named along it, read from the canonical
//!   signed `meta/<ulid>.{provenance,pub}` over coord-ro S3. This is the
//!   exact set whose `by_id/<ulid>/` prefixes a reader operating as the
//!   owned volume may visit (dedup canonicals and delta bases live in
//!   extent sources), so it equals `elide_core::volume::lineage_ulids`
//!   plus the owned volume itself.
//!
//! Trust shape (both walks):
//!
//! - The starting volume's `volume.provenance` is verified against its
//!   trust-anchor pubkey: for [`walk_ancestry`] the `volume.pub` in its
//!   own prefix; for [`walk_lineage_set`] the key the caller supplies —
//!   coord B passes the key it already verified the possession proof
//!   against, so the walk is anchored at the same identity it attested.
//! - Each ancestor step is verified against the `parent_pubkey` embedded
//!   in the *child's* signed provenance — never against whatever
//!   `volume.pub` sits in the ancestor's prefix. This is the same trust
//!   anchoring used at volume open time.

use std::collections::HashSet;
use std::io;

use ed25519_dalek::VerifyingKey;
use elide_core::signing::{VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE, verify_lineage_with_key};
use elide_core::store_keys::{meta_provenance_key, meta_pub_key};
use object_store::Error as ObjectStoreError;
use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use ulid::Ulid;

/// Where a walk reads `volume.{provenance,pub}` from. `ById` is the peer's
/// local copies under `by_id/<ulid>/`; `Meta` is the canonical signed copy
/// at the flat `meta/<ulid>.{provenance,pub}` keys that coord-ro grants.
#[derive(Clone, Copy)]
enum Layout {
    ById,
    Meta,
}

impl Layout {
    fn pub_key(self, vol: &Ulid) -> StorePath {
        match self {
            Layout::ById => StorePath::from(format!("by_id/{vol}/{VOLUME_PUB_FILE}")),
            Layout::Meta => StorePath::from(meta_pub_key(*vol)),
        }
    }

    fn provenance_key(self, vol: &Ulid) -> StorePath {
        match self {
            Layout::ById => StorePath::from(format!("by_id/{vol}/{VOLUME_PROVENANCE_FILE}")),
            Layout::Meta => StorePath::from(meta_provenance_key(*vol)),
        }
    }
}

/// Walk the fork-parent ancestry of `starting_vol_ulid` against the peer's
/// local `by_id/` copies. Returns the set of fork ULIDs in the ancestry,
/// including `starting_vol_ulid` itself. Fork-only; see module docs.
///
/// Each step is signature-verified — failures bubble up as `io::Error`, so
/// callers can map them to 401/403 responses.
pub async fn walk_ancestry(
    store: &dyn ObjectStore,
    starting_vol_ulid: Ulid,
) -> io::Result<HashSet<Ulid>> {
    // Trust anchor for the starting volume: its own local `volume.pub`.
    let start_vk = load_volume_pub(store, &starting_vol_ulid, Layout::ById).await?;
    walk(store, starting_vol_ulid, start_vk, Layout::ById, false).await
}

/// Walk the fork-parent chain of `owned` over coord-ro `meta/*`, unioning
/// every `extent_index` source named along it, anchored at `owned_vk` (the
/// key coord B verified the possession proof against). Returns the full set
/// of volume ULIDs whose `by_id/` prefixes a reader operating as `owned`
/// may visit, including `owned` itself. See module docs.
pub async fn walk_lineage_set(
    store: &dyn ObjectStore,
    owned: Ulid,
    owned_vk: VerifyingKey,
) -> io::Result<HashSet<Ulid>> {
    walk(store, owned, owned_vk, Layout::Meta, true).await
}

/// Shared driver. Follows the fork-parent chain from `start` (anchored at
/// `start_vk`, then each child-committed parent pubkey), inserting every
/// fork ULID. When `include_extents`, also inserts each `extent_index`
/// source named in the provenance at every step — those sources are leaves
/// (the `extent_index` is already flat at attach time, so their own lineage
/// is not expanded).
async fn walk(
    store: &dyn ObjectStore,
    start: Ulid,
    start_vk: VerifyingKey,
    layout: Layout,
    include_extents: bool,
) -> io::Result<HashSet<Ulid>> {
    let mut set = HashSet::new();
    set.insert(start);

    let mut current_ulid = start;
    let mut current_vk = start_vk;

    loop {
        let lineage = load_provenance(store, &current_ulid, &current_vk, layout).await?;

        if include_extents {
            for entry in &lineage.extent_index {
                let (source, _snapshot) =
                    elide_core::volume::parse_lineage_pair(entry).map_err(|e| {
                        io::Error::other(format!(
                            "provenance for {current_ulid}: bad extent_index entry: {e}"
                        ))
                    })?;
                set.insert(source);
            }
        }

        let Some(parent) = lineage.parent else {
            break;
        };

        let parent_ulid = Ulid::from_string(&parent.volume_ulid).map_err(|e| {
            io::Error::other(format!(
                "provenance for {current_ulid}: parent ulid not parseable: {e}"
            ))
        })?;

        // The child's provenance commits the parent's pubkey; that's the
        // trust anchor for the parent's own provenance, not whatever
        // `volume.pub` happens to sit in the parent's prefix.
        let parent_vk = VerifyingKey::from_bytes(&parent.pubkey).map_err(|e| {
            io::Error::other(format!(
                "provenance for {current_ulid}: parent pubkey invalid: {e}"
            ))
        })?;

        if !set.insert(parent_ulid) {
            // Cycle in the parent chain — provenance is supposed to be a
            // DAG rooted at a fresh volume. Treat as data corruption.
            return Err(io::Error::other(format!(
                "ancestry cycle detected at {parent_ulid}"
            )));
        }

        current_ulid = parent_ulid;
        current_vk = parent_vk;
    }

    Ok(set)
}

async fn load_volume_pub(
    store: &dyn ObjectStore,
    vol_ulid: &Ulid,
    layout: Layout,
) -> io::Result<VerifyingKey> {
    let key = layout.pub_key(vol_ulid);
    let body = store
        .get(&key)
        .await
        .map_err(|e| not_found_or_other(e, format!("fetch {VOLUME_PUB_FILE} for {vol_ulid}")))?
        .bytes()
        .await
        .map_err(|e| {
            io::Error::other(format!("read {VOLUME_PUB_FILE} body for {vol_ulid}: {e}"))
        })?;
    let text = std::str::from_utf8(&body).map_err(|e| {
        io::Error::other(format!("{VOLUME_PUB_FILE} for {vol_ulid} not utf-8: {e}"))
    })?;
    parse_pub_hex(text.trim())
        .map_err(|e| io::Error::other(format!("{VOLUME_PUB_FILE} for {vol_ulid} invalid: {e}")))
}

fn parse_pub_hex(s: &str) -> Result<VerifyingKey, String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid ed25519 pubkey: {e}"))
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex byte: 0x{b:02x}")),
    }
}

/// Preserve `NotFound` through the `io::Error` boundary so the auth
/// caller can fail closed (decline → 403) for a fork the peer doesn't
/// serve, rather than treating an absent local chain as a 5xx fault.
fn not_found_or_other(e: ObjectStoreError, context: String) -> io::Error {
    match e {
        ObjectStoreError::NotFound { .. } => io::Error::new(
            io::ErrorKind::NotFound,
            format!("{context}: not served locally"),
        ),
        other => io::Error::other(format!("{context}: {other}")),
    }
}

async fn load_provenance(
    store: &dyn ObjectStore,
    vol_ulid: &Ulid,
    verifying_key: &VerifyingKey,
    layout: Layout,
) -> io::Result<elide_core::signing::ProvenanceLineage> {
    let key = layout.provenance_key(vol_ulid);
    let body = store
        .get(&key)
        .await
        .map_err(|e| {
            not_found_or_other(e, format!("fetch {VOLUME_PROVENANCE_FILE} for {vol_ulid}"))
        })?
        .bytes()
        .await
        .map_err(|e| {
            io::Error::other(format!(
                "read {VOLUME_PROVENANCE_FILE} body for {vol_ulid}: {e}"
            ))
        })?;
    let text = std::str::from_utf8(&body).map_err(|e| {
        io::Error::other(format!(
            "{VOLUME_PROVENANCE_FILE} for {vol_ulid} not utf-8: {e}"
        ))
    })?;
    verify_lineage_with_key(text, verifying_key, VOLUME_PROVENANCE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use elide_core::signing::{ParentRef, ProvenanceLineage, write_provenance};
    use object_store::memory::InMemory;
    use rand_core::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn store() -> Arc<dyn ObjectStore> {
        Arc::new(InMemory::new())
    }

    fn pub_hex(key: &SigningKey) -> String {
        let bytes = key.verifying_key().to_bytes();
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('\n');
        s
    }

    /// Mint a `volume.provenance` for a synthetic volume and publish it
    /// (plus `volume.pub`) under `by_id/<ulid>/` on the given store.
    async fn publish_volume(
        store: &dyn ObjectStore,
        ulid: Ulid,
        key: &SigningKey,
        parent: Option<ParentRef>,
    ) {
        // Use elide-core's signer by writing to a tempdir then reading
        // back — keeps the on-disk format identical without re-implementing
        // the writer.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(VOLUME_PUB_FILE), pub_hex(key)).unwrap();
        let lineage = ProvenanceLineage {
            parent,
            extent_index: Vec::new(),
            oci_source: None,
        };
        write_provenance(tmp.path(), key, VOLUME_PROVENANCE_FILE, &lineage).unwrap();

        let pub_bytes = std::fs::read(tmp.path().join(VOLUME_PUB_FILE)).unwrap();
        let prov_bytes = std::fs::read(tmp.path().join(VOLUME_PROVENANCE_FILE)).unwrap();

        store
            .put(
                &StorePath::from(format!("by_id/{ulid}/{VOLUME_PUB_FILE}")),
                Bytes::from(pub_bytes).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(format!("by_id/{ulid}/{VOLUME_PROVENANCE_FILE}")),
                Bytes::from(prov_bytes).into(),
            )
            .await
            .unwrap();
    }

    /// Write `volume.{provenance,pub}` for `ulid` both to a local
    /// `by_id/<ulid>/` dir (what the sync read-path walk reads) and to
    /// `meta/<ulid>.{provenance,pub}` on the store (what coord B reads),
    /// from one key — so the two walks see byte-identical lineage.
    async fn publish_both(
        by_id: &std::path::Path,
        store: &dyn ObjectStore,
        ulid: Ulid,
        key: &SigningKey,
        parent: Option<ParentRef>,
        extent_index: Vec<String>,
    ) {
        let dir = by_id.join(ulid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VOLUME_PUB_FILE), pub_hex(key)).unwrap();
        let lineage = ProvenanceLineage {
            parent,
            extent_index,
            oci_source: None,
        };
        write_provenance(&dir, key, VOLUME_PROVENANCE_FILE, &lineage).unwrap();

        let prov = std::fs::read(dir.join(VOLUME_PROVENANCE_FILE)).unwrap();
        let pubb = std::fs::read(dir.join(VOLUME_PUB_FILE)).unwrap();
        store
            .put(
                &StorePath::from(meta_provenance_key(ulid)),
                Bytes::from(prov).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(meta_pub_key(ulid)),
                Bytes::from(pubb).into(),
            )
            .await
            .unwrap();
    }

    /// The load-bearing "vouchable ≡ readable" pin: coord B's signed-lineage
    /// walk over `meta/*` returns exactly the read path's
    /// `lineage_ulids` (fork chain ∪ extent sources) plus the owned volume
    /// itself. If a future change makes coord B vouch for more or less than
    /// a reader can reach, this fails.
    #[tokio::test]
    async fn walk_lineage_set_equals_read_path_plus_owned() {
        let by_id = TempDir::new().unwrap();
        let store = store();

        let owned_key = SigningKey::generate(&mut OsRng);
        let parent_key = SigningKey::generate(&mut OsRng);
        let owned = Ulid::new();
        let parent = Ulid::new();
        let extent = Ulid::new();

        publish_both(
            by_id.path(),
            store.as_ref(),
            owned,
            &owned_key,
            Some(ParentRef {
                volume_ulid: parent.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: parent_key.verifying_key().to_bytes(),
                manifest_pubkey: None,
            }),
            vec![format!("{extent}/{}", Ulid::new())],
        )
        .await;
        publish_both(
            by_id.path(),
            store.as_ref(),
            parent,
            &parent_key,
            None,
            Vec::new(),
        )
        .await;

        let owned_dir = by_id.path().join(owned.to_string());
        let mut expected: HashSet<Ulid> =
            elide_core::volume::lineage_ulids(&owned_dir, by_id.path())
                .unwrap()
                .into_iter()
                .collect();
        expected.insert(owned);

        let got = walk_lineage_set(store.as_ref(), owned, owned_key.verifying_key())
            .await
            .unwrap();
        assert_eq!(got, expected, "coord B must vouch exactly the read set");
    }

    #[tokio::test]
    async fn root_volume_returns_singleton() {
        let store = store();
        let key = SigningKey::generate(&mut OsRng);
        let ulid = Ulid::new();
        publish_volume(store.as_ref(), ulid, &key, None).await;

        let set = walk_ancestry(store.as_ref(), ulid).await.unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ulid));
    }

    #[tokio::test]
    async fn fork_chain_walks_to_root() {
        let store = store();
        let root_key = SigningKey::generate(&mut OsRng);
        let mid_key = SigningKey::generate(&mut OsRng);
        let leaf_key = SigningKey::generate(&mut OsRng);

        let root_ulid = Ulid::new();
        let mid_ulid = Ulid::new();
        let leaf_ulid = Ulid::new();

        publish_volume(store.as_ref(), root_ulid, &root_key, None).await;
        publish_volume(
            store.as_ref(),
            mid_ulid,
            &mid_key,
            Some(ParentRef {
                volume_ulid: root_ulid.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: root_key.verifying_key().to_bytes(),
                manifest_pubkey: None,
            }),
        )
        .await;
        publish_volume(
            store.as_ref(),
            leaf_ulid,
            &leaf_key,
            Some(ParentRef {
                volume_ulid: mid_ulid.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: mid_key.verifying_key().to_bytes(),
                manifest_pubkey: None,
            }),
        )
        .await;

        let set = walk_ancestry(store.as_ref(), leaf_ulid).await.unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&leaf_ulid));
        assert!(set.contains(&mid_ulid));
        assert!(set.contains(&root_ulid));
    }

    #[tokio::test]
    async fn missing_provenance_is_error() {
        let store = store();
        let ulid = Ulid::new();
        let err = walk_ancestry(store.as_ref(), ulid)
            .await
            .expect_err("absent");
        let msg = err.to_string();
        assert!(
            msg.contains("volume.pub") || msg.contains("not found"),
            "msg={msg}"
        );
    }

    #[tokio::test]
    async fn tampered_pubkey_in_provenance_fails_at_parent_step() {
        // Child's provenance commits a pubkey that doesn't match the parent's
        // actual signing key — the parent step's verification fails.
        let store = store();
        let root_key = SigningKey::generate(&mut OsRng);
        let leaf_key = SigningKey::generate(&mut OsRng);
        let imposter = SigningKey::generate(&mut OsRng);

        let root_ulid = Ulid::new();
        let leaf_ulid = Ulid::new();

        publish_volume(store.as_ref(), root_ulid, &root_key, None).await;
        // Leaf claims `imposter` as the parent's pubkey, but the published
        // provenance for `root_ulid` is signed by `root_key`. The walk
        // verifies parent provenance against the embedded pubkey, so this
        // mismatch is caught at the parent step.
        publish_volume(
            store.as_ref(),
            leaf_ulid,
            &leaf_key,
            Some(ParentRef {
                volume_ulid: root_ulid.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: imposter.verifying_key().to_bytes(),
                manifest_pubkey: None,
            }),
        )
        .await;

        let err = walk_ancestry(store.as_ref(), leaf_ulid)
            .await
            .expect_err("imposter pubkey");
        assert!(err.to_string().contains("signature invalid"), "got {err}");
    }
}
