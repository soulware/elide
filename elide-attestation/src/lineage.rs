//! coord B's signed-lineage walk over coord-ro `meta/*`.
//!
//! Given the `owned` volume and the verifying key coord B already
//! validated the possession proof against, [`walk_lineage_set`] returns
//! the full set of volume ULIDs whose `by_id/<ulid>/` prefixes a reader
//! operating as `owned` may visit: the fork-parent chain **plus** every
//! `extent_index` source named along it (dedup canonicals and delta bases
//! live in extent sources). That is exactly the read set the local read
//! path computes via `elide_core::volume::lineage_ulids`, plus `owned`
//! itself — pinned by the equivalence test below.
//!
//! The trust-critical per-link step — parse a `volume.provenance`, verify
//! it under the pubkey the *child* committed, extract `parent` /
//! `extent_index` — is single-sourced in `elide-core`
//! (`verify_lineage_with_key` + `parse_lineage_pair`). This module is the
//! async driver over `meta/<ulid>.provenance`; the peer-fetch auth walk
//! (`elide-peer-fetch`) is the sibling fork-only driver over `by_id/`.

use std::collections::HashSet;
use std::io;

use ed25519_dalek::VerifyingKey;
use elide_core::signing::{VOLUME_PROVENANCE_FILE, verify_lineage_with_key};
use elide_core::store_keys::meta_provenance_key;
use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use ulid::Ulid;

/// Walk the fork-parent chain of `owned` over `meta/*`, unioning every
/// `extent_index` source named along it. Anchored at `owned_vk` (the key
/// coord B verified the possession proof against), then each
/// child-committed parent pubkey. Returns the read set including `owned`.
///
/// Each step is signature-verified; failures bubble up as `io::Error`.
/// `extent_index` sources are leaves — the list is already flat at attach
/// time, so their own lineage is not expanded.
pub async fn walk_lineage_set(
    store: &dyn ObjectStore,
    owned: Ulid,
    owned_vk: VerifyingKey,
) -> io::Result<HashSet<Ulid>> {
    let mut set = HashSet::new();
    set.insert(owned);

    let mut current_ulid = owned;
    let mut current_vk = owned_vk;

    loop {
        let lineage = load_provenance(store, &current_ulid, &current_vk).await?;

        for entry in &lineage.extent_index {
            let (source, _snapshot) =
                elide_core::volume::parse_lineage_pair(entry).map_err(|e| {
                    io::Error::other(format!(
                        "provenance for {current_ulid}: bad extent_index entry: {e}"
                    ))
                })?;
            set.insert(source);
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
            // Cycle in the parent chain — provenance is a DAG rooted at a
            // fresh volume. Treat as data corruption.
            return Err(io::Error::other(format!(
                "ancestry cycle detected at {parent_ulid}"
            )));
        }

        current_ulid = parent_ulid;
        current_vk = parent_vk;
    }

    Ok(set)
}

async fn load_provenance(
    store: &dyn ObjectStore,
    vol_ulid: &Ulid,
    verifying_key: &VerifyingKey,
) -> io::Result<elide_core::signing::ProvenanceLineage> {
    let key = StorePath::from(meta_provenance_key(*vol_ulid));
    let body = store
        .get(&key)
        .await
        .map_err(|e| match e {
            object_store::Error::NotFound { .. } => io::Error::new(
                io::ErrorKind::NotFound,
                format!("{VOLUME_PROVENANCE_FILE} for {vol_ulid} not published"),
            ),
            other => io::Error::other(format!(
                "fetch {VOLUME_PROVENANCE_FILE} for {vol_ulid}: {other}"
            )),
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
    use elide_core::signing::{ParentRef, ProvenanceLineage, VOLUME_PUB_FILE, write_provenance};
    use elide_core::store_keys::meta_pub_key;
    use object_store::memory::InMemory;
    use rand_core::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn pub_hex(key: &SigningKey) -> String {
        let mut s = String::with_capacity(64);
        for b in key.verifying_key().to_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('\n');
        s
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
    /// walk over `meta/*` returns exactly the read path's `lineage_ulids`
    /// (fork chain ∪ extent sources) plus the owned volume itself. If a
    /// future change makes coord B vouch for more or less than a reader can
    /// reach, this fails.
    #[tokio::test]
    async fn walk_lineage_set_equals_read_path_plus_owned() {
        let by_id = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

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
    async fn tampered_parent_pubkey_fails_at_parent_step() {
        let by_id = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let owned_key = SigningKey::generate(&mut OsRng);
        let parent_key = SigningKey::generate(&mut OsRng);
        let imposter = SigningKey::generate(&mut OsRng);
        let owned = Ulid::new();
        let parent = Ulid::new();

        // owned commits `imposter` as the parent pubkey, but parent's
        // published provenance is signed by `parent_key` → caught at the
        // parent step.
        publish_both(
            by_id.path(),
            store.as_ref(),
            owned,
            &owned_key,
            Some(ParentRef {
                volume_ulid: parent.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: imposter.verifying_key().to_bytes(),
            }),
            Vec::new(),
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

        let err = walk_lineage_set(store.as_ref(), owned, owned_key.verifying_key())
            .await
            .expect_err("imposter parent pubkey");
        assert!(err.to_string().contains("signature invalid"), "got {err}");
    }
}
