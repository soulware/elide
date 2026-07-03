//! The ancestor-liveness tick (`docs/design/ancestor-liveness.md`):
//! one lineage-forest computation per pass, enforced in both
//! directions. **Heal** re-pulls ancestors an anchor's lineage reaches
//! but which are missing from `by_id/`; **sweep** deletes skeletons no
//! anchor reaches.

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};
use ulid::Ulid;

use crate::lineage_forest::{NodeClass, build_forest};
use crate::stores::ScopedStores;
use crate::volume_state::{CLAIMING_FILE, IMPORTING_FILE};

/// What one pass did, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LivenessOutcome {
    /// Anchors whose chains contained missing ancestors and were run
    /// through the prefetch chain walk.
    pub healed_anchors: usize,
    /// Unreferenced skeletons deleted this pass.
    pub swept: usize,
    /// Why the sweep did not run, when it didn't.
    pub sweep_skipped: Option<&'static str>,
}

/// Run one heal + sweep pass over `data_dir`.
///
/// `condemned` is the caller-held set of skeletons found unreferenced
/// on the *previous* clean pass: a skeleton is deleted only when two
/// consecutive clean passes agree it is dead, so a fork or claim that
/// starts referencing it between the forest snapshot and the delete
/// gets a full tick to land its provenance. The set is cleared
/// whenever the sweep is skipped — condemnation must come from
/// consecutive *clean* observations.
///
/// The sweep runs only on a **complete** forest:
///
/// - no in-flight `volume.claiming` / `volume.importing` markers — a
///   mid-claim fork's just-pulled ancestors are referenced by nothing
///   readable yet;
/// - no lineage-walk errors — an anchor whose walk failed contributes
///   nothing to reachability, so "unreferenced" is unreliable;
/// - no live missing ancestors — a lineage walk stops at a missing
///   hop, so skeletons *above* the break look unreferenced until heal
///   re-pulls it.
///
/// Heal has no such gate: re-pulling a reachable ancestor is safe
/// regardless of what else is in flight (`pull_volume_skeleton` is a
/// no-op when the directory appears meanwhile).
pub async fn liveness_pass(
    data_dir: &Path,
    stores: &Arc<dyn ScopedStores>,
    condemned: &mut HashSet<Ulid>,
) -> io::Result<LivenessOutcome> {
    let by_id = data_dir.join("by_id");
    let forest = build_forest(data_dir)?;
    let mut outcome = LivenessOutcome::default();

    // ── Heal ────────────────────────────────────────────────────────
    let missing_live: Vec<Ulid> = forest
        .nodes
        .iter()
        .filter(|n| n.class == NodeClass::Missing && n.live)
        .map(|n| n.ulid)
        .collect();
    let mut heal_anchors: Vec<Ulid> = missing_live
        .iter()
        .flat_map(|m| forest.referencing_anchors(*m))
        .collect();
    heal_anchors.sort_unstable();
    heal_anchors.dedup();
    for anchor in heal_anchors {
        let anchor_dir = by_id.join(anchor.to_string());
        // A claim or import job hydrates its own fork; healing under it
        // would race the job's pulls.
        if anchor_dir.join(CLAIMING_FILE).exists() || anchor_dir.join(IMPORTING_FILE).exists() {
            continue;
        }
        info!("[heal {anchor}] lineage incomplete; re-pulling missing ancestors");
        match crate::prefetch::prefetch_indexes(&anchor_dir, stores, None).await {
            Ok(r) => {
                outcome.healed_anchors += 1;
                info!(
                    "[heal {anchor}] fetched {} index section(s), {} snapshot artifact(s)",
                    r.fetched, r.snapshots_fetched
                );
            }
            Err(e) => warn!("[heal {anchor}] prefetch failed: {e:#}"),
        }
    }

    // ── Sweep ───────────────────────────────────────────────────────
    let in_flight = forest.nodes.iter().any(|n| {
        let dir = by_id.join(n.ulid.to_string());
        dir.join(CLAIMING_FILE).exists() || dir.join(IMPORTING_FILE).exists()
    });
    let sweep_skipped = if in_flight {
        Some("claim or import in flight")
    } else if forest.nodes.iter().any(|n| n.lineage_error.is_some()) {
        Some("a lineage walk failed; reachability incomplete")
    } else if !missing_live.is_empty() {
        Some("missing ancestors pending heal")
    } else {
        None
    };
    if let Some(reason) = sweep_skipped {
        if !condemned.is_empty() {
            info!("[sweep] skipped: {reason}");
        }
        condemned.clear();
        outcome.sweep_skipped = Some(reason);
        return Ok(outcome);
    }

    let dead: HashSet<Ulid> = forest
        .nodes
        .iter()
        .filter(|n| n.class == NodeClass::Skeleton && !n.live)
        .map(|n| n.ulid)
        .collect();
    let mut swept: HashSet<Ulid> = HashSet::new();
    for ulid in dead.intersection(condemned) {
        let dir = by_id.join(ulid.to_string());
        // Final guard against a job that anchored the dir since the
        // forest snapshot.
        if dir.join(elide_core::signing::VOLUME_KEY_FILE).exists()
            || dir.join(CLAIMING_FILE).exists()
            || dir.join(IMPORTING_FILE).exists()
        {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                swept.insert(*ulid);
                info!("[sweep] removed unreferenced skeleton {ulid}");
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!("[sweep] removing {ulid}: {e}"),
        }
    }
    outcome.swept = swept.len();
    *condemned = &dead - &swept;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::signing::{
        ParentRef, ProvenanceLineage, VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE,
        generate_keypair, write_provenance,
    };
    use std::path::PathBuf;

    const A: &str = "01AAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "01BBBBBBBBBBBBBBBBBBBBBBBB";
    const C: &str = "01CCCCCCCCCCCCCCCCCCCCCCCC";
    const SNAP: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn temp_data_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("liveness-test-{}", Ulid::new()));
        std::fs::create_dir_all(dir.join("by_id")).unwrap();
        std::fs::create_dir_all(dir.join("by_name")).unwrap();
        dir
    }

    fn ulid(s: &str) -> Ulid {
        Ulid::from_string(s).unwrap()
    }

    fn mint_volume(data_dir: &Path, ulid_str: &str, lineage: &ProvenanceLineage) -> [u8; 32] {
        let dir = data_dir.join("by_id").join(ulid_str);
        std::fs::create_dir_all(&dir).unwrap();
        let key = generate_keypair(&dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();
        write_provenance(&dir, &key, VOLUME_PROVENANCE_FILE, lineage).unwrap();
        key.verifying_key().to_bytes()
    }

    fn demote(data_dir: &Path, ulid_str: &str) {
        let dir = data_dir.join("by_id").join(ulid_str);
        std::fs::remove_file(dir.join(VOLUME_KEY_FILE)).unwrap();
        std::fs::write(dir.join("volume.readonly"), "").unwrap();
    }

    fn mem_stores() -> Arc<dyn ScopedStores> {
        Arc::new(crate::stores::PassthroughStores::new(Arc::new(
            object_store::memory::InMemory::new(),
        )))
    }

    #[tokio::test]
    async fn sweep_condemns_then_deletes_dead_skeleton() {
        let data_dir = temp_data_dir();
        mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote(&data_dir, A);
        let dead_dir = data_dir.join("by_id").join(A);
        let stores = mem_stores();
        let mut condemned = HashSet::new();

        let first = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(first.swept, 0, "first clean pass only condemns");
        assert!(dead_dir.exists());
        assert!(condemned.contains(&ulid(A)));

        let second = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(second.swept, 1);
        assert!(!dead_dir.exists(), "second clean pass deletes");
        assert!(condemned.is_empty());
    }

    #[tokio::test]
    async fn live_skeleton_is_never_condemned() {
        let data_dir = temp_data_dir();
        let a_pub = mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote(&data_dir, A);
        mint_volume(
            &data_dir,
            B,
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: A.to_owned(),
                snapshot_ulid: SNAP.to_owned(),
                pubkey: a_pub,
            }),
        );
        let stores = mem_stores();
        let mut condemned = HashSet::new();
        for _ in 0..2 {
            liveness_pass(&data_dir, &stores, &mut condemned)
                .await
                .unwrap();
        }
        assert!(data_dir.join("by_id").join(A).exists());
        assert!(condemned.is_empty());
    }

    #[tokio::test]
    async fn sweep_skips_and_resets_condemnation_while_claiming() {
        let data_dir = temp_data_dir();
        mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote(&data_dir, A);
        let stores = mem_stores();
        let mut condemned = HashSet::new();
        liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert!(condemned.contains(&ulid(A)), "condemned on clean pass");

        // A claim starts: its mid-claim fork appears with the marker.
        let claiming = data_dir.join("by_id").join(C);
        std::fs::create_dir_all(&claiming).unwrap();
        std::fs::write(claiming.join(CLAIMING_FILE), "").unwrap();

        let skipped = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(skipped.swept, 0);
        assert_eq!(skipped.sweep_skipped, Some("claim or import in flight"));
        assert!(data_dir.join("by_id").join(A).exists());
        assert!(condemned.is_empty(), "skip resets condemnation");
    }

    #[tokio::test]
    async fn sweep_defers_while_missing_ancestors_pend_heal() {
        // C (anchor) forks from B, which has no directory: heal is
        // attempted (fails against the empty store — fine), and the
        // sweep must not run, because A-above-the-break scenarios make
        // "unreferenced" unreliable while any hop is missing.
        let data_dir = temp_data_dir();
        mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote(&data_dir, A);
        mint_volume(
            &data_dir,
            C,
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: B.to_owned(),
                snapshot_ulid: SNAP.to_owned(),
                pubkey: [0u8; 32],
            }),
        );
        let stores = mem_stores();
        let mut condemned = HashSet::new();
        for _ in 0..2 {
            let outcome = liveness_pass(&data_dir, &stores, &mut condemned)
                .await
                .unwrap();
            assert_eq!(outcome.swept, 0);
            assert_eq!(
                outcome.sweep_skipped,
                Some("missing ancestors pending heal")
            );
        }
        assert!(data_dir.join("by_id").join(A).exists());
    }

    #[tokio::test]
    async fn heal_repulls_missing_ancestor_from_store() {
        use elide_core::segment::{SegmentEntry, SegmentFlags, write_segment};
        use elide_core::signing::{build_snapshot_manifest_bytes, load_signer};
        use object_store::ObjectStore;

        let data_dir = temp_data_dir();
        let by_id = data_dir.join("by_id");

        // Mint the parent in a scratch dir (its by_id/ dir must NOT
        // exist locally — that's the point), publish its meta pub +
        // provenance, one sealed segment, and the snapshot manifest to
        // the store — the shape a drained-and-removed volume leaves.
        let scratch = data_dir.join("scratch-parent");
        std::fs::create_dir_all(&scratch).unwrap();
        let parent_key = generate_keypair(&scratch, VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();
        write_provenance(
            &scratch,
            &parent_key,
            VOLUME_PROVENANCE_FILE,
            &ProvenanceLineage::root(),
        )
        .unwrap();
        let parent_signer = load_signer(&scratch, VOLUME_KEY_FILE).unwrap();

        let seg_ulid = "01AAAAAAAAAAAAAAAAAAAAAAA1";
        let data = vec![0x5Au8; 4096];
        let mut entries = vec![SegmentEntry::new_data(
            blake3::hash(&data),
            0,
            1,
            SegmentFlags::empty(),
            data,
        )];
        let staging = data_dir.join("seg-staging");
        write_segment(&staging, &mut entries, parent_signer.as_ref()).unwrap();

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        store
            .put(
                &object_store::path::Path::from(elide_core::store_keys::meta_pub_key(ulid(A))),
                std::fs::read(scratch.join(VOLUME_PUB_FILE)).unwrap().into(),
            )
            .await
            .unwrap();
        store
            .put(
                &object_store::path::Path::from(elide_core::store_keys::meta_provenance_key(ulid(
                    A,
                ))),
                std::fs::read(scratch.join(VOLUME_PROVENANCE_FILE))
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        store
            .put(
                &crate::upload::segment_key(ulid(A), ulid(seg_ulid)),
                std::fs::read(&staging).unwrap().into(),
            )
            .await
            .unwrap();
        let manifest = build_snapshot_manifest_bytes(parent_signer.as_ref(), &[ulid(seg_ulid)]);
        crate::volume_data::VolumeData::new(Arc::clone(&store), ulid(A))
            .snapshots()
            .put_manifest(ulid(SNAP), manifest.into())
            .await
            .unwrap();

        // The dependent anchor, forked from the vanished parent.
        mint_volume(
            &data_dir,
            B,
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: A.to_owned(),
                snapshot_ulid: SNAP.to_owned(),
                pubkey: parent_key.verifying_key().to_bytes(),
            }),
        );
        assert!(!by_id.join(A).exists());

        let stores: Arc<dyn ScopedStores> = Arc::new(crate::stores::PassthroughStores::new(store));
        let mut condemned = HashSet::new();
        let outcome = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();

        assert_eq!(outcome.healed_anchors, 1);
        let parent_dir = by_id.join(A);
        assert!(parent_dir.exists(), "skeleton re-materialised");
        assert!(parent_dir.join("volume.readonly").exists());
        assert!(parent_dir.join(VOLUME_PUB_FILE).exists());
        assert!(parent_dir.join(VOLUME_PROVENANCE_FILE).exists());
        assert!(
            parent_dir
                .join("index")
                .join(format!("{seg_ulid}.idx"))
                .exists(),
            "index section pulled"
        );
    }
}
