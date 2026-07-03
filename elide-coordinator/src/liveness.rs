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
/// - no heal-pending anchors — a lineage walk stops at a missing or
///   unreadable hop, so skeletons *above* the break look unreferenced
///   until heal re-pulls it.
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
    // Two triggers, unioned. Missing-node reachability covers
    // extent-index sources, which the fork-chain verify doesn't walk;
    // `verify_ancestor_manifests` — the open path's own check — covers
    // present-but-partial ancestors (missing manifest, missing `.idx`
    // section, gutted identity files), so the heal trigger and the
    // open requirement cannot drift.
    let missing_live: Vec<Ulid> = forest
        .nodes
        .iter()
        .filter(|n| n.class == NodeClass::Missing && n.live)
        .map(|n| n.ulid)
        .collect();
    let anchors_with_missing: HashSet<Ulid> = missing_live
        .iter()
        .flat_map(|m| forest.referencing_anchors(*m))
        .collect();
    let mut heal_pending = false;
    for node in forest.nodes.iter().filter(|n| n.class == NodeClass::Anchor) {
        let anchor = node.ulid;
        let anchor_dir = by_id.join(anchor.to_string());
        // A claim or import job hydrates its own fork; healing under it
        // would race the job's pulls.
        if anchor_dir.join(CLAIMING_FILE).exists() || anchor_dir.join(IMPORTING_FILE).exists() {
            continue;
        }
        let reason: Option<String> = if anchors_with_missing.contains(&anchor) {
            Some("missing ancestor directories".to_owned())
        } else {
            elide_core::volume::verify_ancestor_manifests(&anchor_dir, &by_id)
                .err()
                .map(|e| format!("ancestor verify failed: {e}"))
        };
        let Some(reason) = reason else {
            continue;
        };
        heal_pending = true;
        info!("[heal {anchor}] {reason}; re-pulling ancestors");
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
    } else if heal_pending {
        Some("ancestors incomplete; heal pending")
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
                Some("ancestors incomplete; heal pending")
            );
        }
        assert!(data_dir.join("by_id").join(A).exists());
    }

    const SEG: &str = "01AAAAAAAAAAAAAAAAAAAAAAA1";

    /// Stage parent volume `A` fully in the store — meta pub +
    /// provenance, one sealed segment, and the `SNAP` manifest — the
    /// shape a drained-and-removed volume leaves. Signed identity
    /// files land in a scratch dir under `data_dir` (NOT `by_id/A`);
    /// returns the parent's verifying-key bytes for children's
    /// `ParentRef`s and the scratch path for tests that pre-seed a
    /// partial local dir.
    async fn stage_parent_in_store(
        data_dir: &Path,
        store: &Arc<dyn object_store::ObjectStore>,
    ) -> ([u8; 32], PathBuf) {
        use elide_core::segment::{SegmentEntry, SegmentFlags, write_segment};
        use elide_core::signing::{build_snapshot_manifest_bytes, load_signer};

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
                &crate::upload::segment_key(ulid(A), ulid(SEG)),
                std::fs::read(&staging).unwrap().into(),
            )
            .await
            .unwrap();
        let manifest = build_snapshot_manifest_bytes(parent_signer.as_ref(), &[ulid(SEG)]);
        crate::volume_data::VolumeData::new(Arc::clone(store), ulid(A))
            .snapshots()
            .put_manifest(ulid(SNAP), manifest.into())
            .await
            .unwrap();

        (parent_key.verifying_key().to_bytes(), scratch)
    }

    /// The dependent anchor `B`, forked from parent `A` at `SNAP`.
    fn mint_dependent(data_dir: &Path, parent_pub: [u8; 32]) {
        mint_volume(
            data_dir,
            B,
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: A.to_owned(),
                snapshot_ulid: SNAP.to_owned(),
                pubkey: parent_pub,
            }),
        );
    }

    #[tokio::test]
    async fn heal_repulls_missing_ancestor_from_store() {
        use object_store::ObjectStore;
        let data_dir = temp_data_dir();
        let by_id = data_dir.join("by_id");
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let (parent_pub, _scratch) = stage_parent_in_store(&data_dir, &store).await;
        mint_dependent(&data_dir, parent_pub);
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
        let seg_ulid = SEG;
        assert!(
            parent_dir
                .join("index")
                .join(format!("{seg_ulid}.idx"))
                .exists(),
            "index section pulled"
        );
    }

    #[tokio::test]
    async fn heal_completes_partial_skeleton_missing_manifest() {
        // Parent dir present with valid identity files but no
        // manifest and no .idx — the shape that used to pass the
        // missing-dir trigger and still fail at open. The verify
        // trigger catches it; the next pass is clean.
        use object_store::ObjectStore;
        let data_dir = temp_data_dir();
        let by_id = data_dir.join("by_id");
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let (parent_pub, scratch) = stage_parent_in_store(&data_dir, &store).await;
        mint_dependent(&data_dir, parent_pub);

        let parent_dir = by_id.join(A);
        std::fs::create_dir_all(&parent_dir).unwrap();
        std::fs::write(parent_dir.join("volume.readonly"), "").unwrap();
        std::fs::copy(
            scratch.join(VOLUME_PUB_FILE),
            parent_dir.join(VOLUME_PUB_FILE),
        )
        .unwrap();
        std::fs::copy(
            scratch.join(VOLUME_PROVENANCE_FILE),
            parent_dir.join(VOLUME_PROVENANCE_FILE),
        )
        .unwrap();

        let stores: Arc<dyn ScopedStores> = Arc::new(crate::stores::PassthroughStores::new(store));
        let mut condemned = HashSet::new();
        let outcome = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(outcome.healed_anchors, 1);
        assert_eq!(
            outcome.sweep_skipped,
            Some("ancestors incomplete; heal pending")
        );
        let seg_ulid = SEG;
        assert!(
            parent_dir
                .join("index")
                .join(format!("{seg_ulid}.idx"))
                .exists(),
            "missing index section fetched"
        );

        let clean = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(clean.healed_anchors, 0, "verify passes after heal");
        assert_eq!(clean.sweep_skipped, None);
    }

    #[tokio::test]
    async fn heal_repairs_gutted_skeleton_dir() {
        // A pull that crashed right after the marker write leaves a
        // dir with only volume.readonly — present, so the old
        // missing-dir trigger never fired, and the old
        // pull_volume_skeleton early-return made it unrepairable.
        use object_store::ObjectStore;
        let data_dir = temp_data_dir();
        let by_id = data_dir.join("by_id");
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let (parent_pub, _scratch) = stage_parent_in_store(&data_dir, &store).await;
        mint_dependent(&data_dir, parent_pub);

        let parent_dir = by_id.join(A);
        std::fs::create_dir_all(&parent_dir).unwrap();
        std::fs::write(parent_dir.join("volume.readonly"), "").unwrap();

        let stores: Arc<dyn ScopedStores> = Arc::new(crate::stores::PassthroughStores::new(store));
        let mut condemned = HashSet::new();
        let outcome = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(outcome.healed_anchors, 1);
        assert!(parent_dir.join(VOLUME_PUB_FILE).exists());
        assert!(parent_dir.join(VOLUME_PROVENANCE_FILE).exists());
        let seg_ulid = SEG;
        assert!(
            parent_dir
                .join("index")
                .join(format!("{seg_ulid}.idx"))
                .exists()
        );
    }

    #[tokio::test]
    async fn heal_never_overwrites_a_keyed_dir() {
        // The parent dir holds a volume.key (a writable fork in some
        // broken intermediate state) — pull must not stomp its
        // identity files, and the sweep stays gated on the unhealable
        // anchor.
        use object_store::ObjectStore;
        let data_dir = temp_data_dir();
        let by_id = data_dir.join("by_id");
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let (parent_pub, _scratch) = stage_parent_in_store(&data_dir, &store).await;
        mint_dependent(&data_dir, parent_pub);

        let parent_dir = by_id.join(A);
        std::fs::create_dir_all(&parent_dir).unwrap();
        std::fs::write(parent_dir.join(VOLUME_KEY_FILE), "local key material").unwrap();

        let stores: Arc<dyn ScopedStores> = Arc::new(crate::stores::PassthroughStores::new(store));
        let mut condemned = HashSet::new();
        let outcome = liveness_pass(&data_dir, &stores, &mut condemned)
            .await
            .unwrap();
        assert_eq!(outcome.healed_anchors, 0, "prefetch fails, never repairs");
        assert_eq!(
            outcome.sweep_skipped,
            Some("ancestors incomplete; heal pending")
        );
        assert!(
            !parent_dir.join(VOLUME_PUB_FILE).exists(),
            "keyed dir untouched"
        );
        assert_eq!(
            std::fs::read_to_string(parent_dir.join(VOLUME_KEY_FILE)).unwrap(),
            "local key material"
        );
    }
}
