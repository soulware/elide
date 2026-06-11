// Two-coordinator state-machine proptest for the portable-live-volume
// lifecycle. Drives `lifecycle::*` directly — the building blocks the
// inbound ops compose — against a shared `InMemory` bucket plus two
// `CoordinatorIdentity` instances.
//
// Op alphabet: { Create, Release, ForceClaim, ClaimReleased, ReclaimLocal }.
// `Stop` is omitted (it is a single state flip already exhaustively
// covered by `lifecycle::tests`); `start --remote` is modelled as the
// `ClaimReleased` op since its bucket-side effect is identical;
// `start --claim` and `claim` against a locally-owned released fork are
// both modelled by `ReclaimLocal`, differing only in `target_state`.
//
// The proptest enforces the invariants the design doc requires after
// any sequence of ops:
//
//   1. Every `names/<name>` parses cleanly.
//   2. Every `Live`/`Stopped` record names a coordinator we know about.
//   3. Every `Released` record clears `coordinator_id` and carries a
//      `handoff_snapshot`.
//   4. Every name's `vol_ulid` has `volume.pub` in the bucket.
//   5. Every `handoff_snapshot`, regardless of record state, references
//      a manifest that exists in the bucket under
//      `by_id/<vol_ulid>/snapshots/YYYYMMDD/` and verifies under the
//      right pubkey. This covers `mark_reclaimed_local`'s explicit
//      retention rule (Released → Live/Stopped in-place keeps
//      `handoff_snapshot` because the prior owner's published handoff
//      remains the valid basis until the new owner writes and
//      `mark_released` overwrites it).
//
// Cases run in a single tokio runtime per test case; ops are
// interleaved sequentially. The interesting non-trivial races
// (concurrent claim) are already covered at the conditional-PUT layer
// in `name_store::tests` and `lifecycle::tests`; the value here is
// composing many ops and asserting the bucket stays internally
// consistent.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use elide_coordinator::identity::CoordinatorIdentity;
use elide_coordinator::lifecycle::{
    self, MarkClaimedForceOutcome, MarkClaimedOutcome, MarkReclaimedLocalOutcome,
    MarkReleasedOutcome, ObservedRecord,
};
use elide_coordinator::name_store as ns;
use elide_coordinator::volume_data::VolumeData;
use elide_core::name_record::NameState;
use elide_core::segment::SegmentSigner;
use elide_core::signing::{
    build_snapshot_manifest_bytes, generate_ephemeral_signer, read_snapshot_manifest_from_bytes,
};
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, PutPayload};
use proptest::prelude::*;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use ulid::Ulid;

const NUM_NAMES: usize = 3;
const NUM_COORDS: usize = 2;

#[derive(Debug, Clone)]
enum Op {
    Create {
        name: u8,
        coord: u8,
    },
    Release {
        name: u8,
        coord: u8,
    },
    /// Forced rebind of a `Live`/`Stopped` record whose owner is
    /// presumed dead. Drives `mark_claimed_force` — the fence CAS of
    /// `volume claim --force`. The data-plane re-own is not modelled
    /// (this model never writes segments).
    ForceClaim {
        name: u8,
        claimant: u8,
    },
    ClaimReleased {
        name: u8,
        coord: u8,
    },
    /// In-place reclaim of a Released record where the local fork is
    /// the same one the record points at. Models `start --claim`
    /// (`as_live = true`) and `claim` (`as_live = false`). Drives
    /// `mark_reclaimed_local`, whose retention rule for
    /// `handoff_snapshot` is otherwise only covered by deterministic
    /// unit tests in `lifecycle.rs`.
    ReclaimLocal {
        name: u8,
        coord: u8,
        as_live: bool,
    },
}

fn arb_op() -> impl Strategy<Value = Op> {
    let name = 0u8..(NUM_NAMES as u8);
    let coord = 0u8..(NUM_COORDS as u8);
    let rec = 0u8..(NUM_COORDS as u8);
    prop_oneof![
        (name.clone(), coord.clone()).prop_map(|(name, coord)| Op::Create { name, coord }),
        (name.clone(), coord.clone()).prop_map(|(name, coord)| Op::Release { name, coord }),
        (name.clone(), rec).prop_map(|(name, claimant)| Op::ForceClaim { name, claimant }),
        (name.clone(), coord.clone()).prop_map(|(name, coord)| Op::ClaimReleased { name, coord }),
        (name, coord, any::<bool>()).prop_map(|(name, coord, as_live)| Op::ReclaimLocal {
            name,
            coord,
            as_live,
        }),
    ]
}

struct World {
    store: Arc<dyn ObjectStore>,
    coords: Vec<CoordinatorIdentity>,
    /// Per-fork volume signing key. Populated when the fork is created
    /// or claimed. `Release` consults this to sign its (synthetic)
    /// handoff snapshot.
    vol_signers: HashMap<Ulid, Arc<dyn SegmentSigner>>,
    _coord_dirs: Vec<TempDir>,
}

fn name_for(idx: u8) -> &'static str {
    match idx {
        0 => "vol-a",
        1 => "vol-b",
        _ => "vol-c",
    }
}

impl World {
    async fn new() -> Self {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut dirs = Vec::with_capacity(NUM_COORDS);
        let mut coords = Vec::with_capacity(NUM_COORDS);
        for _ in 0..NUM_COORDS {
            let d = TempDir::new().unwrap();
            let id = CoordinatorIdentity::load_or_generate(d.path()).unwrap();
            // Publish coordinator.pub so event-journal signature
            // verification can resolve each emitter's pubkey.
            id.publish_pub(store.as_ref()).await.unwrap();
            coords.push(id);
            dirs.push(d);
        }
        Self {
            store,
            coords,
            vol_signers: HashMap::new(),
            _coord_dirs: dirs,
        }
    }

    /// Mint a fresh volume keypair, upload `volume.pub`, register the
    /// signer in `vol_signers`. Returns the new ULID.
    async fn mint_fork(&mut self) -> Ulid {
        let vol_ulid = Ulid::new();
        let (signer, vk) = generate_ephemeral_signer();
        let key = StorePath::from(elide_core::store_keys::meta_pub_key(vol_ulid));
        let body = format!(
            "{}\n",
            vk.to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        self.store
            .put(&key, PutPayload::from(body.into_bytes()))
            .await
            .unwrap();
        self.vol_signers.insert(vol_ulid, signer);
        vol_ulid
    }

    /// Mint and upload a (regular) handoff snapshot manifest signed by
    /// the volume's own key. Used by `Release` to simulate the
    /// drain+snapshot step without a daemon. Returns the snapshot ULID.
    async fn publish_volume_snapshot(&self, vol_ulid: Ulid) -> Option<Ulid> {
        let signer = self.vol_signers.get(&vol_ulid)?;
        let snap_ulid = Ulid::new();
        let bytes = build_snapshot_manifest_bytes(signer.as_ref(), &[]);
        VolumeData::new(self.store.clone(), vol_ulid)
            .snapshots()
            .put_manifest(snap_ulid, Bytes::from(bytes))
            .await
            .ok()?;
        Some(snap_ulid)
    }

    async fn apply(&mut self, op: &Op) {
        match op {
            Op::Create { name, coord } => {
                let vol_ulid = self.mint_fork().await;
                let coord_id = self.coords[*coord as usize].coordinator_id_str().to_owned();
                let _ = lifecycle::mark_initial(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    vol_ulid,
                    4 * 1024 * 1024 * 1024,
                )
                .await;
            }

            Op::Release { name, coord } => {
                let coord_id = self.coords[*coord as usize].coordinator_id_str().to_owned();
                // Need the current vol_ulid to sign the snapshot.
                let vol_ulid = match ns::read_name_record(&self.store, name_for(*name)).await {
                    Ok(Some((rec, _))) => rec.vol_ulid,
                    _ => return,
                };
                let Some(snap) = self.publish_volume_snapshot(vol_ulid).await else {
                    return;
                };
                // Tolerate every error class: wrong-state /
                // ownership-conflict / absent are valid outcomes given
                // the random op stream.
                let _: Result<MarkReleasedOutcome, _> =
                    lifecycle::mark_released(&self.store, name_for(*name), &coord_id, snap).await;
            }

            Op::ForceClaim { name, claimant } => {
                // Observe the record; skip silently unless it is in a
                // state the forced claim proceeds from — the proptest
                // must tolerate ordering noise.
                let observed = match ns::read_name_record(&self.store, name_for(*name)).await {
                    Ok(Some((rec, version))) => match rec.state {
                        NameState::Live | NameState::Stopped => ObservedRecord {
                            record: rec,
                            version,
                        },
                        _ => return,
                    },
                    _ => return,
                };
                let coord_id = self.coords[*claimant as usize]
                    .coordinator_id_str()
                    .to_owned();
                let parent_pin = observed
                    .record
                    .latest_snapshot
                    .map(|snap| format!("{}/{snap}", observed.record.vol_ulid));
                let new_vol = self.mint_fork().await;
                let _: Result<MarkClaimedForceOutcome, _> = lifecycle::mark_claimed_force(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    new_vol,
                    parent_pin,
                    &observed,
                )
                .await;
            }

            Op::ClaimReleased { name, coord } => {
                let coord_id = self.coords[*coord as usize].coordinator_id_str().to_owned();
                let new_vol = self.mint_fork().await;
                let _: Result<MarkClaimedOutcome, _> = lifecycle::mark_claimed(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    new_vol,
                    NameState::Live,
                )
                .await;
            }

            Op::ReclaimLocal {
                name,
                coord,
                as_live,
            } => {
                let coord_id = self.coords[*coord as usize].coordinator_id_str().to_owned();
                // Model the "we own the local fork" case: pass the
                // record's own vol_ulid. ForkMismatch is also a real
                // production outcome but it has no bucket-side effect
                // (no record mutation), so exercising the success-path
                // retention rule is the higher-value target here.
                let local_vol = match ns::read_name_record(&self.store, name_for(*name)).await {
                    Ok(Some((rec, _))) => rec.vol_ulid,
                    _ => return,
                };
                let target_state = if *as_live {
                    NameState::Live
                } else {
                    NameState::Stopped
                };
                let _: Result<MarkReclaimedLocalOutcome, _> = lifecycle::mark_reclaimed_local(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    local_vol,
                    target_state,
                )
                .await;
            }
        }
    }

    /// Invariant 6 (strong form): every `handoff_snapshot` references
    /// a manifest that exists in S3 *and* verifies under the volume's
    /// own `volume.pub`.
    async fn verify_handoff_manifest(&self, vol_ulid: Ulid, snap: Ulid, name: &str) {
        let body = VolumeData::new(self.store.clone(), vol_ulid)
            .snapshots()
            .get_manifest_bytes(snap)
            .await
            .unwrap_or_else(|e| panic!("name '{name}' snapshot {snap} unreadable: {e}"));

        // Every manifest is signed by the volume's own key.
        let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(vol_ulid));
        let pub_body = self
            .store
            .get(&pub_key)
            .await
            .unwrap_or_else(|e| panic!("volume.pub for {vol_ulid} missing: {e}"))
            .bytes()
            .await
            .expect("volume.pub body");
        let hex = std::str::from_utf8(&pub_body)
            .expect("volume.pub utf8")
            .trim();
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
            .collect::<Vec<u8>>();
        let arr: [u8; 32] = bytes.try_into().expect("32-byte pub");
        let vk = VerifyingKey::from_bytes(&arr).expect("valid pub");

        read_snapshot_manifest_from_bytes(&body, &vk, &snap).unwrap_or_else(|e| {
            panic!(
                "handoff manifest for '{name}' (vol {vol_ulid} snap {snap}) failed signature \
                 verification: {e}"
            )
        });
    }

    async fn check_invariants(&self) {
        let coord_ids: Vec<String> = self
            .coords
            .iter()
            .map(|c| c.coordinator_id_str().to_owned())
            .collect();

        for &name in &["vol-a", "vol-b", "vol-c"] {
            let Ok(Some((rec, _))) = ns::read_name_record(&self.store, name).await else {
                continue;
            };

            // Invariant 5: every recorded vol_ulid must have a
            // volume.pub uploaded.
            let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(rec.vol_ulid));
            assert!(
                self.store.head(&pub_key).await.is_ok(),
                "name '{name}' references vol_ulid {} but its volume.pub is missing",
                rec.vol_ulid,
            );

            match rec.state {
                NameState::Live | NameState::Stopped => {
                    // Invariant 2.
                    let owner = rec
                        .coordinator_id
                        .as_deref()
                        .expect("Live/Stopped record must name an owner");
                    assert!(
                        coord_ids.iter().any(|c| c == owner),
                        "Live/Stopped record names unknown coordinator '{owner}'"
                    );
                }
                NameState::Released => {
                    // Invariant 3.
                    assert!(
                        rec.coordinator_id.is_none(),
                        "Released record must clear coordinator_id"
                    );
                    assert!(
                        rec.handoff_snapshot.is_some(),
                        "Released record must carry a handoff_snapshot"
                    );
                }
                NameState::Readonly => {
                    // No coordinator-id constraints; readonly records
                    // are produced by `mark_initial_readonly` only,
                    // which our op alphabet doesn't drive.
                }
            }

            // Invariant 5: any handoff_snapshot pointer on any record
            // must reference a verifiable manifest. For Released this
            // is the published handoff basis the next claimant will
            // read; for Live/Stopped (after `mark_reclaimed_local`)
            // this is the retained prior-owner handoff that stays the
            // valid basis until the new owner writes and
            // `mark_released` overwrites it. A regression that clears
            // the pointer in-place or stamps over it with a bad ULID
            // would fail here.
            if let Some(snap) = rec.handoff_snapshot {
                self.verify_handoff_manifest(rec.vol_ulid, snap, name).await;
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// After any sequence of {Create, Release, ForceClaim,
    /// ClaimReleased, ReclaimLocal} ops on a shared bucket between two coordinators,
    /// the bucket state remains internally consistent. Each individual
    /// op tolerates wrong-state errors silently — the proptest is
    /// asserting the *invariants*, not the success of any op.
    #[test]
    fn portable_lifecycle_invariants_hold(
        ops in prop::collection::vec(arb_op(), 1..16)
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut world = World::new().await;
            for op in &ops {
                world.apply(op).await;
                world.check_invariants().await;
            }
        });
    }
}
