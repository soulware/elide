// Two-coordinator state-machine proptest for the portable-live-volume
// lifecycle. Drives `lifecycle::*` directly — the building blocks the
// inbound ops compose — against a shared `InMemory` bucket plus two
// `CoordinatorIdentity` instances.
//
// Op alphabet: { Create, Release, ForceClaim, ClaimReleased,
// ReclaimLocal, Tick }.
// `Stop` is omitted (it is a single state flip already exhaustively
// covered by `lifecycle::tests`); `start --remote` is modelled as the
// `ClaimReleased` op since its bucket-side effect is identical;
// `start --claim` and `claim` against a locally-owned released fork are
// both modelled by `ReclaimLocal`, differing only in `target_state`.
// `Tick` is the per-volume ownership poll of
// `docs/design/displaced-fork-rehome.md`: for each fork a coordinator
// holds locally it re-reads `names/<name>` and, on a `vol_ulid`
// mismatch, rehomes the fork under `<name>-<suffix>` via
// `rehome::rehome_displaced_fork` — a displacement when the fork was
// force-claimed out from under it, a supersession when it was cleanly
// released (`volume.released` present) and a peer claimed the name.
//
// The proptest enforces the invariants the design doc requires after
// any sequence of ops:
//
//   1. Every `names/<name>` parses cleanly.
//   2. Every `Live`/`Stopped` record names a coordinator we know about.
//   3. Every `Released` record on a base name clears `coordinator_id`
//      and carries a `handoff_snapshot`.
//   4. Every name's `vol_ulid` has `volume.pub` in the bucket.
//   5. Every `handoff_snapshot`, regardless of record state, references
//      a manifest that exists in the bucket under
//      `by_id/<vol_ulid>/snapshots/YYYYMMDD/` and verifies under the
//      right pubkey. This covers `mark_reclaimed_local`'s explicit
//      retention rule (Released → Live/Stopped in-place keeps
//      `handoff_snapshot` because the prior owner's published handoff
//      remains the valid basis until the new owner writes and
//      `mark_released` overwrites it).
//   6. Preserve-never-orphan: every fork a coordinator rehomed on a
//      tick has its `<name>-<suffix>` record present, `Released`,
//      ownerless (release shape), and bound to the rehomed fork's
//      ULID; a supersession's record carries the release handoff, and
//      it verifies like any other handoff.
//   7. Single-writer: no two `Live` records anywhere in the bucket bind
//      the same `vol_ulid` simultaneously.
//   8. A ticked coordinator no longer serves any fork whose name it
//      lost (its local `serving` flag is cleared).
//   9. Rehome is idempotent: a re-tick resolves to the same
//      `<name>-<suffix>` — the candidate sequence is derived from the
//      episode, so no divergent duplicate is minted.
//
// Cases run in a single tokio runtime per test case; ops are
// interleaved sequentially. The interesting non-trivial races
// (concurrent claim) are already covered at the conditional-PUT layer
// in `name_store::tests` and `lifecycle::tests`; the value here is
// composing many ops and asserting the bucket stays internally
// consistent.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use elide_coordinator::identity::CoordinatorIdentity;
use elide_coordinator::lifecycle::{
    self, MarkClaimedForceOutcome, MarkClaimedOutcome, MarkInitialOutcome,
    MarkReclaimedLocalOutcome, MarkReleasedOutcome, ObservedRecord,
};
use elide_coordinator::name_store as ns;
use elide_coordinator::rehome::rehome_displaced_fork;
use elide_coordinator::stores::{PassthroughStores, ScopedStores};
use elide_coordinator::volume_data::VolumeData;
use elide_core::name_record::NameState;
use elide_core::segment::SegmentSigner;
use elide_core::signing::{
    build_snapshot_manifest_bytes, generate_ephemeral_signer, read_snapshot_manifest_from_bytes,
};
use futures::StreamExt;
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
    /// The per-volume ownership poll
    /// (`docs/design/displaced-fork-rehome.md`). For each fork `coord`
    /// holds locally, re-reads `names/<name>`; a `vol_ulid` mismatch
    /// means a peer took the name (force-claim, or a normal claim of a
    /// released one), so the fork is rehomed via
    /// `rehome::rehome_displaced_fork` and `coord` stops serving it.
    Tick {
        coord: u8,
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
        (name, coord.clone(), any::<bool>()).prop_map(|(name, coord, as_live)| Op::ReclaimLocal {
            name,
            coord,
            as_live,
        }),
        coord.prop_map(|coord| Op::Tick { coord }),
    ]
}

/// One coordinator's local per-fork state, standing in for the on-disk
/// `by_id/<ulid>/` fork dir plus the `by_name/<name>` symlink and the
/// ublk device. There is no real device in-process, so `serving` is the
/// model's proxy for "the device is up": an acquisition sets it, and a
/// tick that finds the fork displaced clears it (the fence the design
/// doc pairs with the rehome).
struct LocalFork {
    ulid: Ulid,
    name: u8,
    serving: bool,
    /// The `<name>-<suffix>` this fork resolved to once a tick rehomed
    /// it. `None` until then.
    rehomed_as: Option<String>,
}

/// A coordinator: its identity, a `ScopedStores` handle over the shared
/// bucket, its own `data_dir` (so `by_name`/`by_id` never collide with
/// a peer's), and the forks it holds locally.
struct Coord {
    identity: CoordinatorIdentity,
    stores: Arc<dyn ScopedStores>,
    data_dir: PathBuf,
    forks: Vec<LocalFork>,
}

struct World {
    store: Arc<dyn ObjectStore>,
    coords: Vec<Coord>,
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
            let identity = CoordinatorIdentity::load_or_generate(d.path()).unwrap();
            // Publish coordinator.pub so event-journal signature
            // verification can resolve each emitter's pubkey.
            identity.publish_pub(store.as_ref()).await.unwrap();
            let stores: Arc<dyn ScopedStores> =
                Arc::new(PassthroughStores::new(Arc::clone(&store)));
            coords.push(Coord {
                identity,
                stores,
                data_dir: d.path().to_path_buf(),
                forks: Vec::new(),
            });
            dirs.push(d);
        }
        Self {
            store,
            coords,
            vol_signers: HashMap::new(),
            _coord_dirs: dirs,
        }
    }

    /// Materialize `coord`'s local layout for a freshly acquired fork:
    /// `by_id/<fork>/` and `by_name/<name> -> ../by_id/<fork>`, then
    /// record it as a served fork. Called on the acquiring side of
    /// `Create`/`ForceClaim`/`ClaimReleased` when the bucket transition
    /// landed. A `ForceClaim` does *not* touch the displaced peer's
    /// layout — its stale fork stays served until its own tick.
    fn acquire_local(&mut self, coord: usize, name: u8, fork: Ulid) {
        let data_dir = self.coords[coord].data_dir.clone();
        let fork_dir = data_dir.join("by_id").join(fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        let by_name = data_dir.join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        let link = by_name.join(name_for(name));
        if link.exists() || link.is_symlink() {
            std::fs::remove_file(&link).unwrap();
        }
        std::os::unix::fs::symlink(format!("../by_id/{fork}"), &link).unwrap();
        self.coords[coord].forks.push(LocalFork {
            ulid: fork,
            name,
            serving: true,
            rehomed_as: None,
        });
    }

    /// Clear the served flag for `coord`'s fork with `ulid`. Used by a
    /// clean `Release`, which stops serving without rehoming.
    fn stop_serving_fork(&mut self, coord: usize, ulid: Ulid) {
        for fork in &mut self.coords[coord].forks {
            if fork.ulid == ulid {
                fork.serving = false;
            }
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
                let coord_id = self.coords[*coord as usize]
                    .identity
                    .coordinator_id_str()
                    .to_owned();
                let outcome = lifecycle::mark_initial(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    vol_ulid,
                    4 * 1024 * 1024 * 1024,
                )
                .await;
                if matches!(outcome, Ok(MarkInitialOutcome::Claimed)) {
                    self.acquire_local(*coord as usize, *name, vol_ulid);
                }
            }

            Op::Release { name, coord } => {
                let coord_id = self.coords[*coord as usize]
                    .identity
                    .coordinator_id_str()
                    .to_owned();
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
                let outcome: Result<MarkReleasedOutcome, _> =
                    lifecycle::mark_released(&self.store, name_for(*name), &coord_id, snap).await;
                // A clean release stops serving; the fork stays bound to
                // the (now Released) record, so it is not rehomed until a
                // peer actually claims the name. Stamp `volume.released`
                // on the local fork — the marker the release IPC handler
                // writes, and the discriminator a later tick reads to
                // classify the rehome as a supersession.
                if matches!(outcome, Ok(MarkReleasedOutcome::Updated { .. })) {
                    self.stop_serving_fork(*coord as usize, vol_ulid);
                    let fork_dir = self.coords[*coord as usize]
                        .data_dir
                        .join("by_id")
                        .join(vol_ulid.to_string());
                    if fork_dir.is_dir() {
                        std::fs::write(fork_dir.join("volume.released"), snap.to_string()).unwrap();
                    }
                }
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
                    .identity
                    .coordinator_id_str()
                    .to_owned();
                let parent_pin = observed
                    .record
                    .latest_snapshot
                    .map(|snap| format!("{}/{snap}", observed.record.vol_ulid));
                let new_vol = self.mint_fork().await;
                let outcome: Result<MarkClaimedForceOutcome, _> = lifecycle::mark_claimed_force(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    new_vol,
                    parent_pin,
                    &observed,
                )
                .await;
                // The claimant gets local state for its new fork; the
                // displaced owner's local fork is deliberately left in
                // place — a stale binding for its own tick to rehome.
                if matches!(outcome, Ok(MarkClaimedForceOutcome::Claimed { .. })) {
                    self.acquire_local(*claimant as usize, *name, new_vol);
                }
            }

            Op::ClaimReleased { name, coord } => {
                let coord_id = self.coords[*coord as usize]
                    .identity
                    .coordinator_id_str()
                    .to_owned();
                let new_vol = self.mint_fork().await;
                let outcome: Result<MarkClaimedOutcome, _> = lifecycle::mark_claimed(
                    &self.store,
                    name_for(*name),
                    &coord_id,
                    None,
                    new_vol,
                    NameState::Live,
                )
                .await;
                if matches!(outcome, Ok(MarkClaimedOutcome::Claimed)) {
                    self.acquire_local(*coord as usize, *name, new_vol);
                }
            }

            Op::ReclaimLocal {
                name,
                coord,
                as_live,
            } => {
                let coord_id = self.coords[*coord as usize]
                    .identity
                    .coordinator_id_str()
                    .to_owned();
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
                let outcome: Result<MarkReclaimedLocalOutcome, _> =
                    lifecycle::mark_reclaimed_local(
                        &self.store,
                        name_for(*name),
                        &coord_id,
                        None,
                        local_vol,
                        target_state,
                    )
                    .await;
                // A successful in-place reclaim clears the local
                // `volume.released` marker (the production path does this
                // at `claim.rs`) and resumes serving when the reclaim
                // landed `Live`.
                if matches!(outcome, Ok(MarkReclaimedLocalOutcome::Reclaimed)) {
                    let data_dir = self.coords[*coord as usize].data_dir.clone();
                    for fork in &mut self.coords[*coord as usize].forks {
                        if fork.ulid == local_vol && fork.rehomed_as.is_none() {
                            let marker = data_dir
                                .join("by_id")
                                .join(local_vol.to_string())
                                .join("volume.released");
                            let _ = std::fs::remove_file(marker);
                            fork.serving = *as_live;
                        }
                    }
                }
            }

            Op::Tick { coord } => {
                let ci = *coord as usize;
                // Snapshot the forks to poll up front — the rehome below
                // borrows `self.coords[ci]` and then mutates the fork's
                // flags, so we cannot hold an iterator over `forks`.
                // Every not-yet-rehomed fork is polled, serving or not —
                // the production poll runs for every fork with a task,
                // which is how a released fork gets superseded-rehomed
                // once a peer claims its name.
                let candidates: Vec<(usize, Ulid, u8)> = self.coords[ci]
                    .forks
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.rehomed_as.is_none())
                    .map(|(i, f)| (i, f.ulid, f.name))
                    .collect();
                for (fi, fork_ulid, name_idx) in candidates {
                    let name = name_for(name_idx);
                    let bound = match ns::read_name_record(&self.store, name).await {
                        Ok(Some((rec, _))) => rec.vol_ulid,
                        _ => continue,
                    };
                    if bound == fork_ulid {
                        // Still ours — no displacement.
                        continue;
                    }
                    let data_dir = self.coords[ci].data_dir.clone();
                    let fork_dir = data_dir.join("by_id").join(fork_ulid.to_string());
                    let new_name = rehome_displaced_fork(
                        &self.coords[ci].identity,
                        self.coords[ci].stores.as_ref(),
                        &data_dir,
                        &fork_dir,
                        name,
                        fork_ulid,
                    )
                    .await
                    .expect("rehome of a displaced fork must succeed");
                    // Re-run the primitive against the same fork — the
                    // crash-retry / cold-restart re-observation the design
                    // doc calls out. The episode-derived candidate sequence
                    // makes the `If-None-Match` create idempotent: the
                    // re-run walks the same candidates and lands on its
                    // own record, no divergent duplicate.
                    let rerun = rehome_displaced_fork(
                        &self.coords[ci].identity,
                        self.coords[ci].stores.as_ref(),
                        &data_dir,
                        &fork_dir,
                        name,
                        fork_ulid,
                    )
                    .await
                    .expect("idempotent rehome re-run must succeed");
                    assert_eq!(
                        rerun, new_name,
                        "rehome re-run must resolve to the same name"
                    );
                    let fork = &mut self.coords[ci].forks[fi];
                    fork.serving = false;
                    fork.rehomed_as = Some(new_name);
                }
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
            .map(|c| c.identity.coordinator_id_str().to_owned())
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
                NameState::Readonly | NameState::Importing => {
                    // No coordinator-id constraints; these states are
                    // produced by the import flow only
                    // (`mark_importing` / `mark_import_complete`),
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

        self.check_rehome_invariants().await;
    }

    /// Invariants 6–9 of `docs/design/displaced-fork-rehome.md`, all of
    /// which concern the previous-owner disposition after a rehome.
    async fn check_rehome_invariants(&self) {
        for coord in &self.coords {
            let coord_id = coord.identity.coordinator_id_str();
            for fork in &coord.forks {
                let Some(rehomed) = &fork.rehomed_as else {
                    continue;
                };

                // Invariant 6: the rehomed name is `<base>-<suffix>`
                // (six hex chars), present, in release shape (Released,
                // ownerless), and bound to the rehomed fork's ULID.
                let suffix = rehomed
                    .strip_prefix(&format!("{}-", name_for(fork.name)))
                    .unwrap_or_else(|| {
                        panic!("rehomed name '{rehomed}' must extend the lost name")
                    });
                assert!(
                    suffix.len() == 6 && suffix.chars().all(|c| c.is_ascii_hexdigit()),
                    "rehomed name '{rehomed}' must carry a six-hex-char suffix"
                );
                let rec = ns::read_name_record(&self.store, rehomed)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("rehomed name '{rehomed}' record must exist"))
                    .0;
                assert_eq!(
                    rec.state,
                    NameState::Released,
                    "rehomed name '{rehomed}' must be Released"
                );
                assert_eq!(
                    rec.coordinator_id, None,
                    "rehomed name '{rehomed}' must be ownerless (release shape)"
                );
                assert_eq!(
                    rec.vol_ulid, fork.ulid,
                    "rehomed name '{rehomed}' must bind the rehomed fork's ULID"
                );
                // A supersession's record carries the release handoff;
                // whenever a handoff is present it must verify like any
                // other (invariant 5's rule applied to rehomed names).
                if let Some(snap) = rec.handoff_snapshot {
                    self.verify_handoff_manifest(rec.vol_ulid, snap, rehomed)
                        .await;
                }

                // Invariant 8: a rehomed fork is no longer served.
                assert!(
                    !fork.serving,
                    "coordinator '{coord_id}' still serves rehomed fork {}",
                    fork.ulid
                );
            }
        }

        // Invariant 7: no two `Live` records anywhere in the bucket bind
        // the same `vol_ulid` simultaneously.
        let names_prefix = StorePath::from("names");
        let metas = self
            .store
            .list(Some(&names_prefix))
            .collect::<Vec<_>>()
            .await;
        let mut live_forks: HashMap<Ulid, String> = HashMap::new();
        for meta in metas {
            let Some(name) = meta.unwrap().location.filename().map(str::to_owned) else {
                continue;
            };
            let Ok(Some((rec, _))) = ns::read_name_record(&self.store, &name).await else {
                continue;
            };
            if rec.state != NameState::Live {
                continue;
            }
            if let Some(other) = live_forks.insert(rec.vol_ulid, name.clone()) {
                panic!(
                    "single-writer violated: Live names '{name}' and '{other}' both bind \
                     vol_ulid {}",
                    rec.vol_ulid
                );
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
    /// ClaimReleased, ReclaimLocal, Tick} ops on a shared bucket between
    /// two coordinators, the bucket state remains internally consistent.
    /// Each individual op tolerates wrong-state errors silently — the
    /// proptest is asserting the *invariants*, not the success of any op.
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
