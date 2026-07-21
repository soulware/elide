//! Rehome a fork that lost its name.
//!
//! The previous-owner disposition once `names/<name>` binds a different
//! fork (`docs/design/displaced-fork-rehome.md`). [`rehome_displaced_fork`]
//! re-homes the local fork under `<name>-<suffix>` (six hex chars,
//! hash-derived from the episode) — a first-class, `Released` volume
//! recovered by the ordinary reclaim-then-start — rather than silently
//! orphaning it. The `volume.released` marker on the fork picks the
//! disposition, which lives in the event emitted on the new name's log:
//! `superseded` (the fork was cleanly released and a peer claimed the
//! name) or `displaced` (a peer force-claimed the name while this fork
//! still held it).
//!
//! One primitive, called from every site that discovers the loss: the
//! ownership poll, the start-refusal, and `force_claim`'s finalize. It
//! reads `names/<name>` itself to learn the claimant, so callers only
//! name the fork.

use std::path::Path;

use tracing::{info, warn};
use ulid::Ulid;

use elide_core::volume_event::EventKind;

use crate::identity::CoordinatorIdentity;
use crate::lifecycle::{LifecycleError, MarkInitialOutcome};
use crate::name_store::NameStoreError;
use crate::stores::ScopedStores;
use crate::volume_state::RELEASED_FILE;

/// Upper bound on suffix-collision retries. A collision needs another
/// fork's record already sitting at this episode's derived suffix —
/// ~2^-24 per prior husk of the same base name — so the cap is a
/// backstop against a pathological bucket, not a limit expected in
/// practice.
const REHOME_PROBE_CAP: u32 = 64;

/// Derive attempt `i`'s rehome suffix for the (`old_name`, `fork_ulid`)
/// episode: six hex chars of a domain-tagged BLAKE3 over the episode
/// identity. Deterministic, so a crash-interrupted rehome re-derives
/// the identical sequence and lands on its own record; random-looking,
/// so names carry no information and no per-name counter.
pub(crate) fn rehome_suffix(old_name: &str, fork_ulid: Ulid, attempt: u32) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"elide/rehome-name/v1\0");
    h.update(old_name.as_bytes());
    h.update(b"\0");
    h.update(&fork_ulid.to_bytes());
    h.update(&attempt.to_le_bytes());
    h.finalize().to_hex().as_str()[..6].to_owned()
}

/// Errors from [`rehome_displaced_fork`].
#[derive(Debug)]
pub enum RehomeError {
    /// `names/<old_name>` has no record — there is no claimant to
    /// attribute the rehome to. A transient read returning `None`, or a
    /// name deleted out from under us.
    SourceGone(String),
    /// Every derived `<old_name>-<suffix>` candidate up to
    /// [`REHOME_PROBE_CAP`] attempts is bound to some other fork.
    ProbeExhausted {
        base: String,
    },
    Lifecycle(LifecycleError),
    Store(NameStoreError),
    Io(std::io::Error),
}

impl From<LifecycleError> for RehomeError {
    fn from(e: LifecycleError) -> Self {
        Self::Lifecycle(e)
    }
}

impl From<std::io::Error> for RehomeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<NameStoreError> for RehomeError {
    fn from(e: NameStoreError) -> Self {
        Self::Store(e)
    }
}

impl std::fmt::Display for RehomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceGone(name) => write!(f, "names/{name} record is gone; cannot rehome"),
            Self::ProbeExhausted { base } => write!(
                f,
                "no free rehome name for '{base}' after {REHOME_PROBE_CAP} derived candidates"
            ),
            Self::Lifecycle(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RehomeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Re-home `fork_ulid` — this coordinator's local fork that lost
/// `old_name` — under `<old_name>-<suffix>`, the first derived
/// candidate ([`rehome_suffix`]) whose record is free or already bound
/// to this fork.
///
/// Mints an ownerless `Released` `names/<new_name>` carrying the
/// best-available handoff snapshot, rebinds `by_name/<new_name>` and the
/// fork's own `volume.toml` name, emits a `superseded` or `displaced`
/// event on the new name's log, and — displacement only — stamps
/// `volume.released`. The probe is crash-idempotent without persisted
/// state: the candidate sequence is a pure function of the episode, and
/// name records are effectively never deleted, so a retry walks the
/// identical sequence and reaches its own record first. The caller owns
/// `old_name`'s binding: the poll and start-refusal remove
/// `by_name/<old_name>` (the claimant holds it); `force_claim`
/// overwrites it with the new fork.
///
/// Does *not* touch `names/<old_name>` or its log — that name is alive
/// under the claimant. Returns the new name.
pub async fn rehome_displaced_fork(
    identity: &CoordinatorIdentity,
    stores: &dyn ScopedStores,
    data_dir: &Path,
    fork_dir: &Path,
    old_name: &str,
    fork_ulid: Ulid,
) -> Result<String, RehomeError> {
    let name_claims = stores.name_claims();

    // A fork whose own `volume.toml` name already resolves to a record
    // binding it has completed a previous rehome — the caller is holding
    // a stale `by_name/<old_name>` entry. Return the settled name
    // without re-running the event emission below.
    if let Some(current) = crate::tasks::read_volume_name(fork_dir)
        && current != old_name
        && let Ok(Some(rec)) = name_claims.read(&current).await
        && rec.vol_ulid == fork_ulid
    {
        return Ok(current);
    }

    // The marker discriminates the disposition and supplies the handoff:
    // a released fork hands off the snapshot its release recorded; a
    // displaced fork hands off its latest published `User` snapshot
    // (which by construction excludes any undrained tail).
    let marker = fork_dir.join(RELEASED_FILE);
    let supersession = marker.exists();
    let handoff = if supersession {
        std::fs::read_to_string(&marker)
            .ok()
            .and_then(|s| Ulid::from_string(s.trim()).ok())
    } else {
        latest_published_user_snapshot(fork_dir)?
    };

    // Who holds the name we lost. At poll/start-refusal time this is the
    // peer that claimed or force-claimed; at force_claim finalize it is
    // this coordinator's own fresh fork (the CAS already landed).
    let holding = name_claims
        .read(old_name)
        .await?
        .ok_or_else(|| RehomeError::SourceGone(old_name.to_owned()))?;

    // Probe the derived candidates with the conditional create itself: a
    // slot already bound to this fork is a resumed attempt (done); any
    // other binding sends the probe to the next candidate. Racing
    // coordinators resolve by the CAS — the loser observes the winner's
    // record and moves on.
    let mut settled = None;
    for attempt in 0..REHOME_PROBE_CAP {
        let candidate = format!("{old_name}-{}", rehome_suffix(old_name, fork_ulid, attempt));
        match name_claims
            .mark_rehomed(&candidate, fork_ulid, holding.size, handoff)
            .await?
        {
            MarkInitialOutcome::Claimed => {
                settled = Some(candidate);
                break;
            }
            MarkInitialOutcome::AlreadyExists {
                existing_vol_ulid, ..
            } if existing_vol_ulid == fork_ulid => {
                settled = Some(candidate);
                break;
            }
            MarkInitialOutcome::AlreadyExists { .. } => {}
        }
    }
    let Some(new_name) = settled else {
        return Err(RehomeError::ProbeExhausted {
            base: old_name.to_owned(),
        });
    };

    let by_name = data_dir.join("by_name");
    std::fs::create_dir_all(&by_name)?;
    let link = by_name.join(&new_name);
    if link.exists() || link.is_symlink() {
        std::fs::remove_file(&link)?;
    }
    std::os::unix::fs::symlink(format!("../by_id/{fork_ulid}"), &link)?;

    // The disposition lives in the event, not the name: a clean
    // handoff's fork is superseded; a force-claimed one is displaced.
    let kind = if supersession {
        EventKind::Superseded {
            source_name: old_name.to_owned(),
            source_fork: holding.vol_ulid,
            superseded_by: holding.coordinator_id.clone(),
        }
    } else {
        EventKind::Displaced {
            source_name: old_name.to_owned(),
            source_fork: holding.vol_ulid,
            displaced_by: holding.coordinator_id.clone(),
        }
    };
    stores
        .event_journal()
        .emit_best_effort(identity, &new_name, kind, fork_ulid)
        .await;

    if !supersession {
        // The explicit release step a displacement never had; a
        // supersession's marker is already present and left untouched.
        let body = handoff.map(|u| u.to_string()).unwrap_or_default();
        std::fs::write(&marker, body)?;
    }

    // Rebind the fork's own name: `read_volume_name` anchors the
    // attestation discharge for any `by_id/<fork_ulid>/` write, and a
    // stale `old_name` points the liveness lookup at the claimant's
    // record — which no longer binds this fork — so the discharge is
    // denied. This is also both the ownership poll's re-fire signal and
    // the early-return's completion signal, so it comes last.
    elide_core::config::VolumeConfig::set_name(fork_dir, &new_name)?;

    info!(
        "[rehome] {old_name} fork {fork_ulid} rehomed as {new_name} (name now held by {})",
        holding.vol_ulid
    );
    Ok(new_name)
}

/// The highest snapshot ULID with a stable `<ulid>.manifest` under
/// `snapshots/` *and* an upload sentinel under `uploaded/snapshots/` —
/// the newest basis a fresh claimant of the rehomed name could actually
/// fetch. Stop-snapshots are skipped: they are deleted at the volume's
/// next start, so they cannot anchor a `Released` record.
fn latest_published_user_snapshot(fork_dir: &Path) -> std::io::Result<Option<Ulid>> {
    let snap_dir = fork_dir.join("snapshots");
    let entries = match std::fs::read_dir(&snap_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let uploaded = fork_dir.join("uploaded").join("snapshots");
    let mut latest: Option<Ulid> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else { continue };
        let Some((u, elide_core::signing::SnapshotKind::User)) =
            elide_core::signing::parse_snapshot_filename(s)
        else {
            continue;
        };
        if uploaded.join(u.to_string()).exists() && latest.is_none_or(|cur| u > cur) {
            latest = Some(u);
        }
    }
    Ok(latest)
}

/// If `by_name/<name>` points at a local fork, rehome that
/// (soon-to-be-displaced) fork before the caller rebinds or drops the
/// binding. Recovers the fork ULID from the symlink target, then
/// delegates to [`rehome_displaced_fork`]. Best-effort: returns the
/// rehomed name, or `None` when there is no local binding or the rehome
/// fails (logged).
///
/// The two triggers that only hold the *name* — `force_claim` finalize
/// and start-refusal — use this; the poll trigger calls
/// [`rehome_displaced_fork`] directly with the fork it already serves.
pub async fn rehome_existing_local_fork(
    identity: &CoordinatorIdentity,
    stores: &dyn ScopedStores,
    data_dir: &Path,
    old_name: &str,
) -> Option<String> {
    let symlink = data_dir.join("by_name").join(old_name);
    let old_ulid = std::fs::read_link(&symlink).ok().and_then(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| Ulid::from_string(s).ok())
    })?;
    let old_fork_dir = data_dir.join("by_id").join(old_ulid.to_string());
    match rehome_displaced_fork(
        identity,
        stores,
        data_dir,
        &old_fork_dir,
        old_name,
        old_ulid,
    )
    .await
    {
        Ok(new_name) => Some(new_name),
        Err(e) => {
            warn!("[rehome] {old_name} fork {old_ulid}: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::PassthroughStores;
    use elide_core::name_record::NameState;
    use object_store::ObjectStore;
    use object_store::memory::InMemory;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn displacement_rehomes_to_released_derived_name() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        // Our displaced fork, and the peer's fork now holding "prod".
        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        // The fork self-identifies as "prod" and carries a bound ublk id.
        elide_core::config::VolumeConfig {
            ulid: Some(our_fork),
            name: Some("prod".to_owned()),
            size: None,
            ublk: Some(elide_core::config::UblkConfig { dev_id: Some(7) }),
            lazy: None,
            journal_ranges: Default::default(),
        }
        .write(&fork_dir)
        .unwrap();

        // names/prod is held by the displacer.
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        let new_name = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();

        // The first derived candidate for this episode.
        assert_eq!(
            new_name,
            format!("prod-{}", rehome_suffix("prod", our_fork, 0))
        );

        // The rehomed name is an ownerless Released record for our fork
        // — recoverable like any released volume (reclaim, then start).
        let rec = stores
            .name_claims()
            .read(&new_name)
            .await
            .unwrap()
            .expect("rehomed name record must exist");
        assert_eq!(rec.vol_ulid, our_fork);
        assert_eq!(rec.state, NameState::Released);
        assert_eq!(rec.coordinator_id, None);
        assert_eq!(rec.handoff_snapshot, None);
        assert_eq!(rec.size, 4096);

        // The local binding points at our fork; the displacement stamped
        // volume.released (empty body — no published snapshot to hand
        // off).
        let link = data_dir.join("by_name").join(&new_name);
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new(&format!("../by_id/{our_fork}"))
        );
        assert_eq!(
            std::fs::read_to_string(fork_dir.join(RELEASED_FILE)).unwrap(),
            ""
        );

        // The fork's own name is rebound to the rehomed name (so an
        // attestation discharge for its `by_id/` writes anchors on a
        // record that still binds it), and the bound ublk id survives.
        assert_eq!(
            crate::tasks::read_volume_name(&fork_dir).as_deref(),
            Some(new_name.as_str())
        );
        assert_eq!(
            elide_core::config::VolumeConfig::bound_ublk_id(&fork_dir).unwrap(),
            Some(7)
        );

        // names/prod is untouched — it is alive under the displacer.
        let prod = stores.name_claims().read("prod").await.unwrap().unwrap();
        assert_eq!(prod.vol_ulid, their_fork);
    }

    #[tokio::test]
    async fn supersession_rehomes_to_bare_name_with_release_handoff() {
        use futures::StreamExt;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let handoff = Ulid::from_string("01J0000000000000000000000H").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        // The fork was cleanly released: the marker carries the handoff.
        std::fs::write(fork_dir.join(RELEASED_FILE), handoff.to_string()).unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        let new_name = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();

        assert_eq!(
            new_name,
            format!("prod-{}", rehome_suffix("prod", our_fork, 0))
        );

        // Release-shape record carrying the release's own handoff.
        let rec = stores.name_claims().read(&new_name).await.unwrap().unwrap();
        assert_eq!(rec.vol_ulid, our_fork);
        assert_eq!(rec.state, NameState::Released);
        assert_eq!(rec.coordinator_id, None);
        assert_eq!(rec.handoff_snapshot, Some(handoff));

        // The marker body is untouched, and the clean handoff is
        // recorded as a Superseded event on the new name's log.
        assert_eq!(
            std::fs::read_to_string(fork_dir.join(RELEASED_FILE)).unwrap(),
            handoff.to_string()
        );
        let prefix = object_store::path::Path::from(format!("events/{new_name}"));
        let metas: Vec<_> = store.list(Some(&prefix)).collect().await;
        let event_key = metas
            .into_iter()
            .map(|m| m.unwrap().location)
            .find(|k| k.filename() != Some("HEAD"))
            .expect("a Superseded event object must be written");
        let body = store.get(&event_key).await.unwrap().bytes().await.unwrap();
        let ev =
            elide_core::volume_event::VolumeEvent::from_toml(std::str::from_utf8(&body).unwrap())
                .unwrap();
        match ev.kind {
            elide_core::volume_event::EventKind::Superseded {
                source_name,
                source_fork,
                superseded_by,
            } => {
                assert_eq!(source_name, "prod");
                assert_eq!(source_fork, their_fork);
                assert_eq!(
                    superseded_by.as_deref(),
                    Some("01PEERCOORDXXXXXXXXXXXXXXXX")
                );
            }
            other => panic!("expected Superseded event, got {other:?}"),
        }
        assert_eq!(ev.vol_ulid, our_fork);
    }

    #[tokio::test]
    async fn displacement_hands_off_latest_published_user_snapshot() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let published = Ulid::from_string("01J0000000000000000000000P").unwrap();
        let unpublished = Ulid::from_string("01J0000000000000000000000Q").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        let snap_dir = fork_dir.join("snapshots");
        let uploaded = fork_dir.join("uploaded").join("snapshots");
        std::fs::create_dir_all(&snap_dir).unwrap();
        std::fs::create_dir_all(&uploaded).unwrap();
        // One published User snapshot; a newer one without an upload
        // sentinel and a stop-snapshot must both be skipped.
        std::fs::write(snap_dir.join(format!("{published}.manifest")), "").unwrap();
        std::fs::write(uploaded.join(published.to_string()), "").unwrap();
        std::fs::write(snap_dir.join(format!("{unpublished}.manifest")), "").unwrap();
        std::fs::write(snap_dir.join(format!("{unpublished}-stop.manifest")), "").unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        let new_name = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();

        let rec = stores.name_claims().read(&new_name).await.unwrap().unwrap();
        assert_eq!(rec.handoff_snapshot, Some(published));
        // The stamped marker carries the same handoff.
        assert_eq!(
            std::fs::read_to_string(fork_dir.join(RELEASED_FILE)).unwrap(),
            published.to_string()
        );
    }

    #[tokio::test]
    async fn probe_skips_candidates_bound_to_other_forks() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let earlier_fork = Ulid::from_string("01J0000000000000000000000X").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();
        // This episode's first candidate is already taken — a suffix
        // collision with some other fork's record.
        let taken = format!("prod-{}", rehome_suffix("prod", our_fork, 0));
        stores
            .name_claims()
            .mark_rehomed(&taken, earlier_fork, 4096, None)
            .await
            .unwrap();

        let new_name = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();

        assert_eq!(
            new_name,
            format!("prod-{}", rehome_suffix("prod", our_fork, 1))
        );
        // The colliding record is untouched.
        let one = stores.name_claims().read(&taken).await.unwrap().unwrap();
        assert_eq!(one.vol_ulid, earlier_fork);
    }

    #[tokio::test]
    async fn rehome_is_idempotent_on_rerun() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        let first = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();
        let second = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();
        assert_eq!(
            first, second,
            "re-run must resolve to the same rehomed name"
        );
        assert_eq!(
            first,
            format!("prod-{}", rehome_suffix("prod", our_fork, 0))
        );
    }

    #[tokio::test]
    async fn rehome_existing_local_fork_reads_symlink() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        std::fs::create_dir_all(data_dir.join("by_id").join(our_fork.to_string())).unwrap();
        let by_name = data_dir.join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(format!("../by_id/{our_fork}"), by_name.join("prod")).unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        // Resolves the fork from the by_name symlink and rehomes it — the
        // force_claim / start-refusal call path.
        let new_name = rehome_existing_local_fork(&identity, stores.as_ref(), data_dir, "prod")
            .await
            .expect("existing local fork must be rehomed");
        assert_eq!(
            new_name,
            format!("prod-{}", rehome_suffix("prod", our_fork, 0))
        );
        let rec = stores.name_claims().read(&new_name).await.unwrap().unwrap();
        assert_eq!(rec.vol_ulid, our_fork);
        assert_eq!(rec.state, NameState::Released);
    }

    #[tokio::test]
    async fn rehome_existing_local_fork_none_without_binding() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        // No by_name/prod symlink → nothing to rehome.
        assert!(
            rehome_existing_local_fork(&identity, stores.as_ref(), data_dir, "prod")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn rehome_emits_displaced_event() {
        use futures::StreamExt;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = CoordinatorIdentity::load_or_generate(data_dir).unwrap();

        let our_fork = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let their_fork = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let fork_dir = data_dir.join("by_id").join(our_fork.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        stores
            .name_claims()
            .mark_initial(
                "prod",
                "01PEERCOORDXXXXXXXXXXXXXXXX",
                None,
                their_fork,
                4096,
            )
            .await
            .unwrap();

        let new_name = rehome_displaced_fork(
            &identity,
            stores.as_ref(),
            data_dir,
            &fork_dir,
            "prod",
            our_fork,
        )
        .await
        .unwrap();

        // A Displaced event landed on the new name's log with the right
        // provenance (source name, the claimant fork, and its coordinator).
        let prefix = object_store::path::Path::from(format!("events/{new_name}"));
        let metas: Vec<_> = store.list(Some(&prefix)).collect().await;
        let event_key = metas
            .into_iter()
            .map(|m| m.unwrap().location)
            .find(|k| k.filename() != Some("HEAD"))
            .expect("a Displaced event object must be written");
        let body = store.get(&event_key).await.unwrap().bytes().await.unwrap();
        let ev =
            elide_core::volume_event::VolumeEvent::from_toml(std::str::from_utf8(&body).unwrap())
                .unwrap();
        match ev.kind {
            elide_core::volume_event::EventKind::Displaced {
                source_name,
                source_fork,
                displaced_by,
            } => {
                assert_eq!(source_name, "prod");
                assert_eq!(source_fork, their_fork);
                assert_eq!(displaced_by.as_deref(), Some("01PEERCOORDXXXXXXXXXXXXXXXX"));
            }
            other => panic!("expected Displaced event, got {other:?}"),
        }
        assert_eq!(ev.vol_ulid, our_fork);
    }
}
