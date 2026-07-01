//! Rehome a displaced fork under a fresh name.
//!
//! The previous-owner disposition after a peer force-claims a name
//! (`docs/design/displaced-fork-rehome.md`). When this coordinator's
//! local fork for `<name>` is no longer the bound owner, [`rehome_displaced_fork`]
//! re-homes it under `<name>-displaced-<fork_ulid>` — a first-class,
//! `Stopped`, self-owned volume — rather than silently orphaning it.
//!
//! One primitive, called from every site that discovers the loss: the
//! ownership poll, the start-refusal, and `force_claim`'s finalize. It
//! reads `names/<name>` itself to learn the displacer, so callers only
//! name the fork.

use std::path::Path;

use tracing::{info, warn};
use ulid::Ulid;

use elide_core::volume_event::EventKind;

use crate::identity::CoordinatorIdentity;
use crate::lifecycle::{LifecycleError, MarkInitialOutcome};
use crate::name_store::NameStoreError;
use crate::stores::ScopedStores;
use crate::volume_state::STOPPED_FILE;

/// Errors from [`rehome_displaced_fork`].
#[derive(Debug)]
pub enum RehomeError {
    /// `names/<old_name>` has no record — there is no displacer to
    /// attribute the rehome to. A transient read returning `None`, or a
    /// name deleted out from under us.
    SourceGone(String),
    /// `names/<new_name>` already exists bound to a *different* fork —
    /// a genuine collision, not the idempotent re-run of this rehome.
    NameTaken {
        name: String,
        existing_vol_ulid: Ulid,
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
            Self::NameTaken {
                name,
                existing_vol_ulid,
            } => write!(f, "names/{name} already binds {existing_vol_ulid}"),
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

/// Re-home `fork_ulid` — this coordinator's local fork displaced from
/// `old_name` — under `<old_name>-displaced-<fork_ulid>`.
///
/// Mints a `Stopped`, self-owned `names/<new_name>` (`If-None-Match`,
/// idempotent on re-run), rebinds `by_name/<new_name>` to the fork,
/// marks it stopped, and records a `Displaced` event on the new name's
/// log. The caller owns `old_name`'s binding: the poll and start-refusal
/// remove `by_name/<old_name>` (the displacer holds it); `force_claim`
/// overwrites it with the new fork.
///
/// Does *not* touch `names/<old_name>` or its log — that name is alive
/// under the displacer. Returns the new name.
pub async fn rehome_displaced_fork(
    identity: &CoordinatorIdentity,
    stores: &dyn ScopedStores,
    data_dir: &Path,
    fork_dir: &Path,
    old_name: &str,
    fork_ulid: Ulid,
) -> Result<String, RehomeError> {
    let name_claims = stores.name_claims();

    // Learn who displaced us from the name we lost. At poll/start-refusal
    // time this is the peer that force-claimed; at force_claim finalize
    // it is this coordinator's own fresh fork (the CAS already landed).
    let displacing = name_claims
        .read(old_name)
        .await?
        .ok_or_else(|| RehomeError::SourceGone(old_name.to_owned()))?;

    let new_name = format!("{old_name}-displaced-{fork_ulid}");
    let coord_id = identity.coordinator_id_str();

    match name_claims
        .mark_rehomed(
            &new_name,
            coord_id,
            identity.hostname(),
            fork_ulid,
            displacing.size,
        )
        .await?
    {
        MarkInitialOutcome::Claimed => {}
        // Idempotent re-run (a crash between mint and finalize, or a
        // restart re-observing the displacement): the fork's own ULID
        // suffix means our previous attempt owns this name already.
        MarkInitialOutcome::AlreadyExists {
            existing_vol_ulid, ..
        } if existing_vol_ulid == fork_ulid => {}
        MarkInitialOutcome::AlreadyExists {
            existing_vol_ulid, ..
        } => {
            return Err(RehomeError::NameTaken {
                name: new_name,
                existing_vol_ulid,
            });
        }
    }

    let by_name = data_dir.join("by_name");
    std::fs::create_dir_all(&by_name)?;
    let link = by_name.join(&new_name);
    if link.exists() || link.is_symlink() {
        std::fs::remove_file(&link)?;
    }
    std::os::unix::fs::symlink(format!("../by_id/{fork_ulid}"), &link)?;
    std::fs::write(fork_dir.join(STOPPED_FILE), "")?;

    stores
        .event_journal()
        .emit_best_effort(
            identity,
            &new_name,
            EventKind::Displaced {
                source_name: old_name.to_owned(),
                source_fork: displacing.vol_ulid,
                displaced_by: displacing.coordinator_id.clone(),
            },
            fork_ulid,
        )
        .await;

    info!(
        "[rehome] {old_name} fork {fork_ulid} rehomed as {new_name} \
         (displaced by {})",
        displacing.vol_ulid
    );
    Ok(new_name)
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
    async fn rehome_creates_stopped_named_volume() {
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

        assert_eq!(new_name, format!("prod-displaced-{our_fork}"));

        // The rehomed name is a Stopped, self-owned record for our fork.
        let rec = stores
            .name_claims()
            .read(&new_name)
            .await
            .unwrap()
            .expect("rehomed name record must exist");
        assert_eq!(rec.vol_ulid, our_fork);
        assert_eq!(rec.state, NameState::Stopped);
        assert_eq!(
            rec.coordinator_id.as_deref(),
            Some(identity.coordinator_id_str())
        );
        assert_eq!(rec.size, 4096);

        // The local binding points at our fork and it is marked stopped.
        let link = data_dir.join("by_name").join(&new_name);
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new(&format!("../by_id/{our_fork}"))
        );
        assert!(fork_dir.join(STOPPED_FILE).exists());

        // names/prod is untouched — it is alive under the displacer.
        let prod = stores.name_claims().read("prod").await.unwrap().unwrap();
        assert_eq!(prod.vol_ulid, their_fork);
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
        assert_eq!(new_name, format!("prod-displaced-{our_fork}"));
        let rec = stores.name_claims().read(&new_name).await.unwrap().unwrap();
        assert_eq!(rec.vol_ulid, our_fork);
        assert_eq!(rec.state, NameState::Stopped);
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
        // provenance (source name + the fork that displaced us).
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
                ..
            } => {
                assert_eq!(source_name, "prod");
                assert_eq!(source_fork, their_fork);
            }
            other => panic!("expected Displaced event, got {other:?}"),
        }
        assert_eq!(ev.vol_ulid, our_fork);
    }
}
