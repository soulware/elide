//! Discovery hook for the peer-fetch path: identify the previous
//! claimer of a volume from its signed event log so the prefetch tier
//! can warm from that host instead of S3.
//!
//! The handoff scenario this serves:
//!
//! 1. Coordinator A held volume V; cleanly released.
//! 2. Coordinator B is now running `volume claim` (or
//!    [`tasks::run_volume_tasks`] for an existing local fork).
//! 3. Before B's first prefetch tick fires, look up the latest event
//!    in `events/<name>/`. If it's a clean `Released` signed by A and
//!    A has published a peer-fetch endpoint, resolve and return it.
//!
//! Every failure path collapses to `None` — the prefetch loop falls
//! through to S3 silently. The discovery flow adds zero new state,
//! introduces no new artifacts, and is best-effort by design (per
//! `docs/design-peer-segment-fetch.md` § "Discovery").
//!
//! Importantly, `force_released` is **not** a valid handoff signal:
//! the emitter of a `force_released` event is the *recovering*
//! coordinator, not the coordinator that previously held the volume's
//! cache warm. Attempting to peer-fetch from the recovering host
//! gives nothing; the only sensible fallback in that case is direct
//! S3, which is exactly what `None` selects.

use std::sync::Arc;

use elide_core::volume_event::EventKind;
use elide_peer_fetch::PeerEndpoint;
use object_store::ObjectStore;
use tracing::debug;

use crate::ipc::SignatureStatus;
use crate::volume_event_store::list_and_verify_events;

/// Result of discovery: who the previous claimer was, plus where to
/// reach them. Returned by [`discover_peer_for_claim`].
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Coordinator id of the previous (cleanly-released) claimer.
    pub coordinator_id: String,
    /// Reachable endpoint advertised by that coordinator at
    /// `coordinators/<id>/peer-endpoint.toml`.
    pub endpoint: PeerEndpoint,
}

/// Look up the previous claimer of `volume_name` via the volume event
/// log and resolve their peer-fetch endpoint. Returns `Some` only when
/// every step of the happy path succeeds; any failure (no events,
/// missing/invalid signature, non-`Released` latest event, no
/// published endpoint, store error) collapses to `None`.
///
/// The caller — typically the per-volume task at startup — uses the
/// returned peer as a one-shot warming hint for the next prefetch
/// tick. Subsequent prefetch ticks within the same volume task run
/// peer-less; this discovery is intentionally not persisted across
/// runs (the design doc explicitly puts persistent peer-fetch hints
/// out of scope for v1).
pub async fn discover_peer_for_claim(
    store: &Arc<dyn ObjectStore>,
    volume_name: &str,
) -> Option<DiscoveredPeer> {
    let entries = match list_and_verify_events(store, volume_name).await {
        Ok(e) => e,
        Err(e) => {
            debug!("[peer-discovery {volume_name}] event log read failed; skip peer: {e}");
            return None;
        }
    };

    // Latest event by ULID order — `list_and_verify_events` returns
    // entries sorted ascending, so the back of the list is the most
    // recent.
    let latest = entries.last()?;

    if latest.signature_status != SignatureStatus::Valid {
        debug!(
            "[peer-discovery {volume_name}] latest event signature is {:?}; skip peer",
            latest.signature_status
        );
        return None;
    }

    let coord_id = match &latest.event.kind {
        EventKind::Released { .. } => latest.event.coordinator_id.clone(),
        // `ForceReleased` carries the recovering coordinator's id, not
        // the previous owner's — and the whole point of force-release
        // is "the previous owner is gone." S3 is the only sensible
        // fallback. All other kinds (Created, Claimed, ForkedFrom,
        // RenamedTo, RenamedFrom) imply no prior cleanly-released
        // owner to peer-fetch from.
        other => {
            debug!(
                "[peer-discovery {volume_name}] latest event is {}; skip peer",
                other.as_str()
            );
            return None;
        }
    };

    let endpoint = match PeerEndpoint::fetch(store.as_ref(), &coord_id).await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            debug!(
                "[peer-discovery {volume_name}] previous claimer {coord_id} has no published \
                 peer-endpoint; skip peer"
            );
            return None;
        }
        Err(e) => {
            debug!(
                "[peer-discovery {volume_name}] resolving endpoint for {coord_id}: {e}; skip peer"
            );
            return None;
        }
    };

    debug!(
        "[peer-discovery {volume_name}] previous claimer {coord_id} reachable at {}",
        endpoint.url()
    );
    Some(DiscoveredPeer {
        coordinator_id: coord_id,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CoordinatorIdentity;
    use crate::volume_event_store::emit_event;
    use elide_core::volume_event::EventKind;
    use object_store::memory::InMemory;
    use tempfile::TempDir;
    use ulid::Ulid;

    async fn store() -> Arc<dyn ObjectStore> {
        Arc::new(InMemory::new())
    }

    /// Build a coordinator identity in a fresh tempdir, publish its
    /// pubkey to the in-memory store at the canonical key, and return
    /// the identity.
    async fn make_coord(store: &Arc<dyn ObjectStore>) -> (CoordinatorIdentity, TempDir) {
        let dir = TempDir::new().unwrap();
        let ident = CoordinatorIdentity::load_or_generate(dir.path()).unwrap();
        ident.publish_pub(store.as_ref()).await.unwrap();
        (ident, dir)
    }

    #[tokio::test]
    async fn returns_none_when_event_log_is_empty() {
        let store = store().await;
        let result = discover_peer_for_claim(&store, "missing-vol").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_some_for_clean_released_with_endpoint() {
        let store = store().await;
        let (ident, _tmp) = make_coord(&store).await;
        let coord_id = ident.coordinator_id_str().to_owned();

        // Emit Created → Released, both signed by the same coord.
        let vol_ulid = Ulid::new();
        emit_event(&store, &ident, "vol", EventKind::Created, vol_ulid)
            .await
            .unwrap();
        emit_event(
            &store,
            &ident,
            "vol",
            EventKind::Released {
                handoff_snapshot: Ulid::new(),
            },
            vol_ulid,
        )
        .await
        .unwrap();

        // Publish the peer-endpoint for this coordinator.
        PeerEndpoint::new("10.0.0.42".to_owned(), 8443)
            .publish(store.as_ref(), &coord_id)
            .await
            .unwrap();

        let discovered = discover_peer_for_claim(&store, "vol")
            .await
            .expect("peer discovered");
        assert_eq!(discovered.coordinator_id, coord_id);
        assert_eq!(discovered.endpoint.url(), "http://10.0.0.42:8443");
    }

    #[tokio::test]
    async fn returns_none_when_latest_event_is_not_released() {
        let store = store().await;
        let (ident, _tmp) = make_coord(&store).await;
        let vol_ulid = Ulid::new();
        emit_event(&store, &ident, "vol", EventKind::Created, vol_ulid)
            .await
            .unwrap();
        emit_event(&store, &ident, "vol", EventKind::Claimed, vol_ulid)
            .await
            .unwrap();
        // No Released event — latest is Claimed, which means the
        // volume is still owned. No peer-fetch handoff applies.

        let result = discover_peer_for_claim(&store, "vol").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_none_for_force_released() {
        let store = store().await;
        let (ident, _tmp) = make_coord(&store).await;
        let vol_ulid = Ulid::new();
        emit_event(&store, &ident, "vol", EventKind::Created, vol_ulid)
            .await
            .unwrap();
        // ForceReleased — the emitter is the recovering coordinator,
        // not the previous owner; peer-fetch must fall back to S3.
        emit_event(
            &store,
            &ident,
            "vol",
            EventKind::ForceReleased {
                handoff_snapshot: Ulid::new(),
                displaced_coordinator_id: "old-coord".to_owned(),
            },
            vol_ulid,
        )
        .await
        .unwrap();

        let result = discover_peer_for_claim(&store, "vol").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_none_when_endpoint_not_published() {
        let store = store().await;
        let (ident, _tmp) = make_coord(&store).await;
        let vol_ulid = Ulid::new();
        emit_event(&store, &ident, "vol", EventKind::Created, vol_ulid)
            .await
            .unwrap();
        emit_event(
            &store,
            &ident,
            "vol",
            EventKind::Released {
                handoff_snapshot: Ulid::new(),
            },
            vol_ulid,
        )
        .await
        .unwrap();
        // Skip publishing the peer-endpoint — coordinator either
        // didn't enable peer-fetch or hasn't started yet.

        let result = discover_peer_for_claim(&store, "vol").await;
        assert!(result.is_none());
    }
}
