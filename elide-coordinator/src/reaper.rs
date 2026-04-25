// Pending-delete reaper.
//
// Coordinator-wide ticker that walks each owned volume's
// `pending-delete/` prefix, validates each marker through the
// three-checkpoint flow, and deletes the listed S3 keys + the marker
// itself when the retention window has elapsed.
//
// See `docs/design-replica-model.md` (Reaper / Target validation /
// Cadence and dispatch) for the surrounding design.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::TryStreamExt;
use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use tracing::{debug, info, warn};
use ulid::Ulid;

use crate::pending_delete::{
    MAX_TARGETS_PER_MARKER, PendingDeleteMarker, parse_marker_key, parse_target,
};

/// Spawn the coordinator-wide reaper ticker.
///
/// Cadence is `gc_config.reaper_cadence()` — see `GcConfig`. The ticker
/// runs forever until the spawning task is dropped.
pub fn start(store: Arc<dyn ObjectStore>, data_dir: PathBuf, cadence: Duration) {
    tokio::spawn(async move {
        // tokio::time alias used by the rest of the crate. `MissedTickBehavior`
        // here must come from `tokio::time` to match `interval`'s type.
        let mut tick = tokio::time::interval(cadence);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            tick_once(&store, &data_dir).await;
        }
    });
}

/// One tick. Discovers owned volumes under `data_dir`, spawns one
/// non-blocking reap operation per volume, returns immediately.
async fn tick_once(store: &Arc<dyn ObjectStore>, data_dir: &Path) {
    for vol_dir in owned_volumes(data_dir) {
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(e) = reap_volume(&store, &vol_dir).await {
                warn!("[reaper {}] reap failed: {e:#}", vol_dir.display(),);
            }
        });
    }
}

/// Run one reap pass against a single owned volume.
///
/// Errors here are advisory — the caller logs and moves on. The next
/// tick re-lists the prefix and retries any marker that survived.
pub async fn reap_volume(store: &Arc<dyn ObjectStore>, vol_dir: &Path) -> anyhow::Result<()> {
    let vol_ulid = volume_ulid(vol_dir)?;
    reap_volume_inner(store, vol_ulid, SystemTime::now()).await
}

async fn reap_volume_inner(
    store: &Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
    now: SystemTime,
) -> anyhow::Result<()> {
    let prefix = StorePath::from(format!("by_id/{vol_ulid}/pending-delete"));
    let listing: Vec<_> = store
        .list(Some(&prefix))
        .try_collect()
        .await
        .map_err(|e| anyhow::anyhow!("listing {prefix}: {e}"))?;

    for object in listing {
        let key = object.location.as_ref().to_owned();
        if let Err(e) = process_marker(store, vol_ulid, &key, now).await {
            warn!("[reaper {vol_ulid}] skipping marker {key}: {e}");
        }
    }
    Ok(())
}

/// Process one marker. Returns `Err` if the marker should be left in
/// place (validation failure, parse error, or transient S3 error). Any
/// `Err` is purely advisory — the caller logs and the next tick retries.
async fn process_marker(
    store: &Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
    key: &str,
    now: SystemTime,
) -> anyhow::Result<()> {
    // Checkpoint 2: marker-path-parsed volume must equal the invocation ULID.
    let (path_vol, marker_ulid) =
        parse_marker_key(key).map_err(|e| anyhow::anyhow!("parsing marker key: {e}"))?;
    if path_vol != vol_ulid {
        anyhow::bail!("marker path volume {path_vol} does not match invocation {vol_ulid}");
    }

    if !is_expired(marker_ulid, now) {
        debug!("[reaper {vol_ulid}] {marker_ulid} not yet expired; skipping");
        return Ok(());
    }

    // GET, parse, validate.
    let store_key = StorePath::from(key.to_owned());
    let body = store
        .get(&store_key)
        .await
        .map_err(|e| anyhow::anyhow!("fetching marker: {e}"))?
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("reading marker body: {e}"))?;
    let text =
        std::str::from_utf8(&body).map_err(|e| anyhow::anyhow!("marker body not utf-8: {e}"))?;
    let marker = PendingDeleteMarker::from_toml(text)
        .map_err(|e| anyhow::anyhow!("parsing marker toml: {e}"))?;

    if marker.targets.len() > MAX_TARGETS_PER_MARKER {
        anyhow::bail!(
            "marker has {} targets, exceeds cap {MAX_TARGETS_PER_MARKER}",
            marker.targets.len(),
        );
    }

    // Re-check expiry against the stamped retention now that we have it.
    // The deadline is `ulid_timestamp(marker_ulid) + retention`. The
    // earlier `is_expired` check used a placeholder zero-retention proxy
    // (just the ULID timestamp); now we tighten with the real retention.
    let deadline = marker_creation_time(marker_ulid)? + marker.retention;
    if now < deadline {
        debug!("[reaper {vol_ulid}] {marker_ulid} not yet at deadline; skipping");
        return Ok(());
    }

    // Checkpoint 3: parse every target against the invocation ULID before
    // any deletion fires. A single failure rejects the whole marker.
    let mut parsed = Vec::with_capacity(marker.targets.len());
    for raw in &marker.targets {
        let target = parse_target(raw, vol_ulid)
            .map_err(|e| anyhow::anyhow!("invalid target {raw}: {e}"))?;
        parsed.push(target);
    }

    // All checks passed: delete every target, then the marker itself.
    // Order matters — see `docs/design-replica-model.md` (Reaper).
    for target in &parsed {
        let target_key = target.to_key();
        match store.delete(&target_key).await {
            Ok(_) => {}
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => anyhow::bail!("deleting target {target_key}: {e}"),
        }
    }
    match store.delete(&store_key).await {
        Ok(_) => {}
        Err(object_store::Error::NotFound { .. }) => {}
        Err(e) => anyhow::bail!("deleting marker {key}: {e}"),
    }
    info!(
        "[reaper {vol_ulid}] reaped marker {marker_ulid} ({} target(s))",
        parsed.len(),
    );
    Ok(())
}

/// Cheap pre-check: `now > ulid_timestamp(marker_ulid)`. Always true
/// after the millisecond the marker was minted; the real expiry check
/// (against the stamped retention) happens after the marker body is
/// parsed. This skips the GET for markers whose ULID is somehow in the
/// future of the reaper's clock — defensive against clock skew.
fn is_expired(marker_ulid: Ulid, now: SystemTime) -> bool {
    match marker_creation_time(marker_ulid) {
        Ok(t) => now >= t,
        Err(_) => false,
    }
}

fn marker_creation_time(marker_ulid: Ulid) -> anyhow::Result<SystemTime> {
    let ms = marker_ulid.timestamp_ms();
    Ok(UNIX_EPOCH + Duration::from_millis(ms))
}

/// Walk `<data_dir>/by_id/` and return paths to volumes the local
/// coordinator owns as a writer — i.e. directories whose name parses as
/// a ULID and that lack a `volume.readonly` marker.
///
/// Read-only references (cheap-reference replicas of upstream volumes)
/// have no S3 write authority; the upstream's own coordinator reaps
/// their prefixes. See *Scope* in `docs/design-replica-model.md`.
fn owned_volumes(data_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let by_id = data_dir.join("by_id");
    let entries = match std::fs::read_dir(&by_id) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            warn!("[reaper] cannot read {}: {e}", by_id.display());
            return out;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if Ulid::from_string(name).is_err() {
            continue;
        }
        if path.join("volume.readonly").exists() {
            continue;
        }
        out.push(path);
    }
    out
}

fn volume_ulid(vol_dir: &Path) -> anyhow::Result<Ulid> {
    let name = vol_dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("vol dir has no name: {}", vol_dir.display()))?;
    Ulid::from_string(name)
        .map_err(|e| anyhow::anyhow!("vol dir name is not a valid ULID '{name}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending_delete::{PendingDeleteMarker, Reason, marker_key};
    use bytes::Bytes;
    use object_store::PutPayload;
    use object_store::memory::InMemory;
    use ulid::Ulid;

    fn vol_id() -> Ulid {
        Ulid::from_string("01J0000000000000000000000V").unwrap()
    }

    fn seg_at(ms_offset: u64) -> Ulid {
        Ulid::from_parts(1_700_000_000_000 + ms_offset, 42)
    }

    fn marker_at(ms: u64) -> Ulid {
        Ulid::from_parts(ms, 99)
    }

    async fn write_marker(store: &Arc<dyn ObjectStore>, vol: Ulid, marker: Ulid, body: &str) {
        let k = marker_key(vol, marker);
        store
            .put(&k, PutPayload::from(Bytes::from(body.to_owned())))
            .await
            .unwrap();
    }

    async fn put_segment(store: &Arc<dyn ObjectStore>, vol: Ulid, seg: Ulid) -> StorePath {
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let key = StorePath::from(format!("by_id/{vol}/segments/{date}/{seg}"));
        store
            .put(&key, PutPayload::from(Bytes::from_static(b"seg-body")))
            .await
            .unwrap();
        key
    }

    fn store() -> Arc<dyn ObjectStore> {
        Arc::new(InMemory::new())
    }

    #[tokio::test]
    async fn reaps_expired_marker_and_targets() {
        let store = store();
        let vol = vol_id();
        let seg = seg_at(0);
        let target_key = put_segment(&store, vol, seg).await;

        // marker ULID is at t=1_700_000_000_000 ms, retention = 1s
        let marker = marker_at(1_700_000_000_000);
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let body = PendingDeleteMarker {
            retention: Duration::from_secs(1),
            reason: Reason::GcInput,
            targets: vec![format!("by_id/{vol}/segments/{date}/{seg}")],
        }
        .to_toml()
        .unwrap();
        write_marker(&store, vol, marker, &body).await;

        // now well past deadline
        let now = UNIX_EPOCH + Duration::from_millis(1_700_000_010_000);
        reap_volume_inner(&store, vol, now).await.unwrap();

        // segment gone, marker gone
        assert!(matches!(
            store.head(&target_key).await,
            Err(object_store::Error::NotFound { .. })
        ));
        assert!(matches!(
            store.head(&marker_key(vol, marker)).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn leaves_unexpired_marker_alone() {
        let store = store();
        let vol = vol_id();
        let seg = seg_at(0);
        let target_key = put_segment(&store, vol, seg).await;

        let marker = marker_at(1_700_000_000_000);
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let body = PendingDeleteMarker {
            retention: Duration::from_secs(3600),
            reason: Reason::GcInput,
            targets: vec![format!("by_id/{vol}/segments/{date}/{seg}")],
        }
        .to_toml()
        .unwrap();
        write_marker(&store, vol, marker, &body).await;

        // now is one minute after marker creation — well below 1h retention
        let now = UNIX_EPOCH + Duration::from_millis(1_700_000_060_000);
        reap_volume_inner(&store, vol, now).await.unwrap();

        // both still present
        assert!(store.head(&target_key).await.is_ok());
        assert!(store.head(&marker_key(vol, marker)).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_marker_with_cross_volume_target() {
        let store = store();
        let vol = vol_id();
        let other = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let seg = seg_at(0);
        // place segment under the OTHER volume's prefix; the marker is in
        // `vol`'s prefix but lists a target outside its scope.
        let foreign = put_segment(&store, other, seg).await;

        let marker = marker_at(1_700_000_000_000);
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let body = PendingDeleteMarker {
            retention: Duration::from_secs(1),
            reason: Reason::GcInput,
            targets: vec![format!("by_id/{other}/segments/{date}/{seg}")],
        }
        .to_toml()
        .unwrap();
        write_marker(&store, vol, marker, &body).await;

        let now = UNIX_EPOCH + Duration::from_millis(1_700_000_010_000);
        reap_volume_inner(&store, vol, now).await.unwrap();

        // Cross-volume target must NOT have been deleted.
        assert!(store.head(&foreign).await.is_ok());
        // Marker stays in place — operator signal, not silent partial reap.
        assert!(store.head(&marker_key(vol, marker)).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_oversized_marker() {
        let store = store();
        let vol = vol_id();
        let seg = seg_at(0);
        let _victim = put_segment(&store, vol, seg).await;

        let marker = marker_at(1_700_000_000_000);
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let one_target = format!("by_id/{vol}/segments/{date}/{seg}");
        let mut targets = Vec::with_capacity(MAX_TARGETS_PER_MARKER + 1);
        for _ in 0..(MAX_TARGETS_PER_MARKER + 1) {
            targets.push(one_target.clone());
        }
        let body = PendingDeleteMarker {
            retention: Duration::from_secs(1),
            reason: Reason::GcInput,
            targets,
        }
        .to_toml()
        .unwrap();
        write_marker(&store, vol, marker, &body).await;

        let now = UNIX_EPOCH + Duration::from_millis(1_700_000_010_000);
        reap_volume_inner(&store, vol, now).await.unwrap();

        // Marker still present — refused before any delete fired.
        assert!(store.head(&marker_key(vol, marker)).await.is_ok());
    }
}
