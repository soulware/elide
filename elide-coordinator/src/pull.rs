// Pull a readonly ancestor for a volume from S3 into the local data dir.
//
// A pulled ancestor is the minimal on-disk presence needed for the
// coordinator's prefetch task (and downstream code like `Volume::open`) to
// resolve a child's lineage:
//
//   by_id/<ulid>/
//     volume.readonly          — marker (ancestor, not user-managed)
//     volume.pub               — Ed25519 verifying key
//     volume.provenance        — signed lineage (parent + extent_index)
//     index/                   — empty, populated by `prefetch_indexes`
//
// Ancestors carry no `volume.toml` and no size: per
// `docs/design-volume-size-ownership.md` size lives only on
// `names/<name>` for the live volume, and ancestors are read-only segment
// containers reached through a child's LBA map.
//
// The coordinator uses this to auto-heal ancestor chains when a
// newly-discovered volume references a parent that isn't locally present
// (the "self-healing prefetch" path).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use object_store::ObjectStore;
use object_store::path::Path as StorePath;

/// Pull a readonly ancestor for `volume_id` from the object store into
/// `<data_dir>/by_id/<volume_id>/`. If the directory already exists,
/// returns its path without re-pulling (idempotent — safe to call on every
/// prefetch tick).
///
/// Fetches:
///   - `by_id/<volume_id>/volume.pub`
///   - `by_id/<volume_id>/volume.provenance`
///
/// Writes them into `<data_dir>/by_id/<volume_id>/` along with a
/// `volume.readonly` marker and an empty `index/` directory. No
/// `volume.toml` is written: ancestors carry no size, and the absent
/// `by_name/` symlink marks the entry as a pulled ancestor rather than a
/// user-managed volume.
///
/// Signature verification of the downloaded `volume.provenance` is *not*
/// performed here — the caller is responsible for verifying under the
/// pubkey it trusts (typically embedded in the child's `ParentRef`).
/// Doing verification here would require choosing a key, which the pull
/// API has no context to do safely.
pub async fn pull_volume_skeleton(
    store: &Arc<dyn ObjectStore>,
    data_dir: &Path,
    volume_id: &str,
) -> Result<PathBuf> {
    let vol_dir = data_dir.join("by_id").join(volume_id);
    if vol_dir.exists() {
        return Ok(vol_dir);
    }

    // Two independent GETs — fire concurrently so per-ancestor pull
    // latency is bounded by the slowest, not the sum.
    let pub_key = StorePath::from(format!("by_id/{volume_id}/volume.pub"));
    let provenance_key = StorePath::from(format!(
        "by_id/{volume_id}/{}",
        elide_core::signing::VOLUME_PROVENANCE_FILE
    ));
    let (pub_bytes, provenance_bytes) = tokio::try_join!(
        fetch_bytes(store, &pub_key, "volume.pub", volume_id),
        fetch_bytes(
            store,
            &provenance_key,
            elide_core::signing::VOLUME_PROVENANCE_FILE,
            volume_id,
        ),
    )?;

    std::fs::create_dir_all(&vol_dir).with_context(|| format!("creating {}", vol_dir.display()))?;
    std::fs::write(vol_dir.join("volume.readonly"), "")
        .with_context(|| format!("writing volume.readonly for {volume_id}"))?;
    std::fs::write(vol_dir.join("volume.pub"), &pub_bytes)
        .with_context(|| format!("writing volume.pub for {volume_id}"))?;
    std::fs::write(
        vol_dir.join(elide_core::signing::VOLUME_PROVENANCE_FILE),
        &provenance_bytes,
    )
    .with_context(|| format!("writing volume.provenance for {volume_id}"))?;
    std::fs::create_dir_all(vol_dir.join("index"))
        .with_context(|| format!("creating index/ for {volume_id}"))?;

    Ok(vol_dir)
}

async fn fetch_bytes(
    store: &Arc<dyn ObjectStore>,
    key: &StorePath,
    what: &str,
    volume_id: &str,
) -> Result<bytes::Bytes> {
    let resp = store
        .get(key)
        .await
        .with_context(|| format!("downloading {what} for {volume_id}"))?;
    resp.bytes()
        .await
        .with_context(|| format!("reading {what} for {volume_id}"))
}
