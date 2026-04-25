//! Shared test helpers used across the volume module's `#[cfg(test)]`
//! blocks. Compiled only under `cfg(test)`; not part of the public API.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::Volume;

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub(in crate::volume) fn temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("elide-volume-test-{}-{}", std::process::id(), n));
    p
}

/// Simulate coordinator drain: upload all pending segments to S3 (no-op in
/// tests) then call `promote_segment` on each. `promote_segment` writes
/// `index/<ulid>.idx`, copies the body to `cache/`, and deletes `pending/<ulid>`.
pub(in crate::volume) fn simulate_upload(vol: &mut Volume) {
    let pending_dir = vol.base_dir.join("pending");
    for entry in std::fs::read_dir(&pending_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.ends_with(".tmp") {
            continue;
        }
        let ulid = ulid::Ulid::from_string(&name).unwrap();
        vol.promote_segment(ulid).unwrap();
    }
}

/// Generate a keypair and write `volume.key` + `volume.pub` into `dir`.
///
/// Must be called before `Volume::open` in any test that creates a volume.
pub(in crate::volume) fn write_test_keypair(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let key = crate::signing::generate_keypair(
        dir,
        crate::signing::VOLUME_KEY_FILE,
        crate::signing::VOLUME_PUB_FILE,
    )
    .unwrap();
    // Match production volume-setup behaviour: a fresh writable volume
    // also gets a default (root) `volume.provenance`. Skipping this
    // makes `Volume::open` fail in the ancestor walk when another
    // volume forks from this one, because the child's provenance
    // refers back to a volume whose own provenance is missing.
    crate::signing::write_provenance(
        dir,
        &key,
        crate::signing::VOLUME_PROVENANCE_FILE,
        &crate::signing::ProvenanceLineage::default(),
    )
    .unwrap();
}

/// Write a signed `volume.provenance` with the given lineage fields into
/// `dir`. Routes through `write_raw_provenance_for_test` so that
/// syntactically bad `parent_entry` strings can be persisted for
/// parse-error coverage — the file signature is still valid over the raw
/// bytes, so the parse error fires before signature verification.
///
/// When `parent_entry` is `Some`, an all-zero dummy `parent_pubkey` is
/// embedded. Tests that walk the chain only care about structural fields.
pub(in crate::volume) fn write_test_provenance(
    dir: &Path,
    parent_entry: Option<&str>,
    extent_entries: &[&str],
) {
    let (raw_parent, raw_parent_pubkey) = match parent_entry {
        Some(p) => (p.to_owned(), crate::signing::encode_hex(&[0u8; 32])),
        None => (String::new(), String::new()),
    };
    let extent_owned: Vec<String> = extent_entries.iter().map(|s| (*s).to_owned()).collect();
    crate::signing::write_raw_provenance_for_test(
        dir,
        &raw_parent,
        &raw_parent_pubkey,
        &extent_owned,
    )
    .unwrap();
}

/// Create a temp dir and pre-populate it with a test keypair.
///
/// Use in place of `temp_dir()` whenever the dir will be passed directly
/// to `Volume::open`.
pub(in crate::volume) fn keyed_temp_dir() -> PathBuf {
    let dir = temp_dir();
    write_test_keypair(&dir);
    dir
}
