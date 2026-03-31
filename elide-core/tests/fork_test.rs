// Deterministic integration tests for fork ancestry isolation.
//
// For property-based fork tests see fork_proptest.rs.

use std::path::PathBuf;

use elide_core::volume::{Volume, fork_volume};

mod common;

/// Verifies isolation across a three-level ancestry chain: base → child → grandchild.
///
/// Each level writes to distinct LBAs and takes a snapshot before forking.
/// After creating the grandchild, post-branch writes are made at the base and
/// child levels, then the grandchild is crashed and reopened.
///
/// Expected reads from grandchild after crash+rebuild:
///   LBAs 0-1  base values (pre-branch from base)
///   LBAs 2-3  child values (pre-branch from child)
///   LBAs 4-5  grandchild's own values
///   LBAs 6-7  zero (written to base/child post-branch; invisible to grandchild)
#[test]
fn three_level_fork_isolation() {
    let dir = tempfile::TempDir::new().unwrap();
    let volume_dir = dir.path();
    let base_dir: PathBuf = volume_dir.join("base");

    // --- base level ---
    let mut base = Volume::open(&base_dir).unwrap();
    base.write(0, &[0xAA; 4096]).unwrap();
    base.write(1, &[0xBB; 4096]).unwrap();
    base.flush_wal().unwrap();
    base.snapshot().unwrap();

    let child_dir = fork_volume(volume_dir, "child", "base").unwrap();

    // Post-branch base write — must be invisible to child and grandchild.
    base.write(6, &[0xDE; 4096]).unwrap();
    base.flush_wal().unwrap();

    // --- child level ---
    let mut child = Volume::open(&child_dir).unwrap();
    child.write(2, &[0xCC; 4096]).unwrap();
    child.write(3, &[0xDD; 4096]).unwrap();
    child.flush_wal().unwrap();
    child.snapshot().unwrap();

    let grandchild_dir = fork_volume(volume_dir, "grandchild", "child").unwrap();

    // Post-branch child write — must be invisible to grandchild.
    child.write(7, &[0xEF; 4096]).unwrap();
    child.flush_wal().unwrap();

    // --- grandchild level ---
    let mut gc = Volume::open(&grandchild_dir).unwrap();
    gc.write(4, &[0xEE; 4096]).unwrap();
    gc.write(5, &[0xFF; 4096]).unwrap();
    gc.flush_wal().unwrap();

    // Crash + reopen grandchild — walk_ancestors must traverse two levels.
    drop(gc);
    let gc = Volume::open(&grandchild_dir).unwrap();

    // Ancestral data visible.
    assert_eq!(gc.read(0, 1).unwrap(), vec![0xAA; 4096], "lba 0 (base)");
    assert_eq!(gc.read(1, 1).unwrap(), vec![0xBB; 4096], "lba 1 (base)");
    assert_eq!(gc.read(2, 1).unwrap(), vec![0xCC; 4096], "lba 2 (child)");
    assert_eq!(gc.read(3, 1).unwrap(), vec![0xDD; 4096], "lba 3 (child)");

    // Grandchild's own writes visible.
    assert_eq!(
        gc.read(4, 1).unwrap(),
        vec![0xEE; 4096],
        "lba 4 (grandchild)"
    );
    assert_eq!(
        gc.read(5, 1).unwrap(),
        vec![0xFF; 4096],
        "lba 5 (grandchild)"
    );

    // Post-branch writes at base and child levels must be invisible.
    assert_eq!(
        gc.read(6, 1).unwrap(),
        vec![0u8; 4096],
        "lba 6 (post-branch base write)"
    );
    assert_eq!(
        gc.read(7, 1).unwrap(),
        vec![0u8; 4096],
        "lba 7 (post-branch child write)"
    );
}
