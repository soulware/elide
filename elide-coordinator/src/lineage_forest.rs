//! The local lineage forest: every `by_id/<ulid>/` directory classified
//! as an anchor or a skeleton, joined by fork-parent edges, with
//! reachability computed from the anchors' lineage walks
//! (`docs/design/ancestor-liveness.md`).
//!
//! One computation, three consumers: `volume tree` renders it, the
//! sweep deletes skeletons it marks unreachable, the heal pass re-pulls
//! ancestors it marks missing.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::volume_state::{CLAIMING_FILE, IMPORTING_FILE, VolumeLifecycle};
use elide_core::signing::{
    VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE, read_lineage_verifying_signature,
};

/// Ownership class of a `by_id/` directory. Deliberately carries no
/// topological claim — an anchor can sit anywhere in the lineage tree;
/// "root" stays reserved for lineage topology (`ProvenanceLineage::Root`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    /// Explicitly owned: `volume.key`, a `by_name` binding, or an
    /// in-flight marker (`volume.claiming`, `volume.importing`).
    /// Never swept; removed only by verb.
    Anchor,
    /// `volume.readonly`-marked with none of the anchor markers: a
    /// pulled ancestor or a demoted removal. Live only while reachable
    /// from an anchor's lineage.
    Skeleton,
    /// A directory carrying neither anchor markers nor the readonly
    /// marker. Not a shape the lifecycle verbs produce; shown so the
    /// operator sees it, never swept.
    Unclassified,
    /// No directory: the ULID is referenced by a present node's
    /// provenance (or reachable from an anchor's lineage) but absent
    /// from `by_id/`. A heal candidate when live.
    Missing,
}

/// A fork-parent edge: the parent volume and the snapshot the child
/// branched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentEdge {
    pub ulid: Ulid,
    pub snapshot: Ulid,
}

#[derive(Debug, Clone)]
pub struct ForestNode {
    pub ulid: Ulid,
    /// `by_name` binding, when one points at this directory.
    pub name: Option<String>,
    pub class: NodeClass,
    /// On-disk lifecycle for display. `None` for `Missing` nodes.
    pub lifecycle: Option<VolumeLifecycle>,
    pub parent: Option<ParentEdge>,
    /// Count of `extent_index` cross-edges in this volume's provenance.
    pub extent_sources: usize,
    /// Count of transient `recovery_sources` grants in this volume's
    /// provenance (forced-claim re-own in flight).
    pub recovery_sources: usize,
    /// Why this node's provenance (or an anchor's lineage walk) could
    /// not be read. The node still appears, without edges.
    pub lineage_error: Option<String>,
    /// Anchors are live by definition. A skeleton or missing node is
    /// live iff some anchor's `lineage_ulids` reaches it: a dead
    /// skeleton is the sweep's target, a live missing node the heal's.
    pub live: bool,
}

pub struct LineageForest {
    /// All nodes, sorted by ULID (which sorts by mint time).
    pub nodes: Vec<ForestNode>,
    /// Each anchor's full lineage walk, kept so per-target questions
    /// ("who references this?") don't re-walk the disk.
    anchor_chains: Vec<(Ulid, HashSet<Ulid>)>,
}

impl LineageForest {
    pub fn get(&self, ulid: Ulid) -> Option<&ForestNode> {
        self.nodes
            .binary_search_by_key(&ulid, |n| n.ulid)
            .ok()
            .map(|i| &self.nodes[i])
    }

    /// Anchors whose lineage walk reaches `target`, excluding `target`
    /// itself. Non-empty means the target's directory is load-bearing:
    /// `remove` demotes it to a skeleton instead of deleting it.
    pub fn referencing_anchors(&self, target: Ulid) -> Vec<Ulid> {
        self.anchor_chains
            .iter()
            .filter(|(anchor, chain)| *anchor != target && chain.contains(&target))
            .map(|(anchor, _)| *anchor)
            .collect()
    }
}

/// `by_name/<name>` bindings, resolved to the ULID each symlink's
/// target directory is named for. Names are visited in sorted order so
/// the (pathological) case of two names pointing at one directory
/// resolves deterministically to the lexicographically first.
fn name_bindings(data_dir: &Path) -> io::Result<BTreeMap<Ulid, String>> {
    let by_name = data_dir.join("by_name");
    let mut names: Vec<(String, PathBuf)> = Vec::new();
    match std::fs::read_dir(&by_name) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let target = std::fs::read_link(entry.path()).unwrap_or_else(|_| entry.path());
                let target = if target.is_absolute() {
                    target
                } else {
                    by_name.join(target)
                };
                names.push((name, target));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut bindings = BTreeMap::new();
    for (name, target) in names {
        if let Some(ulid) = target
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| Ulid::from_string(s).ok())
        {
            bindings.entry(ulid).or_insert(name);
        }
    }
    Ok(bindings)
}

/// Build the forest for `data_dir`: scan `by_id/`, classify each
/// directory, read its fork-parent edge, walk every anchor's lineage
/// for reachability, and synthesize `Missing` nodes for referenced
/// ULIDs with no directory.
///
/// Per-directory problems (unreadable provenance, failed lineage walk)
/// are recorded on the node as `lineage_error`, never propagated — a
/// mid-claim fork must not take the whole forest down with it.
pub fn build_forest(data_dir: &Path) -> io::Result<LineageForest> {
    let by_id = data_dir.join("by_id");
    let names = name_bindings(data_dir)?;

    let mut nodes: BTreeMap<Ulid, ForestNode> = BTreeMap::new();
    let mut anchor_dirs: Vec<(Ulid, PathBuf)> = Vec::new();

    match std::fs::read_dir(&by_id) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                let Some(ulid) = dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|s| Ulid::from_string(s).ok())
                else {
                    continue;
                };

                let name = names.get(&ulid).cloned();
                let is_anchor = dir.join(VOLUME_KEY_FILE).exists()
                    || name.is_some()
                    || dir.join(CLAIMING_FILE).exists()
                    || dir.join(IMPORTING_FILE).exists();
                let class = if is_anchor {
                    NodeClass::Anchor
                } else if dir.join("volume.readonly").exists() {
                    NodeClass::Skeleton
                } else {
                    NodeClass::Unclassified
                };

                let mut node = ForestNode {
                    ulid,
                    name,
                    class,
                    lifecycle: Some(VolumeLifecycle::from_dir(&dir)),
                    parent: None,
                    extent_sources: 0,
                    recovery_sources: 0,
                    lineage_error: None,
                    live: is_anchor,
                };

                if dir.join(VOLUME_PROVENANCE_FILE).exists() {
                    match read_lineage_verifying_signature(
                        &dir,
                        VOLUME_PUB_FILE,
                        VOLUME_PROVENANCE_FILE,
                    ) {
                        Ok(lineage) => {
                            node.extent_sources = lineage.extent_index().len();
                            node.recovery_sources = lineage.recovery_sources().len();
                            if let Some(parent) = lineage.parent() {
                                match (
                                    Ulid::from_string(&parent.volume_ulid),
                                    Ulid::from_string(&parent.snapshot_ulid),
                                ) {
                                    (Ok(p), Ok(snap)) => {
                                        node.parent = Some(ParentEdge {
                                            ulid: p,
                                            snapshot: snap,
                                        });
                                    }
                                    _ => {
                                        node.lineage_error = Some(format!(
                                            "malformed parent ref: {}",
                                            parent.to_display()
                                        ));
                                    }
                                }
                            }
                        }
                        Err(e) => node.lineage_error = Some(e.to_string()),
                    }
                }

                if is_anchor {
                    anchor_dirs.push((ulid, dir.clone()));
                }
                nodes.insert(ulid, node);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // Reachability: the union of every anchor's lineage walk. A walk
    // that fails (malformed entry mid-chain) is recorded on the anchor;
    // its reachable ancestors then go uncounted, which errs toward
    // showing skeletons as unreferenced rather than hiding the fault.
    let mut reachable: HashSet<Ulid> = HashSet::new();
    let mut anchor_chains: Vec<(Ulid, HashSet<Ulid>)> = Vec::new();
    for (ulid, dir) in &anchor_dirs {
        match elide_core::volume::lineage_ulids(dir, &by_id) {
            Ok(chain) => {
                reachable.extend(chain.iter().copied());
                anchor_chains.push((*ulid, chain.into_iter().collect()));
            }
            Err(e) => {
                if let Some(node) = nodes.get_mut(ulid)
                    && node.lineage_error.is_none()
                {
                    node.lineage_error = Some(format!("lineage walk: {e}"));
                }
            }
        }
    }

    // Synthesize Missing nodes: every ULID referenced by a present
    // node's parent edge or reachable from an anchor, with no
    // directory in by_id/.
    let referenced: Vec<Ulid> = nodes
        .values()
        .filter_map(|n| n.parent.as_ref().map(|p| p.ulid))
        .chain(reachable.iter().copied())
        .collect();
    for ulid in referenced {
        nodes.entry(ulid).or_insert(ForestNode {
            ulid,
            name: None,
            class: NodeClass::Missing,
            lifecycle: None,
            parent: None,
            extent_sources: 0,
            recovery_sources: 0,
            lineage_error: None,
            live: false,
        });
    }

    for node in nodes.values_mut() {
        if !node.live {
            node.live = reachable.contains(&node.ulid);
        }
    }

    Ok(LineageForest {
        nodes: nodes.into_values().collect(),
        anchor_chains,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::signing::{ParentRef, ProvenanceLineage, generate_keypair, write_provenance};

    const A: &str = "01AAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "01BBBBBBBBBBBBBBBBBBBBBBBB";
    const C: &str = "01CCCCCCCCCCCCCCCCCCCCCCCC";
    const SNAP: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn temp_data_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("forest-test-{}", Ulid::new()));
        std::fs::create_dir_all(dir.join("by_id")).unwrap();
        std::fs::create_dir_all(dir.join("by_name")).unwrap();
        dir
    }

    fn ulid(s: &str) -> Ulid {
        Ulid::from_string(s).unwrap()
    }

    /// Mint a keyed dir with signed provenance; returns its verifying
    /// key bytes for embedding in children's ParentRefs.
    fn mint_volume(data_dir: &Path, ulid_str: &str, lineage: &ProvenanceLineage) -> [u8; 32] {
        let dir = data_dir.join("by_id").join(ulid_str);
        std::fs::create_dir_all(&dir).unwrap();
        let key = generate_keypair(&dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();
        write_provenance(&dir, &key, VOLUME_PROVENANCE_FILE, lineage).unwrap();
        key.verifying_key().to_bytes()
    }

    /// Strip a keyed dir down to skeleton shape: drop the key, add the
    /// readonly marker.
    fn demote_to_skeleton(data_dir: &Path, ulid_str: &str) {
        let dir = data_dir.join("by_id").join(ulid_str);
        std::fs::remove_file(dir.join(VOLUME_KEY_FILE)).unwrap();
        std::fs::write(dir.join("volume.readonly"), "").unwrap();
    }

    fn bind_name(data_dir: &Path, name: &str, ulid_str: &str) {
        std::os::unix::fs::symlink(
            data_dir.join("by_id").join(ulid_str),
            data_dir.join("by_name").join(name),
        )
        .unwrap();
    }

    fn parent_ref(ulid_str: &str, pubkey: [u8; 32]) -> ParentRef {
        ParentRef {
            volume_ulid: ulid_str.to_owned(),
            snapshot_ulid: SNAP.to_owned(),
            pubkey,
        }
    }

    #[test]
    fn keyless_root_volume_is_root_anchor() {
        // A keyed root volume with no provenance at all (pre-first-fork
        // shape) classifies as an anchor with no edges.
        let data_dir = temp_data_dir();
        let dir = data_dir.join("by_id").join(A);
        std::fs::create_dir_all(&dir).unwrap();
        generate_keypair(&dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();

        let forest = build_forest(&data_dir).unwrap();
        assert_eq!(forest.nodes.len(), 1);
        let node = forest.get(ulid(A)).unwrap();
        assert_eq!(node.class, NodeClass::Anchor);
        assert!(node.live);
        assert!(node.parent.is_none());
    }

    #[test]
    fn skeleton_live_iff_reachable_from_anchor() {
        // A (skeleton) ← B (anchor fork of A): A is live.
        // C (skeleton, unreferenced): dead — the sweep's target.
        let data_dir = temp_data_dir();
        let a_pub = mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote_to_skeleton(&data_dir, A);
        mint_volume(&data_dir, B, &ProvenanceLineage::fork(parent_ref(A, a_pub)));
        mint_volume(&data_dir, C, &ProvenanceLineage::root());
        demote_to_skeleton(&data_dir, C);

        let forest = build_forest(&data_dir).unwrap();
        let a = forest.get(ulid(A)).unwrap();
        assert_eq!(a.class, NodeClass::Skeleton);
        assert!(a.live, "A is B's parent and must be live");
        let b = forest.get(ulid(B)).unwrap();
        assert_eq!(b.class, NodeClass::Anchor);
        assert_eq!(
            b.parent,
            Some(ParentEdge {
                ulid: ulid(A),
                snapshot: ulid(SNAP)
            })
        );
        let c = forest.get(ulid(C)).unwrap();
        assert_eq!(c.class, NodeClass::Skeleton);
        assert!(!c.live, "unreferenced skeleton is sweepable");
    }

    #[test]
    fn missing_parent_synthesized_and_live() {
        // B (anchor) forks from A, but A has no directory: the incident
        // shape. A appears as a live Missing node — a heal candidate.
        let data_dir = temp_data_dir();
        mint_volume(
            &data_dir,
            B,
            &ProvenanceLineage::fork(parent_ref(A, [0u8; 32])),
        );

        let forest = build_forest(&data_dir).unwrap();
        let a = forest.get(ulid(A)).unwrap();
        assert_eq!(a.class, NodeClass::Missing);
        assert!(a.live, "missing but anchored-to: heal candidate");
        assert!(a.lifecycle.is_none());
    }

    #[test]
    fn grandparent_reachability_through_skeleton_chain() {
        // A (skeleton) ← B (skeleton) ← C (anchor): both ancestors live
        // via C's full-chain walk.
        let data_dir = temp_data_dir();
        let a_pub = mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote_to_skeleton(&data_dir, A);
        let b_pub = mint_volume(&data_dir, B, &ProvenanceLineage::fork(parent_ref(A, a_pub)));
        demote_to_skeleton(&data_dir, B);
        mint_volume(&data_dir, C, &ProvenanceLineage::fork(parent_ref(B, b_pub)));

        let forest = build_forest(&data_dir).unwrap();
        assert!(forest.get(ulid(A)).unwrap().live);
        assert!(forest.get(ulid(B)).unwrap().live);
    }

    #[test]
    fn name_binding_makes_keyless_dir_an_anchor() {
        // An imported readonly base: readonly marker + by_name binding.
        // The binding anchors it (never swept) even without volume.key.
        let data_dir = temp_data_dir();
        mint_volume(&data_dir, A, &ProvenanceLineage::root());
        demote_to_skeleton(&data_dir, A);
        bind_name(&data_dir, "base", A);

        let forest = build_forest(&data_dir).unwrap();
        let a = forest.get(ulid(A)).unwrap();
        assert_eq!(a.class, NodeClass::Anchor);
        assert_eq!(a.name.as_deref(), Some("base"));
    }

    #[test]
    fn unreadable_provenance_recorded_not_fatal() {
        // Garbage provenance (mid-claim shape): the node still appears,
        // classified by its markers, with the error recorded and no
        // edges contributed.
        let data_dir = temp_data_dir();
        let dir = data_dir.join("by_id").join(A);
        std::fs::create_dir_all(&dir).unwrap();
        generate_keypair(&dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();
        std::fs::write(dir.join(VOLUME_PROVENANCE_FILE), "not a provenance").unwrap();
        std::fs::write(dir.join(CLAIMING_FILE), "").unwrap();

        let forest = build_forest(&data_dir).unwrap();
        let a = forest.get(ulid(A)).unwrap();
        assert_eq!(a.class, NodeClass::Anchor);
        assert!(a.lineage_error.is_some());
        assert!(a.parent.is_none());
    }

    #[test]
    fn referencing_anchors_excludes_self_and_finds_dependents() {
        // A (anchor) ← B (anchor fork of A): A is referenced by B
        // only; B by nobody. A's own chain never counts as a
        // self-reference.
        let data_dir = temp_data_dir();
        let a_pub = mint_volume(&data_dir, A, &ProvenanceLineage::root());
        mint_volume(&data_dir, B, &ProvenanceLineage::fork(parent_ref(A, a_pub)));

        let forest = build_forest(&data_dir).unwrap();
        assert_eq!(forest.referencing_anchors(ulid(A)), vec![ulid(B)]);
        assert!(forest.referencing_anchors(ulid(B)).is_empty());
    }

    #[test]
    fn unclassified_dir_shown_never_live() {
        // A bare directory with no markers at all: not a shape the
        // verbs produce; surfaced, and (not being a skeleton) not the
        // sweep's business either.
        let data_dir = temp_data_dir();
        std::fs::create_dir_all(data_dir.join("by_id").join(A)).unwrap();

        let forest = build_forest(&data_dir).unwrap();
        let a = forest.get(ulid(A)).unwrap();
        assert_eq!(a.class, NodeClass::Unclassified);
        assert!(!a.live);
    }
}
