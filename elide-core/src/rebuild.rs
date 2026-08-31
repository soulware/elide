// One walk over a fork chain's segments, feeding any number of builders.
//
// `segment::discover_fork_segments` fixes the listing and processing order
// that both the extent index and the LBA map depend on, and each structure
// derives its own tie-break from that one order: the extent index takes the
// lowest-ULID canonical from the ascending committed walk, the LBA map takes
// the highest-ULID claimant regardless of order. A visitor sees each
// segment once, so every structure a single walk builds observes the same
// segment set — a promote that lands mid-walk moves both views or neither.

use std::io;
use std::path::{Path, PathBuf};

use log::warn;
use ulid::Ulid;

use crate::extentindex::{ExtentIndex, ExtentIndexBuilder};
use crate::lbamap::{LbaMap, LbaMapBuilder};
use crate::segment::{self, SegmentEntry, SegmentRef};
use crate::signing;

/// A consumer of the segment walk.
pub trait SegmentVisitor {
    /// Take one parsed segment. `entries` and `inputs` are the segment's
    /// signed index and its consumed-input list.
    fn visit(
        &mut self,
        fork_dir: &Path,
        sref: &SegmentRef,
        body_section_start: u64,
        entries: &[SegmentEntry],
        inputs: &[Ulid],
    ) -> io::Result<()>;

    /// Take the end of one fork layer. A builder whose admission rule
    /// ranges over a whole layer applies it here.
    fn end_layer(&mut self) {}
}

/// Drive two visitors from one walk. `visit` runs them in tuple order;
/// they build disjoint structures, so the order carries no meaning.
impl<A: SegmentVisitor + ?Sized, B: SegmentVisitor + ?Sized> SegmentVisitor for (&mut A, &mut B) {
    fn visit(
        &mut self,
        fork_dir: &Path,
        sref: &SegmentRef,
        body_section_start: u64,
        entries: &[SegmentEntry],
        inputs: &[Ulid],
    ) -> io::Result<()> {
        self.0
            .visit(fork_dir, sref, body_section_start, entries, inputs)?;
        self.1
            .visit(fork_dir, sref, body_section_start, entries, inputs)
    }

    fn end_layer(&mut self) {
        self.0.end_layer();
        self.1.end_layer();
    }
}

/// Walk every segment of every layer in rebuild-processing order.
///
/// `verify` selects the ed25519 check. Production rebuild paths verify;
/// the runtime consistency checks pass `false` because `Volume::open`
/// already verified and a segment is immutable once written.
pub fn walk_fork_layers<V: SegmentVisitor + ?Sized>(
    layers: &[(PathBuf, Option<String>)],
    verify: bool,
    visitor: &mut V,
) -> io::Result<()> {
    for (fork_dir, branch_ulid) in layers {
        let segments = segment::discover_fork_segments(fork_dir, branch_ulid.as_deref())?;

        if segments.is_empty() {
            continue;
        }

        // Load the verifying key only when this layer has segments to check
        // *and* the caller wants verification.
        let vk = if verify {
            Some(signing::load_verifying_key(
                fork_dir,
                signing::VOLUME_PUB_FILE,
            )?)
        } else {
            None
        };

        for sref in &segments {
            let parsed = match &vk {
                Some(vk) => segment::read_and_verify_segment_index(&sref.path, vk),
                None => segment::read_segment_index(&sref.path),
            };
            let (body_section_start, entries, inputs) = match parsed {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    warn!(
                        "segment vanished during rebuild (GC race): {}",
                        sref.path.display()
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            visitor.visit(fork_dir, sref, body_section_start, &entries, &inputs)?;
        }

        visitor.end_layer();
    }

    Ok(())
}

/// Build the extent index and the LBA map from one walk, with the highest
/// segment ULID the walk read.
///
/// Callers that classify against both views take them from here: one
/// listing feeds both, so a concurrent promote cannot leave the two
/// describing different segment sets.
pub fn rebuild_views(
    layers: &[(PathBuf, Option<String>)],
) -> io::Result<(ExtentIndex, LbaMap, Option<Ulid>)> {
    let mut index = ExtentIndexBuilder::new(None);
    let mut map = LbaMapBuilder::new();
    walk_fork_layers(layers, true, &mut (&mut index, &mut map))?;
    let (lba_map, ceiling) = map.finish();
    Ok((index.finish().0, lba_map, ceiling))
}
