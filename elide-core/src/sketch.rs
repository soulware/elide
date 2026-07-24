//! Resemblance sketches for similarity-based delta source selection.
//!
//! A sketch is a fixed array of super-features. Two extents sharing any
//! super-feature are likely similar, which lets the delta producer find
//! a dictionary source by content resemblance rather than by LBA or path
//! (`docs/design/delta-compression.md`). Sketches are persisted per
//! Data/CanonicalData entry in the segment index's sketch table.
//!
//! This module defines the on-disk representation. The computation that
//! fills a sketch from an extent's raw bytes lives with the delta
//! producer, which already decompresses source content to build zstd
//! dictionaries.

/// Number of 8-byte super-features in a sketch.
pub const NUM_SF: usize = 8;

/// A fixed-size resemblance sketch: `NUM_SF` super-features.
pub type Sketch = [u64; NUM_SF];

/// Serialized byte length of one sketch (`NUM_SF` little-endian `u64`s).
pub const SKETCH_LEN: usize = NUM_SF * 8;
