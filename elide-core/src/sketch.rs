//! Resemblance sketches for similarity-based delta source selection.
//!
//! A sketch is a fixed array of features. Two extents sharing any feature
//! are likely similar, which lets the delta producer find a dictionary
//! source by content resemblance rather than by LBA or path
//! (`docs/design/delta-compression.md`). Sketches are persisted per
//! Data/CanonicalData entry in the segment index's sketch table.
//!
//! [`compute`] is the Broder resemblance sketch: one feature per
//! independent permutation, each the maximum over content-defined sampled
//! window hashes, so the sketch tracks content rather than byte position
//! and survives insertions and deletions. Each feature is a minhash, so
//! the chance that two extents agree on one equals their resemblance over
//! sampled windows, and the number they share estimates it. It runs over
//! an extent's raw (decompressed) bytes at segment formation.

/// Number of features in a sketch.
pub const NUM_FEATURES: usize = 8;

/// A fixed-size resemblance sketch: one value per feature.
pub type Sketch = [u32; NUM_FEATURES];

/// Serialized byte length of one sketch (`NUM_FEATURES` little-endian
/// `u32`s).
pub const SKETCH_LEN: usize = NUM_FEATURES * 4;

/// Smallest extent worth sketching. A sketch more than doubles an
/// entry's 64-byte index footprint, and resemblance between a small
/// target and a large source is low even when the target is a verbatim
/// slice of it, so below this the field buys nothing.
pub const MIN_SKETCH_BYTES: usize = 32 * 1024;

/// Content-defined sampling rate: a window position is sampled when the
/// low bits of the rolling Gear hash are all-ones (~1 in 32 positions).
const SAMPLE_MASK: u64 = 0x1f;

/// Minimum sampled positions for a sketch to be meaningful. Extents that
/// sample fewer windows (low-entropy content) are left unsketched.
const MIN_SAMPLES: u64 = 16;

const fn splitmix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = splitmix(i as u64);
        i += 1;
    }
    t
}

/// Per-byte contribution to the rolling window hash.
static GEAR: [u64; 256] = gear_table();

const fn perm_table() -> [u64; NUM_FEATURES] {
    let mut t = [0u64; NUM_FEATURES];
    let mut i = 0usize;
    while i < NUM_FEATURES {
        t[i] = splitmix(0x1000 + i as u64) | 1;
        i += 1;
    }
    t
}

/// One odd multiplier per feature — a cheap independent permutation of
/// the sampled window hashes.
static PERMS: [u64; NUM_FEATURES] = perm_table();

/// Reduce each raw feature to its stored width. A feature is a maximum
/// of permuted window hashes, whose low bits are not uniform, so it is
/// hashed rather than truncated: the candidate map indexes on those bits.
fn store_features(features: &[u64; NUM_FEATURES]) -> Sketch {
    let mut out = [0u32; NUM_FEATURES];
    for (slot, feature) in out.iter_mut().zip(features) {
        let h = blake3::hash(&feature.to_le_bytes());
        let b = h.as_bytes();
        *slot = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    out
}

/// Compute the resemblance sketch of `data`'s raw bytes.
///
/// Returns `None` for input below [`MIN_SKETCH_BYTES`], or that samples
/// fewer than `MIN_SAMPLES` windows — too little content for the sketch
/// to be meaningful.
pub fn compute(data: &[u8]) -> Option<Sketch> {
    if data.len() < MIN_SKETCH_BYTES {
        return None;
    }
    let mut features = [0u64; NUM_FEATURES];
    let mut samples = 0u64;
    let mut h = 0u64;
    for &b in data {
        h = (h << 1).wrapping_add(GEAR[b as usize]);
        if h & SAMPLE_MASK == SAMPLE_MASK {
            samples += 1;
            for (f, perm) in features.iter_mut().zip(PERMS) {
                let v = h.wrapping_mul(perm);
                if v > *f {
                    *f = v;
                }
            }
        }
    }
    if samples < MIN_SAMPLES {
        return None;
    }
    Some(store_features(&features))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incompressible(seed: u8, len: usize) -> Vec<u8> {
        // A cheap PRNG stream — real extents are high-entropy, and the
        // sketch is only meaningful over content that samples enough
        // windows.
        let mut out = Vec::with_capacity(len);
        let mut x = 0x2545_F491_4F6C_DD1Du64 ^ ((seed as u64) << 32 | seed as u64);
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// A sketchable extent: at or above the size threshold, high-entropy
    /// so it samples enough windows.
    fn sketchable(seed: u8) -> Vec<u8> {
        incompressible(seed, MIN_SKETCH_BYTES)
    }

    #[test]
    fn deterministic() {
        let d = sketchable(1);
        assert_eq!(compute(&d), compute(&d));
    }

    #[test]
    fn identical_content_shares_every_feature() {
        let d = sketchable(2);
        let a = compute(&d).expect("sketchable");
        let b = compute(&d).expect("sketchable");
        assert_eq!(a, b);
    }

    #[test]
    fn similar_content_shares_features() {
        let base = sketchable(3);
        // Prepend a few bytes: a positional sketch would shift every
        // subchunk, but Broder samples by content, so most features
        // survive.
        let mut shifted = vec![0xEF, 0xBE, 0xAD, 0xDE];
        shifted.extend_from_slice(&base);

        let a = compute(&base).expect("sketchable");
        let b = compute(&shifted).expect("sketchable");
        let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert!(
            shared >= NUM_FEATURES - 1,
            "shifted content must still share nearly every feature (shared={shared})"
        );
    }

    #[test]
    fn dissimilar_content_rarely_shares() {
        let a = compute(&sketchable(4)).expect("sketchable");
        let b = compute(&sketchable(200)).expect("sketchable");
        let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert!(
            shared <= 1,
            "unrelated content should not collide across features (shared={shared})"
        );
    }

    #[test]
    fn sub_threshold_input_is_unsketchable() {
        // High-entropy and sampling plenty of windows, rejected on size
        // alone.
        assert_eq!(compute(&incompressible(5, MIN_SKETCH_BYTES - 1)), None);
        assert_eq!(compute(&[0u8; 64]), None);
        assert_eq!(compute(&[]), None);
    }

    #[test]
    fn low_entropy_input_is_unsketchable() {
        // Above the size threshold, but a single repeated byte samples
        // almost no windows.
        assert_eq!(compute(&vec![0x5Au8; MIN_SKETCH_BYTES]), None);
    }
}
