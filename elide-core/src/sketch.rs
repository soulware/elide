//! Resemblance sketches for similarity-based delta source selection.
//!
//! A sketch is a fixed array of super-features. Two extents sharing any
//! super-feature are likely similar, which lets the delta producer find
//! a dictionary source by content resemblance rather than by LBA or path
//! (`docs/design/delta-compression.md`). Sketches are persisted per
//! Data/CanonicalData entry in the segment index's sketch table.
//!
//! [`compute`] is the Broder resemblance sketch: super-features taken as
//! the maxima of `NUM_FEATURES` independent permutations over
//! content-defined sampled window hashes, so the sketch tracks content
//! rather than byte position and survives insertions and deletions. It
//! runs over an extent's raw (decompressed) bytes at segment formation.

/// Number of 8-byte super-features in a sketch.
pub const NUM_SF: usize = 8;

/// A fixed-size resemblance sketch: `NUM_SF` super-features.
pub type Sketch = [u64; NUM_SF];

/// Serialized byte length of one sketch (`NUM_SF` little-endian `u64`s).
pub const SKETCH_LEN: usize = NUM_SF * 8;

/// Features hashed down into each super-feature. Grouping several
/// features per super-feature raises the bar for a coincidental match:
/// two extents share a super-feature only when they agree on all of its
/// features.
const FEATURES_PER_SF: usize = 2;

/// Total independent features sampled before grouping into super-features.
const NUM_FEATURES: usize = NUM_SF * FEATURES_PER_SF;

/// Content-defined sampling rate: a window position is sampled when the
/// low bits of the rolling Gear hash are all-ones (~1 in 32 positions).
const SAMPLE_MASK: u64 = 0x1f;

/// Minimum sampled positions for a sketch to be meaningful. Extents that
/// sample fewer windows (tiny or low-entropy content) are left unsketched.
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

fn sfs_from_features(features: &[u64; NUM_FEATURES]) -> Sketch {
    let mut sfs = [0u64; NUM_SF];
    for (j, sf) in sfs.iter_mut().enumerate() {
        let mut bytes = [0u8; FEATURES_PER_SF * 8];
        for k in 0..FEATURES_PER_SF {
            bytes[k * 8..(k + 1) * 8]
                .copy_from_slice(&features[j * FEATURES_PER_SF + k].to_le_bytes());
        }
        let h = blake3::hash(&bytes);
        let b = h.as_bytes();
        *sf = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    }
    sfs
}

/// Compute the resemblance sketch of `data`'s raw bytes.
///
/// Returns `None` when the input samples fewer than `MIN_SAMPLES`
/// windows — too little content for the sketch to be meaningful.
pub fn compute(data: &[u8]) -> Option<Sketch> {
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
    Some(sfs_from_features(&features))
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

    #[test]
    fn deterministic() {
        let d = incompressible(1, 8192);
        assert_eq!(compute(&d), compute(&d));
    }

    #[test]
    fn identical_content_shares_every_super_feature() {
        let d = incompressible(2, 8192);
        let a = compute(&d).expect("sketchable");
        let b = compute(&d).expect("sketchable");
        assert_eq!(a, b);
    }

    #[test]
    fn similar_content_shares_super_features() {
        let base = incompressible(3, 8192);
        // Prepend a few bytes: a positional sketch would shift every
        // subchunk, but Broder samples by content, so most super-features
        // survive.
        let mut shifted = vec![0xEF, 0xBE, 0xAD, 0xDE];
        shifted.extend_from_slice(&base);

        let a = compute(&base).expect("sketchable");
        let b = compute(&shifted).expect("sketchable");
        let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert!(
            shared >= 1,
            "shifted content must still share a super-feature (shared={shared})"
        );
    }

    #[test]
    fn dissimilar_content_rarely_shares() {
        let a = compute(&incompressible(4, 8192)).expect("sketchable");
        let b = compute(&incompressible(200, 8192)).expect("sketchable");
        let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        assert!(
            shared <= 1,
            "unrelated content should not collide across super-features (shared={shared})"
        );
    }

    #[test]
    fn tiny_input_is_unsketchable() {
        assert_eq!(compute(&[0u8; 64]), None);
        assert_eq!(compute(&[]), None);
    }
}
