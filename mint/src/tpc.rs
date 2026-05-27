//! Third-party caveat primitives: per-coord `r` derivation and the
//! AEAD-encrypted `(VID, CID)` payload mint stamps onto operator-write
//! credentials (`docs/design-auth-service.md` § *Keys*, § *Coord ↔
//! mint enrollment*).
//!
//! Three operations:
//!
//! - [`derive_r`] — `r = BLAKE3-derive-key("elide-mint r-coord v1",
//!   K_M || coord_ulid || r_epoch)`. Deterministic in its inputs, so
//!   mint can re-derive `r` on every exchange call without storing
//!   per-coord state. Bumping `r_epoch` (in `_mint/approved/<sub>`)
//!   rolls `r` to a fresh value, invalidating every existing CID for
//!   the coord.
//!
//! - [`encrypt_vid`] — AES-GCM-SIV(T_{n-1}, plaintext = `r`) with
//!   a fixed all-zero nonce. T_{n-1} is the chain tag at the TPC's
//!   position, so VID is intrinsically per-chain (differs across
//!   credentials with different first-party caveats); decryption is
//!   what lets the verifier recover `r` from VID alone.
//!
//! - [`encrypt_cid`] — AES-GCM-SIV(K_M-A, plaintext =
//!   `r || lp(coord_ulid) || lp(org_id)`) with the same fixed nonce.
//!   Length-prefix every variable field so two different
//!   `(coord_ulid, org_id)` pairs can't produce the same plaintext.
//!   CID is identical across both operator-write credentials for one
//!   coord because the plaintext is identical — that's the property
//!   that lets one discharge satisfy both.
//!
//! **Nonce reuse safety.** AES-GCM-SIV is misuse-resistant by
//! construction: nonce reuse with the same key is safe (the
//! ciphertext+tag are a deterministic function of the plaintext
//! alone). We exploit that to make CID deterministic — same inputs
//! yield byte-identical CID, the property that lets the two
//! operator-write credentials share one CID.

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::caveat::Caveat;

/// Domain-separation context for `r` derivation. Bumping this string
/// rotates every coord's `r` cluster-wide; `r_epoch` is the per-coord
/// equivalent.
const R_KDF_CONTEXT: &str = "elide-mint r-coord v1";

/// Fixed all-zero nonce. AES-GCM-SIV's misuse-resistance is what makes
/// this safe — see module docs.
const FIXED_NONCE: [u8; 12] = [0u8; 12];

/// Per-coord discharge-recovery key. The KDF is keyed by `K_M`
/// directly via BLAKE3's `derive_key` (KMAC-shaped, domain-separated
/// by the context string), so a leaked `r` doesn't reveal `K_M` or
/// any sibling coord's `r`.
pub fn derive_r(k_m: &[u8; 32], coord_ulid: &str, r_epoch: u32) -> [u8; 32] {
    let mut key_material = Vec::with_capacity(32 + coord_ulid.len() + 4);
    key_material.extend_from_slice(k_m);
    key_material.extend_from_slice(coord_ulid.as_bytes());
    key_material.extend_from_slice(&r_epoch.to_be_bytes());
    blake3::derive_key(R_KDF_CONTEXT, &key_material)
}

/// Encrypt `r` under `T_{n-1}` to produce `VID`. T_{n-1} is the
/// macaroon chain tag at the TPC's position; the verifier walks the
/// chain to recover it.
pub fn encrypt_vid(t_n_minus_1: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    aead_encrypt(t_n_minus_1, r)
}

/// Encrypt `r ‖ lp(coord_ulid) ‖ lp(org_id)` under `K_M-A` to produce
/// `CID`. Length-prefixing prevents
/// `(coord, org) = (("ab","cd"), ("abcd",""))` collisions; `r` is
/// fixed-size so doesn't need prefixing.
pub fn encrypt_cid(k_m_a: &[u8; 32], r: &[u8; 32], coord_ulid: &str, org_id: &str) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(32 + 8 + coord_ulid.len() + org_id.len());
    plaintext.extend_from_slice(r);
    plaintext.extend_from_slice(&(coord_ulid.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(coord_ulid.as_bytes());
    plaintext.extend_from_slice(&(org_id.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(org_id.as_bytes());
    aead_encrypt(k_m_a, &plaintext)
}

/// Build the `Caveat::ThirdParty` to append at issuance. `tail` is
/// the chain tag at the appending position — the issuer reads it off
/// the credential's [`tail`](crate::macaroon::Macaroon::tail) before
/// calling [`attenuate`](crate::macaroon::Macaroon::attenuate). Chain
/// extension is keyless, so this composes correctly whether the TPC
/// is the first thing past the chain seed or the Nth caveat.
pub fn build_caveat(
    tail: &[u8; 32],
    r: &[u8; 32],
    k_m_a: &[u8; 32],
    coord_ulid: &str,
    org_id: &str,
    location: impl Into<String>,
) -> Caveat {
    Caveat::ThirdParty {
        location: location.into(),
        vid: encrypt_vid(tail, r),
        cid: encrypt_cid(k_m_a, r, coord_ulid, org_id),
    }
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    // AES-GCM-SIV's misuse-resistance makes the fixed-nonce + same-key
    // + same-plaintext encryption deterministic; the only failure mode
    // is an internal allocator panic, which `expect` surfaces clearly
    // because it would only fire under OOM.
    cipher
        .encrypt(Nonce::from_slice(&FIXED_NONCE), plaintext)
        .expect("AES-GCM-SIV encrypt: internal buffer growth")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_is_deterministic() {
        let k_m = [9u8; 32];
        let r1 = derive_r(&k_m, "01ARZ", 0);
        let r2 = derive_r(&k_m, "01ARZ", 0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn r_differs_per_coord_and_per_epoch() {
        let k_m = [9u8; 32];
        let a = derive_r(&k_m, "01ARZ", 0);
        let b = derive_r(&k_m, "01BXY", 0);
        let c = derive_r(&k_m, "01ARZ", 1);
        assert_ne!(a, b, "different coord_ulid must produce different r");
        assert_ne!(a, c, "different r_epoch must produce different r");
    }

    #[test]
    fn r_independent_of_unrelated_k_m_bits() {
        // A leak of one coord's r must not yield a sibling's r.
        let k_m = [9u8; 32];
        let mut other_k_m = k_m;
        other_k_m[0] ^= 0x80;
        let mine = derive_r(&k_m, "01ARZ", 0);
        let theirs = derive_r(&other_k_m, "01ARZ", 0);
        assert_ne!(mine, theirs);
    }

    #[test]
    fn cid_is_deterministic_across_calls() {
        let k_m_a = [3u8; 32];
        let r = [7u8; 32];
        let a = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        let b = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        assert_eq!(a, b, "same inputs must produce same CID");
    }

    #[test]
    fn cid_changes_per_coord_org_and_r() {
        let k_m_a = [3u8; 32];
        let r0 = [7u8; 32];
        let r1 = [8u8; 32];
        let base = encrypt_cid(&k_m_a, &r0, "01ARZ", "org_demo");
        assert_ne!(base, encrypt_cid(&k_m_a, &r0, "01BXY", "org_demo"));
        assert_ne!(base, encrypt_cid(&k_m_a, &r0, "01ARZ", "org_other"));
        assert_ne!(base, encrypt_cid(&k_m_a, &r1, "01ARZ", "org_demo"));
    }

    #[test]
    fn cid_plaintext_lengths_prevent_boundary_collision() {
        // (coord="ab", org="cd") vs (coord="abcd", org="") must not
        // collide. Without length prefixing the two concatenations
        // would be identical (both end up `..abcd..`).
        let k_m_a = [3u8; 32];
        let r = [7u8; 32];
        let a = encrypt_cid(&k_m_a, &r, "ab", "cd");
        let b = encrypt_cid(&k_m_a, &r, "abcd", "");
        assert_ne!(a, b);
    }

    #[test]
    fn vid_is_deterministic_for_fixed_chain_tag() {
        let t = [4u8; 32];
        let r = [5u8; 32];
        assert_eq!(encrypt_vid(&t, &r), encrypt_vid(&t, &r));
    }

    #[test]
    fn vid_differs_across_chain_tags() {
        let r = [5u8; 32];
        let t1 = [4u8; 32];
        let mut t2 = [4u8; 32];
        t2[0] ^= 0x01;
        assert_ne!(encrypt_vid(&t1, &r), encrypt_vid(&t2, &r));
    }
}
