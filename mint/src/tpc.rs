//! Third-party caveat primitives: per-coord `r` derivation and the
//! AEAD-encrypted `(VID, CID)` payload mint stamps onto operator-write
//! credentials (`docs/design-auth-service.md` § *Keys*, § *Coord ↔
//! mint enrollment*).
//!
//! Three operations:
//!
//! - [`derive_r`] — `r = BLAKE3-derive-key("mint tpc r-key v1",
//!   K_M || client_id || r_epoch)`. Deterministic in its inputs, so
//!   mint can re-derive `r` on every exchange call without storing
//!   per-client state. Bumping `r_epoch` (in `_mint/approved/<sub>`)
//!   rolls `r` to a fresh value, invalidating every existing CID for
//!   the client.
//!
//! - [`encrypt_vid`] — AES-GCM-SIV(T_{n-1}, plaintext = `r`) with
//!   a fixed all-zero nonce. T_{n-1} is the chain tag at the TPC's
//!   position, so VID is intrinsically per-chain (differs across
//!   credentials with different first-party caveats); decryption is
//!   what lets the verifier recover `r` from VID alone.
//!
//! - [`encrypt_cid`] — AES-GCM-SIV(K_M-A, plaintext =
//!   `r || lp(client_id) || lp(org_id)`) with the same fixed nonce.
//!   Length-prefix every variable field so two different
//!   `(client_id, org_id)` pairs can't produce the same plaintext.
//!   CID is identical across credentials a client carries that share
//!   `r` — that's the property that lets one discharge satisfy
//!   several of the client's credentials at once.
//!
//! **Nonce reuse safety.** AES-GCM-SIV is misuse-resistant by
//! construction: nonce reuse with the same key is safe (the
//! ciphertext+tag are a deterministic function of the plaintext
//! alone). We exploit that to make CID deterministic — same inputs
//! yield byte-identical CID, the property that lets multiple
//! credentials share one CID.

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::caveat::Caveat;

/// Domain-separation context for `r` derivation. Bumping this string
/// rotates every client's `r` cluster-wide; `r_epoch` is the per-client
/// equivalent.
const R_KDF_CONTEXT: &str = "mint tpc r-key v1";

/// Fixed all-zero nonce. AES-GCM-SIV's misuse-resistance is what makes
/// this safe — see module docs.
const FIXED_NONCE: [u8; 12] = [0u8; 12];

/// Per-client discharge-recovery key. The KDF is keyed by `K_M`
/// directly via BLAKE3's `derive_key` (KMAC-shaped, domain-separated
/// by the context string), so a leaked `r` doesn't reveal `K_M` or
/// any sibling client's `r`.
pub fn derive_r(k_m: &[u8; 32], client_id: &str, r_epoch: u32) -> [u8; 32] {
    let mut key_material = Vec::with_capacity(32 + client_id.len() + 4);
    key_material.extend_from_slice(k_m);
    key_material.extend_from_slice(client_id.as_bytes());
    key_material.extend_from_slice(&r_epoch.to_be_bytes());
    blake3::derive_key(R_KDF_CONTEXT, &key_material)
}

/// Encrypt `r` under `T_{n-1}` to produce `VID`. T_{n-1} is the
/// macaroon chain tag at the TPC's position; the verifier walks the
/// chain to recover it.
pub fn encrypt_vid(t_n_minus_1: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    aead_encrypt(t_n_minus_1, r)
}

/// Encrypt `r ‖ lp(client_id) ‖ lp(org_id)` under `K_M-A` to produce
/// `CID`. Length-prefixing prevents
/// `(client, org) = (("ab","cd"), ("abcd",""))` collisions; `r` is
/// fixed-size so doesn't need prefixing.
pub fn encrypt_cid(k_m_a: &[u8; 32], r: &[u8; 32], client_id: &str, org_id: &str) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(32 + 8 + client_id.len() + org_id.len());
    plaintext.extend_from_slice(r);
    plaintext.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(client_id.as_bytes());
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
    client_id: &str,
    org_id: &str,
    location: impl Into<String>,
) -> Caveat {
    Caveat::ThirdParty {
        location: location.into(),
        vid: encrypt_vid(tail, r),
        cid: encrypt_cid(k_m_a, r, client_id, org_id),
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

fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, TpcError> {
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&FIXED_NONCE), ciphertext)
        .map_err(|_| TpcError::Aead)
}

/// Why a TPC decrypt or parse failed. Deliberately coarse — a verifier
/// returning these to a client should collapse them to one opaque
/// failure (the indistinguishability rule from
/// `docs/design-mint.md` § *Authentication*); the variants are for
/// audit and tests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TpcError {
    /// AEAD tag mismatch — wrong key, tampered ciphertext, or
    /// otherwise corrupt input.
    #[error("AEAD authentication failed")]
    Aead,
    /// Decrypted plaintext is shorter than the minimum the layout
    /// requires (32 bytes of `r` plus two length prefixes).
    #[error("plaintext truncated")]
    Truncated,
    /// A length-prefixed field claims a length past the end of the
    /// plaintext.
    #[error("length-prefix overrun")]
    Overrun,
    /// Decrypted bytes that should be UTF-8 (the `client_id` or
    /// `org_id`) are not.
    #[error("non-utf-8 field")]
    BadUtf8,
    /// Trailing bytes after the last parsed field — the plaintext
    /// is longer than the layout says it should be.
    #[error("trailing bytes")]
    Trailing,
}

/// The plaintext bound into a CID by [`encrypt_cid`], recovered by
/// [`decrypt_cid`]. `r` is the per-client discharge-recovery key;
/// `client_id` and `org_id` are the bound identity strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidPlaintext {
    pub r: [u8; 32],
    pub client_id: String,
    pub org_id: String,
}

/// Decrypt `VID` under the chain tag `T_{n-1}` to recover `r`. The
/// verifier walks the primary's chain up to the TPC step, captures
/// the chain tag at that position, and calls this to obtain the
/// discharge-MAC key without ever needing `K_M-A`.
pub fn decrypt_vid(t_n_minus_1: &[u8; 32], vid: &[u8]) -> Result<[u8; 32], TpcError> {
    let plaintext = aead_decrypt(t_n_minus_1, vid)?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| TpcError::Truncated)
}

/// Decrypt `CID` under `K_M-A` to recover `(r, client_id, org_id)`.
/// The alternate path to `r` for parties that hold `K_M-A` (mint,
/// and auth at discharge-issuance time) — yields the same `r` as
/// [`decrypt_vid`] for the same primary, plus the bound identity
/// strings as a cross-check.
pub fn decrypt_cid(k_m_a: &[u8; 32], cid: &[u8]) -> Result<CidPlaintext, TpcError> {
    let plaintext = aead_decrypt(k_m_a, cid)?;
    parse_cid_plaintext(&plaintext)
}

fn parse_cid_plaintext(buf: &[u8]) -> Result<CidPlaintext, TpcError> {
    if buf.len() < 32 {
        return Err(TpcError::Truncated);
    }
    let r: [u8; 32] = buf[..32].try_into().expect("32-byte slice");
    let mut pos = 32;
    let client_id = read_length_prefixed_str(buf, &mut pos)?;
    let org_id = read_length_prefixed_str(buf, &mut pos)?;
    if pos != buf.len() {
        return Err(TpcError::Trailing);
    }
    Ok(CidPlaintext {
        r,
        client_id,
        org_id,
    })
}

fn read_length_prefixed_str(buf: &[u8], pos: &mut usize) -> Result<String, TpcError> {
    if *pos + 4 > buf.len() {
        return Err(TpcError::Truncated);
    }
    let len = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().expect("4-byte slice")) as usize;
    *pos += 4;
    let end = pos.checked_add(len).ok_or(TpcError::Overrun)?;
    if end > buf.len() {
        return Err(TpcError::Overrun);
    }
    let s = std::str::from_utf8(&buf[*pos..end])
        .map_err(|_| TpcError::BadUtf8)?
        .to_owned();
    *pos = end;
    Ok(s)
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
    fn r_differs_per_client_and_per_epoch() {
        let k_m = [9u8; 32];
        let a = derive_r(&k_m, "01ARZ", 0);
        let b = derive_r(&k_m, "01BXY", 0);
        let c = derive_r(&k_m, "01ARZ", 1);
        assert_ne!(a, b, "different client_id must produce different r");
        assert_ne!(a, c, "different r_epoch must produce different r");
    }

    #[test]
    fn r_independent_of_unrelated_k_m_bits() {
        // A leak of one client's r must not yield a sibling's r.
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
    fn cid_changes_per_client_org_and_r() {
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
        // (client="ab", org="cd") vs (client="abcd", org="") must not
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

    #[test]
    fn vid_round_trips_under_correct_tag() {
        let t = [4u8; 32];
        let r = [5u8; 32];
        let vid = encrypt_vid(&t, &r);
        assert_eq!(decrypt_vid(&t, &vid).expect("decrypt"), r);
    }

    #[test]
    fn vid_decrypt_fails_under_wrong_tag() {
        let t = [4u8; 32];
        let r = [5u8; 32];
        let vid = encrypt_vid(&t, &r);
        let mut wrong = t;
        wrong[0] ^= 0x80;
        assert_eq!(decrypt_vid(&wrong, &vid), Err(TpcError::Aead));
    }

    #[test]
    fn vid_decrypt_fails_on_tampered_ciphertext() {
        // AES-GCM-SIV's authentication tag should detect a single
        // bit-flip — that's the misuse-resistance property we lean on.
        let t = [4u8; 32];
        let r = [5u8; 32];
        let mut vid = encrypt_vid(&t, &r);
        vid[0] ^= 0x01;
        assert_eq!(decrypt_vid(&t, &vid), Err(TpcError::Aead));
    }

    #[test]
    fn cid_round_trips_to_bound_identity() {
        let k_m_a = [3u8; 32];
        let r = [7u8; 32];
        let cid = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        let pt = decrypt_cid(&k_m_a, &cid).expect("decrypt");
        assert_eq!(pt.r, r);
        assert_eq!(pt.client_id, "01ARZ");
        assert_eq!(pt.org_id, "org_demo");
    }

    #[test]
    fn cid_decrypt_fails_under_wrong_k_m_a() {
        let k_m_a = [3u8; 32];
        let r = [7u8; 32];
        let cid = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        let mut wrong = k_m_a;
        wrong[31] ^= 0x40;
        assert_eq!(decrypt_cid(&wrong, &cid), Err(TpcError::Aead));
    }

    #[test]
    fn cid_decrypt_recovers_exact_field_bytes() {
        // Empty `org_id` and unicode `client_id` exercise the
        // length-prefix parser at its boundaries.
        let k_m_a = [3u8; 32];
        let r = [9u8; 32];
        let cid = encrypt_cid(&k_m_a, &r, "01ÆØÅ", "");
        let pt = decrypt_cid(&k_m_a, &cid).expect("decrypt");
        assert_eq!(pt.client_id, "01ÆØÅ");
        assert_eq!(pt.org_id, "");
    }

    #[test]
    fn cid_and_vid_agree_on_r() {
        // The whole point of the dual-path construction: mint can
        // recover `r` either by walking the chain (VID) or by
        // decrypting CID under K_M-A — both yield the same key.
        let k_m_a = [3u8; 32];
        let r = derive_r(&[1u8; 32], "01ARZ", 0);
        let tail = [11u8; 32];
        let vid = encrypt_vid(&tail, &r);
        let cid = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        let via_vid = decrypt_vid(&tail, &vid).expect("vid");
        let via_cid = decrypt_cid(&k_m_a, &cid).expect("cid").r;
        assert_eq!(via_vid, via_cid);
    }
}
