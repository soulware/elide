//! Third-party caveat primitives: the AEAD-encrypted `(VID, CID)`
//! payload mint stamps onto TPC-bearing anchors and credentials
//! (`docs/design-auth-service.md` § *Keys*, § *Coord ↔ mint
//! enrollment*).
//!
//! The operations:
//!
//! - [`build_caveat`] / [`build_caveat_attested`] — draw a fresh
//!   random `r` (the discharge root key) and seal it twice, below.
//!   `r` is ephemeral: it exists nowhere outside the one caveat it is
//!   drawn for, so a discharge is MAC-valid against exactly the
//!   caveat it was minted to satisfy.
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
//!
//! - [`encrypt_cid_attested`] — the same layout plus one trailing
//!   length-prefixed `mode` string, sealed under a second authority key
//!   (`K_M-B`). `mode` is opaque to mint: it is carried verbatim from a
//!   role's config to the discharging authority, which alone interprets
//!   it. mint never inspects it, keeping mint agnostic to the
//!   authority's vocabulary.
//!
//! **Nonce reuse safety.** AES-GCM-SIV is misuse-resistant by
//! construction: nonce reuse with the same key is safe (the
//! ciphertext+tag are a deterministic function of the plaintext
//! alone), and every plaintext sealed here embeds its own fresh `r`.

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};

use crate::caveat::Caveat;

/// Fixed all-zero nonce. AES-GCM-SIV's misuse-resistance is what makes
/// this safe — see module docs.
const FIXED_NONCE: [u8; 12] = [0u8; 12];

/// Draw a fresh discharge root key for one caveat.
fn fresh_r() -> [u8; 32] {
    let mut r = [0u8; 32];
    OsRng.fill_bytes(&mut r);
    r
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

/// Build the `Caveat::ThirdParty` to append at issuance, drawing a
/// fresh `r` for it. `tail` is the chain tag at the appending
/// position — the issuer reads it off the credential's
/// [`tail`](crate::macaroon::Macaroon::tail) before calling
/// [`attenuate`](crate::macaroon::Macaroon::attenuate). Chain
/// extension is keyless, so this composes correctly whether the TPC
/// is the first thing past the chain seed or the Nth caveat.
pub fn build_caveat(
    tail: &[u8; 32],
    k_m_a: &[u8; 32],
    client_id: &str,
    org_id: &str,
    location: impl Into<String>,
) -> Caveat {
    let r = fresh_r();
    Caveat::ThirdParty {
        location: location.into(),
        vid: encrypt_vid(tail, &r),
        cid: encrypt_cid(k_m_a, &r, client_id, org_id),
    }
}

/// Encrypt `r ‖ lp(client_id) ‖ lp(org_id) ‖ lp(mode)` under `K_M-B` to
/// produce an **attested** TPC's `CID` — the auth CID layout
/// ([`encrypt_cid`]) extended with one role-supplied opaque string,
/// sealed under the key mint shares with the discharging authority
/// (coord B). `mode` is **opaque to mint**: it is transported verbatim
/// from the role's config to the authority, which alone assigns it
/// meaning. mint never inspects or validates it, so mint stays agnostic
/// to the authority's vocabulary
/// (`docs/design-mint.md` § *Attestation contract*).
pub fn encrypt_cid_attested(
    k_m_b: &[u8; 32],
    r: &[u8; 32],
    client_id: &str,
    org_id: &str,
    mode: &str,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(32 + 12 + client_id.len() + org_id.len() + mode.len());
    plaintext.extend_from_slice(r);
    plaintext.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(client_id.as_bytes());
    plaintext.extend_from_slice(&(org_id.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(org_id.as_bytes());
    plaintext.extend_from_slice(&(mode.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(mode.as_bytes());
    aead_encrypt(k_m_b, &plaintext)
}

/// Build an attested `Caveat::ThirdParty` to append at credential
/// issuance, naming the discharging authority at `location`, drawing a
/// fresh `r` for it. `tail` is the chain tag at the appending position;
/// `r` is recovered by mint via `VID` ([`encrypt_vid`]) and by the
/// authority via `CID` ([`encrypt_cid_attested`]), but never by the
/// holder. Mirrors [`build_caveat`] for the auth TPC, plus the opaque
/// `mode`.
pub fn build_caveat_attested(
    tail: &[u8; 32],
    k_m_b: &[u8; 32],
    client_id: &str,
    org_id: &str,
    mode: &str,
    location: impl Into<String>,
) -> Caveat {
    let r = fresh_r();
    Caveat::ThirdParty {
        location: location.into(),
        vid: encrypt_vid(tail, &r),
        cid: encrypt_cid_attested(k_m_b, &r, client_id, org_id, mode),
    }
}

/// The request path of a TPC `location` (a full URL, e.g.
/// `https://auth.example/v1/discharge`). The location's host is never
/// dialed — a separately-supplied transport carries the connection — so
/// only the path is taken. `None` if the location does not parse as a
/// URI or carries no path (bare authority, or just `/`).
pub fn location_path(location: &str) -> Option<String> {
    let uri: hyper::Uri = location.parse().ok()?;
    let path = uri.path();
    if path.is_empty() || path == "/" {
        return None;
    }
    Some(path.to_string())
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

/// The plaintext bound into an attested CID by [`encrypt_cid_attested`],
/// recovered by [`decrypt_cid_attested`]. Extends [`CidPlaintext`] with
/// the opaque `mode` string mint transported at issuance — meaningful
/// only to the discharging authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCidPlaintext {
    pub r: [u8; 32],
    pub client_id: String,
    pub org_id: String,
    pub mode: String,
}

/// Decrypt an **attested** `CID` under `K_M-B` to recover
/// `(r, client_id, org_id, mode)`. The path the discharging authority
/// takes to obtain the discharge-MAC key `r`, the bound identity
/// strings, and the opaque `mode` it interprets. Mirrors [`decrypt_cid`]
/// for the auth TPC.
pub fn decrypt_cid_attested(
    k_m_b: &[u8; 32],
    cid: &[u8],
) -> Result<AttestedCidPlaintext, TpcError> {
    let plaintext = aead_decrypt(k_m_b, cid)?;
    parse_attested_cid_plaintext(&plaintext)
}

fn parse_attested_cid_plaintext(buf: &[u8]) -> Result<AttestedCidPlaintext, TpcError> {
    if buf.len() < 32 {
        return Err(TpcError::Truncated);
    }
    let r: [u8; 32] = buf[..32].try_into().expect("32-byte slice");
    let mut pos = 32;
    let client_id = read_length_prefixed_str(buf, &mut pos)?;
    let org_id = read_length_prefixed_str(buf, &mut pos)?;
    let mode = read_length_prefixed_str(buf, &mut pos)?;
    if pos != buf.len() {
        return Err(TpcError::Trailing);
    }
    Ok(AttestedCidPlaintext {
        r,
        client_id,
        org_id,
        mode,
    })
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

    /// `(vid, cid)` of a built caveat, for comparing two builds.
    fn caveat_payload(c: Caveat) -> (Vec<u8>, Vec<u8>) {
        match c {
            Caveat::ThirdParty { vid, cid, .. } => (vid, cid),
            other => panic!("expected a third-party caveat, got {other:?}"),
        }
    }

    #[test]
    fn built_caveats_draw_fresh_r() {
        // Identical inputs, two builds: every encrypted field differs,
        // because each build seals its own ephemeral `r`. A discharge
        // minted for one caveat is therefore inert against the other.
        let tail = [11u8; 32];
        let k = [3u8; 32];
        let (vid1, cid1) =
            caveat_payload(build_caveat(&tail, &k, "01ARZ", "org_demo", "https://a"));
        let (vid2, cid2) =
            caveat_payload(build_caveat(&tail, &k, "01ARZ", "org_demo", "https://a"));
        assert_ne!(vid1, vid2);
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn built_attested_caveats_draw_fresh_r() {
        let tail = [11u8; 32];
        let k = [3u8; 32];
        let (vid1, cid1) = caveat_payload(build_caveat_attested(
            &tail,
            &k,
            "01ARZ",
            "org_demo",
            "volume-rw",
            "https://a",
        ));
        let (vid2, cid2) = caveat_payload(build_caveat_attested(
            &tail,
            &k,
            "01ARZ",
            "org_demo",
            "volume-rw",
            "https://a",
        ));
        assert_ne!(vid1, vid2);
        assert_ne!(cid1, cid2);
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
    fn location_path_takes_only_the_path() {
        assert_eq!(
            location_path("https://auth.example/v1/discharge").as_deref(),
            Some("/v1/discharge")
        );
        assert_eq!(
            location_path("http://localhost/v1/login").as_deref(),
            Some("/v1/login")
        );
        // No path to dial: bare authority or root.
        assert_eq!(location_path("https://auth.example/"), None);
        assert_eq!(location_path("https://auth.example"), None);
        // Not a URI.
        assert_eq!(location_path(""), None);
    }

    #[test]
    fn attested_cid_round_trips_to_bound_identity_and_mode() {
        let k_m_b = [2u8; 32];
        let r = [7u8; 32];
        // mint treats `mode` as opaque; exercise arbitrary strings.
        for mode in ["volume-rw", "volume-ro", ""] {
            let cid = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", mode);
            let pt = decrypt_cid_attested(&k_m_b, &cid).expect("decrypt");
            assert_eq!(pt.r, r);
            assert_eq!(pt.client_id, "01ARZ");
            assert_eq!(pt.org_id, "org_demo");
            assert_eq!(pt.mode, mode);
        }
    }

    #[test]
    fn attested_cid_changes_with_mode() {
        let k_m_b = [2u8; 32];
        let r = [7u8; 32];
        let rw = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-rw");
        let ro = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-ro");
        assert_ne!(rw, ro, "mode must affect the ciphertext");
    }

    #[test]
    fn attested_cid_is_deterministic_across_calls() {
        let k_m_b = [2u8; 32];
        let r = [7u8; 32];
        let a = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-ro");
        let b = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-ro");
        assert_eq!(a, b, "same inputs must produce the same attested CID");
    }

    #[test]
    fn attested_cid_mode_length_prevents_boundary_collision() {
        // (org="cd", mode="ef") vs (org="cdef", mode="") must not collide —
        // the mode's length prefix is what separates them.
        let k_m_b = [2u8; 32];
        let r = [7u8; 32];
        let a = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "cd", "ef");
        let b = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "cdef", "");
        assert_ne!(a, b);
    }

    #[test]
    fn attested_cid_decrypt_fails_under_wrong_k_m_b() {
        let k_m_b = [2u8; 32];
        let r = [7u8; 32];
        let cid = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-rw");
        let mut wrong = k_m_b;
        wrong[0] ^= 0x40;
        assert_eq!(decrypt_cid_attested(&wrong, &cid), Err(TpcError::Aead));
    }

    #[test]
    fn auth_cid_does_not_parse_as_an_attested_cid() {
        // Layout separation: an auth CID (no trailing mode field) decrypted
        // with the attested parser under the same key is truncated — there
        // is no length-prefixed mode to read. The two CID layouts do not
        // alias.
        let key = [3u8; 32];
        let r = [7u8; 32];
        let auth = encrypt_cid(&key, &r, "01ARZ", "org_demo");
        assert_eq!(decrypt_cid_attested(&key, &auth), Err(TpcError::Truncated));
    }

    #[test]
    fn attested_cid_does_not_parse_as_an_auth_cid() {
        // The reverse: an attested CID carries a trailing mode field the
        // auth parser reads as trailing bytes, never silently dropped.
        let key = [3u8; 32];
        let r = [7u8; 32];
        let attested = encrypt_cid_attested(&key, &r, "01ARZ", "org_demo", "volume-rw");
        assert_eq!(decrypt_cid(&key, &attested), Err(TpcError::Trailing));
    }

    #[test]
    fn attested_cid_and_vid_agree_on_r() {
        let k_m_b = [2u8; 32];
        let r = fresh_r();
        let tail = [11u8; 32];
        let vid = encrypt_vid(&tail, &r);
        let cid = encrypt_cid_attested(&k_m_b, &r, "01ARZ", "org_demo", "volume-ro");
        let via_vid = decrypt_vid(&tail, &vid).expect("vid");
        let via_cid = decrypt_cid_attested(&k_m_b, &cid).expect("cid").r;
        assert_eq!(via_vid, via_cid);
    }

    #[test]
    fn cid_and_vid_agree_on_r() {
        // The whole point of the dual-path construction: mint can
        // recover `r` either by walking the chain (VID) or by
        // decrypting CID under K_M-A — both yield the same key.
        let k_m_a = [3u8; 32];
        let r = fresh_r();
        let tail = [11u8; 32];
        let vid = encrypt_vid(&tail, &r);
        let cid = encrypt_cid(&k_m_a, &r, "01ARZ", "org_demo");
        let via_vid = decrypt_vid(&tail, &vid).expect("vid");
        let via_cid = decrypt_cid(&k_m_a, &cid).expect("cid").r;
        assert_eq!(via_vid, via_cid);
    }
}

/// Property-based tests for the TPC crypto primitives. The example tests
/// above pin specific keys, fields, and tamper sites; these assert the
/// round-trip, injectivity, key-binding, tamper-detection, and
/// layout-separation invariants over arbitrary keys and arbitrary
/// (possibly empty, multi-byte, or token-looking) identity strings —
/// fuzzing the length-prefix parser at every boundary the examples
/// reach by hand. `client_id`/`org_id`/`mode` are arbitrary `String`s
/// because mint treats them as opaque byte-fields, not validated input.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn key() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    proptest! {
        /// VID round-trips under its chain tag.
        #[test]
        fn vid_round_trips(tag in key(), r in key()) {
            let vid = encrypt_vid(&tag, &r);
            prop_assert_eq!(decrypt_vid(&tag, &vid), Ok(r));
        }

        /// CID round-trips to its bound identity for any fields, including
        /// empty and multi-byte strings — the length-prefix parser
        /// recovers the exact bytes.
        #[test]
        fn cid_round_trips(key in key(), r in key(), client in any::<String>(), org in any::<String>()) {
            let cid = encrypt_cid(&key, &r, &client, &org);
            prop_assert_eq!(
                decrypt_cid(&key, &cid),
                Ok(CidPlaintext { r, client_id: client, org_id: org })
            );
        }

        /// Attested CID round-trips to its bound identity and opaque mode.
        #[test]
        fn attested_cid_round_trips(
            key in key(), r in key(),
            client in any::<String>(), org in any::<String>(), mode in any::<String>(),
        ) {
            let cid = encrypt_cid_attested(&key, &r, &client, &org, &mode);
            prop_assert_eq!(
                decrypt_cid_attested(&key, &cid),
                Ok(AttestedCidPlaintext { r, client_id: client, org_id: org, mode })
            );
        }

        /// CID is injective in its identity fields: with key and `r` held
        /// fixed, two CIDs are byte-equal iff their `(client, org)` pairs
        /// are equal. The forward direction is determinism; the reverse is
        /// the length-prefix anti-collision guarantee, over all string
        /// pairs (not just the `("ab","cd")` vs `("abcd","")` example).
        #[test]
        fn cid_is_injective_in_its_fields(
            key in key(), r in key(),
            c1 in any::<String>(), o1 in any::<String>(),
            c2 in any::<String>(), o2 in any::<String>(),
        ) {
            let a = encrypt_cid(&key, &r, &c1, &o1);
            let b = encrypt_cid(&key, &r, &c2, &o2);
            prop_assert_eq!(a == b, (&c1, &o1) == (&c2, &o2));
        }

        /// Attested CID is injective in `(client, org, mode)` — the mode's
        /// own length prefix keeps `(org="cd", mode="ef")` distinct from
        /// `(org="cdef", mode="")` for all strings.
        #[test]
        fn attested_cid_is_injective_in_its_fields(
            key in key(), r in key(),
            c1 in any::<String>(), o1 in any::<String>(), m1 in any::<String>(),
            c2 in any::<String>(), o2 in any::<String>(), m2 in any::<String>(),
        ) {
            let a = encrypt_cid_attested(&key, &r, &c1, &o1, &m1);
            let b = encrypt_cid_attested(&key, &r, &c2, &o2, &m2);
            prop_assert_eq!(a == b, (&c1, &o1, &m1) == (&c2, &o2, &m2));
        }

        /// Decryption under any key other than the encrypting one fails the
        /// AEAD tag check — the key binding holds for arbitrary keys, not
        /// just a single flipped bit.
        #[test]
        fn cid_decrypt_under_wrong_key_fails(
            k1 in key(), k2 in key(), r in key(),
            client in any::<String>(), org in any::<String>(),
        ) {
            prop_assume!(k1 != k2);
            let cid = encrypt_cid(&k1, &r, &client, &org);
            prop_assert_eq!(decrypt_cid(&k2, &cid), Err(TpcError::Aead));
        }

        /// Any single-bit tamper anywhere in a VID is caught by the AEAD
        /// tag — decryption fails rather than returning a corrupted `r`.
        #[test]
        fn tampered_vid_fails(tag in key(), r in key(), idx in any::<usize>(), bit in 0u8..8) {
            let mut vid = encrypt_vid(&tag, &r);
            let i = idx % vid.len();
            vid[i] ^= 1 << bit;
            prop_assert_eq!(decrypt_vid(&tag, &vid), Err(TpcError::Aead));
        }

        /// The auth and attested CID layouts never alias: an auth CID
        /// (no mode field) read by the attested parser is `Truncated`,
        /// and an attested CID read by the auth parser has `Trailing`
        /// bytes — for any fields, under the same key.
        #[test]
        fn cid_layouts_do_not_alias(
            key in key(), r in key(),
            client in any::<String>(), org in any::<String>(), mode in any::<String>(),
        ) {
            let auth = encrypt_cid(&key, &r, &client, &org);
            let attested = encrypt_cid_attested(&key, &r, &client, &org, &mode);
            prop_assert_eq!(decrypt_cid_attested(&key, &auth), Err(TpcError::Truncated));
            prop_assert_eq!(decrypt_cid(&key, &attested), Err(TpcError::Trailing));
        }

        /// The dual recovery paths agree: `r` recovered by walking the
        /// chain (VID) equals `r` recovered by decrypting CID under K_M-A,
        /// for arbitrary keys, tags, and fields.
        #[test]
        fn vid_and_cid_recover_the_same_r(
            k_m_a in key(), tag in key(), r in key(),
            client in any::<String>(), org in any::<String>(),
        ) {
            let via_vid = decrypt_vid(&tag, &encrypt_vid(&tag, &r));
            let via_cid = decrypt_cid(&k_m_a, &encrypt_cid(&k_m_a, &r, &client, &org)).map(|pt| pt.r);
            prop_assert_eq!(via_vid, Ok(r));
            prop_assert_eq!(via_cid, Ok(r));
        }
    }
}
