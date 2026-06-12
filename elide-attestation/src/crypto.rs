//! The discharge-mint crypto, reimplemented against mint's spec.
//!
//! coord B mints a discharge but lives in the coordinator, which cannot
//! link `mint` (a standalone workspace —
//! `docs/design-mint-volume-attestation.md` § *coord B mints the
//! discharge*). So the two primitives coord B needs are re-expressed here:
//!
//! - [`decrypt_cid_attested`] — ChaCha20-Poly1305(`K_M-B`) over an attested
//!   TPC's CID (`nonce ‖ ciphertext`, the nonce its leading 12 bytes),
//!   recovering `r ‖ lp(client_id) ‖ lp(org_id) ‖ lp(mode)`. The twin
//!   of mint's `tpc::decrypt_cid_attested`.
//! - [`mint_discharge_with_nonce`] — a keyless chained-BLAKE3 macaroon
//!   rooted at the recovered `r`, carrying the discharge keyref, its
//!   nonce holding the [`ticket_id`] so mint pairs it to the caveat it
//!   answers, encoded to mint's `mnt2_` wire form. The twin of mint's
//!   `macaroon::mint_under_key_with_nonce` + `encode`.
//!
//! Only the *composition* is reimplemented — the AEAD, BLAKE3, and MsgPack
//! primitives are the identical crates mint uses, so the drift surface is
//! the layout, not the cryptography. A shared known-answer fixture
//! (`testdata/mint-discharge-vectors.json`) pins this against the canonical
//! mint implementation in both test suites; see the test below and
//! `mint/tests/discharge_vectors.rs`.
//!
//! coord B never *encrypts* a CID in production (mint does) and never
//! *verifies* a discharge (mint does). A test-only [`encrypt_cid_attested`]
//! is the exact inverse of the decrypt half, used to construct
//! discharge-predicate fixtures for `mode`s the shared vector omits; it is
//! pinned to the canonical layout by re-sealing the fixture CID under the
//! fixture's own nonce.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Wire prefix for a base64url-encoded mint macaroon (`mint::macaroon`).
const WIRE_PREFIX: &str = "mnt2_";
/// Chain-seed domain separator (`mint::macaroon::DOMAIN`).
const DOMAIN: &[u8] = b"mint-macaroon-v6";
/// Macaroon nonce length (`mint::macaroon::NONCE_LEN`).
const NONCE_LEN: usize = 16;
/// Per-step type tag for a first-party caveat (`mint::macaroon`). coord B
/// only ever mints first-party scalar caveats, so the third-party tag is
/// not reimplemented.
const TYPE_FIRST_PARTY: u64 = 0;
/// Wire tag of the discharge keyref (`mint::macaroon::KEYREF_DISCHARGE`).
/// A discharge's keyref is the MsgPack array `[1]` — no kid; the chain is
/// rooted at `r`, not at a keyring generation.
const KEYREF_DISCHARGE: u64 = 1;
/// AEAD nonce length (`mint::tpc::AEAD_NONCE_LEN`): every sealed CID
/// carries its nonce as the leading bytes.
const AEAD_NONCE_LEN: usize = 12;

/// The plaintext recovered from an attested TPC's CID — mint's
/// `tpc::AttestedCidPlaintext`. `r` is the discharge-MAC root key; `mode`
/// is the opaque role string coord B interprets; `client_id`/`org_id` are
/// the bound identity strings (carried for discharge attribution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCid {
    pub r: [u8; 32],
    pub client_id: String,
    pub org_id: String,
    pub mode: String,
}

/// Why a CID decrypt or parse failed. Mirrors mint's `tpc::TpcError`; kept
/// coarse — a handler returning these to a client should collapse them to
/// one opaque failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("AEAD authentication failed")]
    Aead,
    #[error("plaintext truncated")]
    Truncated,
    #[error("length-prefix overrun")]
    Overrun,
    #[error("non-utf-8 field")]
    BadUtf8,
    #[error("trailing bytes")]
    Trailing,
}

/// Decrypt an attested CID under `K_M-B`, recovering
/// `(r, client_id, org_id, mode)`. coord B alone holds `K_M-B`; mint sealed
/// the CID at credential issuance via `tpc::encrypt_cid_attested`.
pub fn decrypt_cid_attested(k_m_b: &[u8; 32], cid: &[u8]) -> Result<AttestedCid, CryptoError> {
    let (nonce, ciphertext) = cid
        .split_at_checked(AEAD_NONCE_LEN)
        .ok_or(CryptoError::Aead)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_m_b));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Aead)?;
    parse_attested_cid(&plaintext)
}

fn parse_attested_cid(buf: &[u8]) -> Result<AttestedCid, CryptoError> {
    if buf.len() < 32 {
        return Err(CryptoError::Truncated);
    }
    let r: [u8; 32] = buf[..32].try_into().map_err(|_| CryptoError::Truncated)?;
    let mut pos = 32;
    let client_id = read_length_prefixed_str(buf, &mut pos)?;
    let org_id = read_length_prefixed_str(buf, &mut pos)?;
    let mode = read_length_prefixed_str(buf, &mut pos)?;
    if pos != buf.len() {
        return Err(CryptoError::Trailing);
    }
    Ok(AttestedCid {
        r,
        client_id,
        org_id,
        mode,
    })
}

/// Test-only inverse of [`decrypt_cid_attested`]: seal
/// `r ‖ lp(client_id) ‖ lp(org_id) ‖ lp(mode)` under `K_M-B` with the
/// caller's nonce prepended. Production never seals CIDs — mint does — so
/// this exists only to construct fixtures for `mode`s the shared vector
/// does not carry. Its layout is pinned to the canonical one by
/// `encrypt_reproduces_fixture_cid` below.
#[cfg(test)]
pub(crate) fn encrypt_cid_attested(
    k_m_b: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_LEN],
    r: &[u8; 32],
    client_id: &str,
    org_id: &str,
    mode: &str,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(32 + client_id.len() + org_id.len() + mode.len() + 12);
    plaintext.extend_from_slice(r);
    for s in [client_id, org_id, mode] {
        let len: u32 = s.len().try_into().expect("field fits u32");
        plaintext.extend_from_slice(&len.to_be_bytes());
        plaintext.extend_from_slice(s.as_bytes());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_m_b));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_slice())
        .expect("chacha20-poly1305 encrypt is infallible for this payload size");
    let mut sealed = Vec::with_capacity(AEAD_NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

fn read_length_prefixed_str(buf: &[u8], pos: &mut usize) -> Result<String, CryptoError> {
    if *pos + 4 > buf.len() {
        return Err(CryptoError::Truncated);
    }
    let len = u32::from_be_bytes(
        buf[*pos..*pos + 4]
            .try_into()
            .map_err(|_| CryptoError::Truncated)?,
    ) as usize;
    *pos += 4;
    let end = pos.checked_add(len).ok_or(CryptoError::Overrun)?;
    if end > buf.len() {
        return Err(CryptoError::Overrun);
    }
    let s = std::str::from_utf8(&buf[*pos..end])
        .map_err(|_| CryptoError::BadUtf8)?
        .to_owned();
    *pos = end;
    Ok(s)
}

/// The ticket id a discharge stamps into its nonce so mint's verifier
/// pairs it with the third-party caveat it answers by identity, not by
/// bundle position: `blake3(CID)[..NONCE_LEN]` (`mint::tpc::ticket_id`).
pub fn ticket_id(cid: &[u8]) -> [u8; NONCE_LEN] {
    let mut id = [0u8; NONCE_LEN];
    id.copy_from_slice(&blake3::hash(cid).as_bytes()[..NONCE_LEN]);
    id
}

/// Mint a discharge macaroon rooted at `r` carrying `caveats` (scalar
/// first-party `(name, value)` pairs), with `nonce` carrying the ticket
/// id ([`ticket_id`]) so mint's verifier pairs it with the third-party
/// caveat it answers. Returns the `mnt2_` wire form mint verifies under
/// `r` and clears.
pub fn mint_discharge_with_nonce(
    r: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    caveats: &[(&str, &str)],
) -> String {
    let mut mac = seed_mac(r, nonce);
    for (name, value) in caveats {
        mac = step_mac(&mac, name, value);
    }
    encode(nonce, &mac, caveats)
}

/// Canonical MsgPack encoding of the discharge keyref
/// (`mint::macaroon::serialize_key_ref`). Used both as the first envelope
/// element and as the seed-MAC input.
fn serialize_key_ref_discharge() -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_array_len(&mut out, 1).expect("vec writer");
    rmp::encode::write_uint(&mut out, KEYREF_DISCHARGE).expect("vec writer");
    out
}

/// Initial chain tag: keyed BLAKE3 over `DOMAIN ‖ keyref ‖ nonce`
/// (`mint::macaroon::seed_mac`).
fn seed_mac(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let kr = serialize_key_ref_discharge();
    let mut msg = Vec::with_capacity(DOMAIN.len() + kr.len() + NONCE_LEN);
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(&kr);
    msg.extend_from_slice(nonce);
    *blake3::keyed_hash(key, &msg).as_bytes()
}

/// One chain step: `BLAKE3-keyed(prev, serialize_one(name, value))`
/// (`mint::macaroon::step_mac`).
fn step_mac(prev: &[u8; 32], name: &str, value: &str) -> [u8; 32] {
    *blake3::keyed_hash(prev, &serialize_one(name, value)).as_bytes()
}

/// Canonical per-caveat MsgPack encoding for a first-party scalar caveat:
/// `[0, name, value]` (`mint::macaroon::serialize_one`). Used both as the
/// MAC-chain input and embedded verbatim in the wire envelope.
fn serialize_one(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing to a `Vec<u8>` is infallible; the only failure mode rmp
    // surfaces is an underlying writer error, which `Vec` cannot produce.
    rmp::encode::write_array_len(&mut out, 3).expect("vec writer");
    rmp::encode::write_uint(&mut out, TYPE_FIRST_PARTY).expect("vec writer");
    rmp::encode::write_str(&mut out, name).expect("vec writer");
    rmp::encode::write_str(&mut out, value).expect("vec writer");
    out
}

/// Serialize to `mnt2_<base64url-no-pad>` of the canonical-MsgPack envelope
/// `[keyref, nonce, mac, [caveats]]` (`mint::macaroon::encode`).
fn encode(nonce: &[u8; NONCE_LEN], mac: &[u8; 32], caveats: &[(&str, &str)]) -> String {
    let mut buf = Vec::new();
    rmp::encode::write_array_len(&mut buf, 4).expect("vec writer");
    buf.extend_from_slice(&serialize_key_ref_discharge());
    rmp::encode::write_bin(&mut buf, nonce).expect("vec writer");
    rmp::encode::write_bin(&mut buf, mac).expect("vec writer");
    let count: u32 = caveats.len().try_into().expect("caveat count fits u32");
    rmp::encode::write_array_len(&mut buf, count).expect("vec writer");
    for (name, value) in caveats {
        buf.extend_from_slice(&serialize_one(name, value));
    }
    let mut out = String::with_capacity(WIRE_PREFIX.len() + (buf.len() * 4 / 3 + 4));
    out.push_str(WIRE_PREFIX);
    BASE64.encode_string(&buf, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::signing::decode_hex;

    /// The shared cross-implementation fixture, generated from canonical
    /// mint (`mint/tests/discharge_vectors.rs`). Read from the repo root so
    /// both workspaces pin against the identical file.
    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/mint-discharge-vectors.json"
        );
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).expect("parse vectors json")
    }

    fn hex32(v: &serde_json::Value, key: &str) -> [u8; 32] {
        decode_hex(v[key].as_str().expect("hex string"))
            .expect("decode hex")
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn decrypt_cid_attested_matches_canonical_vector() {
        let v = vectors();
        let k_m_b = hex32(&v, "k_m_b");
        let cid = decode_hex(v["cid"].as_str().unwrap()).expect("decode cid");
        let pt = decrypt_cid_attested(&k_m_b, &cid).expect("decrypt");
        assert_eq!(pt.r, hex32(&v, "r"));
        assert_eq!(pt.client_id, v["client_id"].as_str().unwrap());
        assert_eq!(pt.org_id, v["org_id"].as_str().unwrap());
        assert_eq!(pt.mode, v["mode"].as_str().unwrap());
    }

    #[test]
    fn mint_discharge_matches_canonical_vector() {
        let v = vectors();
        let r = hex32(&v, "r");
        let nonce: [u8; NONCE_LEN] = decode_hex(v["discharge_nonce"].as_str().unwrap())
            .expect("decode nonce")
            .try_into()
            .expect("16 bytes");
        let volume = v["volume"].as_str().unwrap();
        let exp = v["exp"].as_str().unwrap();
        let wire = mint_discharge_with_nonce(&r, &nonce, &[("volume", volume), ("exp", exp)]);
        assert_eq!(wire, v["discharge_wire"].as_str().unwrap());
    }

    /// The nonce a fixture CID was sealed under — its leading bytes.
    /// Re-sealing under it must reproduce the fixture byte-for-byte.
    fn fixture_nonce(cid: &[u8]) -> [u8; AEAD_NONCE_LEN] {
        cid[..AEAD_NONCE_LEN].try_into().expect("nonce prefix")
    }

    #[test]
    fn volume_ro_fixture_cid_is_canonical() {
        // `cid_volume_ro` differs from `cid` only in the baked mode
        // string and its nonce. Re-sealing under the fixture's own nonce
        // pins it the same way `encrypt_reproduces_fixture_cid` pins the
        // volume-rw CID.
        let v = vectors();
        let k_m_b = hex32(&v, "k_m_b");
        let r = hex32(&v, "r");
        let fixture = decode_hex(v["cid_volume_ro"].as_str().unwrap()).unwrap();
        let cid = encrypt_cid_attested(
            &k_m_b,
            &fixture_nonce(&fixture),
            &r,
            v["client_id"].as_str().unwrap(),
            v["org_id"].as_str().unwrap(),
            "volume-ro",
        );
        assert_eq!(cid, fixture);
    }

    #[test]
    fn encrypt_reproduces_fixture_cid() {
        // ChaCha20-Poly1305 is deterministic for a fixed nonce, so the
        // test-only sealer re-sealing under the fixture CID's own nonce
        // must reproduce mint's canonical CID byte-for-byte — pinning
        // its layout to the same vector the decrypt half is pinned to.
        let v = vectors();
        let k_m_b = hex32(&v, "k_m_b");
        let r = hex32(&v, "r");
        let fixture = decode_hex(v["cid"].as_str().unwrap()).unwrap();
        let cid = encrypt_cid_attested(
            &k_m_b,
            &fixture_nonce(&fixture),
            &r,
            v["client_id"].as_str().unwrap(),
            v["org_id"].as_str().unwrap(),
            v["mode"].as_str().unwrap(),
        );
        assert_eq!(cid, fixture);
    }

    #[test]
    fn encrypt_decrypt_round_trips_an_arbitrary_mode() {
        let v = vectors();
        let k_m_b = hex32(&v, "k_m_b");
        let r = hex32(&v, "r");
        let cid = encrypt_cid_attested(
            &k_m_b,
            &[7u8; AEAD_NONCE_LEN],
            &r,
            "client-x",
            "org-y",
            "volume-ro",
        );
        let pt = decrypt_cid_attested(&k_m_b, &cid).expect("decrypt");
        assert_eq!(pt.r, r);
        assert_eq!(pt.client_id, "client-x");
        assert_eq!(pt.org_id, "org-y");
        assert_eq!(pt.mode, "volume-ro");
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let v = vectors();
        let mut k_m_b = hex32(&v, "k_m_b");
        k_m_b[0] ^= 0x80;
        let cid = decode_hex(v["cid"].as_str().unwrap()).unwrap();
        assert_eq!(decrypt_cid_attested(&k_m_b, &cid), Err(CryptoError::Aead));
    }

    #[test]
    fn decrypt_rejects_tampered_cid() {
        let v = vectors();
        let k_m_b = hex32(&v, "k_m_b");
        let mut cid = decode_hex(v["cid"].as_str().unwrap()).unwrap();
        cid[0] ^= 0x01;
        assert_eq!(decrypt_cid_attested(&k_m_b, &cid), Err(CryptoError::Aead));
    }
}
