//! Generic chained-MAC macaroon.
//!
//! Standard chained-keyed-BLAKE3 construction over named **scalar**
//! caveats, with a per-step type tag that lets a chain interleave
//! first-party and third-party caveats:
//!
//! ```text
//! mac_seed = blake3_keyed(key, DOMAIN || serialize_key_ref(key_ref) || nonce)
//! mac_i    = blake3_keyed(mac_{i-1}, serialize_one(c_i))
//! ```
//!
//! Each step's key is the previous step's MAC, so any holder of the
//! trailing MAC can append a caveat (the additive-restriction property)
//! but cannot remove one. Every macaroon declares which key roots its
//! chain via a [`KeyRef`] bound into the seed: a credential names a
//! [`Keyring`] generation, a discharge is rooted at its TPC's `r`, a
//! session at `K_session`. Each verifier matches the variant it serves
//! and replays the chain; because the keyref is under the MAC, the
//! kinds are domain-separated cryptographically, not by convention.
//!
//! Wire format: canonical MsgPack envelope, base64url-no-pad encoded,
//! prefixed with `mnt2_` for log greppability. Per
//! `docs/design-mint.md` § *Authentication*, macaroons ship in
//! `Authorization: MintV1 mnt2_<b64url>[,mnt2_<b64url>...]` (bundles at
//! the verify+clear endpoints) or as a lone `Authorization: MintV1
//! mnt2_<b64url>` (single-credential enrollment endpoints).
//!
//! ```text
//! envelope             [keyref, nonce (bin), mac (bin), [caveats]]
//! keyref               [0, kid (uint)] | [1] (discharge) | [2] (session)
//! first-party caveat   [0, name (str), value (str)]
//! third-party caveat   [1, location (str), vid (bin), cid (bin)]
//! ```
//!
//! `serialize_one` is the per-caveat canonical-MsgPack encoding fed
//! into the MAC chain; the same bytes appear in the envelope so a
//! decoded macaroon re-MACs identically.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use rand_core::{OsRng, RngCore};

use crate::caveat::Caveat;
use crate::keyring::{Keyring, Kid};

/// Wire prefix for a base64url-encoded mint macaroon. Makes each
/// macaroon individually greppable in logs even when concatenated
/// into a bundle (`mnt2_AbCd...,mnt2_EfGh...`). `mnt2` = "mint
/// macaroon, wire generation 2".
pub const WIRE_PREFIX: &str = "mnt2_";

const DOMAIN: &[u8] = b"mint-macaroon-v5";
pub const NONCE_LEN: usize = 16;

/// Per-step type tag in the canonical MsgPack encoding (first element
/// of every caveat array). First-party = 0; third-party = 1. The tag
/// is part of `serialize_one`'s output, so a TPC can never be confused
/// with a first-party caveat under the MAC chain.
const TYPE_FIRST_PARTY: u64 = 0;
const TYPE_THIRD_PARTY: u64 = 1;

/// Wire tag of a keyref — the first element of the keyref array in the
/// envelope. Keyring = 0 (followed by the kid), discharge = 1,
/// session = 2.
const KEYREF_KEYRING: u64 = 0;
const KEYREF_DISCHARGE: u64 = 1;
const KEYREF_SESSION: u64 = 2;

/// The key a macaroon's chain is rooted in. Bound into the chain seed
/// and carried in the wire envelope, so the kinds are domain-separated
/// under the MAC itself. Each verifier matches the variant it serves:
/// `verify_and_clear` anchors a bundle on a [`KeyRef::Keyring`] primary
/// only, the bundle walk accepts [`KeyRef::Discharge`] discharges only,
/// and the auth role's session gate accepts [`KeyRef::Session`] only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRef {
    /// A mint keyring generation — the only kind that can anchor a
    /// bundle. The kid selects which generation to verify under.
    Keyring(Kid),
    /// A discharge, rooted at the `r` of the third-party caveat it
    /// answers.
    Discharge,
    /// A demo auth-role session under `K_session`.
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macaroon {
    key_ref: KeyRef,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
    // Held as blake3::Hash so tag comparison (`==`) is constant-time.
    mac: blake3::Hash,
}

/// A third-party caveat encountered while walking a macaroon's chain,
/// captured with the chain tag at the step *before* the TPC was
/// appended. Returned by [`Macaroon::verify_collecting_tpcs`]; the
/// `t_n_minus_1` field is the input the verifier feeds into
/// [`crate::tpc::decrypt_vid`] to recover the discharge key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpcSite<'a> {
    pub t_n_minus_1: [u8; 32],
    pub location: &'a str,
    pub vid: &'a [u8],
    pub cid: &'a [u8],
}

/// Errors decoding a wire macaroon. Deliberately coarse — the HTTP
/// layer collapses every parse failure to `401` with no detail so an
/// attacker can't distinguish "tampered" from "malformed" (see
/// `docs/design-mint.md` § *Authentication*).
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("missing mnt2_ prefix")]
    BadPrefix,
    #[error("base64url decode failed")]
    Base64,
    #[error("truncated macaroon")]
    Truncated,
    #[error("invalid caveat encoding")]
    BadCaveat,
}

/// Canonical per-caveat MsgPack encoding. Used both as the wire
/// representation inside the envelope's caveats array and as the
/// MAC-chain input — see [`step_mac`]. Writing to `Vec<u8>` is
/// infallible; the `expect` documents that invariant.
fn serialize_one(c: &Caveat) -> Vec<u8> {
    let mut out = Vec::new();
    match c {
        Caveat::FirstParty { name, value } => {
            rmp::encode::write_array_len(&mut out, 3).expect("vec writer");
            rmp::encode::write_uint(&mut out, TYPE_FIRST_PARTY).expect("vec writer");
            rmp::encode::write_str(&mut out, name).expect("vec writer");
            rmp::encode::write_str(&mut out, value).expect("vec writer");
        }
        Caveat::ThirdParty { location, vid, cid } => {
            rmp::encode::write_array_len(&mut out, 4).expect("vec writer");
            rmp::encode::write_uint(&mut out, TYPE_THIRD_PARTY).expect("vec writer");
            rmp::encode::write_str(&mut out, location).expect("vec writer");
            rmp::encode::write_bin(&mut out, vid).expect("vec writer");
            rmp::encode::write_bin(&mut out, cid).expect("vec writer");
        }
    }
    out
}

/// Canonical MsgPack encoding of a [`KeyRef`]. Used both as the wire
/// representation (first envelope element) and as the seed-MAC input —
/// see [`seed_mac`] — so a decoded macaroon re-MACs identically.
fn serialize_key_ref(key_ref: &KeyRef) -> Vec<u8> {
    let mut out = Vec::new();
    match key_ref {
        KeyRef::Keyring(kid) => {
            rmp::encode::write_array_len(&mut out, 2).expect("vec writer");
            rmp::encode::write_uint(&mut out, KEYREF_KEYRING).expect("vec writer");
            rmp::encode::write_uint(&mut out, *kid as u64).expect("vec writer");
        }
        KeyRef::Discharge => {
            rmp::encode::write_array_len(&mut out, 1).expect("vec writer");
            rmp::encode::write_uint(&mut out, KEYREF_DISCHARGE).expect("vec writer");
        }
        KeyRef::Session => {
            rmp::encode::write_array_len(&mut out, 1).expect("vec writer");
            rmp::encode::write_uint(&mut out, KEYREF_SESSION).expect("vec writer");
        }
    }
    out
}

/// Initial chain tag: keyed BLAKE3 over `DOMAIN || keyref || nonce`.
/// The keyref is bound here so a key recovered for one kind — or one
/// keyring generation — cannot be replayed under a different claim.
fn seed_mac(key: &[u8; 32], key_ref: &KeyRef, nonce: &[u8; NONCE_LEN]) -> blake3::Hash {
    let kr = serialize_key_ref(key_ref);
    let mut seed_msg = Vec::with_capacity(DOMAIN.len() + kr.len() + NONCE_LEN);
    seed_msg.extend_from_slice(DOMAIN);
    seed_msg.extend_from_slice(&kr);
    seed_msg.extend_from_slice(nonce);
    blake3::keyed_hash(key, &seed_msg)
}

/// One step of the chain MAC: `BLAKE3-keyed(prev_mac, serialize_one(c))`.
fn step_mac(prev: &blake3::Hash, c: &Caveat) -> blake3::Hash {
    blake3::keyed_hash(prev.as_bytes(), &serialize_one(c))
}

/// Walk the chain end-to-end. Used by [`Macaroon::verify`] and by
/// [`mint`] when no TPC is being stamped.
fn chain_mac(
    key: &[u8; 32],
    key_ref: &KeyRef,
    nonce: &[u8; NONCE_LEN],
    caveats: &[Caveat],
) -> blake3::Hash {
    let mut mac = seed_mac(key, key_ref, nonce);
    for c in caveats {
        mac = step_mac(&mac, c);
    }
    mac
}

/// Mint a macaroon under the keyring's **current** generation. Mint is
/// the issuer *and* verifier of the credential macaroon (the root never
/// leaves the process — see `docs/design-mint.md` § *Trust model*);
/// this is the issuer side.
///
/// Mint stamps a third-party caveat onto an issued credential by
/// calling [`Macaroon::attenuate`] with a `Caveat::ThirdParty` value:
/// chain extension is keyless (the trailing MAC is enough), so a TPC
/// appended at issuance is byte-identical to one inserted into the
/// initial chain — the MAC is incremental and additive. The TPC
/// `vid` reads the appended-to credential's [`tail`](Macaroon::tail)
/// as `T_{n-1}`. [`crate::tpc`] holds the AEAD primitives.
pub fn mint(keyring: &Keyring, caveats: Vec<Caveat>) -> Macaroon {
    let key_ref = KeyRef::Keyring(keyring.current_kid());
    let key = keyring.current_key();
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mac = chain_mac(key, &key_ref, &nonce, &caveats);
    Macaroon {
        key_ref,
        nonce,
        caveats,
        mac,
    }
}

/// Mint a macaroon under a raw 32-byte key — the keyring-less twin
/// of [`mint`], used when the issuer holds the key directly:
/// discharges (MAC'd under the per-caveat ephemeral `r`,
/// [`KeyRef::Discharge`]) and demo sessions (`K_session`,
/// [`KeyRef::Session`]).
pub fn mint_under_key(key: &[u8; 32], key_ref: KeyRef, caveats: Vec<Caveat>) -> Macaroon {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    mint_under_key_with_nonce(key, key_ref, nonce, caveats)
}

/// As [`mint_under_key`] but with a caller-supplied nonce, for callers
/// that need a deterministic wire (cross-implementation test vectors,
/// the chain-MAC proptests).
pub fn mint_under_key_with_nonce(
    key: &[u8; 32],
    key_ref: KeyRef,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
) -> Macaroon {
    let mac = chain_mac(key, &key_ref, &nonce, &caveats);
    Macaroon {
        key_ref,
        nonce,
        caveats,
        mac,
    }
}

impl Macaroon {
    pub fn key_ref(&self) -> KeyRef {
        self.key_ref
    }

    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The trailing MAC. This is the holder-of-key PoP anchor: the
    /// `cnf` proof signs over `tail ‖ BLAKE3(body)`, so the
    /// tail binds the proof to *this* exact attenuated macaroon
    /// (`docs/design-mint.md` § *Credential macaroon & lifecycle*, [`crate::pop`]).
    pub fn tail(&self) -> &[u8; 32] {
        self.mac.as_bytes()
    }

    /// Hex of the nonce — a stable per-token identity for the audit log.
    pub fn nonce_hex(&self) -> String {
        self.nonce.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Append `c`, extending the MAC chain with only the trailing MAC.
    /// Caveats are AND-evaluated, so this can only restrict authority.
    pub fn attenuate(mut self, c: Caveat) -> Macaroon {
        let step = serialize_one(&c);
        self.mac = blake3::keyed_hash(self.mac.as_bytes(), &step);
        self.caveats.push(c);
        self
    }

    /// Constant-time MAC verification against `keyring`. Only a
    /// [`KeyRef::Keyring`] macaroon can verify here: its kid selects
    /// which generation to verify under, and an absent kid (retired or
    /// never existed) — or a non-keyring keyref — fails verification
    /// with the same opacity as a bad MAC. Caveat-value checks
    /// (audience, role, ttl) are the caller's job — see [`crate::role`].
    pub fn verify(&self, keyring: &Keyring) -> bool {
        let KeyRef::Keyring(kid) = self.key_ref else {
            return false;
        };
        let Some(key) = keyring.get(kid) else {
            return false;
        };
        self.verify_under_key(key)
    }

    /// Constant-time MAC verification against a raw 32-byte key. The
    /// keyring-less twin of [`verify`](Self::verify), used when the
    /// verifier holds the key directly rather than via a generation
    /// lookup — discharges (under the per-caveat `r`) and sessions
    /// (under `K_session`) verify through this path. The keyref still
    /// participates in the chain seed, so a macaroon claiming a
    /// different kind cannot verify under the same key.
    pub fn verify_under_key(&self, key: &[u8; 32]) -> bool {
        let expected = chain_mac(key, &self.key_ref, &self.nonce, &self.caveats);
        expected == self.mac
    }

    /// Verify the chain MAC under `key` and return the third-party
    /// caveats encountered along the way, each annotated with the
    /// chain tag `T_{n-1}` *before* the TPC was appended. That tag
    /// is the AEAD key the verifier needs to recover `r` from this
    /// TPC's VID (see [`crate::tpc::decrypt_vid`]). The order is
    /// the chain order. Returns `None` if the MAC doesn't verify;
    /// returns an empty vec for a chain with no TPCs.
    pub fn verify_collecting_tpcs(&self, key: &[u8; 32]) -> Option<Vec<TpcSite<'_>>> {
        let mut mac = seed_mac(key, &self.key_ref, &self.nonce);
        let mut sites: Vec<TpcSite<'_>> = Vec::new();
        for c in &self.caveats {
            if let Caveat::ThirdParty { location, vid, cid } = c {
                sites.push(TpcSite {
                    t_n_minus_1: *mac.as_bytes(),
                    location,
                    vid,
                    cid,
                });
            }
            mac = step_mac(&mac, c);
        }
        if mac == self.mac { Some(sites) } else { None }
    }

    /// Serialize to the wire form: `mnt2_<base64url-no-pad>` of the
    /// canonical-MsgPack envelope.
    pub fn encode(&self) -> String {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).expect("vec writer");
        buf.extend_from_slice(&serialize_key_ref(&self.key_ref));
        rmp::encode::write_bin(&mut buf, &self.nonce).expect("vec writer");
        rmp::encode::write_bin(&mut buf, self.mac.as_bytes()).expect("vec writer");
        // Caveats array: the elements are the same canonical MsgPack
        // bytes used as MAC-chain inputs (`serialize_one`), so the
        // envelope embeds them by extending the buffer directly.
        let count: u32 = self
            .caveats
            .len()
            .try_into()
            .expect("caveat count fits u32");
        rmp::encode::write_array_len(&mut buf, count).expect("vec writer");
        for c in &self.caveats {
            buf.extend_from_slice(&serialize_one(c));
        }
        let mut out = String::with_capacity(WIRE_PREFIX.len() + (buf.len() * 4 / 3 + 4));
        out.push_str(WIRE_PREFIX);
        BASE64.encode_string(&buf, &mut out);
        out
    }

    /// Parse the wire form. Every error variant maps to the same
    /// opaque `401` at the HTTP layer — see `docs/design-mint.md`
    /// § *Authentication*.
    pub fn decode(s: &str) -> Result<Macaroon, DecodeError> {
        let body = s
            .trim()
            .strip_prefix(WIRE_PREFIX)
            .ok_or(DecodeError::BadPrefix)?;
        let buf = BASE64.decode(body).map_err(|_| DecodeError::Base64)?;
        let mut r: &[u8] = &buf;

        let env_len = rmp::decode::read_array_len(&mut r).map_err(|_| DecodeError::Truncated)?;
        if env_len != 4 {
            return Err(DecodeError::BadCaveat);
        }

        let key_ref = decode_key_ref(&mut r)?;

        let nonce = read_bin_fixed::<NONCE_LEN>(&mut r)?;
        let mac = blake3::Hash::from_bytes(read_bin_fixed::<32>(&mut r)?);

        let count = rmp::decode::read_array_len(&mut r).map_err(|_| DecodeError::Truncated)?;
        let mut caveats = Vec::with_capacity(count as usize);
        for _ in 0..count {
            caveats.push(decode_caveat(&mut r)?);
        }

        if !r.is_empty() {
            return Err(DecodeError::BadCaveat);
        }

        Ok(Macaroon {
            key_ref,
            nonce,
            caveats,
            mac,
        })
    }
}

fn decode_key_ref(r: &mut &[u8]) -> Result<KeyRef, DecodeError> {
    let arr_len = rmp::decode::read_array_len(r).map_err(|_| DecodeError::Truncated)?;
    let tag: u64 = rmp::decode::read_int(r).map_err(|_| DecodeError::Truncated)?;
    match (tag, arr_len) {
        (KEYREF_KEYRING, 2) => {
            let kid_u64: u64 = rmp::decode::read_int(r).map_err(|_| DecodeError::Truncated)?;
            let kid: Kid = kid_u64.try_into().map_err(|_| DecodeError::BadCaveat)?;
            Ok(KeyRef::Keyring(kid))
        }
        (KEYREF_DISCHARGE, 1) => Ok(KeyRef::Discharge),
        (KEYREF_SESSION, 1) => Ok(KeyRef::Session),
        _ => Err(DecodeError::BadCaveat),
    }
}

fn read_bin_fixed<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], DecodeError> {
    let len = rmp::decode::read_bin_len(r).map_err(|_| DecodeError::Truncated)? as usize;
    if len != N {
        return Err(DecodeError::BadCaveat);
    }
    let (head, tail) = r.split_at_checked(N).ok_or(DecodeError::Truncated)?;
    let arr: [u8; N] = head.try_into().map_err(|_| DecodeError::Truncated)?;
    *r = tail;
    Ok(arr)
}

fn read_str(r: &mut &[u8]) -> Result<String, DecodeError> {
    let len = rmp::decode::read_str_len(r).map_err(|_| DecodeError::Truncated)? as usize;
    let (head, tail) = r.split_at_checked(len).ok_or(DecodeError::Truncated)?;
    *r = tail;
    String::from_utf8(head.to_vec()).map_err(|_| DecodeError::BadCaveat)
}

fn read_bin(r: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    let len = rmp::decode::read_bin_len(r).map_err(|_| DecodeError::Truncated)? as usize;
    let (head, tail) = r.split_at_checked(len).ok_or(DecodeError::Truncated)?;
    *r = tail;
    Ok(head.to_vec())
}

fn decode_caveat(r: &mut &[u8]) -> Result<Caveat, DecodeError> {
    let arr_len = rmp::decode::read_array_len(r).map_err(|_| DecodeError::Truncated)?;
    let tag: u64 = rmp::decode::read_int(r).map_err(|_| DecodeError::Truncated)?;
    match (tag, arr_len) {
        (0, 3) => {
            let name = read_str(r)?;
            let value = read_str(r)?;
            Ok(Caveat::FirstParty { name, value })
        }
        (1, 4) => {
            let location = read_str(r)?;
            let vid = read_bin(r)?;
            let cid = read_bin(r)?;
            Ok(Caveat::ThirdParty { location, vid, cid })
        }
        _ => Err(DecodeError::BadCaveat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> Keyring {
        Keyring::single([7u8; 32])
    }

    #[test]
    fn mint_verify_roundtrip() {
        let m = mint(
            &ring(),
            vec![
                Caveat::scalar("Audience", "mint"),
                Caveat::scalar("elide:Volume", "01ARZ"),
            ],
        );
        assert!(m.verify(&ring()));
        assert!(!m.verify(&Keyring::single([9u8; 32])));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let m = mint(
            &ring(),
            vec![
                Caveat::scalar("Audience", "mint"),
                Caveat::scalar("elide:Volume", "01ARZ"),
                Caveat::scalar("exp", "1700000000"),
            ],
        );
        let wire = m.encode();
        assert!(wire.starts_with(WIRE_PREFIX));
        let back = Macaroon::decode(&wire).expect("decode");
        assert_eq!(m, back);
        assert!(back.verify(&ring()));
    }

    #[test]
    fn encode_decode_roundtrip_with_third_party() {
        let m = mint(
            &ring(),
            vec![
                Caveat::scalar("Audience", "mint"),
                Caveat::third_party("https://auth.example/", vec![1u8; 28], vec![2u8; 60]),
                Caveat::scalar("exp", "1700000000"),
            ],
        );
        let wire = m.encode();
        let back = Macaroon::decode(&wire).expect("decode");
        assert_eq!(m, back);
        assert!(back.verify(&ring()));
        match &back.caveats()[1] {
            Caveat::ThirdParty { location, vid, cid } => {
                assert_eq!(location, "https://auth.example/");
                assert_eq!(vid, &vec![1u8; 28]);
                assert_eq!(cid, &vec![2u8; 60]);
            }
            other => panic!("expected ThirdParty, got {other:?}"),
        }
    }

    #[test]
    fn tampered_tpc_field_fails_verify() {
        let m = mint(
            &ring(),
            vec![
                Caveat::scalar("Audience", "mint"),
                Caveat::third_party("https://auth.example/", vec![1u8; 28], vec![2u8; 60]),
            ],
        );
        let mut tampered = Macaroon::decode(&m.encode()).expect("decode");
        match &mut tampered.caveats[1] {
            Caveat::ThirdParty { vid, .. } => vid[0] ^= 0x80,
            other => panic!("expected ThirdParty, got {other:?}"),
        }
        assert!(!tampered.verify(&ring()));
    }

    #[test]
    fn type_tag_distinguishes_first_from_third_party() {
        // Two macaroons with the same string fields, one as first-party
        // ("loc","value") and one as third-party (location=..., vid+cid
        // chosen so the bytes "look similar"). Their chain MACs must
        // differ — the type byte enforces the distinction.
        let fp = mint(
            &ring(),
            vec![Caveat::scalar("https://auth.example/", "abc")],
        );
        let tp = mint(
            &ring(),
            vec![Caveat::third_party(
                "https://auth.example/",
                b"a".to_vec(),
                b"bc".to_vec(),
            )],
        );
        assert_ne!(fp.tail(), tp.tail());
    }

    #[test]
    fn mint_under_key_round_trips_under_same_key() {
        let r = [9u8; 32];
        let m = mint_under_key(
            &r,
            KeyRef::Discharge,
            vec![
                Caveat::scalar("Subject", "usr_abc"),
                Caveat::scalar("CoordId", "01ARZ"),
                Caveat::scalar("exp", "1700000000"),
            ],
        );
        assert_eq!(m.key_ref(), KeyRef::Discharge);
        assert!(m.verify_under_key(&r));
    }

    #[test]
    fn verify_under_key_rejects_wrong_key() {
        let r = [9u8; 32];
        let m = mint_under_key(
            &r,
            KeyRef::Discharge,
            vec![Caveat::scalar("Subject", "usr_abc")],
        );
        let mut wrong = r;
        wrong[15] ^= 0x80;
        assert!(!m.verify_under_key(&wrong));
    }

    #[test]
    fn verify_under_key_rejects_tampered_caveat() {
        let r = [9u8; 32];
        let m = mint_under_key(
            &r,
            KeyRef::Discharge,
            vec![Caveat::scalar("CoordId", "01ARZ")],
        );
        let mut forged = Macaroon::decode(&m.encode()).unwrap();
        forged.caveats[0] = Caveat::scalar("CoordId", "01EVIL");
        assert!(!forged.verify_under_key(&r));
    }

    #[test]
    fn verify_collecting_tpcs_returns_chain_tags_in_chain_order() {
        let r = ring();
        let m = mint(
            &r,
            vec![
                Caveat::scalar("aud", "mint"),
                Caveat::third_party("https://auth1/", vec![1u8; 28], vec![2u8; 60]),
                Caveat::scalar("sub", "01ARZ"),
                Caveat::third_party("https://auth2/", vec![3u8; 28], vec![4u8; 60]),
            ],
        );
        let sites = m.verify_collecting_tpcs(r.current_key()).expect("verify");
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].location, "https://auth1/");
        assert_eq!(sites[1].location, "https://auth2/");
        assert_ne!(sites[0].t_n_minus_1, sites[1].t_n_minus_1);
    }

    #[test]
    fn verify_collecting_tpcs_rejects_tampered_mac() {
        let r = ring();
        let m = mint(
            &r,
            vec![
                Caveat::scalar("aud", "mint"),
                Caveat::third_party("https://auth/", vec![1u8; 28], vec![2u8; 60]),
            ],
        );
        let mut bad = Macaroon::decode(&m.encode()).unwrap();
        match &mut bad.caveats[1] {
            Caveat::ThirdParty { vid, .. } => vid[0] ^= 0x01,
            _ => panic!(),
        }
        assert!(bad.verify_collecting_tpcs(r.current_key()).is_none());
    }

    #[test]
    fn verify_collecting_tpcs_empty_for_no_tpc_chain() {
        let r = ring();
        let m = mint(&r, vec![Caveat::scalar("aud", "mint")]);
        let sites = m.verify_collecting_tpcs(r.current_key()).expect("verify");
        assert!(sites.is_empty());
    }

    #[test]
    fn non_keyring_keyref_never_verifies_via_keyring() {
        // Only a `KeyRef::Keyring` macaroon can verify against the
        // keyring. A discharge verifies under `r` directly (right
        // key); `verify(&keyring)` rejects it structurally, before
        // any key lookup.
        let r = [0xff; 32];
        let m = mint_under_key(
            &r,
            KeyRef::Discharge,
            vec![Caveat::scalar("Subject", "usr_abc")],
        );
        assert!(m.verify_under_key(&r));
        assert!(!m.verify(&ring()));
    }

    #[test]
    fn keyref_variants_are_domain_separated_under_one_key() {
        // The keyref is bound into the chain seed: the same key, nonce,
        // and caveats under different keyrefs yield different MACs, so
        // one kind's macaroon can never verify as another's.
        let k = [5u8; 32];
        let n = [3u8; NONCE_LEN];
        let caveats = vec![Caveat::scalar("sub", "alice")];
        let discharge = mint_under_key_with_nonce(&k, KeyRef::Discharge, n, caveats.clone());
        let session = mint_under_key_with_nonce(&k, KeyRef::Session, n, caveats.clone());
        let keyring = mint_under_key_with_nonce(&k, KeyRef::Keyring(0), n, caveats);
        assert_ne!(discharge.tail(), session.tail());
        assert_ne!(discharge.tail(), keyring.tail());
        assert_ne!(session.tail(), keyring.tail());
    }

    #[test]
    fn attenuation_only_narrows_and_still_verifies() {
        let m = mint(&ring(), vec![Caveat::scalar("Audience", "mint")]);
        let attenuated = m.attenuate(Caveat::scalar("elide:Volume", "01ARZ"));
        assert!(attenuated.verify(&ring()));
        assert_eq!(attenuated.caveats().len(), 2);
    }

    #[test]
    fn tampered_caveat_fails_verify() {
        let m = mint(&ring(), vec![Caveat::scalar("elide:Volume", "good")]);
        let mut tampered = Macaroon::decode(&m.encode()).expect("decode");
        tampered.caveats[0] = Caveat::scalar("elide:Volume", "evil");
        assert!(!tampered.verify(&ring()));
    }

    #[test]
    fn tampered_kid_fails_verify_even_if_key_exists() {
        let dir = tempfile::tempdir().unwrap();
        let mut kr = Keyring::open(&dir.path().join("rk"), None).unwrap();
        kr.add_and_promote(&dir.path().join("rk"), None).unwrap();
        let m = mint(&kr, vec![Caveat::scalar("Audience", "mint")]);
        assert_eq!(m.key_ref(), KeyRef::Keyring(1));
        let mut forged = Macaroon::decode(&m.encode()).unwrap();
        forged.key_ref = KeyRef::Keyring(0);
        assert!(!forged.verify(&kr));
    }

    #[test]
    fn garbage_decode_is_error_not_panic() {
        assert!(Macaroon::decode("not-prefixed").is_err());
        assert!(Macaroon::decode("mnt2_!!!").is_err());
        assert!(Macaroon::decode(&format!("{WIRE_PREFIX}{}", BASE64.encode([0u8; 3]))).is_err());
    }

    #[test]
    fn token_minted_under_old_kid_still_verifies_until_retired() {
        let dir = tempfile::tempdir().unwrap();
        let rk = dir.path().join("rk");
        let mut kr = Keyring::open(&rk, None).unwrap();
        let token_under_zero = mint(&kr, vec![Caveat::scalar("Audience", "mint")]);
        let new_kid = kr.add_and_promote(&rk, None).unwrap();
        assert_eq!(new_kid, 1);
        assert!(token_under_zero.verify(&kr));
        kr.retire(&rk, 0).unwrap();
        assert!(!token_under_zero.verify(&kr));
    }

    #[test]
    fn wire_has_prefix_and_is_base64url() {
        // The wire must be base64url-no-pad (no `+`, `/`, `=` chars,
        // only A-Z a-z 0-9 - _) so it's safe to drop into URLs, log
        // lines, and comma-separated bundles without quoting hazards.
        let m = mint(&ring(), vec![Caveat::scalar("aud", "mint")]);
        let wire = m.encode();
        assert!(wire.starts_with(WIRE_PREFIX));
        let body = wire.strip_prefix(WIRE_PREFIX).unwrap();
        for c in body.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-base64url char {c:?} in wire {wire}"
            );
        }
    }
}

/// Property-based tests for the chained-MAC construction. The example
/// tests above pin specific chains; these assert the chain invariants —
/// verify round-trip, wire round-trip, additive attenuation, and
/// tamper/key/keyref binding — over arbitrary keys, keyrefs, nonces, and
/// chains that interleave first- and third-party caveats. Most properties
/// mint through [`mint_under_key_with_nonce`] so the nonce is generated
/// (deterministic and shrinkable) rather than drawn from `OsRng`.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn key() -> impl Strategy<Value = [u8; 32]> {
        proptest::array::uniform32(any::<u8>())
    }

    fn nonce() -> impl Strategy<Value = [u8; NONCE_LEN]> {
        proptest::array::uniform16(any::<u8>())
    }

    fn key_ref() -> impl Strategy<Value = KeyRef> {
        prop_oneof![
            any::<Kid>().prop_map(KeyRef::Keyring),
            Just(KeyRef::Discharge),
            Just(KeyRef::Session),
        ]
    }

    /// A chain step: mostly first-party scalars, occasionally a
    /// third-party caveat, so generated chains interleave both kinds.
    fn any_caveat() -> impl Strategy<Value = Caveat> {
        prop_oneof![
            3 => (".{0,12}", ".{0,12}").prop_map(|(n, v)| Caveat::scalar(n, v)),
            1 => ("[a-z:/.]{0,16}", vec(any::<u8>(), 0..40), vec(any::<u8>(), 0..40))
                .prop_map(|(loc, vid, cid)| Caveat::third_party(loc, vid, cid)),
        ]
    }

    fn chain() -> impl Strategy<Value = Vec<Caveat>> {
        vec(any_caveat(), 0..10)
    }

    proptest! {
        /// Minting through the keyring and verifying against it round-trips;
        /// a keyring holding any other key rejects.
        #[test]
        fn mint_via_keyring_round_trips(k in key(), other in key(), caveats in chain()) {
            let kr = Keyring::single(k);
            let m = mint(&kr, caveats);
            prop_assert!(m.verify(&kr));
            if k != other {
                prop_assert!(!m.verify(&Keyring::single(other)));
            }
        }

        /// A macaroon verifies under the key it was minted with and under
        /// no other key — for any keyref, nonce, and chain.
        #[test]
        fn verifies_under_its_key_and_not_others(
            k in key(), other in key(), kr in key_ref(), nonce in nonce(), caveats in chain(),
        ) {
            let m = mint_under_key_with_nonce(&k, kr, nonce, caveats);
            prop_assert!(m.verify_under_key(&k));
            if k != other {
                prop_assert!(!m.verify_under_key(&other));
            }
        }

        /// The wire form round-trips: decode∘encode is the identity, and
        /// the decoded macaroon still verifies.
        #[test]
        fn encode_decode_round_trips(
            k in key(), kr in key_ref(), nonce in nonce(), caveats in chain(),
        ) {
            let m = mint_under_key_with_nonce(&k, kr, nonce, caveats);
            let back = Macaroon::decode(&m.encode()).expect("decode its own encoding");
            prop_assert_eq!(&m, &back);
            prop_assert!(back.verify_under_key(&k));
        }

        /// Attenuation *is* chain extension: minting `base` then appending
        /// `extra` one at a time yields a macaroon byte-identical to minting
        /// `base ++ extra` directly (same keyref/nonce). So attenuation only
        /// ever appends — it can never alter an existing caveat or the seed.
        #[test]
        fn attenuation_equals_minting_the_concatenation(
            k in key(), kr in key_ref(), nonce in nonce(),
            base in chain(), extra in vec(any_caveat(), 0..6),
        ) {
            let mut attenuated = mint_under_key_with_nonce(&k, kr, nonce, base.clone());
            for c in &extra {
                attenuated = attenuated.attenuate(c.clone());
            }
            let mut all = base;
            all.extend(extra);
            let direct = mint_under_key_with_nonce(&k, kr, nonce, all);
            prop_assert_eq!(&attenuated, &direct);
            prop_assert!(attenuated.verify_under_key(&k));
        }

        /// Appending any caveat changes the trailing MAC — the PoP anchor
        /// moves, so a proof over the old tail won't bind the new macaroon.
        #[test]
        fn appending_a_caveat_changes_the_tail(
            k in key(), kr in key_ref(), nonce in nonce(), base in chain(), c in any_caveat(),
        ) {
            let m = mint_under_key_with_nonce(&k, kr, nonce, base);
            let before = *m.tail();
            let after = m.attenuate(c);
            prop_assert_ne!(&before, after.tail());
        }

        /// Replacing any caveat with a different one breaks verification —
        /// the holder cannot rewrite a caveat under the trailing MAC.
        #[test]
        fn tampering_a_caveat_fails_verify(
            k in key(), kr in key_ref(), nonce in nonce(),
            caveats in vec(any_caveat(), 1..10), idx in any::<usize>(), replacement in any_caveat(),
        ) {
            let i = idx % caveats.len();
            prop_assume!(caveats[i] != replacement);
            let mut forged = mint_under_key_with_nonce(&k, kr, nonce, caveats);
            forged.caveats[i] = replacement;
            prop_assert!(!forged.verify_under_key(&k));
        }

        /// The keyref is bound into the chain seed: changing it after
        /// minting breaks verification even under the correct key.
        #[test]
        fn changing_key_ref_fails_verify(
            k in key(), kr in key_ref(), other_kr in key_ref(),
            nonce in nonce(), caveats in chain(),
        ) {
            prop_assume!(kr != other_kr);
            let mut m = mint_under_key_with_nonce(&k, kr, nonce, caveats);
            m.key_ref = other_kr;
            prop_assert!(!m.verify_under_key(&k));
        }

        /// Any single-bit flip in the MAC fails verification.
        #[test]
        fn flipping_the_mac_fails_verify(
            k in key(), kr in key_ref(), nonce in nonce(), caveats in chain(),
            byte in 0usize..32, bit in 0u8..8,
        ) {
            let mut m = mint_under_key_with_nonce(&k, kr, nonce, caveats);
            let mut flipped = *m.mac.as_bytes();
            flipped[byte] ^= 1 << bit;
            m.mac = blake3::Hash::from_bytes(flipped);
            prop_assert!(!m.verify_under_key(&k));
        }

        /// `verify_collecting_tpcs` agrees with `verify` and surfaces every
        /// third-party caveat, in chain order — for any chain.
        #[test]
        fn collecting_tpcs_matches_verify_and_lists_tpcs_in_order(
            k in key(), kr in key_ref(), nonce in nonce(), caveats in chain(),
        ) {
            let m = mint_under_key_with_nonce(&k, kr, nonce, caveats.clone());
            let sites = m.verify_collecting_tpcs(&k).expect("minted under k must verify");
            let tpc_locations: Vec<&str> = caveats
                .iter()
                .filter_map(|c| match c {
                    Caveat::ThirdParty { location, .. } => Some(location.as_str()),
                    _ => None,
                })
                .collect();
            prop_assert_eq!(sites.len(), tpc_locations.len());
            for (site, loc) in sites.iter().zip(&tpc_locations) {
                prop_assert_eq!(site.location, *loc);
            }
        }
    }
}
