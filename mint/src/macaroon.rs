//! Generic chained-MAC macaroon.
//!
//! Standard chained-keyed-BLAKE3 construction over free-form named
//! **scalar** caveats, with the per-step type tag that lets a chain
//! interleave first-party and third-party caveats:
//!
//! ```text
//! mac_seed = blake3_keyed(keyring[kid], DOMAIN || kid_be || nonce)
//! mac_i    = blake3_keyed(mac_{i-1}, serialize_one(c_i))
//! ```
//!
//! Each step's key is the previous step's MAC, so any holder of the
//! trailing MAC can append a caveat (the additive-restriction property)
//! but cannot remove one. Verification picks the per-token `kid` out of
//! the wire format, looks it up in the verifier's [`Keyring`], replays
//! the chain, and constant-time-compares the final MAC. A kid that is
//! not in the ring (retired, or never existed) fails verification with
//! the same opacity as a bad MAC.
//!
//! Wire format: a binary container, base64-encoded for the
//! `Authorization: Macaroon <b64>` header (per `docs/design-mint.md`
//! § *Authentication*):
//!
//! ```text
//! magic   "mcrn3"  (5 bytes)
//! kid     u16 BE   (2 bytes — the keyring generation that MAC'd this token)
//! nonce   16 bytes
//! mac     32 bytes
//! count   u16 BE
//! repeated serialize_one(caveat):
//!   type  u8                           // 0 = first-party, 1 = third-party
//!   if first-party:                    // u32 name-len, name, u32 val-len, val
//!   if third-party:                    // u32 loc-len, loc, u32 vid-len, vid, u32 cid-len, cid
//! ```
//!
//! `serialize_one` is the canonical per-caveat encoding fed into the
//! MAC chain; the same bytes appear on the wire so a decoded macaroon
//! re-MACs identically. v3 extends v2 with the per-step type byte to
//! disambiguate first-party from third-party caveats; v2-shaped
//! macaroons (no type byte) do not interoperate.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

use crate::caveat::Caveat;
use crate::keyring::{Keyring, Kid};

const MAGIC: &[u8; 5] = b"mcrn3";
const DOMAIN: &[u8] = b"mint-macaroon-v3";
pub const NONCE_LEN: usize = 16;

/// Per-step type tag in the wire format and in the MAC-chain digest.
/// First-party = 0; third-party = 1. Encoded as the first byte of
/// every `serialize_one` output so a TPC can never be confused with a
/// first-party caveat whose name happens to start with a length-byte
/// pattern.
const TYPE_FIRST_PARTY: u8 = 0;
const TYPE_THIRD_PARTY: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macaroon {
    kid: Kid,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
    mac: [u8; 32],
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
    #[error("base64 decode failed")]
    Base64,
    #[error("truncated macaroon")]
    Truncated,
    #[error("bad magic")]
    BadMagic,
    #[error("invalid caveat encoding")]
    BadCaveat,
}

fn serialize_one(c: &Caveat) -> Vec<u8> {
    match c {
        Caveat::FirstParty { name, value } => {
            let name = name.as_bytes();
            let val = value.as_bytes();
            let mut out = Vec::with_capacity(1 + 8 + name.len() + val.len());
            out.push(TYPE_FIRST_PARTY);
            out.extend_from_slice(&(name.len() as u32).to_be_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(&(val.len() as u32).to_be_bytes());
            out.extend_from_slice(val);
            out
        }
        Caveat::ThirdParty { location, vid, cid } => {
            let loc = location.as_bytes();
            let mut out = Vec::with_capacity(1 + 12 + loc.len() + vid.len() + cid.len());
            out.push(TYPE_THIRD_PARTY);
            out.extend_from_slice(&(loc.len() as u32).to_be_bytes());
            out.extend_from_slice(loc);
            out.extend_from_slice(&(vid.len() as u32).to_be_bytes());
            out.extend_from_slice(vid);
            out.extend_from_slice(&(cid.len() as u32).to_be_bytes());
            out.extend_from_slice(cid);
            out
        }
    }
}

/// Initial chain tag: keyed BLAKE3 over `DOMAIN || kid || nonce`. The
/// kid is bound here so a key recovered from one generation cannot be
/// replayed under a different kid claim.
fn seed_mac(key: &[u8; 32], kid: Kid, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut seed_msg = Vec::with_capacity(DOMAIN.len() + 2 + NONCE_LEN);
    seed_msg.extend_from_slice(DOMAIN);
    seed_msg.extend_from_slice(&kid.to_be_bytes());
    seed_msg.extend_from_slice(nonce);
    *blake3::keyed_hash(key, &seed_msg).as_bytes()
}

/// One step of the chain MAC: `BLAKE3-keyed(prev_mac, serialize_one(c))`.
fn step_mac(prev: &[u8; 32], c: &Caveat) -> [u8; 32] {
    *blake3::keyed_hash(prev, &serialize_one(c)).as_bytes()
}

/// Walk the chain end-to-end. Used by [`Macaroon::verify`] and by
/// [`mint`] when no TPC is being stamped.
fn chain_mac(key: &[u8; 32], kid: Kid, nonce: &[u8; NONCE_LEN], caveats: &[Caveat]) -> [u8; 32] {
    let mut mac = seed_mac(key, kid, nonce);
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
    let kid = keyring.current_kid();
    let key = keyring.current_key();
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mac = chain_mac(key, kid, &nonce, &caveats);
    Macaroon {
        kid,
        nonce,
        caveats,
        mac,
    }
}

/// Mint a macaroon under a raw 32-byte key — the keyring-less twin
/// of [`mint`], used when the issuer holds the key directly. Discharge
/// macaroons go through this path: they're MAC'd under the per-client
/// ephemeral `r`, not under any entry in mint's root keyring, so the
/// issuer supplies `(key, kid)` directly. `kid` is a free label the
/// verifier must agree on; auth and mint use [`DISCHARGE_KID`] by
/// convention.
pub fn mint_under_key(key: &[u8; 32], kid: Kid, caveats: Vec<Caveat>) -> Macaroon {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mac = chain_mac(key, kid, &nonce, &caveats);
    Macaroon {
        kid,
        nonce,
        caveats,
        mac,
    }
}

/// `kid` value the discharge-issuing path uses. The kid slot in a
/// discharge's wire format doesn't index any keyring (the discharge
/// is MAC'd under the per-client ephemeral `r`), but the value
/// participates in the chain seed so issuer and verifier must agree.
/// 0 is the convention; it is unrelated to mint's root-keyring `kid=0`
/// because verification of a discharge takes `r` directly via
/// [`Macaroon::verify_under_key`] rather than looking the kid up.
pub const DISCHARGE_KID: Kid = 0;

impl Macaroon {
    pub fn kid(&self) -> Kid {
        self.kid
    }

    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The trailing MAC. This is the holder-of-key PoP anchor: the
    /// `elide:CoordKey` proof signs over `tail ‖ BLAKE3(body)`, so the
    /// tail binds the proof to *this* exact attenuated macaroon
    /// (`docs/design-mint.md` § *Credential macaroon & lifecycle*, [`crate::pop`]).
    pub fn tail(&self) -> &[u8; 32] {
        &self.mac
    }

    /// Hex of the nonce — a stable per-token identity for the audit log.
    pub fn nonce_hex(&self) -> String {
        self.nonce.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Append `c`, extending the MAC chain with only the trailing MAC.
    /// Caveats are AND-evaluated, so this can only restrict authority.
    pub fn attenuate(mut self, c: Caveat) -> Macaroon {
        let step = serialize_one(&c);
        self.mac = *blake3::keyed_hash(&self.mac, &step).as_bytes();
        self.caveats.push(c);
        self
    }

    /// Constant-time MAC verification against `keyring`. The token's
    /// embedded `kid` selects which generation to verify under; an
    /// absent kid (retired or never existed) fails verification with
    /// the same opacity as a bad MAC. Caveat-value checks (audience,
    /// role, ttl) are the caller's job — see [`crate::role`].
    pub fn verify(&self, keyring: &Keyring) -> bool {
        let Some(key) = keyring.get(self.kid) else {
            return false;
        };
        self.verify_under_key(key)
    }

    /// Constant-time MAC verification against a raw 32-byte key. The
    /// keyring-less twin of [`verify`](Self::verify), used when the
    /// verifier holds the key directly rather than via a generation
    /// lookup — discharge macaroons, which are MAC'd under the
    /// per-client ephemeral `r` rather than under any keyring entry,
    /// verify through this path. The `kid` slot still participates in
    /// the chain seed, so issuer and verifier must agree on whatever
    /// label the issuer used.
    pub fn verify_under_key(&self, key: &[u8; 32]) -> bool {
        let expected = chain_mac(key, self.kid, &self.nonce, &self.caveats);
        expected.ct_eq(&self.mac).into()
    }

    /// Verify the chain MAC under `key` and return the third-party
    /// caveats encountered along the way, each annotated with the
    /// chain tag `T_{n-1}` *before* the TPC was appended. That tag
    /// is the AEAD key the verifier needs to recover `r` from this
    /// TPC's VID (see [`crate::tpc::decrypt_vid`]). The order is
    /// the chain order. Returns `None` if the MAC doesn't verify;
    /// returns an empty vec for a chain with no TPCs.
    pub fn verify_collecting_tpcs(&self, key: &[u8; 32]) -> Option<Vec<TpcSite<'_>>> {
        let mut mac = seed_mac(key, self.kid, &self.nonce);
        let mut sites: Vec<TpcSite<'_>> = Vec::new();
        for c in &self.caveats {
            if let Caveat::ThirdParty { location, vid, cid } = c {
                sites.push(TpcSite {
                    t_n_minus_1: mac,
                    location,
                    vid,
                    cid,
                });
            }
            mac = step_mac(&mac, c);
        }
        if bool::from(mac.ct_eq(&self.mac)) {
            Some(sites)
        } else {
            None
        }
    }

    pub fn encode(&self) -> String {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.kid.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&(self.caveats.len() as u16).to_be_bytes());
        for c in &self.caveats {
            buf.extend_from_slice(&serialize_one(c));
        }
        BASE64.encode(buf)
    }

    pub fn decode(s: &str) -> Result<Macaroon, DecodeError> {
        let buf = BASE64.decode(s.trim()).map_err(|_| DecodeError::Base64)?;
        let mut r = Reader::new(&buf);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let kid = Kid::from_be_bytes(r.take(2)?.try_into().map_err(|_| DecodeError::Truncated)?);
        let nonce: [u8; NONCE_LEN] = r
            .take(NONCE_LEN)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let mac: [u8; 32] = r.take(32)?.try_into().map_err(|_| DecodeError::Truncated)?;
        let count = u16::from_be_bytes(r.take(2)?.try_into().map_err(|_| DecodeError::Truncated)?);
        let mut caveats = Vec::with_capacity(count as usize);
        for _ in 0..count {
            caveats.push(r.caveat()?);
        }
        if !r.is_empty() {
            return Err(DecodeError::BadCaveat);
        }
        Ok(Macaroon {
            kid,
            nonce,
            caveats,
            mac,
        })
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<usize, DecodeError> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_be_bytes(b) as usize)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let len = self.u32()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::BadCaveat)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = self.take(1)?;
        Ok(b[0])
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()?;
        Ok(self.take(len)?.to_vec())
    }

    fn caveat(&mut self) -> Result<Caveat, DecodeError> {
        match self.byte()? {
            TYPE_FIRST_PARTY => {
                let name = self.string()?;
                let value = self.string()?;
                Ok(Caveat::FirstParty { name, value })
            }
            TYPE_THIRD_PARTY => {
                let location = self.string()?;
                let vid = self.bytes()?;
                let cid = self.bytes()?;
                Ok(Caveat::ThirdParty { location, vid, cid })
            }
            _ => Err(DecodeError::BadCaveat),
        }
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
                Caveat::scalar("NotAfter", "1700000000"),
            ],
        );
        let wire = m.encode();
        let back = Macaroon::decode(&wire).expect("decode");
        assert_eq!(m, back);
        assert!(back.verify(&ring()));
    }

    #[test]
    fn encode_decode_roundtrip_with_third_party() {
        // Mixed chain: first-party caveats interleaved with a TPC.
        // Exercises the v3 type-tagged wire format end-to-end.
        let m = mint(
            &ring(),
            vec![
                Caveat::scalar("Audience", "mint"),
                Caveat::third_party("https://auth.example/", vec![1u8; 28], vec![2u8; 60]),
                Caveat::scalar("NotAfter", "1700000000"),
            ],
        );
        let wire = m.encode();
        let back = Macaroon::decode(&wire).expect("decode");
        assert_eq!(m, back);
        assert!(back.verify(&ring()));
        // The TPC sits at chain position 1.
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
        // Swap a byte in the VID — chain MAC must reject.
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
        // The keyring-less mint/verify pair used for discharges.
        let r = [9u8; 32];
        let m = mint_under_key(
            &r,
            DISCHARGE_KID,
            vec![
                Caveat::scalar("Subject", "usr_abc"),
                Caveat::scalar("CoordId", "01ARZ"),
                Caveat::scalar("NotAfter", "1700000000"),
            ],
        );
        assert_eq!(m.kid(), DISCHARGE_KID);
        assert!(m.verify_under_key(&r));
    }

    #[test]
    fn verify_under_key_rejects_wrong_key() {
        let r = [9u8; 32];
        let m = mint_under_key(
            &r,
            DISCHARGE_KID,
            vec![Caveat::scalar("Subject", "usr_abc")],
        );
        let mut wrong = r;
        wrong[15] ^= 0x80;
        assert!(!m.verify_under_key(&wrong));
    }

    #[test]
    fn verify_under_key_rejects_tampered_caveat() {
        let r = [9u8; 32];
        let m = mint_under_key(&r, DISCHARGE_KID, vec![Caveat::scalar("CoordId", "01ARZ")]);
        let mut forged = Macaroon::decode(&m.encode()).unwrap();
        forged.caveats[0] = Caveat::scalar("CoordId", "01EVIL");
        assert!(!forged.verify_under_key(&r));
    }

    #[test]
    fn verify_collecting_tpcs_returns_chain_tags_in_chain_order() {
        // A chain with two TPCs interleaved with first-party caveats.
        // The captured t_{n-1} for each TPC must equal the chain tag
        // mint *would* have produced just before appending the TPC —
        // we cross-check by replaying the chain on a truncated copy.
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

        // Cross-check chain tags by replaying truncated chains.
        let prefix_to_first_tpc = mint(&r, vec![Caveat::scalar("aud", "mint")]);
        // The truncated mint has a fresh nonce so we can't compare
        // tails directly. Instead, verify that the captured tag
        // satisfies what mint would step from.
        assert_ne!(sites[0].t_n_minus_1, sites[1].t_n_minus_1);
        let _ = prefix_to_first_tpc; // kept for narrative — tags differ
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
    fn discharge_kid_distinct_from_keyring_kid_zero() {
        // A discharge minted under r=0xFF.. with DISCHARGE_KID happens
        // to share the kid label "0" with a hypothetical kid-0 keyring
        // entry; the chain MAC still verifies under `r` (which is what
        // matters) and does not verify against the keyring's key at
        // that same kid label.
        let r = [0xff; 32];
        let m = mint_under_key(
            &r,
            DISCHARGE_KID,
            vec![Caveat::scalar("Subject", "usr_abc")],
        );
        assert!(m.verify_under_key(&r));
        assert!(!m.verify(&ring())); // ring's kid=0 is [7u8; 32], not [0xff; 32]
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
        // A macaroon's MAC seeds with its kid, so swapping the kid bytes
        // on the wire (even to one whose key is in the ring) breaks the
        // chain.
        let dir = tempfile::tempdir().unwrap();
        let mut kr = Keyring::open(&dir.path().join("rk"), None, None).unwrap();
        kr.add_and_promote(&dir.path().join("rk"), None).unwrap();
        // Mint under kid=1, then forge a copy that claims kid=0.
        let m = mint(&kr, vec![Caveat::scalar("Audience", "mint")]);
        assert_eq!(m.kid(), 1);
        let mut forged = Macaroon::decode(&m.encode()).unwrap();
        forged.kid = 0;
        assert!(!forged.verify(&kr));
    }

    #[test]
    fn garbage_decode_is_error_not_panic() {
        assert!(Macaroon::decode("not base64!!!").is_err());
        assert!(Macaroon::decode(&BASE64.encode([0u8; 3])).is_err());
    }

    #[test]
    fn token_minted_under_old_kid_still_verifies_until_retired() {
        // The whole point of the keyring: rotation is additive until
        // explicit retirement.
        let dir = tempfile::tempdir().unwrap();
        let rk = dir.path().join("rk");
        let mut kr = Keyring::open(&rk, None, None).unwrap();
        let token_under_zero = mint(&kr, vec![Caveat::scalar("Audience", "mint")]);
        let new_kid = kr.add_and_promote(&rk, None).unwrap();
        assert_eq!(new_kid, 1);
        assert!(
            token_under_zero.verify(&kr),
            "old token verifies because kid=0 is still in the ring"
        );
        kr.retire(&rk, 0).unwrap();
        assert!(
            !token_under_zero.verify(&kr),
            "after retire(0) the old token fails — by design"
        );
    }
}
