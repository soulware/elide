//! Generic chained-MAC macaroon.
//!
//! Same construction as the elide coordinator's v2 macaroon
//! (`elide-coordinator/src/macaroon.rs`) and `docs/design-auth-model.md`,
//! generalised to free-form named **scalar** caveats:
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
//! magic   "mcrn2"  (5 bytes)
//! kid     u16 BE   (2 bytes — the keyring generation that MAC'd this token)
//! nonce   16 bytes
//! mac     32 bytes
//! count   u16 BE
//! repeated serialize_one(caveat)  // u32 name-len, name, u32 val-len, val
//! ```
//!
//! `serialize_one` is the canonical per-caveat encoding fed into the
//! MAC chain; the same bytes appear on the wire so a decoded macaroon
//! re-MACs identically.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

use crate::caveat::Caveat;
use crate::keyring::{Keyring, Kid};

const MAGIC: &[u8; 5] = b"mcrn2";
const DOMAIN: &[u8] = b"mint-macaroon-v2";
pub const NONCE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macaroon {
    kid: Kid,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
    mac: [u8; 32],
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
    let name = c.name.as_bytes();
    let val = c.value.as_bytes();
    let mut out = Vec::with_capacity(name.len() + val.len() + 8);
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(val.len() as u32).to_be_bytes());
    out.extend_from_slice(val);
    out
}

/// Chain the MAC under `key`, binding the seed to `kid` so a key
/// recovered from one generation cannot be replayed under a different
/// kid claim (paranoia — the verifier already picks the key by kid).
fn chain_mac(key: &[u8; 32], kid: Kid, nonce: &[u8; NONCE_LEN], caveats: &[Caveat]) -> [u8; 32] {
    let mut seed_msg = Vec::with_capacity(DOMAIN.len() + 2 + NONCE_LEN);
    seed_msg.extend_from_slice(DOMAIN);
    seed_msg.extend_from_slice(&kid.to_be_bytes());
    seed_msg.extend_from_slice(nonce);
    let mut mac = *blake3::keyed_hash(key, &seed_msg).as_bytes();
    for c in caveats {
        let step = serialize_one(c);
        mac = *blake3::keyed_hash(&mac, &step).as_bytes();
    }
    mac
}

/// Mint a macaroon under the keyring's **current** generation. Mint is
/// the issuer *and* verifier of the credential macaroon (the root never
/// leaves the process — see `docs/design-mint.md` § *Trust model*);
/// this is the issuer side.
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
        let expected = chain_mac(key, self.kid, &self.nonce, &self.caveats);
        expected.ct_eq(&self.mac).into()
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

    fn caveat(&mut self) -> Result<Caveat, DecodeError> {
        let name = self.string()?;
        let value = self.string()?;
        Ok(Caveat { name, value })
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
