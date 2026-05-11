// Typed macaroons for coordinator-issued credentials.
//
// A macaroon is a bearer token bound to a chain of typed caveats, MACed
// with the coordinator's root key. Verification is stateless: the
// coordinator re-derives the expected MAC from the root key + caveat
// chain — no token storage is needed.
//
// Wire format (a single hex line, fits the existing IPC line protocol):
//     v1.<32-byte mac, hex>.<caveats blob, hex>
//
// Caveats blob (binary, hex-encoded for transport):
//     u8: count
//     repeated:
//       u8 tag
//       Volume   (tag 0): u8 len, N UTF-8 bytes
//       Scope    (tag 1): u8 (0 = credentials, 1 = fetch-worker)
//       Pid      (tag 2): i32 BE
//       NotAfter (tag 3): u64 BE  (unix seconds)
//       Role     (tag 4): u8 (0 = operator)
//       Nonce    (tag 5): 16 bytes (random)
//
// The MAC is `blake3::keyed_hash(root_key, caveats_blob)`. blake3 in keyed
// mode is HMAC-equivalent for our purposes (per the blake3 spec).

use std::io;

const MAGIC: &str = "v1";
const TAG_VOLUME: u8 = 0;
const TAG_SCOPE: u8 = 1;
const TAG_PID: u8 = 2;
const TAG_NOT_AFTER: u8 = 3;
const TAG_ROLE: u8 = 4;
const TAG_NONCE: u8 = 5;

const SCOPE_CREDENTIALS: u8 = 0;
const SCOPE_FETCH_WORKER: u8 = 1;

const ROLE_OPERATOR: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Issued to a registered volume daemon. Backs the
    /// `Request::Credentials` IPC for demand-fetch creds.
    Credentials,
    /// Issued to a coordinator-spawned `elide fetch-volume` worker.
    /// PID-bound to the worker via a `fetch.pid` file (not
    /// `volume.pid`, which is reserved for the volume daemon).
    /// Otherwise indistinguishable from a `Credentials`-scoped
    /// macaroon at the IPC layer — both grant short-lived S3 creds
    /// for the same volume — but separating the scope keeps a
    /// leaked fetch macaroon from being usable as if it were a
    /// volume-daemon credential.
    FetchWorker,
}

impl Scope {
    fn to_byte(self) -> u8 {
        match self {
            Self::Credentials => SCOPE_CREDENTIALS,
            Self::FetchWorker => SCOPE_FETCH_WORKER,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            SCOPE_CREDENTIALS => Some(Self::Credentials),
            SCOPE_FETCH_WORKER => Some(Self::FetchWorker),
            _ => None,
        }
    }
}

/// Distinguishes operator-issued tokens (human CLI users) from
/// volume-process tokens. Volume tokens carry `Scope` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Operator macaroon: not PID-bound, gates coordinator mutations
    /// (currently `Remove`). Requires a `NotAfter` caveat.
    Operator,
}

impl Role {
    fn to_byte(self) -> u8 {
        match self {
            Self::Operator => ROLE_OPERATOR,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            ROLE_OPERATOR => Some(Self::Operator),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    Volume(String),
    Scope(Scope),
    Pid(i32),
    NotAfter(u64),
    Role(Role),
    Nonce([u8; 16]),
}

#[derive(Debug, Clone)]
pub struct Macaroon {
    caveats: Vec<Caveat>,
    mac: [u8; 32],
}

impl Macaroon {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    pub fn volume(&self) -> Option<&str> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Volume(v) => Some(v.as_str()),
            _ => None,
        })
    }

    pub fn scope(&self) -> Option<Scope> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Scope(s) => Some(*s),
            _ => None,
        })
    }

    pub fn pid(&self) -> Option<i32> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Pid(p) => Some(*p),
            _ => None,
        })
    }

    pub fn not_after(&self) -> Option<u64> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::NotAfter(t) => Some(*t),
            _ => None,
        })
    }

    pub fn role(&self) -> Option<Role> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Role(r) => Some(*r),
            _ => None,
        })
    }

    pub fn nonce(&self) -> Option<[u8; 16]> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Nonce(n) => Some(*n),
            _ => None,
        })
    }

    pub fn encode(&self) -> String {
        let blob = serialize_caveats(&self.caveats);
        format!("{MAGIC}.{}.{}", encode_hex(&self.mac), encode_hex(&blob))
    }

    pub fn parse(s: &str) -> io::Result<Self> {
        let mut parts = s.splitn(3, '.');
        let magic = parts
            .next()
            .ok_or_else(|| io::Error::other("malformed macaroon"))?;
        if magic != MAGIC {
            return Err(io::Error::other(format!(
                "unsupported macaroon version: {magic}"
            )));
        }
        let mac_hex = parts
            .next()
            .ok_or_else(|| io::Error::other("malformed macaroon"))?;
        let cav_hex = parts
            .next()
            .ok_or_else(|| io::Error::other("malformed macaroon"))?;
        let mac = decode_hex_fixed::<32>(mac_hex)?;
        let blob = decode_hex(cav_hex)?;
        let caveats = deserialize_caveats(&blob)?;
        Ok(Self { caveats, mac })
    }
}

/// Mint a macaroon by MACing the serialized caveat chain with `root_key`.
pub fn mint(root_key: &[u8; 32], caveats: Vec<Caveat>) -> Macaroon {
    let blob = serialize_caveats(&caveats);
    let mac = blake3::keyed_hash(root_key, &blob);
    Macaroon {
        caveats,
        mac: *mac.as_bytes(),
    }
}

/// Constant-time MAC verification. The caller is still responsible for
/// checking individual caveat values against runtime context (volume,
/// scope, pid, expiry).
pub fn verify(root_key: &[u8; 32], m: &Macaroon) -> bool {
    let blob = serialize_caveats(&m.caveats);
    let expected = blake3::keyed_hash(root_key, &blob);
    constant_time_eq(expected.as_bytes(), &m.mac)
}

/// Mint an operator macaroon. `expires_unix` is required (no
/// indefinite operator tokens, per `docs/architecture.md` § *Operator
/// tokens*). `volume` optionally restricts the token to operations on
/// one volume name. A fresh 16-byte random nonce is included so the
/// audit log can tie each authenticated operation back to a specific
/// `token create` event.
pub fn mint_operator(root_key: &[u8; 32], expires_unix: u64, volume: Option<&str>) -> Macaroon {
    use rand_core::RngCore;
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let mut caveats = vec![Caveat::Role(Role::Operator), Caveat::NotAfter(expires_unix)];
    if let Some(v) = volume {
        caveats.push(Caveat::Volume(v.to_owned()));
    }
    caveats.push(Caveat::Nonce(nonce));
    mint(root_key, caveats)
}

/// Reasons an operator token may be rejected. Distinguishes "no token
/// presented" from "token presented but invalid" so the dispatcher can
/// log differently. Values are intentionally coarse — leaking finer
/// detail would help an attacker probe token state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorReject {
    Malformed,
    BadMac,
    WrongRole,
    Expired,
    VolumeMismatch,
}

/// Verify an encoded operator macaroon against the coordinator's root
/// key and the current operation's runtime context.
///
/// Checks, in order: parseable; MAC matches; carries
/// `Role::Operator`; `NotAfter` is present and in the future; if a
/// `Volume` caveat is present, it matches the operation's target
/// volume.
pub fn verify_operator(
    root_key: &[u8; 32],
    encoded: &str,
    now_unix: u64,
    op_volume: Option<&str>,
) -> Result<Macaroon, OperatorReject> {
    let m = Macaroon::parse(encoded).map_err(|_| OperatorReject::Malformed)?;
    if !verify(root_key, &m) {
        return Err(OperatorReject::BadMac);
    }
    if m.role() != Some(Role::Operator) {
        return Err(OperatorReject::WrongRole);
    }
    let expiry = m.not_after().ok_or(OperatorReject::Expired)?;
    if expiry <= now_unix {
        return Err(OperatorReject::Expired);
    }
    if let Some(scoped_to) = m.volume() {
        match op_volume {
            Some(req_volume) if req_volume == scoped_to => {}
            _ => return Err(OperatorReject::VolumeMismatch),
        }
    }
    Ok(m)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn serialize_caveats(caveats: &[Caveat]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(caveats.len() as u8);
    for c in caveats {
        match c {
            Caveat::Volume(v) => {
                out.push(TAG_VOLUME);
                let bytes = v.as_bytes();
                debug_assert!(bytes.len() <= u8::MAX as usize);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            Caveat::Scope(s) => {
                out.push(TAG_SCOPE);
                out.push(s.to_byte());
            }
            Caveat::Pid(p) => {
                out.push(TAG_PID);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Caveat::NotAfter(t) => {
                out.push(TAG_NOT_AFTER);
                out.extend_from_slice(&t.to_be_bytes());
            }
            Caveat::Role(r) => {
                out.push(TAG_ROLE);
                out.push(r.to_byte());
            }
            Caveat::Nonce(n) => {
                out.push(TAG_NONCE);
                out.extend_from_slice(n);
            }
        }
    }
    out
}

fn deserialize_caveats(blob: &[u8]) -> io::Result<Vec<Caveat>> {
    let mut cur = blob;
    let count = read_u8(&mut cur)?;
    let mut caveats = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let tag = read_u8(&mut cur)?;
        let c = match tag {
            TAG_VOLUME => {
                let len = read_u8(&mut cur)? as usize;
                let bytes = read_n(&mut cur, len)?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|_| io::Error::other("non-utf8 volume caveat"))?;
                Caveat::Volume(s.to_owned())
            }
            TAG_SCOPE => {
                let b = read_u8(&mut cur)?;
                Caveat::Scope(
                    Scope::from_byte(b)
                        .ok_or_else(|| io::Error::other(format!("unknown scope: {b}")))?,
                )
            }
            TAG_PID => {
                let bytes = read_n(&mut cur, 4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(bytes);
                Caveat::Pid(i32::from_be_bytes(a))
            }
            TAG_NOT_AFTER => {
                let bytes = read_n(&mut cur, 8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(bytes);
                Caveat::NotAfter(u64::from_be_bytes(a))
            }
            TAG_ROLE => {
                let b = read_u8(&mut cur)?;
                Caveat::Role(
                    Role::from_byte(b)
                        .ok_or_else(|| io::Error::other(format!("unknown role: {b}")))?,
                )
            }
            TAG_NONCE => {
                let bytes = read_n(&mut cur, 16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(bytes);
                Caveat::Nonce(a)
            }
            _ => return Err(io::Error::other(format!("unknown caveat tag: {tag}"))),
        };
        caveats.push(c);
    }
    if !cur.is_empty() {
        return Err(io::Error::other("trailing bytes in caveat blob"));
    }
    Ok(caveats)
}

fn read_u8(cur: &mut &[u8]) -> io::Result<u8> {
    if cur.is_empty() {
        return Err(io::Error::other("unexpected eof in caveat blob"));
    }
    let b = cur[0];
    *cur = &cur[1..];
    Ok(b)
}

fn read_n<'a>(cur: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if cur.len() < n {
        return Err(io::Error::other("unexpected eof in caveat blob"));
    }
    let r = &cur[..n];
    *cur = &cur[n..];
    Ok(r)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> io::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(io::Error::other("hex string has odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| io::Error::other(format!("invalid hex at position {i}")))
        })
        .collect()
}

fn decode_hex_fixed<const N: usize>(s: &str) -> io::Result<[u8; N]> {
    let v = decode_hex(s)?;
    v.try_into()
        .map_err(|v: Vec<u8>| io::Error::other(format!("expected {N} bytes, got {}", v.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn sample_caveats() -> Vec<Caveat> {
        vec![
            Caveat::Volume("01JQAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
            Caveat::Scope(Scope::Credentials),
            Caveat::Pid(12345),
        ]
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let m = mint(&key(), sample_caveats());
        assert!(verify(&key(), &m));
    }

    #[test]
    fn encode_then_parse_roundtrip() {
        let m = mint(&key(), sample_caveats());
        let s = m.encode();
        let parsed = Macaroon::parse(&s).unwrap();
        assert_eq!(parsed.caveats, m.caveats);
        assert_eq!(parsed.mac, m.mac);
        assert!(verify(&key(), &parsed));
    }

    #[test]
    fn accessors_extract_caveat_values() {
        let m = mint(&key(), sample_caveats());
        assert_eq!(m.volume(), Some("01JQAAAAAAAAAAAAAAAAAAAAAA"));
        assert_eq!(m.scope(), Some(Scope::Credentials));
        assert_eq!(m.pid(), Some(12345));
        assert_eq!(m.not_after(), None);
    }

    #[test]
    fn tampered_mac_fails_verify() {
        let m = mint(&key(), sample_caveats());
        let mut s = m.encode();
        // Flip a byte in the MAC region: format is `v1.<mac>.<blob>`,
        // so the first dot is at index 2.
        let dot = s.find('.').unwrap();
        let pos = dot + 2;
        let bytes = unsafe { s.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'a' { b'b' } else { b'a' };
        let parsed = Macaroon::parse(&s).unwrap();
        assert!(!verify(&key(), &parsed));
    }

    #[test]
    fn tampered_caveat_fails_verify() {
        let m = mint(&key(), sample_caveats());
        let mut new_caveats = m.caveats().to_vec();
        // Mutate the pid — verify must reject because the MAC was over the
        // original caveat chain.
        for c in &mut new_caveats {
            if let Caveat::Pid(p) = c {
                *p = 99999;
            }
        }
        let forged = Macaroon {
            caveats: new_caveats,
            mac: m.mac,
        };
        assert!(!verify(&key(), &forged));
    }

    #[test]
    fn wrong_root_key_fails_verify() {
        let m = mint(&key(), sample_caveats());
        let mut other = key();
        other[0] ^= 0xFF;
        assert!(!verify(&other, &m));
    }

    #[test]
    fn parse_rejects_unknown_version() {
        let err = Macaroon::parse("v9.0011.00").unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn parse_rejects_truncated_blob() {
        // Valid hex MAC, blob claims one Volume caveat but no length byte.
        let mac = "00".repeat(32);
        let blob_hex = encode_hex(&[1u8, TAG_VOLUME]);
        let s = format!("v1.{mac}.{blob_hex}");
        assert!(Macaroon::parse(&s).is_err());
    }

    #[test]
    fn operator_mint_verify_happy_path() {
        let m = mint_operator(&key(), 2_000_000_000, None);
        let s = m.encode();
        let v = verify_operator(&key(), &s, 1_000_000_000, None).expect("valid");
        assert_eq!(v.role(), Some(Role::Operator));
        assert_eq!(v.not_after(), Some(2_000_000_000));
        assert!(v.nonce().is_some());
        assert!(v.volume().is_none());
    }

    #[test]
    fn operator_token_rejects_expired() {
        let m = mint_operator(&key(), 1_000, None);
        let s = m.encode();
        let err = verify_operator(&key(), &s, 2_000, None).unwrap_err();
        assert_eq!(err, OperatorReject::Expired);
    }

    #[test]
    fn operator_token_rejects_tampered_mac() {
        let m = mint_operator(&key(), 2_000_000_000, None);
        let mut other = key();
        other[0] ^= 0xFF;
        let s = m.encode();
        let err = verify_operator(&other, &s, 1_000_000_000, None).unwrap_err();
        assert_eq!(err, OperatorReject::BadMac);
    }

    #[test]
    fn operator_token_rejects_wrong_role() {
        // Mint a credentials-scoped macaroon and try verifying it as operator.
        let m = mint(
            &key(),
            vec![
                Caveat::Scope(Scope::Credentials),
                Caveat::NotAfter(2_000_000_000),
            ],
        );
        let s = m.encode();
        let err = verify_operator(&key(), &s, 1_000_000_000, None).unwrap_err();
        assert_eq!(err, OperatorReject::WrongRole);
    }

    #[test]
    fn operator_volume_caveat_must_match_request() {
        let m = mint_operator(&key(), 2_000_000_000, Some("vol-a"));
        let s = m.encode();
        // Request targets vol-b: rejected.
        let err = verify_operator(&key(), &s, 1_000_000_000, Some("vol-b")).unwrap_err();
        assert_eq!(err, OperatorReject::VolumeMismatch);
        // Request omits volume: also rejected (token is scoped, request must name it).
        let err = verify_operator(&key(), &s, 1_000_000_000, None).unwrap_err();
        assert_eq!(err, OperatorReject::VolumeMismatch);
        // Request matches: accepted.
        assert!(verify_operator(&key(), &s, 1_000_000_000, Some("vol-a")).is_ok());
    }

    #[test]
    fn operator_unscoped_token_works_for_any_volume() {
        let m = mint_operator(&key(), 2_000_000_000, None);
        let s = m.encode();
        assert!(verify_operator(&key(), &s, 1_000_000_000, Some("vol-a")).is_ok());
        assert!(verify_operator(&key(), &s, 1_000_000_000, None).is_ok());
    }

    #[test]
    fn operator_token_nonces_are_unique() {
        let a = mint_operator(&key(), 2_000_000_000, None).nonce().unwrap();
        let b = mint_operator(&key(), 2_000_000_000, None).nonce().unwrap();
        assert_ne!(a, b, "OsRng must not produce duplicate nonces");
    }

    #[test]
    fn not_after_caveat_roundtrips() {
        let caveats = vec![
            Caveat::Volume("vol".to_owned()),
            Caveat::Scope(Scope::Credentials),
            Caveat::Pid(1),
            Caveat::NotAfter(1_700_000_000),
        ];
        let m = mint(&key(), caveats);
        let s = m.encode();
        let parsed = Macaroon::parse(&s).unwrap();
        assert_eq!(parsed.not_after(), Some(1_700_000_000));
        assert!(verify(&key(), &parsed));
    }
}
