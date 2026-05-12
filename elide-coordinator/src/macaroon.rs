// Typed macaroons for coordinator-issued credentials.
//
// A macaroon is a bearer token bound to a chain of typed caveats. The MAC is a
// chained keyed-blake3 walk: each caveat narrows authority and re-keys the
// MAC for the next link. The holder of a macaroon can append further caveats
// without the root key — they just extend the chain from the previous tail.
// Verification replays the chain from the root and checks the final tail in
// constant time.
//
//     mac_0 = HMAC(root_key,    encode(c_0))
//     mac_i = HMAC(mac_{i-1},   encode(c_i))   for i = 1..n
//     sig   = mac_n
//
// Wire format (single hex line, fits the existing IPC line protocol):
//     v1.<32-byte mac, hex>.<caveats blob, hex>
//
// Caveats blob:
//     u8: count
//     repeated (count times):
//       u8 tag, then a tag-specific body:
//         Volume   (tag 0): u8 len, N UTF-8 bytes
//         Scope    (tag 1): u8 (0 = credentials, 1 = fetch-worker)
//         Pid      (tag 2): i32 BE
//         NotAfter (tag 3): u64 BE  (unix seconds)
//         Role     (tag 4): u8 (0 = operator)
//         Nonce    (tag 5): 16 bytes
//         Op       (tag 6): u8 (0 = remove)
//
// See docs/design-auth-model.md for the full design.

use std::io;

const MAGIC: &str = "v1";
const TAG_VOLUME: u8 = 0;
const TAG_SCOPE: u8 = 1;
const TAG_PID: u8 = 2;
const TAG_NOT_AFTER: u8 = 3;
const TAG_ROLE: u8 = 4;
const TAG_NONCE: u8 = 5;
const TAG_OP: u8 = 6;

const SCOPE_CREDENTIALS: u8 = 0;
const SCOPE_FETCH_WORKER: u8 = 1;

const ROLE_OPERATOR: u8 = 0;

const OP_REMOVE: u8 = 0;

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
    /// Operator macaroon: not PID-bound, gates coordinator mutations.
    /// Minted by the coordinator on `Request::MintOperatorToken`,
    /// attenuated by the CLI per use (see `Caveat::Op`,
    /// `docs/design-auth-model.md`).
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

/// Coordinator operations gated by an operator token. Exhaustive: the
/// dispatcher hands `verify_operator` the variant for the verb it is
/// about to execute, and the verifier requires the chain to carry the
/// matching `Caveat::Op`. New gated verbs slot in as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorOp {
    Remove,
}

impl OperatorOp {
    fn to_byte(self) -> u8 {
        match self {
            Self::Remove => OP_REMOVE,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            OP_REMOVE => Some(Self::Remove),
            _ => None,
        }
    }

    /// Lowercase verb name for logs and CLI integration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Remove => "remove",
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
    Op(OperatorOp),
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

    pub fn op(&self) -> Option<OperatorOp> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::Op(o) => Some(*o),
            _ => None,
        })
    }

    /// Narrowest `NotAfter` in the chain, if any. Attenuation cannot
    /// extend authority, so the smallest `NotAfter` always binds.
    pub fn narrowest_not_after(&self) -> Option<u64> {
        self.caveats.iter().fold(None, |acc, c| match c {
            Caveat::NotAfter(t) => Some(acc.map_or(*t, |e: u64| e.min(*t))),
            _ => acc,
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

    /// Extend an existing macaroon with further caveats, narrowing
    /// authority. The new tail MAC is derived from the previous tail
    /// — no root key access required. Verifying the result replays
    /// the whole chain from the root and matches the final tail.
    pub fn attenuate(self, new_caveats: Vec<Caveat>) -> Self {
        let mut mac = self.mac;
        let mut caveats = self.caveats;
        for c in new_caveats {
            let bytes = encode_caveat(&c);
            mac = *blake3::keyed_hash(&mac, &bytes).as_bytes();
            caveats.push(c);
        }
        Self { caveats, mac }
    }
}

/// Mint a macaroon: walk the caveat chain from the root key,
/// producing the tail MAC as the signature.
pub fn mint(root_key: &[u8; 32], caveats: Vec<Caveat>) -> Macaroon {
    debug_assert!(!caveats.is_empty(), "mint requires at least one caveat");
    let mut mac = *root_key;
    for c in &caveats {
        let bytes = encode_caveat(c);
        mac = *blake3::keyed_hash(&mac, &bytes).as_bytes();
    }
    Macaroon { caveats, mac }
}

/// Constant-time MAC verification. The caller is still responsible for
/// checking individual caveat values against runtime context (volume,
/// scope, pid, expiry, op).
pub fn verify(root_key: &[u8; 32], m: &Macaroon) -> bool {
    let mut mac = *root_key;
    for c in &m.caveats {
        let bytes = encode_caveat(c);
        mac = *blake3::keyed_hash(&mac, &bytes).as_bytes();
    }
    constant_time_eq(&mac, &m.mac)
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

/// Mint an operator macaroon. The root token is coordinator-wide: no
/// `Volume` or `Op` caveats. The CLI narrows per use by appending
/// `Op(<verb>)`, `Volume(<target>)`, and a short `NotAfter` before
/// sending the token to the coordinator.
///
/// `expires_unix` is required (no indefinite operator tokens). A fresh
/// 16-byte random nonce is included so the audit log can tie each
/// authenticated operation back to a specific `token create` event.
pub fn mint_operator(root_key: &[u8; 32], expires_unix: u64) -> Macaroon {
    use rand_core::RngCore;
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let caveats = vec![
        Caveat::Role(Role::Operator),
        Caveat::Nonce(nonce),
        Caveat::NotAfter(expires_unix),
    ];
    mint(root_key, caveats)
}

/// Reasons an operator token may be rejected. Coarse by design —
/// finer detail would help an attacker probe token state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorReject {
    Malformed,
    BadMac,
    WrongRole,
    Expired,
    WrongOp,
    VolumeMismatch,
}

/// Verify an attenuated operator macaroon against the coordinator's
/// root key and the current operation's context.
///
/// Checks: parseable; MAC chain replays to the presented tail;
/// `Role::Operator`; narrowest `NotAfter` is in the future; an `Op`
/// caveat is present and equals `op`; a `Volume` caveat is present
/// and equals `op_volume`.
///
/// A token without an `Op` or `Volume` caveat is rejected: those are
/// always added by the CLI's per-use attenuation. The minted root
/// token alone is not enough to authorise a verb — it must be
/// narrowed at the moment of use.
pub fn verify_operator(
    root_key: &[u8; 32],
    encoded: &str,
    now_unix: u64,
    op: OperatorOp,
    op_volume: &str,
) -> Result<Macaroon, OperatorReject> {
    let m = Macaroon::parse(encoded).map_err(|_| OperatorReject::Malformed)?;
    if !verify(root_key, &m) {
        return Err(OperatorReject::BadMac);
    }
    if m.role() != Some(Role::Operator) {
        return Err(OperatorReject::WrongRole);
    }
    let expiry = m.narrowest_not_after().ok_or(OperatorReject::Expired)?;
    if expiry <= now_unix {
        return Err(OperatorReject::Expired);
    }
    if m.op() != Some(op) {
        return Err(OperatorReject::WrongOp);
    }
    match m.volume() {
        Some(v) if v == op_volume => {}
        _ => return Err(OperatorReject::VolumeMismatch),
    }
    Ok(m)
}

fn encode_caveat(c: &Caveat) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
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
        Caveat::Op(op) => {
            out.push(TAG_OP);
            out.push(op.to_byte());
        }
    }
    out
}

fn serialize_caveats(caveats: &[Caveat]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(caveats.len() as u8);
    for c in caveats {
        out.extend_from_slice(&encode_caveat(c));
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
            TAG_OP => {
                let b = read_u8(&mut cur)?;
                Caveat::Op(
                    OperatorOp::from_byte(b)
                        .ok_or_else(|| io::Error::other(format!("unknown op: {b}")))?,
                )
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

/// Format a 16-byte nonce as a hex string for logging.
pub fn nonce_hex(n: &[u8; 16]) -> String {
    encode_hex(n)
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

    fn volume_caveats() -> Vec<Caveat> {
        vec![
            Caveat::Volume("01JQAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
            Caveat::Scope(Scope::Credentials),
            Caveat::Pid(12345),
        ]
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let m = mint(&key(), volume_caveats());
        assert!(verify(&key(), &m));
    }

    #[test]
    fn encode_then_parse_roundtrip() {
        let m = mint(&key(), volume_caveats());
        let s = m.encode();
        let parsed = Macaroon::parse(&s).unwrap();
        assert_eq!(parsed.caveats, m.caveats);
        assert_eq!(parsed.mac, m.mac);
        assert!(verify(&key(), &parsed));
    }

    #[test]
    fn accessors_extract_caveat_values() {
        let m = mint(&key(), volume_caveats());
        assert_eq!(m.volume(), Some("01JQAAAAAAAAAAAAAAAAAAAAAA"));
        assert_eq!(m.scope(), Some(Scope::Credentials));
        assert_eq!(m.pid(), Some(12345));
        assert_eq!(m.not_after(), None);
    }

    #[test]
    fn tampered_mac_fails_verify() {
        let m = mint(&key(), volume_caveats());
        let mut s = m.encode();
        let dot = s.find('.').unwrap();
        let pos = dot + 2;
        let bytes = unsafe { s.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'a' { b'b' } else { b'a' };
        let parsed = Macaroon::parse(&s).unwrap();
        assert!(!verify(&key(), &parsed));
    }

    #[test]
    fn tampered_caveat_fails_verify() {
        let m = mint(&key(), volume_caveats());
        let mut new_caveats = m.caveats().to_vec();
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
    fn reordered_caveats_fail_verify() {
        // The chained MAC depends on caveat order; reversing the chain
        // must invalidate it.
        let m = mint(&key(), volume_caveats());
        let mut reordered = m.caveats().to_vec();
        reordered.reverse();
        let forged = Macaroon {
            caveats: reordered,
            mac: m.mac,
        };
        assert!(!verify(&key(), &forged));
    }

    #[test]
    fn wrong_root_key_fails_verify() {
        let m = mint(&key(), volume_caveats());
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
        let mac = "00".repeat(32);
        let blob_hex = encode_hex(&[1u8, TAG_VOLUME]);
        let s = format!("v1.{mac}.{blob_hex}");
        assert!(Macaroon::parse(&s).is_err());
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

    // ── attenuation ────────────────────────────────────────────────

    #[test]
    fn attenuate_then_verify_roundtrip() {
        let root = mint_operator(&key(), 1_900_000_000);
        let attenuated = root.attenuate(vec![
            Caveat::Op(OperatorOp::Remove),
            Caveat::Volume("myvm".to_owned()),
            Caveat::NotAfter(1_800_000_000),
        ]);
        assert!(verify(&key(), &attenuated));
    }

    #[test]
    fn attenuate_then_encode_parse_roundtrips() {
        let root = mint_operator(&key(), 1_900_000_000);
        let attenuated = root.attenuate(vec![
            Caveat::Op(OperatorOp::Remove),
            Caveat::Volume("myvm".to_owned()),
            Caveat::NotAfter(1_800_000_000),
        ]);
        let s = attenuated.encode();
        let parsed = Macaroon::parse(&s).unwrap();
        assert!(verify(&key(), &parsed));
        assert_eq!(parsed.op(), Some(OperatorOp::Remove));
        assert_eq!(parsed.volume(), Some("myvm"));
        assert_eq!(parsed.narrowest_not_after(), Some(1_800_000_000));
    }

    #[test]
    fn forging_attenuation_without_chain_fails() {
        // An attacker who only sees the encoded root macaroon cannot
        // attach a Volume caveat without recomputing the chain. If
        // they just append the caveat and keep the old MAC, verify
        // must reject.
        let root = mint_operator(&key(), 1_900_000_000);
        let mut forged_caveats = root.caveats().to_vec();
        forged_caveats.push(Caveat::Volume("myvm".to_owned()));
        let forged = Macaroon {
            caveats: forged_caveats,
            mac: root.mac,
        };
        assert!(!verify(&key(), &forged));
    }

    // ── operator-token verification ────────────────────────────────

    fn now() -> u64 {
        1_750_000_000
    }

    fn attenuated_operator_token(
        expiry_root: u64,
        op: OperatorOp,
        vol: &str,
        expiry_use: u64,
    ) -> String {
        mint_operator(&key(), expiry_root)
            .attenuate(vec![
                Caveat::Op(op),
                Caveat::Volume(vol.to_owned()),
                Caveat::NotAfter(expiry_use),
            ])
            .encode()
    }

    #[test]
    fn verify_operator_happy_path() {
        let t =
            attenuated_operator_token(now() + 30 * 86_400, OperatorOp::Remove, "myvm", now() + 60);
        let m = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap();
        assert_eq!(m.op(), Some(OperatorOp::Remove));
        assert_eq!(m.volume(), Some("myvm"));
        assert!(m.nonce().is_some());
    }

    #[test]
    fn verify_operator_expired() {
        // Use-time expiry is already in the past.
        let t =
            attenuated_operator_token(now() + 30 * 86_400, OperatorOp::Remove, "myvm", now() - 1);
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::Expired);
    }

    #[test]
    fn verify_operator_root_expired_even_if_use_window_open() {
        // The root token has expired; CLI attenuation with a fresher
        // not-after cannot extend authority — narrowest binds.
        let t = attenuated_operator_token(now() - 1, OperatorOp::Remove, "myvm", now() + 60);
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::Expired);
    }

    #[test]
    fn verify_operator_bad_mac() {
        let mut t =
            attenuated_operator_token(now() + 86_400, OperatorOp::Remove, "myvm", now() + 60);
        // Flip a byte inside the MAC region.
        let dot = t.find('.').unwrap();
        let pos = dot + 2;
        let bytes = unsafe { t.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'a' { b'b' } else { b'a' };
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::BadMac);
    }

    #[test]
    fn verify_operator_wrong_role() {
        // Volume-scoped token cannot be presented as an operator
        // token — wrong role caveat.
        let m = mint(&key(), volume_caveats());
        let err =
            verify_operator(&key(), &m.encode(), now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::WrongRole);
    }

    #[test]
    fn verify_operator_wrong_op_caveat() {
        // Token attenuated for Remove cannot authorise a different
        // verb. (No other variants today, but simulate by stripping
        // the Op caveat entirely.)
        let root = mint_operator(&key(), now() + 86_400);
        let t = root
            .attenuate(vec![
                Caveat::Volume("myvm".to_owned()),
                Caveat::NotAfter(now() + 60),
            ])
            .encode();
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::WrongOp);
    }

    #[test]
    fn verify_operator_volume_mismatch() {
        let t = attenuated_operator_token(now() + 86_400, OperatorOp::Remove, "myvm", now() + 60);
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "othervm").unwrap_err();
        assert_eq!(err, OperatorReject::VolumeMismatch);
    }

    #[test]
    fn verify_operator_missing_volume() {
        // Operator token without a Volume caveat is rejected: CLI
        // must always attenuate by volume.
        let root = mint_operator(&key(), now() + 86_400);
        let t = root
            .attenuate(vec![
                Caveat::Op(OperatorOp::Remove),
                Caveat::NotAfter(now() + 60),
            ])
            .encode();
        let err = verify_operator(&key(), &t, now(), OperatorOp::Remove, "myvm").unwrap_err();
        assert_eq!(err, OperatorReject::VolumeMismatch);
    }

    #[test]
    fn mint_operator_produces_unique_nonces() {
        let a = mint_operator(&key(), now() + 86_400);
        let b = mint_operator(&key(), now() + 86_400);
        assert_ne!(a.nonce(), b.nonce());
    }
}
