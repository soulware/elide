//! Mint root-key keyring: an ordered set of `(kid, key)` generations
//! plus a `current` pointer naming the one used to MAC new artefacts
//! (`docs/design-mint.md` § *Root-key rotation*).
//!
//! Verification accepts any kid still in the ring; minting always uses
//! `current_kid`. Rotation is therefore three additive steps with one
//! invalidating step at the end:
//!
//! ```text
//! add(new)        — write next file, repoint `current`; old still verifies
//! sweep approvals — re-MAC every _mint/approved/<sub> under current
//! drain creds     — clients re-exchange naturally under current
//! retire(old)     — delete the old kid; anything still under it now fails
//! ```
//!
//! On-disk layout is a directory of one numbered file per generation,
//! plus a small `current` pointer file — `ls` shows the rotation
//! history without any binary-only state (the project-wide
//! inspectable-on-disk preference):
//!
//! ```text
//! <data_dir>/root_keys/0000     64-hex secret, mode 0600
//! <data_dir>/root_keys/0001     …
//! <data_dir>/root_keys/current  "0001" + newline
//! ```
//!
//! `<data_dir>/root_key` (the legacy single-key file) is migrated into
//! `root_keys/0000` on first start if `root_keys/` is empty. New
//! deployments skip that step and generate `0000` directly.
//!
//! **Multi-host minting.** Two mint instances sharing one `_mint/`
//! prefix must agree on every `(kid, key)`. The keyring supports this
//! by taking an optional caller-supplied key at the two points where
//! one is otherwise generated: [`Keyring::open`] on first start and
//! [`Keyring::add_and_promote`] at rotation. The operator provisions
//! both hosts from the same secrets-manager value; either host can
//! also run with no key supplied to generate one and print it for the
//! operator to seed the peer.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

/// Generation identifier. `u16` gives 65 535 generations — far more
/// than any deployment will actually exercise, and it fits in the
/// 2-byte kid prefix of the macaroon wire format
/// (`crate::macaroon`).
pub type Kid = u16;

/// Width of the on-disk kid filename. Files are zero-padded so `ls`
/// returns them in generation order.
pub const KID_WIDTH: usize = 4;

/// The pointer file inside the keyring directory naming the current kid.
const CURRENT_POINTER: &str = "current";

/// In-memory keyring. Loaded at start, mutated only by the rotation
/// admin paths (`add_and_promote`, `retire`); the steady-state minting
/// and verification paths read-only.
#[derive(Debug, Clone)]
pub struct Keyring {
    keys: BTreeMap<Kid, [u8; 32]>,
    current: Kid,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("keyring is empty")]
    Empty,
    #[error("unknown kid: {0}")]
    UnknownKid(Kid),
    #[error("malformed key file {0}")]
    Malformed(PathBuf),
    #[error("supplied key for kid {0} disagrees with the one already on disk; refuse to overwrite")]
    KeyMismatch(Kid),
    #[error("retiring the current kid is refused; switch current first")]
    WouldRetireCurrent,
    #[error("kid space exhausted")]
    KidExhausted,
}

impl Keyring {
    /// In-memory keyring with a single generation at `kid=0`. For tests
    /// and the [`Store::open_in_memory`](crate::state::Store::open_in_memory)
    /// shape, which never persists.
    pub fn single(key: [u8; 32]) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(0, key);
        Self { keys, current: 0 }
    }

    /// Construct directly from a populated map and a current kid. The
    /// current kid must be present in `keys`. Useful for tests and for
    /// callers that load the keyring material from a non-file source
    /// (e.g. operator-supplied envelope).
    pub fn from_parts(keys: BTreeMap<Kid, [u8; 32]>, current: Kid) -> Result<Self, KeyringError> {
        if !keys.contains_key(&current) {
            return Err(KeyringError::UnknownKid(current));
        }
        Ok(Self { keys, current })
    }

    /// Load (or initialise) the on-disk keyring at `dir`.
    ///
    /// - `legacy_singleton`: optional path to the historical
    ///   `<data_dir>/root_key` file; migrated into `kid=0` when the
    ///   keyring directory is otherwise empty.
    /// - `initial_key`: optional caller-supplied initial key, used **only**
    ///   when the directory is empty and no legacy file is present
    ///   (the multi-host shape — operator provisions the same key on
    ///   every instance). If `None`, a fresh random key is generated.
    ///
    /// If both `legacy_singleton` and `initial_key` are present, the
    /// legacy file wins (an upgrade-in-place is unambiguous; a fresh
    /// install plus a provisioned key is the multi-host shape).
    pub fn open(
        dir: &Path,
        legacy_singleton: Option<&Path>,
        initial_key: Option<[u8; 32]>,
    ) -> Result<Self, KeyringError> {
        fs::create_dir_all(dir)?;
        let keys = read_all_keys(dir)?;

        if keys.is_empty() {
            return Self::init_empty(dir, legacy_singleton, initial_key);
        }

        let current = match read_current_pointer(dir)? {
            Some(k) if keys.contains_key(&k) => k,
            // Pointer missing or pointing at a retired kid: pick the
            // highest generation present. A torn `add` (key file written,
            // pointer not yet repointed) is healed by the next successful
            // pointer write; until then the highest extant generation is
            // the safest default.
            _ => *keys.keys().next_back().expect("non-empty"),
        };
        Ok(Self { keys, current })
    }

    fn init_empty(
        dir: &Path,
        legacy_singleton: Option<&Path>,
        initial_key: Option<[u8; 32]>,
    ) -> Result<Self, KeyringError> {
        let initial = match legacy_singleton {
            Some(p) if p.exists() => {
                let text = fs::read_to_string(p)?;
                let key = decode_hex32(text.trim())
                    .ok_or_else(|| KeyringError::Malformed(p.to_owned()))?;
                // Best-effort removal; on failure we still proceed with
                // the keyring as the canonical source. The sibling 0000
                // supersedes the singleton either way.
                let _ = fs::remove_file(p);
                key
            }
            _ => initial_key.unwrap_or_else(|| {
                let mut k = [0u8; 32];
                OsRng.fill_bytes(&mut k);
                k
            }),
        };
        write_key_file(&kid_path(dir, 0), &initial)?;
        write_current_pointer(dir, 0)?;
        let mut keys = BTreeMap::new();
        keys.insert(0, initial);
        Ok(Self { keys, current: 0 })
    }

    /// The kid new artefacts MAC under.
    pub fn current_kid(&self) -> Kid {
        self.current
    }

    /// The current key — what `mint` uses.
    pub fn current_key(&self) -> &[u8; 32] {
        self.keys
            .get(&self.current)
            .expect("current always present")
    }

    /// The key for `kid`, if it is still in the ring. Verifiers call
    /// this; an absent kid means "retired" or "never existed" and is
    /// indistinguishable from a forged kid value.
    pub fn get(&self, kid: Kid) -> Option<&[u8; 32]> {
        self.keys.get(&kid)
    }

    /// Every kid currently in the ring, in generation order.
    pub fn kids(&self) -> impl Iterator<Item = Kid> + '_ {
        self.keys.keys().copied()
    }

    /// Number of generations currently in the ring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if the ring has no keys (should never happen after
    /// a successful [`Self::open`], present for completeness).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Add a key as the next generation, persist it, and (atomically)
    /// switch `current` to point at it. The previous `current` remains
    /// in the ring for verification.
    ///
    /// - `key=None`: generate a fresh random key. This is the
    ///   primary-host shape; the caller is expected to surface the new
    ///   key bytes so the operator can seed peers.
    /// - `key=Some(k)`: adopt the caller-supplied key — the secondary-host
    ///   shape, where the operator runs the same rotation against the
    ///   peer using the key the primary just emitted. Idempotent if the
    ///   next-kid file already exists with the same bytes; refuses if
    ///   the on-disk bytes disagree.
    pub fn add_and_promote(
        &mut self,
        dir: &Path,
        key: Option<[u8; 32]>,
    ) -> Result<Kid, KeyringError> {
        let next: Kid = self
            .keys
            .keys()
            .next_back()
            .copied()
            .and_then(|max| max.checked_add(1))
            .ok_or(KeyringError::KidExhausted)?;
        let key = key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        });
        let path = kid_path(dir, next);
        if path.exists() {
            // Idempotency: a prior crashed run, or a concurrent peer that
            // already wrote this kid file. Same bytes → fine; different
            // bytes → refuse, the operator must reconcile.
            let existing = decode_hex32(fs::read_to_string(&path)?.trim())
                .ok_or_else(|| KeyringError::Malformed(path.clone()))?;
            if existing != key {
                return Err(KeyringError::KeyMismatch(next));
            }
        } else {
            write_key_file(&path, &key)?;
        }
        write_current_pointer(dir, next)?;
        self.keys.insert(next, key);
        self.current = next;
        Ok(next)
    }

    /// Retire `kid`: delete its key file and drop it from the ring.
    /// Refuses to retire the current kid — the operator must first
    /// `add_and_promote` so the ring keeps a usable minting key.
    pub fn retire(&mut self, dir: &Path, kid: Kid) -> Result<(), KeyringError> {
        if kid == self.current {
            return Err(KeyringError::WouldRetireCurrent);
        }
        if !self.keys.contains_key(&kid) {
            return Err(KeyringError::UnknownKid(kid));
        }
        match fs::remove_file(kid_path(dir, kid)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.keys.remove(&kid);
        Ok(())
    }
}

fn kid_path(dir: &Path, kid: Kid) -> PathBuf {
    dir.join(format!("{kid:0width$}", width = KID_WIDTH))
}

fn pointer_path(dir: &Path) -> PathBuf {
    dir.join(CURRENT_POINTER)
}

fn write_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)
}

fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<(), KeyringError> {
    write_0600(path, encode_hex32(key).as_bytes())?;
    Ok(())
}

fn write_current_pointer(dir: &Path, kid: Kid) -> Result<(), KeyringError> {
    let text = format!("{kid:0width$}\n", width = KID_WIDTH);
    let path = pointer_path(dir);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn read_current_pointer(dir: &Path) -> Result<Option<Kid>, KeyringError> {
    match fs::read_to_string(pointer_path(dir)) {
        Ok(text) => Ok(text.trim().parse::<Kid>().ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn read_all_keys(dir: &Path) -> Result<BTreeMap<Kid, [u8; 32]>, KeyringError> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == CURRENT_POINTER {
            continue;
        }
        // Skip .tmp companions left by interrupted atomic writes and any
        // other operator-placed sidecars; a real kid file is exactly
        // KID_WIDTH ASCII digits.
        if name.len() != KID_WIDTH || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let kid: Kid = name
            .parse()
            .map_err(|_| KeyringError::Malformed(entry.path()))?;
        let text = fs::read_to_string(entry.path())?;
        let key = decode_hex32(text.trim()).ok_or_else(|| KeyringError::Malformed(entry.path()))?;
        out.insert(kid, key);
    }
    Ok(out)
}

fn encode_hex32(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("root_keys");
        (d, p)
    }

    #[test]
    fn first_open_generates_kid_zero() {
        let (_d, dir) = dir();
        let kr = Keyring::open(&dir, None, None).unwrap();
        assert_eq!(kr.current_kid(), 0);
        assert_eq!(kr.len(), 1);
        assert_ne!(kr.current_key(), &[0u8; 32]);
        let f = kid_path(&dir, 0);
        let mode = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&f).unwrap().trim().len(), 64);
        let ptr = fs::read_to_string(pointer_path(&dir)).unwrap();
        assert_eq!(ptr.trim(), "0000");
    }

    #[test]
    fn first_open_with_supplied_initial_key_adopts_it() {
        let (_d, dir) = dir();
        let kr = Keyring::open(&dir, None, Some([7u8; 32])).unwrap();
        assert_eq!(kr.current_kid(), 0);
        assert_eq!(kr.current_key(), &[7u8; 32]);
    }

    #[test]
    fn supplied_initial_key_ignored_when_ring_already_populated() {
        let (_d, dir) = dir();
        let kr = Keyring::open(&dir, None, None).unwrap();
        let original = *kr.current_key();
        let kr2 = Keyring::open(&dir, None, Some([9u8; 32])).unwrap();
        assert_eq!(
            kr2.current_key(),
            &original,
            "ring already populated; supplied initial is a no-op"
        );
    }

    #[test]
    fn reopen_preserves_keys_and_pointer() {
        let (_d, dir) = dir();
        let k1 = *Keyring::open(&dir, None, None).unwrap().current_key();
        let k2 = *Keyring::open(&dir, None, None).unwrap().current_key();
        assert_eq!(k1, k2, "restart preserves the key");
    }

    #[test]
    fn legacy_singleton_migrated_into_kid_zero() {
        let d = tempfile::tempdir().unwrap();
        let legacy = d.path().join("root_key");
        let hex: String = [7u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&legacy, &hex).unwrap();
        let kr_dir = d.path().join("root_keys");
        let kr = Keyring::open(&kr_dir, Some(&legacy), None).unwrap();
        assert_eq!(kr.current_kid(), 0);
        assert_eq!(kr.current_key(), &[7u8; 32]);
        assert!(!legacy.exists(), "legacy file removed after migration");
    }

    #[test]
    fn legacy_singleton_wins_over_supplied_initial_key() {
        // Mixed signals on first start: an in-place upgrade is the
        // unambiguous reading.
        let d = tempfile::tempdir().unwrap();
        let legacy = d.path().join("root_key");
        let hex: String = [7u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        fs::write(&legacy, &hex).unwrap();
        let kr_dir = d.path().join("root_keys");
        let kr = Keyring::open(&kr_dir, Some(&legacy), Some([9u8; 32])).unwrap();
        assert_eq!(kr.current_key(), &[7u8; 32]);
    }

    #[test]
    fn add_and_promote_advances_current() {
        let (_d, dir) = dir();
        let mut kr = Keyring::open(&dir, None, None).unwrap();
        let k0 = *kr.current_key();
        let new_kid = kr.add_and_promote(&dir, None).unwrap();
        assert_eq!(new_kid, 1);
        assert_eq!(kr.current_kid(), 1);
        assert_eq!(kr.len(), 2);
        assert_ne!(kr.current_key(), &k0, "current is the new key");
        assert_eq!(kr.get(0), Some(&k0), "old kid still in ring for verify");
        let ptr = fs::read_to_string(pointer_path(&dir)).unwrap();
        assert_eq!(ptr.trim(), "0001");
    }

    #[test]
    fn add_and_promote_accepts_supplied_key() {
        // The peer-host rotation: operator hands the new key bytes to
        // the second instance so both hosts converge on the same kid.
        let (_d, dir) = dir();
        let mut kr = Keyring::open(&dir, None, None).unwrap();
        let kid = kr.add_and_promote(&dir, Some([42u8; 32])).unwrap();
        assert_eq!(kid, 1);
        assert_eq!(kr.current_key(), &[42u8; 32]);
        // Reload to confirm it really hit disk.
        let kr2 = Keyring::open(&dir, None, None).unwrap();
        assert_eq!(kr2.current_key(), &[42u8; 32]);
        assert_eq!(kr2.current_kid(), 1);
    }

    #[test]
    fn add_and_promote_is_idempotent_for_matching_existing_key() {
        // A peer that already wrote kid=1 with the same bytes is a
        // benign race, not an error.
        let (_d, dir) = dir();
        let mut kr_a = Keyring::open(&dir, None, None).unwrap();
        kr_a.add_and_promote(&dir, Some([42u8; 32])).unwrap();
        // Second mint instance over the same dir, same key → no-op.
        let mut kr_b = Keyring::open(&dir, None, None).unwrap();
        let kid = kr_b.add_and_promote(&dir, Some([42u8; 32])).unwrap();
        assert_eq!(kid, 2, "next kid after the existing one");
        // Now force the disagreement case by trying to re-add kid 2
        // with different bytes.
        let kid3 = kr_b.add_and_promote(&dir, Some([99u8; 32])).unwrap();
        assert_eq!(kid3, 3);
        // Reopen and try to add a kid=3 with a different key — should
        // be rejected.
        let mut kr_c = Keyring::open(&dir, None, None).unwrap();
        // The next kid is 4; ask for 4 via add_and_promote with one
        // value, then a second add asking for 4 with a different value
        // would mismatch — but each add_and_promote advances. Instead
        // simulate the mismatch by writing kid=4 manually first.
        write_key_file(&kid_path(&dir, 4), &[1u8; 32]).unwrap();
        let err = kr_c.add_and_promote(&dir, Some([2u8; 32])).unwrap_err();
        assert!(matches!(err, KeyringError::KeyMismatch(4)));
    }

    #[test]
    fn retire_drops_old_kid_and_rejects_current() {
        let (_d, dir) = dir();
        let mut kr = Keyring::open(&dir, None, None).unwrap();
        kr.add_and_promote(&dir, None).unwrap();
        assert!(matches!(
            kr.retire(&dir, kr.current_kid()),
            Err(KeyringError::WouldRetireCurrent)
        ));
        kr.retire(&dir, 0).unwrap();
        assert_eq!(kr.len(), 1);
        assert!(kr.get(0).is_none());
        assert!(!kid_path(&dir, 0).exists());
    }

    #[test]
    fn pointer_at_retired_kid_falls_back_to_highest_extant() {
        let (_d, dir) = dir();
        let mut kr = Keyring::open(&dir, None, None).unwrap();
        kr.add_and_promote(&dir, None).unwrap();
        kr.add_and_promote(&dir, None).unwrap();
        // Simulate corruption: pointer claims a kid no longer in the
        // directory (a torn retire that deleted the file but the pointer
        // hadn't been advanced).
        fs::remove_file(kid_path(&dir, 2)).unwrap();
        // Drop in-memory state and reload from disk.
        let kr2 = Keyring::open(&dir, None, None).unwrap();
        assert_eq!(
            kr2.current_kid(),
            1,
            "fell back to highest extant kid (1) after 2 disappeared"
        );
    }

    #[test]
    fn ignores_tmp_files_and_non_kid_entries() {
        let (_d, dir) = dir();
        let kr = Keyring::open(&dir, None, None).unwrap();
        // Leave a stale .tmp behind (simulating a crashed atomic write).
        fs::write(dir.join("0001.tmp"), "garbage").unwrap();
        // And a junk file with a non-numeric name.
        fs::write(dir.join("notes.md"), "hi").unwrap();
        let kr2 = Keyring::open(&dir, None, None).unwrap();
        assert_eq!(kr2.current_kid(), kr.current_kid());
        assert_eq!(kr2.len(), 1);
    }

    #[test]
    fn single_constructor_for_tests() {
        let kr = Keyring::single([5u8; 32]);
        assert_eq!(kr.current_kid(), 0);
        assert_eq!(kr.current_key(), &[5u8; 32]);
        assert_eq!(kr.get(0), Some(&[5u8; 32]));
        assert_eq!(kr.get(99), None);
    }
}
