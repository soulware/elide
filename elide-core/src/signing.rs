// Ed25519 keypair management and signed provenance.
//
// `volume.provenance` is the signed statement of a volume's lineage:
// which other volumes it is related to via fork parent and extent-index
// sources. Both relationships are carried in the same file, under the
// same signature, so tampering with lineage is detectable with the
// volume's own public key.
//
// Key file naming convention (all volumes, flat layout):
//   volume.key / volume.pub / volume.provenance  (under <by_id>/<ulid>/)
//
// File contents:
//   *.key         — Ed25519 private key (32 raw bytes, never uploaded)
//   *.pub         — Ed25519 public key (64 lowercase hex chars + newline, uploaded to S3)
//   *.provenance  — signed lineage (parent + extent_index), uploaded to S3
//
// provenance file format:
//   parent: <volume-ulid>/<snapshot-ulid>              (empty string if none)
//   parent_pubkey: <64 lowercase hex chars>            (empty string if no parent)
//   extent_index:
//     <volume-ulid>/<snapshot-ulid>
//     <volume-ulid>/<snapshot-ulid>
//     ...
//   sig: <hex-encoded 64-byte Ed25519 signature>
//
// The `parent:` and `parent_pubkey:` lines are always present, even when
// empty, so "no parent" and "empty parent" are the same thing — both in
// signing input and parser. The `extent_index:` header is always present;
// the list may be empty.
//
// The `parent_pubkey` field is the Ed25519 verifying key of the parent
// volume at fork time, embedded under the child's signature. It is the
// trust anchor for verifying the parent's own signed artefacts
// (`volume.provenance`, `snapshots/<ulid>.manifest`) at open time without
// having to trust whatever `volume.pub` happens to sit in the parent's
// directory. Keys never rotate — if one needs to change, fork — so the
// embedded value is authoritative for the life of the child.
//
// Signing input (NUL-separated, fixed field order):
//   parent_or_empty ‖ NUL ‖ parent_pubkey_hex_or_empty ‖ NUL ‖
//   extent_entry_1 ‖ NUL ‖ extent_entry_2 ‖ NUL ‖ … ‖ extent_entry_N
//
// An empty extent_index contributes zero trailing entries (the signing
// input ends after the parent_pubkey field's terminating NUL).
//
// Signing input for segments: passed in from segment::SegmentSigner::sign(); the caller
//   (segment.rs) pre-hashes with BLAKE3 before calling sign(), so the key signs
//   the 32-byte hash.

use std::io;
use std::path::Path;
use std::sync::Arc;

pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand_core::OsRng;

use crate::segment::SegmentSigner;

// File name constants.
pub const VOLUME_KEY_FILE: &str = "volume.key";
pub const VOLUME_PUB_FILE: &str = "volume.pub";
pub const VOLUME_PROVENANCE_FILE: &str = "volume.provenance";

/// Suffix appended to a snapshot ULID to form the signed segments manifest
/// filename, e.g. `snapshots/01ABC....manifest`.
pub const SNAPSHOT_MANIFEST_SUFFIX: &str = ".manifest";

/// Suffix for stop-snapshot manifests — the ephemeral checkpoints written
/// by `volume stop` to give a future `start` a basis to hydrate from.
/// The signed payload is byte-identical to a user snapshot; only the
/// filename differs. See `docs/architecture.md` *Stop-snapshot lifecycle*.
///
/// The hyphen joins the ULID and `stop` into a single stem, so the file
/// matches `*.manifest` globs cleanly and the kind tag does not look
/// like a file extension.
pub const STOP_SNAPSHOT_MANIFEST_SUFFIX: &str = "-stop.manifest";

/// Discriminates `<ulid>.manifest` (user-pinned, stable) from
/// `<ulid>-stop.manifest` (ephemeral checkpoint owned by the stop/start
/// lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    User,
    Stop,
}

impl SnapshotKind {
    pub fn suffix(self) -> &'static str {
        match self {
            SnapshotKind::User => SNAPSHOT_MANIFEST_SUFFIX,
            SnapshotKind::Stop => STOP_SNAPSHOT_MANIFEST_SUFFIX,
        }
    }
}

/// Parse a snapshot filename like `<ulid>.manifest` or `<ulid>-stop.manifest`
/// into its `(ulid, kind)`. Returns `None` for anything that doesn't match
/// either shape — including segments, indexes, and partial writes.
///
/// Stop is checked first because `-stop.manifest` also ends in `.manifest`.
pub fn parse_snapshot_filename(name: &str) -> Option<(ulid::Ulid, SnapshotKind)> {
    if let Some(stem) = name.strip_suffix(STOP_SNAPSHOT_MANIFEST_SUFFIX) {
        return ulid::Ulid::from_string(stem)
            .ok()
            .map(|u| (u, SnapshotKind::Stop));
    }
    if let Some(stem) = name.strip_suffix(SNAPSHOT_MANIFEST_SUFFIX) {
        return ulid::Ulid::from_string(stem)
            .ok()
            .map(|u| (u, SnapshotKind::User));
    }
    None
}

// --- Ed25519Signer ---

pub struct Ed25519Signer {
    key: SigningKey,
}

impl SegmentSigner for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
}

// --- keypair generation ---

/// Generate a new Ed25519 keypair and write the key files to `dir`.
///
/// `key_file` and `pub_file` are the filenames within `dir` (e.g. `"fork.key"`
/// and `"fork.pub"`, or `"base.key"` and `"base.pub"`).
///
/// Returns the signing key so the caller can immediately write an origin file
/// without re-reading from disk.
pub fn generate_keypair(dir: &Path, key_file: &str, pub_file: &str) -> io::Result<SigningKey> {
    let key = SigningKey::generate(&mut OsRng);
    crate::segment::write_file_atomic(&dir.join(key_file), &key.to_bytes())?;
    let pub_hex = encode_hex(&key.verifying_key().to_bytes()) + "\n";
    crate::segment::write_file_atomic(&dir.join(pub_file), pub_hex.as_bytes())?;
    Ok(key)
}

/// Construct an Ed25519 signer from raw 32-byte key material. Used by
/// the coordinator's breadcrumb-only release path to load a signing
/// key from `data_dir/keys/<vol_ulid>.key` without touching the
/// volume's on-disk `volume.key` (the local fork has already been
/// removed by the time release runs).
pub fn signer_from_bytes(bytes: &[u8]) -> io::Result<(Arc<dyn SegmentSigner>, VerifyingKey)> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::other("expected 32-byte Ed25519 signing key"))?;
    let key = SigningKey::from_bytes(&arr);
    let verifying_key = key.verifying_key();
    Ok((Arc::new(Ed25519Signer { key }), verifying_key))
}

/// Load an Ed25519 signing key from `dir/<key_file>` and return a `SegmentSigner`.
pub fn load_signer(dir: &Path, key_file: &str) -> io::Result<Arc<dyn SegmentSigner>> {
    let (signer, _) = load_keypair(dir, key_file)?;
    Ok(signer)
}

/// Load an Ed25519 signing key and derive its verifying key.
///
/// Returns `(signer, verifying_key)`. The verifying key is derived directly
/// from the signing key — no separate `volume.pub` read is needed.
pub fn load_keypair(
    dir: &Path,
    key_file: &str,
) -> io::Result<(Arc<dyn SegmentSigner>, VerifyingKey)> {
    let bytes = std::fs::read(dir.join(key_file))
        .map_err(|e| io::Error::other(format!("{key_file} not readable: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::other(format!("{key_file} wrong length (expected 32 bytes)")))?;
    let key = SigningKey::from_bytes(&arr);
    let verifying_key = key.verifying_key();
    Ok((Arc::new(Ed25519Signer { key }), verifying_key))
}

/// Load an Ed25519 verifying key from `dir/<pub_file>`.
///
/// The file must contain exactly 64 lowercase hex chars followed by a newline.
pub fn load_verifying_key(dir: &Path, pub_file: &str) -> io::Result<VerifyingKey> {
    let hex = std::fs::read_to_string(dir.join(pub_file))
        .map_err(|e| io::Error::other(format!("{pub_file} not readable: {e}")))?;
    let bytes = decode_hex(hex.trim())
        .map_err(|_| io::Error::other(format!("{pub_file} is not valid hex")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        io::Error::other(format!("{pub_file} wrong length (expected 64 hex chars)"))
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| io::Error::other(format!("{pub_file} invalid: {e}")))
}

/// Generate an ephemeral Ed25519 keypair in memory.
///
/// Returns `(signer, verifying_key)`. Nothing is written to disk.
pub fn generate_ephemeral_signer() -> (Arc<dyn SegmentSigner>, VerifyingKey) {
    let key = SigningKey::generate(&mut OsRng);
    let verifying_key = key.verifying_key();
    (Arc::new(Ed25519Signer { key }), verifying_key)
}

/// A reference to a specific snapshot of a parent volume, plus the
/// parent's verifying key captured at fork time.
///
/// This is the trust anchor for walking the fork ancestry chain: the
/// child signs over the parent's pubkey, and verification of the parent's
/// own `volume.provenance` and `snapshots/<ulid>.manifest` uses this
/// embedded key rather than whatever `volume.pub` happens to sit in the
/// parent's directory. Keys never rotate — if a volume's key needs to
/// change, the operation is "fork the volume" — so the embedded value is
/// authoritative for the lifetime of the child and all its descendants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentRef {
    /// ULID of the parent volume.
    pub volume_ulid: String,
    /// ULID of the specific snapshot on the parent that this fork branches from.
    pub snapshot_ulid: String,
    /// Parent volume's Ed25519 verifying key at fork time (32 raw bytes).
    pub pubkey: [u8; 32],
}

impl ParentRef {
    /// On-disk `<volume-ulid>/<snapshot-ulid>` form written to
    /// `volume.provenance` and fed into the signing input.
    pub fn to_display(&self) -> String {
        format!("{}/{}", self.volume_ulid, self.snapshot_ulid)
    }
}

/// OCI source recorded on the import root of a volume.
///
/// Present iff the volume was created via `elide volume import` from an
/// OCI image. Forks of an imported volume do not inherit it — the field
/// describes how a *root* was built, not how a child branched. Tools
/// that want the OCI label on a fork walk up the parent chain to the
/// import root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciSource {
    /// e.g. `docker.io/library/ubuntu:24.04`.
    pub image: String,
    /// `sha256:…` of the resolved platform manifest.
    pub digest: String,
    /// `amd64` / `arm64` / …
    pub arch: String,
}

/// Lineage embedded in `volume.provenance` under the signature, in one of
/// three shapes: a `Root` (no fork parent — a fresh writable volume or an
/// import), a `Fork` descending from a `parent` snapshot, or a transient
/// `Recovering` (a forced-claim re-own in flight).
///
/// `extent_index` is a flat list of `<volume-ulid>/<snapshot-ulid>`
/// hash-source snapshots whose extents seed the child's extent index for
/// dedup and delta compression; it never merges into the LBA map, and every
/// shape may carry it. `oci_source` records how an import root was built and
/// exists only on `Root`. `recovery_sources` — volumes a forced-claim re-own
/// reads transiently but does not derive content from, walked into the read
/// set as leaves — exists only on `Recovering`, so a steady-state provenance
/// structurally cannot carry one (`docs/design/mint-volume-attestation.md`
/// § *The no-basis re-own and `recovery_sources`*). `Recovering` collapses
/// to `Root`/`Fork` at finalize via [`Self::cleared_recovery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceLineage {
    /// A volume with no fork parent: a fresh writable volume, or an
    /// import (`oci_source` present iff OCI-imported).
    Root {
        extent_index: Vec<String>,
        oci_source: Option<OciSource>,
    },
    /// A volume forked from `parent`'s snapshot.
    Fork {
        parent: ParentRef,
        extent_index: Vec<String>,
    },
    /// A forced-claim re-own in flight: the eventual steady-state shape
    /// (`parent` present → `Fork`, absent → `Root`) plus the transient
    /// `recovery_sources` grant that authorises reading the dead fork.
    /// Collapsed to its steady-state variant at finalize.
    Recovering {
        parent: Option<ParentRef>,
        extent_index: Vec<String>,
        recovery_sources: Vec<ulid::Ulid>,
    },
}

impl Default for ProvenanceLineage {
    fn default() -> Self {
        Self::root()
    }
}

impl ProvenanceLineage {
    /// A root volume: no parent, no extent sources.
    pub fn root() -> Self {
        Self::Root {
            extent_index: Vec::new(),
            oci_source: None,
        }
    }

    /// A fork descending from `parent`, with no extent sources.
    pub fn fork(parent: ParentRef) -> Self {
        Self::Fork {
            parent,
            extent_index: Vec::new(),
        }
    }

    /// The variant implied by the parts: a `Recovering` when a recovery
    /// grant is present, else a `Fork` (parent present) or `Root`. What
    /// callers reach for when the shape is dynamic — a claim's provisional
    /// basis, a re-own grant.
    pub fn from_parts(
        parent: Option<ParentRef>,
        extent_index: Vec<String>,
        recovery_sources: Vec<ulid::Ulid>,
    ) -> Self {
        if !recovery_sources.is_empty() {
            return Self::Recovering {
                parent,
                extent_index,
                recovery_sources,
            };
        }
        match parent {
            Some(parent) => Self::Fork {
                parent,
                extent_index,
            },
            None => Self::Root {
                extent_index,
                oci_source: None,
            },
        }
    }

    /// The fork parent, or `None` for a root.
    pub fn parent(&self) -> Option<&ParentRef> {
        match self {
            Self::Fork { parent, .. } => Some(parent),
            Self::Recovering { parent, .. } => parent.as_ref(),
            Self::Root { .. } => None,
        }
    }

    /// The extent-index hash-source snapshots (every shape may carry them).
    pub fn extent_index(&self) -> &[String] {
        match self {
            Self::Root { extent_index, .. }
            | Self::Fork { extent_index, .. }
            | Self::Recovering { extent_index, .. } => extent_index,
        }
    }

    /// The OCI import source — only a `Root` can have one.
    pub fn oci_source(&self) -> Option<&OciSource> {
        match self {
            Self::Root { oci_source, .. } => oci_source.as_ref(),
            _ => None,
        }
    }

    /// The transient forced-claim recovery grant — only `Recovering` has
    /// one; empty for every steady-state shape.
    pub fn recovery_sources(&self) -> &[ulid::Ulid] {
        match self {
            Self::Recovering {
                recovery_sources, ..
            } => recovery_sources,
            _ => &[],
        }
    }

    /// Collapse a `Recovering` lineage to its steady-state `Root`/`Fork`
    /// (by `parent`) once the re-own is done; identity on `Root`/`Fork`.
    pub fn cleared_recovery(self) -> Self {
        match self {
            Self::Recovering {
                parent,
                extent_index,
                ..
            } => match parent {
                Some(parent) => Self::Fork {
                    parent,
                    extent_index,
                },
                None => Self::Root {
                    extent_index,
                    oci_source: None,
                },
            },
            other => other,
        }
    }
}

/// Set up an importing volume's identity and return a signer for
/// segment writing.
///
/// Generates an Ed25519 keypair, writes `volume.key`, `volume.pub`, and
/// `volume.provenance` (with the given `lineage`), and returns the
/// signer. The importing window is the volume's rw phase, so the key is
/// persisted like any other rw volume's: the worker signs segments with
/// it and the coordinator signs `volume-rw` possession proofs from it.
/// The completion flip to `Readonly` destroys it — a `Readonly` record
/// implies the key is gone, so the published base is cryptographically
/// immutable (`docs/design/mint-volume-attestation.md` § *Import runs under
/// an `Importing` record*).
pub fn setup_import_identity(
    dir: &Path,
    key_file: &str,
    pub_file: &str,
    provenance_file: &str,
    lineage: &ProvenanceLineage,
) -> io::Result<Arc<dyn SegmentSigner>> {
    let key = generate_keypair(dir, key_file, pub_file)?;
    write_provenance(dir, &key, provenance_file, lineage)?;
    Ok(Arc::new(Ed25519Signer { key }))
}

// --- provenance files ---

/// Write a signed provenance file recording the volume's lineage.
pub fn write_provenance(
    dir: &Path,
    key: &SigningKey,
    provenance_file: &str,
    lineage: &ProvenanceLineage,
) -> io::Result<()> {
    let sig = sign_provenance(key, lineage);
    let content = serialize_provenance(lineage, &sig);
    crate::segment::write_file_atomic(&dir.join(provenance_file), content.as_bytes())
}

/// Read lineage from a volume's provenance, verifying the Ed25519
/// signature against `pub_file` sitting in the same directory.
///
/// Used by the current volume's open path and by ancestor walks that
/// don't have a caller-supplied trust anchor yet.
pub fn read_lineage_verifying_signature(
    dir: &Path,
    pub_file: &str,
    provenance_file: &str,
) -> io::Result<ProvenanceLineage> {
    let verifying_key = load_verifying_key(dir, pub_file)?;
    read_lineage_with_key(dir, &verifying_key, provenance_file)
}

/// Read lineage from an ancestor volume's provenance, verifying the
/// signature with a **caller-supplied** verifying key rather than the
/// `volume.pub` sitting in the ancestor's directory. Used by the
/// `Volume::open` ancestor walk, where the trust anchor for each step is
/// the `parent_pubkey` embedded in the child's signed provenance — not
/// whatever `volume.pub` happens to be on disk at the ancestor path.
pub fn read_lineage_with_key(
    dir: &Path,
    verifying_key: &VerifyingKey,
    provenance_file: &str,
) -> io::Result<ProvenanceLineage> {
    let content = std::fs::read_to_string(dir.join(provenance_file)).map_err(|e| {
        io::Error::other(format!(
            "{provenance_file} in {} not readable: {e}",
            dir.display()
        ))
    })?;
    verify_lineage_with_key(&content, verifying_key, provenance_file)
}

/// Verify and parse a provenance file from its in-memory bytes, using
/// a caller-supplied verifying key.
///
/// Same trust shape as [`read_lineage_with_key`] — for ancestor walks
/// where the trust anchor for each step is the `parent_pubkey` embedded
/// in the child's signed provenance — but takes the file contents
/// directly rather than reading from disk. Used by callers that fetch
/// provenance from object stores (e.g. peer-fetch auth) and don't want
/// to round-trip through the local filesystem.
///
/// `file_label` is used only in error messages.
pub fn verify_lineage_with_key(
    content: &str,
    verifying_key: &VerifyingKey,
    file_label: &str,
) -> io::Result<ProvenanceLineage> {
    let (lineage, sig_bytes) = parse_provenance(content, file_label)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        io::Error::other(format!("{file_label} sig wrong length (expected 64 bytes)"))
    })?;
    let signature = Signature::from_bytes(&sig_arr);
    let msg = provenance_signing_input(&lineage);
    verifying_key
        .verify(&msg, &signature)
        .map_err(|_| io::Error::other(format!("{file_label} signature invalid")))?;
    Ok(lineage)
}

/// Domain-separation prefix for the volume-possession proof
/// (`docs/design/mint-volume-attestation.md` § *Possession-proof
/// binding*). A coordinator proves it holds a live volume's `volume.key`
/// — without revealing it — by signing this payload; the attestation
/// coordinator (coord B) verifies it against the volume's public
/// `meta/<owned>.pub`. Bumping the suffix invalidates every prior proof.
const VOLUME_POSSESSION_DOMAIN: &str = "elide-volume-possession-v1";

/// The signed payload of a volume-possession proof: domain-separated,
/// NUL-joined `owned ‖ target ‖ blake3_hex(cid) ‖ ts ‖ nonce_hex`. Built in
/// one place so the signer (coord A) and verifier (coord B) cannot drift.
///
/// Hashing the attested TPC's `cid` binds the proof to *this* TPC instance,
/// so a captured proof cannot be lifted onto another credential's discharge
/// request (the anti-transfer binding); `ts` and `nonce` bound replay.
pub fn volume_possession_signing_input(
    owned: &ulid::Ulid,
    target: &ulid::Ulid,
    cid: &[u8],
    ts: u64,
    nonce: &[u8],
) -> Vec<u8> {
    let owned_s = owned.to_string();
    let target_s = target.to_string();
    let ts_s = ts.to_string();
    let cid_hash_hex = encode_hex(blake3::hash(cid).as_bytes());
    let nonce_hex = encode_hex(nonce);
    let fields: [&str; 6] = [
        VOLUME_POSSESSION_DOMAIN,
        &owned_s,
        &target_s,
        &cid_hash_hex,
        &ts_s,
        &nonce_hex,
    ];
    let mut msg = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            msg.push(0u8);
        }
        msg.extend_from_slice(f.as_bytes());
    }
    msg
}

/// Sign a volume-possession proof with `owned`'s `volume.key` — the
/// requesting coordinator (coord A) side.
pub fn sign_volume_possession(
    signer: &dyn SegmentSigner,
    owned: &ulid::Ulid,
    target: &ulid::Ulid,
    cid: &[u8],
    ts: u64,
    nonce: &[u8],
) -> [u8; 64] {
    signer.sign(&volume_possession_signing_input(
        owned, target, cid, ts, nonce,
    ))
}

/// Verify a volume-possession proof against `owned`'s public key — the
/// attestation coordinator (coord B) side. coord B fetches `meta/<owned>.pub`,
/// recomputes the payload, and checks the signature. Errors (mapped to a
/// denial by the caller) on any mismatch.
pub fn verify_volume_possession(
    owned_pub: &VerifyingKey,
    owned: &ulid::Ulid,
    target: &ulid::Ulid,
    cid: &[u8],
    ts: u64,
    nonce: &[u8],
    proof: &[u8; 64],
) -> io::Result<()> {
    let signature = Signature::from_bytes(proof);
    let msg = volume_possession_signing_input(owned, target, cid, ts, nonce);
    owned_pub
        .verify(&msg, &signature)
        .map_err(|_| io::Error::other("volume-possession proof signature invalid"))
}

// --- internal helpers ---

fn sign_provenance(key: &SigningKey, lineage: &ProvenanceLineage) -> [u8; 64] {
    key.sign(&provenance_signing_input(lineage)).to_bytes()
}

/// Domain tag prefixing the `recovery_sources` block in the signing
/// input, so a bare recovery ULID can never alias an `extent_index`
/// entry's bytes (entries carry a `/`, the tag does not).
const PROVENANCE_RECOVERY_SOURCES_DOMAIN: &str = "elide-recovery-sources-v1";

/// Signing input (NUL-separated, fixed field order):
///   parent_or_empty || NUL || parent_pubkey_hex_or_empty || NUL ||
///   entry_1 || NUL || entry_2 || NUL || … || entry_N
///   [ || NUL || oci_image || NUL || oci_digest || NUL || oci_arch ]
///                                                              (only when Some)
///   [ || NUL || recovery_domain || NUL || rsrc_1 || NUL || … || rsrc_M ]
///                                                       (only when non-empty)
///
/// Empty `extent_index` contributes zero trailing entries. The optional
/// `oci_source` and `recovery_sources` suffixes are included only when
/// present — when both absent, the signing input is byte-identical to the
/// original format, so existing provenance signatures continue to verify
/// under the same input.
fn provenance_signing_input(lineage: &ProvenanceLineage) -> Vec<u8> {
    let parent_display = lineage.parent().map(ParentRef::to_display);
    let parent_str = parent_display.as_deref().unwrap_or("");
    let parent_pubkey_hex = lineage
        .parent()
        .map(|p| encode_hex(&p.pubkey))
        .unwrap_or_default();
    let mut total = parent_str.len() + 1 + parent_pubkey_hex.len() + lineage.extent_index().len();
    for entry in lineage.extent_index() {
        total += entry.len();
    }
    if let Some(src) = lineage.oci_source() {
        total += 3 + src.image.len() + src.digest.len() + src.arch.len();
    }
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(parent_str.as_bytes());
    msg.push(0u8);
    msg.extend_from_slice(parent_pubkey_hex.as_bytes());
    for entry in lineage.extent_index() {
        msg.push(0u8);
        msg.extend_from_slice(entry.as_bytes());
    }
    if let Some(src) = lineage.oci_source() {
        msg.push(0u8);
        msg.extend_from_slice(src.image.as_bytes());
        msg.push(0u8);
        msg.extend_from_slice(src.digest.as_bytes());
        msg.push(0u8);
        msg.extend_from_slice(src.arch.as_bytes());
    }
    if !lineage.recovery_sources().is_empty() {
        msg.push(0u8);
        msg.extend_from_slice(PROVENANCE_RECOVERY_SOURCES_DOMAIN.as_bytes());
        for src in lineage.recovery_sources() {
            msg.push(0u8);
            msg.extend_from_slice(src.to_string().as_bytes());
        }
    }
    msg
}

fn serialize_provenance(lineage: &ProvenanceLineage, sig: &[u8; 64]) -> String {
    let parent_display = lineage.parent().map(ParentRef::to_display);
    let parent_str = parent_display.as_deref().unwrap_or("");
    let parent_pubkey_hex = lineage
        .parent()
        .map(|p| encode_hex(&p.pubkey))
        .unwrap_or_default();
    let mut content = String::new();
    content.push_str("parent: ");
    content.push_str(parent_str);
    content.push('\n');
    content.push_str("parent_pubkey: ");
    content.push_str(&parent_pubkey_hex);
    content.push('\n');
    content.push_str("extent_index:\n");
    for entry in lineage.extent_index() {
        content.push_str("  ");
        content.push_str(entry);
        content.push('\n');
    }
    // Only emit when set, so non-OCI roots serialise byte-identically
    // to the pre-oci_source format.
    if let Some(src) = lineage.oci_source() {
        content.push_str("oci_image: ");
        content.push_str(&src.image);
        content.push('\n');
        content.push_str("oci_digest: ");
        content.push_str(&src.digest);
        content.push('\n');
        content.push_str("oci_arch: ");
        content.push_str(&src.arch);
        content.push('\n');
    }
    // Only emit when non-empty, so steady-state provenance serialises
    // byte-identically to the pre-`recovery_sources` format.
    if !lineage.recovery_sources().is_empty() {
        content.push_str("recovery_sources:\n");
        for src in lineage.recovery_sources() {
            content.push_str("  ");
            content.push_str(&src.to_string());
            content.push('\n');
        }
    }
    content.push_str("sig: ");
    content.push_str(&encode_hex(sig));
    content.push('\n');
    content
}

/// Parse the on-disk file into its typed fields.
///
/// Field order is not required, but every required field must be present.
/// `extent_index:` is a header followed by zero or more indented lines
/// (two-space prefix). A blank line or a `key:` line ends the list.
fn parse_provenance(
    content: &str,
    provenance_file: &str,
) -> io::Result<(ProvenanceLineage, Vec<u8>)> {
    let mut parent_str: Option<Option<String>> = None;
    let mut parent_pubkey_str: Option<Option<String>> = None;
    let mut extent_index: Option<Vec<String>> = None;
    let mut oci_image: Option<String> = None;
    let mut oci_digest: Option<String> = None;
    let mut oci_arch: Option<String> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut recovery_sources: Vec<ulid::Ulid> = Vec::new();

    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(v) = line.strip_prefix("oci_image: ") {
            oci_image = Some(v.to_owned());
        } else if let Some(v) = line.strip_prefix("oci_digest: ") {
            oci_digest = Some(v.to_owned());
        } else if let Some(v) = line.strip_prefix("oci_arch: ") {
            oci_arch = Some(v.to_owned());
        } else if let Some(v) = line.strip_prefix("parent_pubkey: ") {
            parent_pubkey_str = Some(if v.is_empty() {
                None
            } else {
                Some(v.to_owned())
            });
        } else if let Some(stripped) = line.strip_prefix("parent_pubkey:") {
            // "parent_pubkey:" (no trailing space, no value) is equivalent to empty.
            if stripped.is_empty() {
                parent_pubkey_str = Some(None);
            }
        } else if let Some(v) = line.strip_prefix("parent: ") {
            parent_str = Some(if v.is_empty() {
                None
            } else {
                Some(v.to_owned())
            });
        } else if let Some(stripped) = line.strip_prefix("parent:") {
            // "parent:" (no trailing space, no value) is equivalent to empty.
            if stripped.is_empty() {
                parent_str = Some(None);
            }
        } else if line == "extent_index:" {
            let mut entries: Vec<String> = Vec::new();
            while let Some(peek) = lines.peek() {
                if let Some(entry) = peek.strip_prefix("  ") {
                    entries.push(entry.to_owned());
                    lines.next();
                } else {
                    break;
                }
            }
            extent_index = Some(entries);
        } else if line == "recovery_sources:" {
            while let Some(peek) = lines.peek() {
                if let Some(entry) = peek.strip_prefix("  ") {
                    let ulid = ulid::Ulid::from_string(entry).map_err(|e| {
                        io::Error::other(format!(
                            "{provenance_file} recovery_sources entry {entry:?} not a ulid: {e}"
                        ))
                    })?;
                    recovery_sources.push(ulid);
                    lines.next();
                } else {
                    break;
                }
            }
        } else if let Some(v) = line.strip_prefix("sig: ") {
            sig = Some(decode_hex(v)?);
        }
    }

    let parent_str = parent_str
        .ok_or_else(|| io::Error::other(format!("{provenance_file} missing parent line")))?;
    let parent_pubkey_str = parent_pubkey_str
        .ok_or_else(|| io::Error::other(format!("{provenance_file} missing parent_pubkey line")))?;
    let extent_index = extent_index.ok_or_else(|| {
        io::Error::other(format!("{provenance_file} missing extent_index section"))
    })?;
    let sig = sig.ok_or_else(|| io::Error::other(format!("{provenance_file} missing sig line")))?;

    let parent = match (parent_str, parent_pubkey_str) {
        (None, None) => None,
        (Some(s), Some(hex)) => {
            let (volume_ulid, snapshot_ulid) = s.split_once('/').ok_or_else(|| {
                io::Error::other(format!(
                    "{provenance_file} parent {s:?} missing '/' separator"
                ))
            })?;
            let volume_ulid = ulid::Ulid::from_string(volume_ulid)
                .map_err(|e| {
                    io::Error::other(format!("{provenance_file} parent volume ulid invalid: {e}"))
                })?
                .to_string();
            let snapshot_ulid = ulid::Ulid::from_string(snapshot_ulid)
                .map_err(|e| {
                    io::Error::other(format!(
                        "{provenance_file} parent snapshot ulid invalid: {e}"
                    ))
                })?
                .to_string();
            let pubkey_bytes = decode_hex(&hex)?;
            let pubkey: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                io::Error::other(format!(
                    "{provenance_file} parent_pubkey wrong length (expected 64 hex chars)"
                ))
            })?;
            Some(ParentRef {
                volume_ulid,
                snapshot_ulid,
                pubkey,
            })
        }
        (Some(_), None) => {
            return Err(io::Error::other(format!(
                "{provenance_file} has parent but missing parent_pubkey"
            )));
        }
        (None, Some(_)) => {
            return Err(io::Error::other(format!(
                "{provenance_file} has parent_pubkey but missing parent"
            )));
        }
    };

    let oci_source = match (oci_image, oci_digest, oci_arch) {
        (None, None, None) => None,
        (Some(image), Some(digest), Some(arch)) => Some(OciSource {
            image,
            digest,
            arch,
        }),
        _ => {
            return Err(io::Error::other(format!(
                "{provenance_file} has partial oci_source (need all of oci_image, oci_digest, oci_arch or none)"
            )));
        }
    };

    let lineage = if !recovery_sources.is_empty() {
        if oci_source.is_some() {
            return Err(io::Error::other(format!(
                "{provenance_file} carries both recovery_sources and oci_source"
            )));
        }
        ProvenanceLineage::Recovering {
            parent,
            extent_index,
            recovery_sources,
        }
    } else {
        match parent {
            Some(parent) => {
                if oci_source.is_some() {
                    return Err(io::Error::other(format!(
                        "{provenance_file} carries both a parent and oci_source (a fork cannot be an OCI root)"
                    )));
                }
                ProvenanceLineage::Fork {
                    parent,
                    extent_index,
                }
            }
            None => ProvenanceLineage::Root {
                extent_index,
                oci_source,
            },
        }
    };
    Ok((lineage, sig))
}

// --- snapshot manifest (`snapshots/<ulid>.manifest`) ---
//
// A snapshot manifest is the authoritative list of every segment ULID that
// belongs to a given snapshot of a volume — i.e. every `.idx` that the
// caller needs present under `index/` to fully reconstruct the LBA map for
// that snapshot. It is a *full* manifest (not a delta over the previous
// snapshot in the same volume), so open-time ancestor verification can
// walk the fork chain by reading exactly one `.manifest` per ancestor
// volume rather than chaining through every intermediate snapshot.
//
// File format (under `snapshots/<snap_ulid>.manifest`):
//
//   segments:
//     <segment-ulid>
//     <segment-ulid>
//     ...
//   sig: <hex-encoded 64-byte Ed25519 signature>
//
// ULIDs are sorted lexicographically (= chronologically for ULIDs).
//
// Signing input: NUL-separated concatenation of sorted ULIDs; an empty
// manifest signs the empty byte string. Every manifest is signed by
// its volume's own key.

/// Build the filename for `snap_ulid`'s segments manifest
/// (`<snap_ulid>.manifest`) inside a volume's `snapshots/` directory.
pub fn snapshot_manifest_filename(snap_ulid: &ulid::Ulid) -> String {
    format!("{snap_ulid}{SNAPSHOT_MANIFEST_SUFFIX}")
}

/// Build the filename for `snap_ulid`'s stop-snapshot manifest
/// (`<snap_ulid>-stop.manifest`) — the ephemeral checkpoint written by
/// `volume stop`.
pub fn stop_snapshot_manifest_filename(snap_ulid: &ulid::Ulid) -> String {
    format!("{snap_ulid}{STOP_SNAPSHOT_MANIFEST_SUFFIX}")
}

/// Result of parsing and verifying a snapshot manifest.
#[derive(Debug, Clone)]
pub struct SnapshotManifest {
    /// Segment ULIDs in strictly ascending order.
    pub segment_ulids: Vec<ulid::Ulid>,
}

/// Write a signed snapshot manifest for `snap_ulid`.
///
/// `segment_ulids` is the unsorted list of segment ULIDs belonging to the
/// snapshot — typically every `.idx` present in the volume's `index/`
/// directory. The list is sorted and deduplicated before signing and
/// serialisation.
///
/// Writes `vol_dir/snapshots/<snap_ulid>.manifest` atomically.
pub fn write_snapshot_manifest(
    vol_dir: &Path,
    signer: &dyn SegmentSigner,
    snap_ulid: &ulid::Ulid,
    segment_ulids: &[ulid::Ulid],
) -> io::Result<()> {
    let content = build_snapshot_manifest_bytes(signer, segment_ulids);
    let path = vol_dir
        .join("snapshots")
        .join(snapshot_manifest_filename(snap_ulid));
    crate::segment::write_file_atomic(&path, &content)
}

/// Write a signed stop-snapshot manifest for `snap_ulid` at
/// `vol_dir/snapshots/<snap_ulid>-stop.manifest`. The signed payload is
/// byte-identical to [`write_snapshot_manifest`]; only the filename
/// differs. Stop-snapshots are the ephemeral checkpoint variant — see
/// `docs/architecture.md` *Stop-snapshot lifecycle*.
pub fn write_stop_snapshot_manifest(
    vol_dir: &Path,
    signer: &dyn SegmentSigner,
    snap_ulid: &ulid::Ulid,
    segment_ulids: &[ulid::Ulid],
) -> io::Result<()> {
    let content = build_snapshot_manifest_bytes(signer, segment_ulids);
    let path = vol_dir
        .join("snapshots")
        .join(stop_snapshot_manifest_filename(snap_ulid));
    crate::segment::write_file_atomic(&path, &content)
}

/// Build the signed bytes of a snapshot manifest without writing
/// anything to disk. Used by callers that need to publish the
/// manifest somewhere other than a local volume directory.
///
/// The output is identical, byte-for-byte, to what
/// `write_snapshot_manifest` would write for the same inputs. Segment
/// ULIDs are sorted and deduplicated internally before signing.
pub fn build_snapshot_manifest_bytes(
    signer: &dyn SegmentSigner,
    segment_ulids: &[ulid::Ulid],
) -> Vec<u8> {
    let mut sorted: Vec<String> = segment_ulids.iter().map(|u| u.to_string()).collect();
    sorted.sort();
    sorted.dedup();

    let msg = manifest_signing_input(&sorted);
    let sig = signer.sign(&msg);
    serialize_snapshot_manifest(&sorted, &sig).into_bytes()
}

/// Read and verify a snapshot manifest from disk, returning its
/// sorted segment ULIDs.
///
/// `verifying_key` is the volume's signing pubkey (for ancestor
/// verification this comes from the child's `volume.provenance`, not
/// the ancestor directory's `volume.pub`).
///
/// Fails if the file is missing, unparseable, the signature does not
/// match, or the ULIDs are not in strictly ascending order.
pub fn read_snapshot_manifest(
    vol_dir: &Path,
    verifying_key: &VerifyingKey,
    snap_ulid: &ulid::Ulid,
) -> io::Result<SnapshotManifest> {
    // The filename is just addressing; the signed payload is identical
    // for `<ulid>.manifest` and `<ulid>-stop.manifest`. Probe the
    // stable filename first (the common case), then fall back to the
    // stop variant — this is hit on the hydrate-from-bucket path,
    // where the basis manifest written by `stop` is `-stop.manifest`.
    let snap_dir = vol_dir.join("snapshots");
    let user_filename = snapshot_manifest_filename(snap_ulid);
    let content = match std::fs::read_to_string(snap_dir.join(&user_filename)) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let stop_filename = stop_snapshot_manifest_filename(snap_ulid);
            std::fs::read_to_string(snap_dir.join(&stop_filename)).map_err(|e2| {
                io::Error::other(format!(
                    "neither {user_filename} nor {stop_filename} in {} are readable \
                     (user: {e}; stop: {e2})",
                    vol_dir.display()
                ))
            })?
        }
        Err(e) => {
            return Err(io::Error::other(format!(
                "{user_filename} in {} not readable: {e}",
                vol_dir.display()
            )));
        }
    };
    read_snapshot_manifest_from_bytes(content.as_bytes(), verifying_key, snap_ulid)
}

/// Read and verify a snapshot manifest from raw bytes, returning its
/// sorted segment ULIDs.
///
/// Same semantics as [`read_snapshot_manifest`] but takes a byte
/// slice directly. Used by callers that fetch a manifest from S3
/// rather than a local volume directory.
///
/// `snap_ulid` is used only for diagnostic strings; signature
/// verification is over the canonical content bytes.
pub fn read_snapshot_manifest_from_bytes(
    content: &[u8],
    verifying_key: &VerifyingKey,
    snap_ulid: &ulid::Ulid,
) -> io::Result<SnapshotManifest> {
    let filename = snapshot_manifest_filename(snap_ulid);
    let content_str = std::str::from_utf8(content)
        .map_err(|e| io::Error::other(format!("{filename} not valid utf-8: {e}")))?;

    let parsed = parse_snapshot_manifest(content_str, &filename)?;
    let sig_arr: [u8; 64] = parsed.sig.try_into().map_err(|_| {
        io::Error::other(format!("{filename} sig wrong length (expected 64 bytes)"))
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    let msg = manifest_signing_input(&parsed.entries);
    verifying_key
        .verify(&msg, &signature)
        .map_err(|_| io::Error::other(format!("{filename} signature invalid")))?;

    // Parse each entry as a typed ULID, enforcing strictly ascending order
    // (sort + dedup is done at write time, so any deviation is tamper or
    // corruption).
    let mut out: Vec<ulid::Ulid> = Vec::with_capacity(parsed.entries.len());
    for entry in &parsed.entries {
        let ulid = ulid::Ulid::from_string(entry).map_err(|e| {
            io::Error::other(format!(
                "{filename} contains invalid segment ULID {entry:?}: {e}"
            ))
        })?;
        if let Some(last) = out.last()
            && &ulid <= last
        {
            return Err(io::Error::other(format!(
                "{filename} segment ULIDs not in strictly ascending order at {entry}"
            )));
        }
        out.push(ulid);
    }
    Ok(SnapshotManifest { segment_ulids: out })
}

/// Signing input for a snapshot manifest: the NUL-separated
/// concatenation of sorted ULIDs (an empty manifest signs the empty
/// byte string).
fn manifest_signing_input(sorted_ulids: &[String]) -> Vec<u8> {
    let mut msg = Vec::new();
    for (i, u) in sorted_ulids.iter().enumerate() {
        if i > 0 {
            msg.push(0u8);
        }
        msg.extend_from_slice(u.as_bytes());
    }
    msg
}

fn serialize_snapshot_manifest(sorted_ulids: &[String], sig: &[u8; 64]) -> String {
    let mut content = String::new();
    content.push_str("segments:\n");
    for u in sorted_ulids {
        content.push_str("  ");
        content.push_str(u);
        content.push('\n');
    }
    content.push_str("sig: ");
    content.push_str(&encode_hex(sig));
    content.push('\n');
    content
}

struct ParsedManifest {
    entries: Vec<String>,
    sig: Vec<u8>,
}

fn parse_snapshot_manifest(content: &str, filename: &str) -> io::Result<ParsedManifest> {
    let mut entries: Option<Vec<String>> = None;
    let mut sig: Option<Vec<u8>> = None;

    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        if line == "segments:" {
            let mut list: Vec<String> = Vec::new();
            while let Some(peek) = lines.peek() {
                if let Some(entry) = peek.strip_prefix("  ") {
                    list.push(entry.to_owned());
                    lines.next();
                } else {
                    break;
                }
            }
            entries = Some(list);
        } else if let Some(v) = line.strip_prefix("sig: ") {
            sig = Some(decode_hex(v)?);
        }
    }

    let entries =
        entries.ok_or_else(|| io::Error::other(format!("{filename} missing segments section")))?;
    let sig = sig.ok_or_else(|| io::Error::other(format!("{filename} missing sig line")))?;

    Ok(ParsedManifest { entries, sig })
}

/// Test-only helper: write a signed `volume.provenance` with raw, unvalidated
/// parent and parent_pubkey strings. Signs over the content as written so
/// signature verification passes; parse errors fire downstream at
/// `ParentRef` construction. Used to exercise parser error paths with
/// syntactically bad content.
#[cfg(test)]
pub(crate) fn write_raw_provenance_for_test(
    dir: &Path,
    raw_parent: &str,
    raw_parent_pubkey_hex: &str,
    extent_index: &[String],
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let key = SigningKey::generate(&mut OsRng);
    let pub_hex = encode_hex(&key.verifying_key().to_bytes()) + "\n";
    crate::segment::write_file_atomic(&dir.join(VOLUME_PUB_FILE), pub_hex.as_bytes())?;

    let mut msg = Vec::new();
    msg.extend_from_slice(raw_parent.as_bytes());
    msg.push(0);
    msg.extend_from_slice(raw_parent_pubkey_hex.as_bytes());
    for entry in extent_index {
        msg.push(0);
        msg.extend_from_slice(entry.as_bytes());
    }
    let sig = key.sign(&msg).to_bytes();

    let mut content = String::new();
    content.push_str("parent: ");
    content.push_str(raw_parent);
    content.push('\n');
    content.push_str("parent_pubkey: ");
    content.push_str(raw_parent_pubkey_hex);
    content.push('\n');
    content.push_str("extent_index:\n");
    for entry in extent_index {
        content.push_str("  ");
        content.push_str(entry);
        content.push('\n');
    }
    content.push_str("sig: ");
    content.push_str(&encode_hex(&sig));
    content.push('\n');

    crate::segment::write_file_atomic(&dir.join(VOLUME_PROVENANCE_FILE), content.as_bytes())
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_hex(s: &str) -> io::Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use ulid::Ulid;

    fn make_ulid(s: &str) -> Ulid {
        Ulid::from_string(s).unwrap()
    }

    #[test]
    fn volume_possession_round_trips_and_binds_every_field() {
        let (signer, vk) = generate_ephemeral_signer();
        let owned = make_ulid("01BX5ZZKBKACTAV9WEVGEMMVRZ");
        let target = owned;
        let cid = b"attested-tpc-cid-bytes";
        let ts = 1_700_000_000u64;
        let nonce = [0x11u8; 16];
        let proof = sign_volume_possession(signer.as_ref(), &owned, &target, cid, ts, &nonce);

        // Honest proof verifies.
        assert!(verify_volume_possession(&vk, &owned, &target, cid, ts, &nonce, &proof).is_ok());

        // A different signing key fails.
        let (_, other_vk) = generate_ephemeral_signer();
        assert!(
            verify_volume_possession(&other_vk, &owned, &target, cid, ts, &nonce, &proof).is_err()
        );

        // Each bound field, perturbed, fails — the proof is not transferable.
        let other = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert!(
            verify_volume_possession(&vk, &other, &target, cid, ts, &nonce, &proof).is_err(),
            "owned must bind"
        );
        assert!(
            verify_volume_possession(&vk, &owned, &other, cid, ts, &nonce, &proof).is_err(),
            "target must bind"
        );
        assert!(
            verify_volume_possession(&vk, &owned, &target, b"other-cid", ts, &nonce, &proof)
                .is_err(),
            "cid must bind (anti-transfer)"
        );
        assert!(
            verify_volume_possession(&vk, &owned, &target, cid, ts + 1, &nonce, &proof).is_err(),
            "ts must bind"
        );
        assert!(
            verify_volume_possession(&vk, &owned, &target, cid, ts, &[0x22u8; 16], &proof).is_err(),
            "nonce must bind"
        );
    }

    fn signer_from(key: SigningKey) -> Ed25519Signer {
        Ed25519Signer { key }
    }

    #[test]
    fn parse_snapshot_filename_user() {
        let u = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let name = snapshot_manifest_filename(&u);
        let (parsed, kind) = parse_snapshot_filename(&name).expect("parses");
        assert_eq!(parsed, u);
        assert_eq!(kind, SnapshotKind::User);
    }

    #[test]
    fn parse_snapshot_filename_stop() {
        let u = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let name = stop_snapshot_manifest_filename(&u);
        let (parsed, kind) = parse_snapshot_filename(&name).expect("parses");
        assert_eq!(parsed, u);
        assert_eq!(kind, SnapshotKind::Stop);
    }

    #[test]
    fn parse_snapshot_filename_rejects_bare_marker() {
        // Historically `snapshots/<ulid>` (no extension) was the bare
        // snapshot marker. The parser should not treat it as a
        // manifest — only `<ulid>.manifest` and `<ulid>-stop.manifest`
        // are accepted.
        assert!(parse_snapshot_filename("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_none());
    }

    #[test]
    fn parse_snapshot_filename_rejects_filemap() {
        assert!(parse_snapshot_filename("01ARZ3NDEKTSV4RRFFQ69G5FAV.filemap").is_none());
    }

    #[test]
    fn stop_and_user_filenames_differ() {
        let u = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_ne!(
            snapshot_manifest_filename(&u),
            stop_snapshot_manifest_filename(&u)
        );
    }

    /// OCI-imported root: `oci_source` survives a write/read round-trip
    /// via the signed `volume.provenance` file and verifies under the
    /// volume's pubkey.
    #[test]
    fn provenance_round_trips_oci_source() {
        let tmp = TempDir::new().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let pub_hex = encode_hex(&key.verifying_key().to_bytes()) + "\n";
        crate::segment::write_file_atomic(&tmp.path().join(VOLUME_PUB_FILE), pub_hex.as_bytes())
            .unwrap();

        let lineage = ProvenanceLineage::Root {
            extent_index: vec![],
            oci_source: Some(OciSource {
                image: "docker.io/library/ubuntu:24.04".to_owned(),
                digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
                arch: "amd64".to_owned(),
            }),
        };
        write_provenance(tmp.path(), &key, VOLUME_PROVENANCE_FILE, &lineage).unwrap();

        let got =
            read_lineage_verifying_signature(tmp.path(), VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .unwrap();
        assert_eq!(got, lineage);
    }

    /// `oci_source = None` produces a signing input byte-identical to a
    /// pre-`oci_source` provenance, so non-OCI roots' signatures stay
    /// stable across the schema extension.
    #[test]
    fn provenance_signing_input_unchanged_when_oci_source_absent() {
        let lineage = ProvenanceLineage::Root {
            extent_index: vec!["01ABC/01DEF".to_owned()],
            oci_source: None,
        };
        let with_oci_none = provenance_signing_input(&lineage);

        // Reference: same content, manually built without the trailing
        // `oci_source` block. Encoding rule from `provenance_signing_input`.
        let mut expected = Vec::new();
        expected.push(0u8); // empty parent
        // empty parent_pubkey_hex
        expected.push(0u8);
        expected.extend_from_slice(b"01ABC/01DEF");
        assert_eq!(with_oci_none, expected);
    }

    /// A non-empty `recovery_sources` round-trips through serialize/parse
    /// and contributes a domain-tagged suffix to the signing input; an
    /// empty one stays byte-identical to the pre-`recovery_sources` format.
    #[test]
    fn provenance_recovery_sources_round_trip_and_signing_input() {
        let tmp = TempDir::new().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let pub_hex = encode_hex(&key.verifying_key().to_bytes()) + "\n";
        crate::segment::write_file_atomic(&tmp.path().join(VOLUME_PUB_FILE), pub_hex.as_bytes())
            .unwrap();

        let a = ulid::Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let b = ulid::Ulid::from_string("01BX5ZZKBKACTAV9WEVGEMMVRZ").unwrap();
        let lineage = ProvenanceLineage::Recovering {
            parent: None,
            extent_index: vec![],
            recovery_sources: vec![a, b],
        };
        write_provenance(tmp.path(), &key, VOLUME_PROVENANCE_FILE, &lineage).unwrap();
        let got =
            read_lineage_verifying_signature(tmp.path(), VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .unwrap();
        assert_eq!(got, lineage, "recovery_sources must round-trip");

        let mut expected = Vec::new();
        expected.push(0u8); // NUL between empty parent and empty parent_pubkey
        expected.push(0u8); // NUL prefixing the recovery_sources suffix
        expected.extend_from_slice(PROVENANCE_RECOVERY_SOURCES_DOMAIN.as_bytes());
        expected.push(0u8);
        expected.extend_from_slice(a.to_string().as_bytes());
        expected.push(0u8);
        expected.extend_from_slice(b.to_string().as_bytes());
        assert_eq!(provenance_signing_input(&lineage), expected);

        let empty = lineage.cleared_recovery();
        assert_eq!(
            provenance_signing_input(&empty),
            vec![0u8],
            "empty recovery_sources contributes no suffix"
        );
    }

    /// Partial `oci_*` lines (e.g. only `oci_image:` without `oci_digest:`)
    /// must be rejected at parse time — not silently accepted as a no-op.
    #[test]
    fn provenance_rejects_partial_oci_source() {
        let tmp = TempDir::new().unwrap();
        // Build a hand-crafted provenance with only oci_image set. We
        // can sign it with any key (the partial-oci check happens before
        // signature verification).
        let key = SigningKey::generate(&mut OsRng);
        let pub_hex = encode_hex(&key.verifying_key().to_bytes()) + "\n";
        crate::segment::write_file_atomic(&tmp.path().join(VOLUME_PUB_FILE), pub_hex.as_bytes())
            .unwrap();
        let body = "parent: \nparent_pubkey: \nextent_index:\noci_image: foo:bar\nsig: deadbeef\n";
        crate::segment::write_file_atomic(
            &tmp.path().join(VOLUME_PROVENANCE_FILE),
            body.as_bytes(),
        )
        .unwrap();

        let err =
            read_lineage_verifying_signature(tmp.path(), VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .unwrap_err();
        assert!(err.to_string().contains("partial oci_source"), "{err}");
    }

    #[test]
    fn snapshot_manifest_roundtrip() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();

        let raw_key = SigningKey::generate(&mut OsRng);
        let verifying = raw_key.verifying_key();
        let key = signer_from(raw_key);
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        // Intentionally unsorted to exercise the sort-at-write step.
        let segs = vec![
            make_ulid("01BX5ZZKJKTSV4RRFFQ69G5FAV"),
            make_ulid("01AAAAAAAAAAAAAAAAAAAAAAAA"),
            make_ulid("01BBBBBBBBBBBBBBBBBBBBBBBB"),
        ];

        write_snapshot_manifest(tmp.path(), &key, &snap, &segs).unwrap();
        let got = read_snapshot_manifest(tmp.path(), &verifying, &snap).unwrap();

        let mut expected = segs.clone();
        expected.sort();
        assert_eq!(got.segment_ulids, expected);
    }

    #[test]
    fn snapshot_manifest_empty_list() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();

        let raw_key = SigningKey::generate(&mut OsRng);
        let verifying = raw_key.verifying_key();
        let key = signer_from(raw_key);
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");

        write_snapshot_manifest(tmp.path(), &key, &snap, &[]).unwrap();
        let got = read_snapshot_manifest(tmp.path(), &verifying, &snap).unwrap();
        assert!(got.segment_ulids.is_empty());
    }

    #[test]
    fn snapshot_manifest_dedupes() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();

        let raw_key = SigningKey::generate(&mut OsRng);
        let verifying = raw_key.verifying_key();
        let key = signer_from(raw_key);
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let dup = make_ulid("01BX5ZZKJKTSV4RRFFQ69G5FAV");
        let segs = vec![dup, dup];

        write_snapshot_manifest(tmp.path(), &key, &snap, &segs).unwrap();
        let got = read_snapshot_manifest(tmp.path(), &verifying, &snap).unwrap();
        assert_eq!(got.segment_ulids, vec![dup]);
    }

    #[test]
    fn snapshot_manifest_rejects_wrong_key() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();

        let signing_key = signer_from(SigningKey::generate(&mut OsRng));
        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        write_snapshot_manifest(
            tmp.path(),
            &signing_key,
            &snap,
            &[make_ulid("01BX5ZZKJKTSV4RRFFQ69G5FAV")],
        )
        .unwrap();

        let err = read_snapshot_manifest(tmp.path(), &wrong_key, &snap).unwrap_err();
        assert!(err.to_string().contains("signature invalid"), "{err}");
    }

    #[test]
    fn snapshot_manifest_rejects_missing_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert!(read_snapshot_manifest(tmp.path(), &key, &snap).is_err());
    }

    #[test]
    fn read_from_bytes_round_trips_normal_manifest() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();

        let raw_key = SigningKey::generate(&mut OsRng);
        let verifying = raw_key.verifying_key();
        let key = signer_from(raw_key);
        let snap = make_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let segs = vec![
            make_ulid("01BX5ZZKJKTSV4RRFFQ69G5FAV"),
            make_ulid("01AAAAAAAAAAAAAAAAAAAAAAAA"),
        ];
        write_snapshot_manifest(tmp.path(), &key, &snap, &segs).unwrap();

        let bytes = std::fs::read(
            tmp.path()
                .join("snapshots")
                .join(snapshot_manifest_filename(&snap)),
        )
        .unwrap();
        let got = read_snapshot_manifest_from_bytes(&bytes, &verifying, &snap).unwrap();
        let mut expected = segs;
        expected.sort();
        assert_eq!(got.segment_ulids, expected);
    }
}
