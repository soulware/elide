//! Cross-implementation test vectors for the discharge-mint crypto.
//!
//! coord B (the attestation coordinator, `elide-peer-fetch`) reimplements
//! two of mint's macaroon primitives against the spec, because `mint` is a
//! standalone workspace the coordinator cannot link
//! (`docs/design-mint-volume-attestation.md` § *coord B mints the
//! discharge*): it **decrypts** an attested TPC's CID under `K_M-B` to
//! recover `r`, and **mints** a discharge rooted at `r`. Two
//! implementations of one security primitive can drift, so a shared fixture
//! of known-answer vectors pins them: this test asserts mint — the
//! canonical implementation — reproduces the committed bytes, and the
//! mirror in `elide-peer-fetch/src/discharge/crypto.rs` asserts the
//! reimplementation reproduces the *same* bytes. Any divergence in either
//! direction fails CI.
//!
//! The fixture lives at the repo root (`testdata/mint-discharge-vectors.json`)
//! so both workspaces read the identical file. Regenerate by running with
//! `MINT_EMIT_VECTORS=1` and pasting the printed JSON.

use mint::caveat::{Caveat, name};
use mint::macaroon::{self, DISCHARGE_KID};
use mint::tpc;

/// Canonical inputs. Chosen deterministic and non-trivial; the same `r`
/// threads both halves (decrypt the CID → mint under the recovered `r`),
/// mirroring the real coord B flow.
fn k_m_b() -> [u8; 32] {
    [0x2a; 32]
}
fn r() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = i as u8;
    }
    r
}
fn nonce() -> [u8; macaroon::NONCE_LEN] {
    let mut n = [0u8; macaroon::NONCE_LEN];
    for (i, b) in n.iter_mut().enumerate() {
        *b = (0xf0 + i) as u8;
    }
    n
}
const CLIENT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "org_demo";
const MODE: &str = "rw-self";
const MODE_RO: &str = "ro-ancestor";
const VOLUME: &str = "01BX5ZZKBKACTAV9WEVGEMMVRZ";
const EXP: &str = "2099999999";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vectors_json() -> String {
    let cid = tpc::encrypt_cid_attested(&k_m_b(), &r(), CLIENT_ID, ORG_ID, MODE);
    let cid_ro_ancestor = tpc::encrypt_cid_attested(&k_m_b(), &r(), CLIENT_ID, ORG_ID, MODE_RO);
    let wire = macaroon::mint_under_key_with_nonce(
        &r(),
        DISCHARGE_KID,
        nonce(),
        vec![
            Caveat::scalar("volume", VOLUME),
            Caveat::scalar(name::EXP, EXP),
        ],
    )
    .encode();
    format!(
        concat!(
            "{{\n",
            "  \"k_m_b\": \"{}\",\n",
            "  \"r\": \"{}\",\n",
            "  \"client_id\": \"{}\",\n",
            "  \"org_id\": \"{}\",\n",
            "  \"mode\": \"{}\",\n",
            "  \"cid\": \"{}\",\n",
            "  \"cid_ro_ancestor\": \"{}\",\n",
            "  \"discharge_nonce\": \"{}\",\n",
            "  \"discharge_kid\": {},\n",
            "  \"volume\": \"{}\",\n",
            "  \"exp\": \"{}\",\n",
            "  \"discharge_wire\": \"{}\"\n",
            "}}\n"
        ),
        hex(&k_m_b()),
        hex(&r()),
        CLIENT_ID,
        ORG_ID,
        MODE,
        hex(&cid),
        hex(&cid_ro_ancestor),
        hex(&nonce()),
        DISCHARGE_KID,
        VOLUME,
        EXP,
        wire,
    )
}

#[test]
fn mint_reproduces_committed_vectors() {
    let actual = vectors_json();
    if std::env::var("MINT_EMIT_VECTORS").is_ok() {
        // Bootstrap path: print so the fixture can be (re)written.
        print!("{actual}");
        return;
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/mint-discharge-vectors.json"
    );
    let committed = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e} (run with MINT_EMIT_VECTORS=1 to bootstrap)"));
    assert_eq!(
        actual, committed,
        "mint no longer reproduces the committed discharge vectors; if this is an intended \
         crypto change, regenerate with MINT_EMIT_VECTORS=1 and update the coord B reimplementation"
    );
}
