//! End-to-end template-seal flow (`docs/design-mint-template-seal.md`):
//! stage a pending via the same path the CLI takes → `mint serve`
//! startup publishes it → subsequent restarts verify against the
//! canonical bucket seal. Plus the refuse-closed cases that matter:
//! tampered template, missing seal, pending under a retired kid.
//!
//! The tests exercise [`mint::seal::publish_pending_and_verify`]
//! directly (the helper `mint serve` calls), against an in-memory
//! [`Store`] backend and a real filesystem `data_dir`. The
//! `PutMode::Update` quirk of [`object_store::local::LocalFileSystem`]
//! doesn't apply here — seal writes are plain overwrites.

use std::collections::BTreeMap;
use std::sync::Arc;

use mint::Config;
use mint::keyring::Keyring;
use mint::seal::{Seal, publish_pending_and_verify, write_pending};
use mint::state::Store;

const SAMPLE_TOML: &str = r#"
audience = "mint"

[tenant]
bucket = "demo-bucket"

[[role]]
name = "volume-ro"
required_caveats = ["elide:Volume", "Audience", "NotAfter"]
min_ttl_seconds = 60
max_ttl_seconds = 2592000
default_ttl_seconds = 2592000
policy_file = "volume-ro.json"
"#;

const POLICY: &str = r#"{"Version":"2012-10-17","Statement":[]}"#;

/// Build a config whose `data_dir` is a real tempdir (so the seal
/// helper has somewhere to look for `pending-seal.json`), and an
/// in-memory store with a fixed kid=0 keyring. Returns the tempdir
/// holding both data_dir and roles_dir (kept alive so the test
/// keeps access through the run).
async fn setup() -> (tempfile::TempDir, Config, Arc<Store>) {
    let d = tempfile::tempdir().expect("tempdir");
    let roles_dir = d.path().join("roles");
    let data_dir = d.path().join("data");
    std::fs::create_dir_all(&roles_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(roles_dir.join("volume-ro.json"), POLICY).unwrap();
    let toml = SAMPLE_TOML.replacen(
        "[tenant]",
        &format!(
            "data_dir = {:?}\nroles_dir = {:?}\n[tenant]",
            data_dir.display().to_string(),
            roles_dir.display().to_string()
        ),
        1,
    );
    let cfg = Config::from_toml_str(&toml).expect("parse");
    let store = Arc::new(Store::open_in_memory([7u8; 32]).await.expect("store"));
    (d, cfg, store)
}

/// Stage a pending seal at `<data_dir>/pending-seal.json` under the
/// store's current keyring, mirroring what `mint seal` does. Returns
/// the path for tests that need to inspect or remove it.
async fn stage_pending(config: &Config, store: &Store, sealed_at: &str) -> std::path::PathBuf {
    let kr = store.keyring().await;
    let seal = Seal::build_from_config(config, &kr, sealed_at);
    let p = config.data_dir.join("pending-seal.json");
    write_pending(&p, &seal).unwrap();
    p
}

#[tokio::test]
async fn happy_path_stage_publish_verify() {
    let (_d, cfg, store) = setup().await;
    let p = stage_pending(&cfg, &store, "2026-05-24T12:00:00Z").await;

    publish_pending_and_verify(&cfg, &store).await.unwrap();

    // Pending file consumed; bucket seal published; seal verifies.
    assert!(!p.exists(), "pending file removed after publish");
    let bucket = store.get_template_seal().await.unwrap().expect("present");
    assert_eq!(bucket.sealed_at, "2026-05-24T12:00:00Z");
    bucket.verify(&*store.keyring().await).unwrap();

    // Subsequent restarts (no pending file) pass against the same bucket seal.
    publish_pending_and_verify(&cfg, &store).await.unwrap();
}

#[tokio::test]
async fn missing_bucket_seal_refuses_start() {
    let (_d, cfg, store) = setup().await;
    // No pending, no bucket seal: fail-closed.
    let err = publish_pending_and_verify(&cfg, &store)
        .await
        .expect_err("must refuse to start without a seal");
    assert!(
        err.contains("no template seal"),
        "error should name the missing seal: {err}",
    );
    assert!(
        err.contains("mint seal"),
        "error should suggest the fix: {err}"
    );
}

#[tokio::test]
async fn tampered_template_refuses_start_with_named_diff() {
    // Seal one version of the template, then drop in a different
    // body on disk and try to start. The bucket seal's hash for
    // volume-ro no longer matches the disk; diff names the role and
    // the specific divergence.
    let (d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "t1").await;
    publish_pending_and_verify(&cfg, &store).await.unwrap();

    // Overwrite the template file with semantically-different content.
    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["EVIL"]}"#,
    )
    .unwrap();
    // Reload config so the new bytes are picked up.
    let cfg2 = reload_config(&d).await;

    let err = publish_pending_and_verify(&cfg2, &store)
        .await
        .expect_err("tampered template must refuse to start");
    assert!(
        err.contains("volume-ro"),
        "diff should name the divergent role: {err}",
    );
    assert!(
        err.contains("policy_blake3"),
        "diff should name what differs: {err}",
    );
}

/// Reparse the config with the same data_dir + roles_dir as `setup()`
/// laid down, so a test can pick up newly-written-on-disk template
/// content without rebuilding the whole environment.
async fn reload_config(d: &tempfile::TempDir) -> Config {
    let roles_dir = d.path().join("roles");
    let data_dir = d.path().join("data");
    let toml = SAMPLE_TOML.replacen(
        "[tenant]",
        &format!(
            "data_dir = {:?}\nroles_dir = {:?}\n[tenant]",
            data_dir.display().to_string(),
            roles_dir.display().to_string()
        ),
        1,
    );
    Config::from_toml_str(&toml).expect("reparse")
}

#[tokio::test]
async fn pending_under_retired_kid_leaves_file_and_refuses() {
    // Stage a pending under kid=0, then rotate the keyring such that
    // kid=0 is no longer present, then try to publish. Must
    // refuse-closed AND leave the file in place for inspection.
    let (_d, cfg, store) = setup().await;
    let pending_path = stage_pending(&cfg, &store, "t1").await;
    assert!(pending_path.exists());

    // Replace the keyring with one containing only kid=1.
    let mut ring = BTreeMap::new();
    ring.insert(1, [99u8; 32]);
    store
        .set_keyring(Keyring::from_parts(ring, 1).unwrap())
        .await;

    let err = publish_pending_and_verify(&cfg, &store)
        .await
        .expect_err("retired kid pending must refuse to start");
    assert!(
        err.contains("kid that is no longer in the keyring") || err.contains("is signed under"),
        "error should explain the retired-kid case: {err}",
    );
    assert!(
        pending_path.exists(),
        "pending file MUST be preserved on fail-closed, not silently deleted",
    );

    // Resolution: operator re-runs `mint seal` under the new kid.
    // We simulate that by re-staging.
    stage_pending(&cfg, &store, "t2").await;
    publish_pending_and_verify(&cfg, &store).await.unwrap();
    assert!(!pending_path.exists(), "fresh re-seal publishes cleanly");
    let bucket = store.get_template_seal().await.unwrap().unwrap();
    assert_eq!(bucket.kid, 1, "now under the current kid");
}

#[tokio::test]
async fn semantic_equality_skips_redundant_put() {
    // The every-host-signs / first-restart-wins pattern: host A
    // publishes its seal; host B comes up with its own pending that
    // expresses the same intent at a different sealed_at. B's
    // publish path should observe the bucket already represents
    // the intent and discard B's pending without overwriting A's.
    let (_d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "host-A").await;
    publish_pending_and_verify(&cfg, &store).await.unwrap();
    let after_a = store.get_template_seal().await.unwrap().unwrap();
    assert_eq!(after_a.sealed_at, "host-A");

    stage_pending(&cfg, &store, "host-B").await;
    publish_pending_and_verify(&cfg, &store).await.unwrap();
    let after_b = store.get_template_seal().await.unwrap().unwrap();
    assert_eq!(
        after_b.sealed_at, "host-A",
        "bucket seal NOT overwritten — same intent reconciled away",
    );
}

#[tokio::test]
async fn semantically_different_pending_overwrites() {
    // Inverse of the above: if host B's intent genuinely diverges
    // from the bucket seal, B publishes its pending (and the
    // operator's rolling restart converges the fleet).
    let (d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "host-A").await;
    publish_pending_and_verify(&cfg, &store).await.unwrap();

    // Host B has a different template body on disk (different intent).
    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["DIFFERENT"]}"#,
    )
    .unwrap();
    let cfg_b = reload_config(&d).await;
    stage_pending(&cfg_b, &store, "host-B").await;
    publish_pending_and_verify(&cfg_b, &store).await.unwrap();

    let after_b = store.get_template_seal().await.unwrap().unwrap();
    assert_eq!(after_b.sealed_at, "host-B", "diverging intent overwrote");
}

#[tokio::test]
async fn pending_with_corrupt_body_refuses_start() {
    // A junk file at the pending path (not valid JSON) is a hard
    // refuse — the operator's intent is unparsable; treat as a
    // tamper signal, not silently discard.
    let (_d, cfg, store) = setup().await;
    let p = cfg.data_dir.join("pending-seal.json");
    std::fs::write(&p, b"this is not json").unwrap();
    let err = publish_pending_and_verify(&cfg, &store)
        .await
        .expect_err("corrupt pending body must refuse");
    assert!(
        err.contains("decode") || err.contains("seal"),
        "error should mention decoding: {err}",
    );
    assert!(p.exists(), "corrupt pending file preserved for inspection");
}

#[tokio::test]
async fn empty_bucket_with_no_pending_refuses_start() {
    // Sanity: no operator has run `mint seal` ever — startup is
    // refused with a clear "run mint seal first" message.
    let (_d, cfg, store) = setup().await;
    let err = publish_pending_and_verify(&cfg, &store)
        .await
        .expect_err("must refuse without seal");
    assert!(err.contains("no template seal"));
}
