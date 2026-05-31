//! End-to-end template-seal startup (`docs/design-mint-template-seal.md`
//! § *Startup*): stage a pending via the same path the CLI takes →
//! `mint serve` startup publishes it, adopts it from `roles_dir/`, and
//! serves → restarts serve from the local sealed cache. Plus the states
//! that close the role-rendering plane: **dormant** on a missing or
//! host-can't-satisfy seal, and the hard refuses that survive (a pending
//! under a retired kid, or a corrupt pending body).
//!
//! The tests drive [`mint::seal::resolve_startup`] (the helper `mint
//! serve` calls) against an in-memory [`Store`] and a real-filesystem
//! `data_dir` (so the sealed cache and `pending-seal.json` have somewhere
//! to live).

use std::collections::BTreeMap;
use std::sync::Arc;

use mint::Config;
use mint::keyring::Keyring;
use mint::seal::{Seal, resolve_startup, write_pending};
use mint::sealed_cache::SealState;
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

/// Build a config whose `data_dir` and `roles_dir` are real tempdirs (so
/// the seal startup has somewhere to read `pending-seal.json` and write
/// `<data_dir>/sealed/`), and an in-memory store with a fixed kid=0
/// keyring. The returned tempdir holds both and is kept alive for the run.
async fn setup() -> (tempfile::TempDir, Config, Arc<Store>) {
    let d = tempfile::tempdir().expect("tempdir");
    let roles_dir = d.path().join("roles");
    let data_dir = d.path().join("data");
    std::fs::create_dir_all(&roles_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(roles_dir.join("volume-ro.json"), POLICY).unwrap();
    let cfg = reload_config(&d).await;
    let store = Arc::new(Store::open_in_memory([7u8; 32]).await.expect("store"));
    (d, cfg, store)
}

/// Reparse the config against the same data_dir + roles_dir `setup()`
/// laid down, so a test can pick up newly-written-on-disk template
/// content without rebuilding the environment.
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

/// Stage a pending seal at `<data_dir>/pending-seal.json` under the
/// store's current keyring, mirroring what `mint seal` does. Returns the
/// path for tests that inspect or remove it.
async fn stage_pending(config: &Config, store: &Store, sealed_at: &str) -> std::path::PathBuf {
    let kr = store.keyring().await;
    let seal = Seal::build_from_config(config, &kr, sealed_at);
    let p = config.data_dir.join("pending-seal.json");
    write_pending(&p, &seal).unwrap();
    p
}

#[tokio::test]
async fn happy_path_stage_publish_then_serves_from_cache() {
    let (_d, cfg, store) = setup().await;
    let p = stage_pending(&cfg, &store, "2026-05-24T12:00:00Z").await;

    // Publish the pending, adopt it from roles_dir/, and serve.
    match resolve_startup(&cfg, &store).await.unwrap() {
        SealState::Serving(surface) => assert_eq!(surface.policy("volume-ro").unwrap(), POLICY),
        SealState::Dormant => panic!("should serve after publishing a pending seal"),
    }
    assert!(!p.exists(), "pending file removed after publish");
    let bucket = store.get_template_seal().await.unwrap().expect("present");
    assert_eq!(bucket.sealed_at, "2026-05-24T12:00:00Z");
    bucket.verify(&*store.keyring().await).unwrap();

    // Restart (no pending): the bucket seal is unchanged, so it serves
    // straight from the local cache.
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Serving(_)
    ));
}

#[tokio::test]
async fn missing_bucket_seal_runs_dormant() {
    let (_d, cfg, store) = setup().await;
    // No pending, no bucket seal: mint never commits the on-disk bytes
    // on its own — it runs dormant and publishes nothing.
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Dormant
    ));
    assert!(
        store.get_template_seal().await.unwrap().is_none(),
        "dormant start must not publish a baseline seal"
    );
}

#[tokio::test]
async fn tampered_template_after_seal_still_serves_cache() {
    // Seal one version, then tamper the on-disk template. The bucket seal
    // is unchanged, so a restart serves the *cached* (sealed) bytes and
    // ignores the drifted disk — the "restart before re-seal is safe"
    // property. The tamper takes effect only via an explicit re-seal.
    let (d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "t1").await;
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Serving(_)
    ));

    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["EVIL"]}"#,
    )
    .unwrap();
    let cfg2 = reload_config(&d).await;

    match resolve_startup(&cfg2, &store).await.unwrap() {
        SealState::Serving(surface) => assert_eq!(
            surface.policy("volume-ro").unwrap(),
            POLICY,
            "the sealed cache bytes are served, not the tampered disk"
        ),
        SealState::Dormant => {
            panic!("a host already serving the seal must not dormant on disk drift")
        }
    }
}

#[tokio::test]
async fn host_behind_the_bucket_seal_runs_dormant() {
    // Another host sealed newer templates this host hasn't received. The
    // bucket seal verifies, but this host's roles_dir/ can't produce it
    // and it has no cache for it → dormant (held out of rotation), not a
    // crash and not serving stale content.
    let (d, cfg, store) = setup().await;
    let kr = store.keyring().await;

    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["NEWER"]}"#,
    )
    .unwrap();
    let cfg_newer = reload_config(&d).await;
    let newer = Seal::build_from_config(&cfg_newer, &kr, "newer");
    store.put_template_seal(&newer).await.unwrap();

    // This host's on-disk templates are the older content.
    std::fs::write(d.path().join("roles/volume-ro.json"), POLICY).unwrap();
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Dormant
    ));
}

#[tokio::test]
async fn pending_under_retired_kid_leaves_file_and_refuses() {
    // A pending staged under kid=0, then the keyring rotates so kid=0 is
    // gone. Publishing it is a hard refuse (the operator's intent can't
    // be verified) AND the file is preserved for inspection.
    let (_d, cfg, store) = setup().await;
    let pending_path = stage_pending(&cfg, &store, "t1").await;
    assert!(pending_path.exists());

    let mut ring = BTreeMap::new();
    ring.insert(1, [99u8; 32]);
    store
        .set_keyring(Keyring::from_parts(ring, 1).unwrap())
        .await;

    let err = resolve_startup(&cfg, &store)
        .await
        .expect_err("retired-kid pending must refuse to start");
    assert!(
        err.contains("kid that is no longer in the keyring") || err.contains("is signed under"),
        "error should explain the retired-kid case: {err}",
    );
    assert!(
        pending_path.exists(),
        "pending file MUST be preserved on fail-closed, not silently deleted",
    );

    // Resolution: the operator re-seals under the new kid (re-staged here).
    stage_pending(&cfg, &store, "t2").await;
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Serving(_)
    ));
    assert!(!pending_path.exists(), "fresh re-seal publishes cleanly");
    let bucket = store.get_template_seal().await.unwrap().unwrap();
    assert_eq!(bucket.kid, 1, "now under the current kid");
}

#[tokio::test]
async fn semantically_equal_pending_skips_redundant_put() {
    // Every-host-signs / first-restart-wins: host A publishes its seal;
    // host B comes up with its own pending expressing the same intent at
    // a different sealed_at. B observes the bucket already represents the
    // intent and discards its pending without overwriting A's.
    let (_d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "host-A").await;
    resolve_startup(&cfg, &store).await.unwrap();
    assert_eq!(
        store.get_template_seal().await.unwrap().unwrap().sealed_at,
        "host-A"
    );

    stage_pending(&cfg, &store, "host-B").await;
    resolve_startup(&cfg, &store).await.unwrap();
    assert_eq!(
        store.get_template_seal().await.unwrap().unwrap().sealed_at,
        "host-A",
        "bucket seal NOT overwritten — same intent reconciled away",
    );
}

#[tokio::test]
async fn semantically_different_pending_overwrites() {
    // If host B's intent genuinely diverges, B publishes its pending (and
    // an operator's rolling restart converges the fleet).
    let (d, cfg, store) = setup().await;
    stage_pending(&cfg, &store, "host-A").await;
    resolve_startup(&cfg, &store).await.unwrap();

    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["DIFFERENT"]}"#,
    )
    .unwrap();
    let cfg_b = reload_config(&d).await;
    stage_pending(&cfg_b, &store, "host-B").await;
    match resolve_startup(&cfg_b, &store).await.unwrap() {
        SealState::Serving(surface) => {
            assert!(surface.policy("volume-ro").unwrap().contains("DIFFERENT"))
        }
        SealState::Dormant => panic!("diverging intent should publish and serve"),
    }
    assert_eq!(
        store.get_template_seal().await.unwrap().unwrap().sealed_at,
        "host-B",
        "diverging intent overwrote",
    );
}

#[tokio::test]
async fn pending_with_corrupt_body_refuses_start() {
    // A junk file at the pending path is a hard refuse — the operator's
    // intent is unparsable; treat as a tamper signal, not silently drop.
    let (_d, cfg, store) = setup().await;
    let p = cfg.data_dir.join("pending-seal.json");
    std::fs::write(&p, b"this is not json").unwrap();
    let err = resolve_startup(&cfg, &store)
        .await
        .expect_err("corrupt pending body must refuse");
    assert!(
        err.contains("decode") || err.contains("seal"),
        "error should mention decoding: {err}",
    );
    assert!(p.exists(), "corrupt pending file preserved for inspection");
}
