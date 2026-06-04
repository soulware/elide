//! `mint serve` startup seal resolution (`docs/design-mint-template-seal.md`
//! § *Startup*): given a canonical bucket seal (published by
//! `POST /v1/admin/seal` — exercised end-to-end in `admin_discharge.rs`),
//! [`mint::seal::resolve_startup`] serves the local sealed cache, adopts
//! the seal from `roles_dir/`, or runs **dormant** when there is no
//! verifiable seal this host can satisfy.
//!
//! These tests stand in for the authoring endpoint by PUTting a seal
//! straight into the [`Store`] (what the handler does after verifying the
//! operator bundle), then drive `resolve_startup` against an in-memory
//! store and a real-filesystem `data_dir` (so the sealed cache has
//! somewhere to live).

use std::sync::Arc;

use mint::Config;
use mint::seal::{Seal, resolve_startup};
use mint::sealed_cache::SealState;
use mint::state::Store;

const SAMPLE_TOML: &str = r#"
audience = "mint"

[store]
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

/// Build a config whose `data_dir` + `roles_dir` are real tempdirs (so
/// startup can write `<data_dir>/sealed/`), and an in-memory store with a
/// fixed kid=0 keyring. The tempdir holds both and is kept alive for the run.
async fn setup() -> (tempfile::TempDir, Config, Arc<Store>) {
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(d.path().join("roles")).unwrap();
    std::fs::create_dir_all(d.path().join("data")).unwrap();
    std::fs::write(d.path().join("roles/volume-ro.json"), POLICY).unwrap();
    let cfg = reload_config(&d).await;
    let store = Arc::new(Store::open_in_memory([7u8; 32]).await.expect("store"));
    (d, cfg, store)
}

/// Reparse the config against the same data_dir + roles_dir, so a test
/// can pick up newly-written-on-disk template content.
async fn reload_config(d: &tempfile::TempDir) -> Config {
    let toml = SAMPLE_TOML.replacen(
        "[store]",
        &format!(
            "data_dir = {:?}\nroles_dir = {:?}\n[store]",
            d.path().join("data").display().to_string(),
            d.path().join("roles").display().to_string()
        ),
        1,
    );
    Config::from_toml_str(&toml).expect("reparse")
}

/// Publish a canonical seal for `config` to the bucket — what
/// `POST /v1/admin/seal` does after verifying the operator bundle.
async fn publish_seal(config: &Config, store: &Store, sealed_at: &str) {
    let seal = Seal::build_from_config(config, &*store.keyring().await, sealed_at);
    store.put_template_seal(&seal).await.expect("publish");
}

#[tokio::test]
async fn adopts_published_seal_then_serves_from_cache() {
    let (_d, cfg, store) = setup().await;
    publish_seal(&cfg, &store, "2026-05-24T12:00:00Z").await;

    // First start after sealing: no cache yet → adopt from roles_dir/,
    // write the cache, serve.
    match resolve_startup(&cfg, &store).await.unwrap() {
        SealState::Serving(surface) => assert_eq!(surface.policy("volume-ro").unwrap(), POLICY),
        SealState::Dormant => panic!("should adopt + serve once a seal exists"),
    }

    // Restart: the bucket seal is unchanged → serves straight from cache.
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Serving(_)
    ));
}

#[tokio::test]
async fn missing_bucket_seal_runs_dormant() {
    let (_d, cfg, store) = setup().await;
    // No seal: mint never commits the on-disk bytes on its own — dormant,
    // and nothing published.
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
async fn unverifiable_bucket_seal_runs_dormant() {
    let (_d, cfg, store) = setup().await;
    // A seal MAC'd under a key this store's keyring does not hold can't
    // verify → dormant, not a hard error.
    let foreign = Seal::build_from_config(&cfg, &mint::keyring::Keyring::single([0xAB; 32]), "t");
    store.put_template_seal(&foreign).await.unwrap();
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Dormant
    ));
}

#[tokio::test]
async fn tampered_template_after_seal_still_serves_cache() {
    // Seal one version, then tamper the on-disk template. The bucket seal
    // is unchanged, so a restart serves the *cached* (sealed) bytes and
    // ignores the drifted disk — the "restart before re-seal is safe"
    // property. The tamper takes effect only via an explicit re-seal.
    let (d, cfg, store) = setup().await;
    publish_seal(&cfg, &store, "t1").await;
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
    // and it has no cache for it → dormant (held out of rotation).
    let (d, cfg, store) = setup().await;

    std::fs::write(
        d.path().join("roles/volume-ro.json"),
        r#"{"Version":"2012-10-17","Statement":["NEWER"]}"#,
    )
    .unwrap();
    let cfg_newer = reload_config(&d).await;
    publish_seal(&cfg_newer, &store, "newer").await;

    // This host's on-disk templates are the older content.
    std::fs::write(d.path().join("roles/volume-ro.json"), POLICY).unwrap();
    assert!(matches!(
        resolve_startup(&cfg, &store).await.unwrap(),
        SealState::Dormant
    ));
}
