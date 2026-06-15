//! The shipped example configs under `examples/` must parse. They are
//! the operator's starting point; a config that can't load is a broken
//! example. `roles_dir` in each is relative, so the config resolves it
//! against the process cwd — pinned here to the crate dir (where the
//! `examples/` policy templates live) so the test is invocation-agnostic.

use mint::config::Config;

/// Absolute path to a file under the crate's `examples/` directory.
fn example(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

/// Pin cwd to the crate dir so `roles_dir = "examples/…"` resolves.
/// Idempotent (always the same target), so the parallel test threads
/// don't contend meaningfully.
fn pin_cwd() {
    let _ = std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
}

#[test]
fn mint_demo_config_loads() {
    pin_cwd();
    let cfg = Config::load(&example("mint-demo.toml")).expect("mint-demo.toml");
    cfg.validate_policy_surface()
        .expect("demo templates satisfy the seal-authoring surface checks");
    // The demo colocates the auth role so the operator admin plane
    // (login / invite / enroll) has a discharge issuer and a admin-service.
    let demo = cfg.demo_auth.expect("[demo_auth] present");
    assert!(demo.enabled, "demo colocates the auth role");
    assert!(demo.socket.is_some(), "demo auth role binds a UDS");
    assert!(
        cfg.auth_location.is_some(),
        "demo configures the admin-service location"
    );
    // …and the attestation authority, so `demo-attested` has a
    // discharge issuer for its attested TPC.
    let attest = cfg.demo_attestation.expect("[demo_attestation] present");
    assert!(attest.enabled, "demo colocates the attestation authority");
    assert!(attest.socket.is_some(), "demo attestation binds a UDS");
    assert!(
        cfg.attestation_location.is_some(),
        "the attested role requires attestation_location"
    );
    // The two-role demo inventory, together substituting every
    // template namespace.
    let mut names: Vec<&str> = cfg.roles.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["demo", "demo-attested"]);
    assert!(
        cfg.roles["demo-attested"].attestation_mode.is_some(),
        "demo-attested carries the attested TPC"
    );
}

#[test]
fn mint_elide_config_loads() {
    pin_cwd();
    let cfg = Config::load(&example("mint-elide.toml")).expect("mint-elide.toml");
    cfg.validate_policy_surface()
        .expect("elide templates satisfy the seal-authoring surface checks");
    // The Elide inventory needs `auth_location`: enrollment is
    // operator-gated (the invite + ticket carry the enroll/exchange
    // gates, keyed by K_M-A).
    assert!(
        cfg.auth_location.is_some(),
        "enrollment gates require auth_location"
    );
    // The four-role inventory: coord-ro/coord-rw/volume-ro/volume-rw,
    // none carrying a third-party caveat (operator authority moved to
    // enrollment).
    let mut names: Vec<&str> = cfg.roles.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["coord-ro", "coord-rw", "volume-ro", "volume-rw"]);
}
