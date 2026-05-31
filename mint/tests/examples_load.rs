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
    // The demo colocates the auth role so the operator admin plane
    // (login / invite / enroll) has a discharge issuer and a cli-token.
    let auth = cfg.auth.expect("[auth] present");
    assert!(auth.demo_enabled, "demo colocates the auth role");
    assert!(auth.socket.is_some(), "demo auth role binds a UDS");
}

#[test]
fn mint_elide_config_loads() {
    pin_cwd();
    let cfg = Config::load(&example("mint-elide.toml")).expect("mint-elide.toml");
    // The Elide inventory carries `[role.tpc]` roles, which require an
    // `[auth]` block (the TPC is keyed by K_M-A).
    assert!(cfg.auth.is_some(), "TPC roles require [auth]");
    assert!(
        cfg.roles.values().any(|r| r.tpc.is_some()),
        "inventory has at least one TPC role"
    );
}
