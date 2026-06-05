//! `mint role list` / `mint role inspect` against the sealed surface
//! (`docs/design-mint-template-seal.md`). The served seal is authoritative:
//! the commands report each role as served / drifted / unsealed and, on
//! drift, show the *sealed* bytes — never the live `roles_dir/` template.
//!
//! The cache is staged straight on disk with `sealed_cache::write` (what
//! the adopt/seal path does after verifying a seal); these commands read
//! it offline, so no daemon or store is involved.

use std::path::{Path, PathBuf};
use std::process::Command;

use mint::Config;
use mint::keyring::Keyring;
use mint::seal::Seal;
use mint::sealed_cache::{self, policies_from_config};

const RO_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"ro"}]}"#;
const RW_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"rw"}]}"#;

/// Write a two-role config with absolute `data_dir`/`roles_dir` (so
/// resolution is cwd-independent) and its policy files. Returns the
/// `mint.toml` path.
fn write_config(d: &Path) -> PathBuf {
    let data = d.join("data");
    let roles = d.join("roles");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&roles).unwrap();
    std::fs::write(roles.join("volume-ro.json"), RO_POLICY).unwrap();
    std::fs::write(roles.join("volume-rw.json"), RW_POLICY).unwrap();
    let data = data.display().to_string();
    let roles = roles.display().to_string();
    let toml = format!(
        r#"
audience = "mint"
data_dir = {data:?}
roles_dir = {roles:?}

[store]
bucket = "demo-bucket"

[env]
bucket = "demo-bucket"

[[role]]
name = "volume-ro"
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 3600

[[role]]
name = "volume-rw"
min_ttl_seconds = 60
max_ttl_seconds = 86400
default_ttl_seconds = 86400
"#
    );
    let path = d.join("mint.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

/// Materialise a sealed cache for the config as it stands now — the
/// served surface a later `role` command compares the live config against.
fn stage_cache(cfg_path: &Path) {
    let cfg = Config::load(cfg_path).expect("load config");
    let seal = Seal::build_from_config(&cfg, &Keyring::single([7u8; 32]), "2026-06-05T00:00:00Z");
    sealed_cache::write(&cfg.data_dir, &seal, &policies_from_config(&cfg), &cfg.env)
        .expect("write cache");
}

/// Run the compiled binary, returning stdout+stderr combined (the table /
/// template land on stdout, diagnostics on stderr).
fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_mint"))
        .args(args)
        .output()
        .expect("run mint");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

#[test]
fn unsealed_when_no_cache() {
    let d = tempfile::tempdir().unwrap();
    let cfg = write_config(d.path());
    let cfg = cfg.to_str().unwrap();

    let list = run(&["role", "list", "--config", cfg]);
    assert!(list.contains("STATE"), "{list}");
    assert!(list.contains("unsealed"), "{list}");

    let insp = run(&["role", "inspect", "--config", cfg, "volume-rw"]);
    assert!(insp.contains("NOT SEALED"), "{insp}");
    assert!(insp.contains("local draft"), "{insp}");
}

#[test]
fn served_when_cache_matches_config() {
    let d = tempfile::tempdir().unwrap();
    let cfg = write_config(d.path());
    stage_cache(&cfg);
    let cfg = cfg.to_str().unwrap();

    let list = run(&["role", "list", "--config", cfg]);
    assert!(list.contains("served"), "{list}");
    assert!(!list.contains("drifted"), "{list}");
    assert!(!list.contains("unsealed"), "{list}");

    let insp = run(&["role", "inspect", "--config", cfg, "volume-rw"]);
    assert!(insp.contains("served (sealed at"), "{insp}");
    assert!(!insp.contains("drifted"), "{insp}");
    assert!(
        insp.contains(r#""Sid":"rw""#),
        "served template printed: {insp}"
    );
}

#[test]
fn drifted_when_local_template_changes_after_seal() {
    let d = tempfile::tempdir().unwrap();
    let cfg = write_config(d.path());
    stage_cache(&cfg);
    // Widen the live volume-rw template after sealing; volume-ro is left
    // matching the seal.
    std::fs::write(
        d.path().join("roles/volume-rw.json"),
        r#"{"Version":"2012-10-17","Statement":[{"Sid":"WIDENED"}]}"#,
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();

    let list = run(&["role", "list", "--config", cfg]);
    assert!(list.contains("drifted"), "{list}");
    assert!(
        list.contains("served"),
        "untouched role still served: {list}"
    );

    let insp = run(&["role", "inspect", "--config", cfg, "volume-rw"]);
    assert!(insp.contains("has drifted from the seal"), "{insp}");
    // The served (sealed) bytes are authoritative — the widened local
    // template must never be what inspect prints.
    assert!(insp.contains(r#""Sid":"rw""#), "{insp}");
    assert!(
        !insp.contains("WIDENED"),
        "must not print live drift: {insp}"
    );
}
