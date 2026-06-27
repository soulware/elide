//! Bakes the version the elide binaries report via `--version`.
//!
//! The git tag is the release version's single source of truth: the release
//! workflow passes it as `ELIDE_RELEASE_VERSION`. Absent it, the build reports a
//! `-dev` version off the manifest. Exposed as `elide_core::VERSION`. See
//! `docs/release-artifacts.md`.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=ELIDE_RELEASE_VERSION");

    let version = match env::var("ELIDE_RELEASE_VERSION") {
        Ok(tag) if !tag.trim().is_empty() => tag.trim().trim_start_matches('v').to_string(),
        _ => format!("{}-dev", env::var("CARGO_PKG_VERSION").unwrap_or_default()),
    };
    println!("cargo:rustc-env=ELIDE_VERSION={version}");
}
