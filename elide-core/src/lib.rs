/// Build-time version: the release tag, or `<manifest>-dev` otherwise.
pub const VERSION: &str = env!("ELIDE_VERSION");

pub mod actor;
pub mod blake3_id_hasher;
pub mod block_reader;
pub mod chunk_tree;
pub mod config;
pub mod delta_compute;
pub mod dmat;
pub mod ext4_scan;
pub mod extentindex;
pub mod filemap;
pub mod import;
pub mod ipc;
pub mod journal;
pub mod lbamap;
pub mod lock_stats;
pub mod malloc_debug;
pub mod malloc_policy;
pub mod name_record;
pub mod operator_session;
pub mod process;
pub mod rewrite_apply;
pub mod rewrite_plan;
pub mod segment;
pub mod segment_cache;
pub mod segment_classify;
pub mod signing;
pub mod sketch;
pub mod sketch_index;
pub mod store_keys;
pub mod ulid_mint;
pub mod volume;
pub mod volume_event;
pub mod volume_ipc;
pub mod writelog;
pub mod wtrace;

/// Whether the volume's self-check assertions run.
///
/// Each one rebuilds a structure from disk and diffs it against memory,
/// which costs more than the mutation it guards, so it answers to
/// `ELIDE_VOLUME_INVARIANTS` at runtime and falls back to the
/// `volume-invariants` build feature. Reading the variable once keeps a
/// disabled check to a single load.
pub fn volume_invariants_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| match std::env::var("ELIDE_VOLUME_INVARIANTS") {
            Ok(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
            Err(_) => cfg!(feature = "volume-invariants"),
        });
    *ENABLED
}

/// Whether the promote worker's delta tiers run.
///
/// Both tiers — same-LBA against a sealed snapshot, and the resemblance
/// probe — answer to `ELIDE_VOLUME_DELTA` so one release binary serves
/// both arms of a measurement. Off leaves each entry as the Data entry
/// it already was; segments written earlier keep their Delta entries and
/// still read.
pub fn volume_delta_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| env_switch("ELIDE_VOLUME_DELTA", true));
    *ENABLED
}

/// Whether the volume server's segment writes populate resemblance
/// sketches.
///
/// Sketches are read by the resemblance tier alone, and computing one
/// decompresses the body it describes, so they answer to
/// `ELIDE_VOLUME_SKETCHES`. Import writes its own segments sketched
/// either way — its delta producer matches on filemap paths, and this
/// switch reaches only the writes the volume server makes.
pub fn volume_sketches_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| env_switch("ELIDE_VOLUME_SKETCHES", true));
    *ENABLED
}

fn env_switch(key: &str, default: bool) -> bool {
    parse_switch(std::env::var(key).ok().as_deref(), default)
}

/// Hold `default` for a value that names neither state — a typo must not
/// silently select the other arm.
fn parse_switch(value: Option<&str>, default: bool) -> bool {
    match value {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

#[cfg(test)]
mod switch_tests {
    use super::parse_switch;

    #[test]
    fn a_switch_reads_both_states_and_holds_its_default() {
        for on in ["1", "true", "yes", "on"] {
            assert!(parse_switch(Some(on), false), "{on} names the on state");
        }
        for off in ["0", "false", "no", "off"] {
            assert!(!parse_switch(Some(off), true), "{off} names the off state");
        }
        assert!(parse_switch(Some("of"), true), "a typo holds the default");
        assert!(!parse_switch(Some("of"), false), "a typo holds the default");
        assert!(parse_switch(None, true));
        assert!(!parse_switch(None, false));
    }
}
