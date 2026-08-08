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
