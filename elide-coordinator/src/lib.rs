pub mod config;
pub mod control;
pub mod delta;
pub mod gc;
pub mod prefetch;
pub mod tasks;
pub mod upload;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

/// Registry of per-fork eviction channels.
///
/// Maps each fork directory path to its evict request sender.  The coordinator
/// daemon populates this on fork discovery; the inbound handler looks up the
/// sender to forward eviction requests into the fork's task loop.
pub type EvictRegistry =
    Arc<Mutex<HashMap<PathBuf, mpsc::Sender<(Option<String>, tasks::EvictReply)>>>>;
