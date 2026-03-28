// elide-coordinator: manages segment upload and object store lifecycle.
//
// Subcommands:
//   drain-pending <fork-dir>
//     Upload all committed segments from pending/ to the object store, then exit.
//     Each segment is handled independently; partial success is possible.
//     Exits non-zero if any segment failed to upload.
//
// Store selection (mutually exclusive):
//   --local <path>          Use a local directory as the object store (no server needed).
//   (default)               Use S3 via env vars: ELIDE_S3_BUCKET, AWS_ENDPOINT_URL,
//                           AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.

mod store;
mod upload;

use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use object_store::ObjectStore;

#[derive(Parser)]
#[command(about = "Elide coordinator: manages segment upload and object store lifecycle")]
struct Args {
    /// Use a local directory as the object store instead of S3.
    /// Useful for testing without a running object store server.
    #[arg(long, global = true, value_name = "PATH")]
    local: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Upload all pending segments for a fork to the object store, then exit.
    DrainPending {
        /// Path to the fork directory (e.g. volumes/myvm/base or volumes/myvm/forks/vm1)
        fork_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        process::exit(1);
    }
}

fn build_store(local: Option<PathBuf>) -> Result<Arc<dyn ObjectStore>> {
    if let Some(path) = local {
        std::fs::create_dir_all(&path)
            .with_context(|| format!("creating local store dir: {}", path.display()))?;
        Ok(Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(&path)
                .context("building local store")?,
        ))
    } else {
        store::StoreConfig::from_env()?.build()
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let store = build_store(args.local)?;

    match args.command {
        Command::DrainPending { fork_dir } => {
            let (volume_id, fork_name) = upload::derive_names(&fork_dir)
                .context("resolving volume and fork names from fork dir")?;

            let result = upload::drain_pending(&fork_dir, &volume_id, &fork_name, &store).await?;

            println!("{} uploaded, {} failed", result.uploaded, result.failed);

            if result.failed > 0 {
                process::exit(1);
            }

            Ok(())
        }
    }
}
