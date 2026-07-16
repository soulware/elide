//! Upload micro-benchmark for the segment-drain path.
//!
//! Drives the real [`crate::volume_data::SegmentsView::put_from_file`]
//! against the configured object store in isolation from the daemon's
//! other work, so the upload throughput can be attributed to the path
//! itself rather than to reactor contention with the live coordinator.
//!
//! Two knobs isolate the two competing explanations for the slow live
//! drain: `parallel` reproduces several volumes draining at once on one
//! runtime, and `worker_threads` sizes that runtime. A single object
//! at `worker_threads = 1` matches the production coordinator on a
//! one-vCPU host; comparing it against wider runtimes and against the
//! raw `s5cmd` figure locates the bottleneck.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use object_store::ObjectStore;
use ulid::Ulid;

use crate::config::CoordinatorConfig;
use crate::volume_data::VolumeData;

/// Parameters for one benchmark run.
pub struct BenchOpts {
    /// Object size in MiB. Each iteration uploads `parallel` objects of
    /// this size.
    pub size_mb: usize,
    /// Timed iterations. The report is the median across them.
    pub iters: usize,
    /// Concurrent `put_from_file` calls per iteration, each its own
    /// segment. `1` measures an isolated upload; higher values
    /// reproduce concurrent per-volume drains sharing one runtime.
    pub parallel: usize,
    /// Worker threads for the runtime under test. `0` uses tokio's
    /// default (one per CPU) — the production coordinator's setting.
    pub worker_threads: usize,
    /// Leave the uploaded objects in place instead of deleting them.
    pub keep: bool,
    /// Object-key prefix. When non-empty, every key is written under
    /// it (via a wrapping store), confining probe objects to one prefix
    /// in a shared bucket.
    pub key_prefix: String,
}

/// Build the store from `config`, generate a source file, and run the
/// upload benchmark on a dedicated runtime. Blocking: constructs and
/// owns its own tokio runtime so `worker_threads` is honoured
/// independently of any caller runtime.
pub fn run_blocking(config: CoordinatorConfig, opts: BenchOpts) -> Result<()> {
    if opts.size_mb == 0 {
        bail!("size-mb must be non-zero");
    }
    if opts.iters == 0 {
        bail!("iters must be non-zero");
    }
    if opts.parallel == 0 {
        bail!("parallel must be non-zero");
    }

    let base = config.store.build().context("building object store")?;
    let store: Arc<dyn ObjectStore> = if opts.key_prefix.is_empty() {
        base
    } else {
        Arc::new(object_store::prefix::PrefixStore::new(
            base,
            opts.key_prefix.as_str(),
        ))
    };
    let part_size = config.store.multipart_part_size_bytes();
    crate::upload::set_part_size_bytes(part_size);

    let size_bytes = opts.size_mb * 1024 * 1024;
    let src = generate_source(&config.data_dir, size_bytes)
        .context("generating benchmark source file")?;

    let vol_ulid = Ulid::new();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if opts.worker_threads > 0 {
        builder.worker_threads(opts.worker_threads);
    }
    let rt = builder.build().context("building benchmark runtime")?;

    println!("[s3-bench] store: {}", config.store.describe());
    println!(
        "[s3-bench] object={}MiB iters={} parallel={} worker_threads={} vol={}",
        opts.size_mb,
        opts.iters,
        opts.parallel,
        if opts.worker_threads == 0 {
            "default".to_owned()
        } else {
            opts.worker_threads.to_string()
        },
        vol_ulid,
    );
    if !opts.key_prefix.is_empty() {
        println!("[s3-bench] key prefix: {}", opts.key_prefix);
    }

    let result = rt.block_on(run_iters(
        store.clone(),
        vol_ulid,
        &src.path,
        size_bytes,
        &opts,
    ));

    // Best-effort cleanup regardless of how the timed run finished, so a
    // partial failure doesn't leak probe objects into the bucket.
    if !opts.keep {
        rt.block_on(cleanup(&store, vol_ulid));
    } else {
        println!("[s3-bench] --keep set; objects left under by_id/{vol_ulid}/segments/");
    }
    let _ = std::fs::remove_file(&src.path);

    result
}

/// A generated source file that removes itself on drop as a backstop;
/// the caller also deletes it explicitly after the run.
struct SourceFile {
    path: PathBuf,
}

impl Drop for SourceFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write `size_bytes` of incompressible data to a file under
/// `data_dir`, then read it once to warm the page cache so timings
/// reflect the network path rather than a cold disk read (matching the
/// `s5cmd` probe conditions).
fn generate_source(data_dir: &Path, size_bytes: usize) -> Result<SourceFile> {
    use std::io::{Read, Write};

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let path = data_dir.join(format!("s3-bench-src-{}", Ulid::new()));

    let mut f =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    // A fixed 1 MiB pattern is enough to defeat compression on the wire
    // without spending the run on RNG; the bytes never round-trip back
    // for comparison, so the pattern's content is immaterial.
    let mut chunk = vec![0u8; 1024 * 1024];
    for (i, b) in chunk.iter_mut().enumerate() {
        *b = (i * 31 + 7) as u8;
    }
    let mut written = 0;
    while written < size_bytes {
        let n = (size_bytes - written).min(chunk.len());
        f.write_all(&chunk[..n])?;
        written += n;
    }
    f.flush()?;
    drop(f);

    let mut warm = std::fs::File::open(&path)?;
    let mut sink = vec![0u8; chunk.len()];
    while warm.read(&mut sink)? != 0 {}

    Ok(SourceFile { path })
}

async fn run_iters(
    store: Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
    src: &Path,
    size_bytes: usize,
    opts: &BenchOpts,
) -> Result<()> {
    let vd = VolumeData::new(store, vol_ulid);
    let mut rates = Vec::with_capacity(opts.iters);

    for iter in 0..opts.iters {
        let started = Instant::now();
        let mut tasks = Vec::with_capacity(opts.parallel);
        for _ in 0..opts.parallel {
            let vd = vd.clone();
            let src = src.to_path_buf();
            let seg = Ulid::new();
            tasks.push(tokio::spawn(async move {
                let mut segments = vd.segments();
                let t = Instant::now();
                segments
                    .put_from_file(seg, &src)
                    .await
                    .map_err(anyhow::Error::from)?;
                Ok::<Duration, anyhow::Error>(t.elapsed())
            }));
        }

        let mut worst = Duration::ZERO;
        for task in tasks {
            let elapsed = task.await.context("benchmark upload task panicked")??;
            worst = worst.max(elapsed);
        }
        let wall = started.elapsed();

        let total_mb = (size_bytes * opts.parallel) as f64 / (1024.0 * 1024.0);
        let rate = total_mb / wall.as_secs_f64();
        rates.push(rate);
        println!(
            "iter {:>2}: {} obj  {:6.2}s wall  slowest {:6.2}s  {:7.2} MB/s",
            iter + 1,
            opts.parallel,
            wall.as_secs_f64(),
            worst.as_secs_f64(),
            rate,
        );
    }

    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = rates[rates.len() / 2];
    println!(
        "[s3-bench] median {median:.2} MB/s over {} iters ({:.2}–{:.2})",
        opts.iters,
        rates.first().copied().unwrap_or(0.0),
        rates.last().copied().unwrap_or(0.0),
    );
    Ok(())
}

async fn cleanup(store: &Arc<dyn ObjectStore>, vol_ulid: Ulid) {
    use futures::StreamExt;
    use object_store::path::Path as StorePath;

    let prefix = StorePath::from(format!("by_id/{vol_ulid}/segments"));
    let mut stream = store.list(Some(&prefix));
    let mut deleted = 0usize;
    let mut errors = 0usize;
    while let Some(entry) = stream.next().await {
        match entry {
            Ok(meta) => match store.delete(&meta.location).await {
                Ok(()) => deleted += 1,
                Err(_) => errors += 1,
            },
            Err(_) => errors += 1,
        }
    }
    if errors == 0 {
        println!("[s3-bench] cleaned up {deleted} object(s)");
    } else {
        println!(
            "[s3-bench] cleaned up {deleted} object(s), {errors} failed; \
             remainder under by_id/{vol_ulid}/segments/"
        );
    }
}
