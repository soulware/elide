use std::time::Duration;

const DEFAULT_HZ: i32 = 99;
const DEFAULT_SECS: u64 = 180;

/// Sample this process's CPU for a fixed window and write a flamegraph.
///
/// `ELIDE_CPU_PROFILE` names the SVG to write and switches sampling on, so
/// a release binary profiles one run without a rebuild.
/// `ELIDE_CPU_PROFILE_SECS` and `ELIDE_CPU_PROFILE_HZ` size the window and
/// the sample rate.
///
/// The window is fixed rather than ending at shutdown because the volume
/// server is normally killed outright, and a report written on a clean exit
/// would never be written at all.
pub fn spawn_if_enabled() {
    let Ok(path) = std::env::var("ELIDE_CPU_PROFILE") else {
        return;
    };
    let hz = env_parsed("ELIDE_CPU_PROFILE_HZ", DEFAULT_HZ);
    let secs = env_parsed("ELIDE_CPU_PROFILE_SECS", DEFAULT_SECS);

    let spawned = std::thread::Builder::new()
        .name("cpu-profile".to_owned())
        .spawn(move || run(&path, hz, secs));
    if let Err(e) = spawned {
        tracing::error!("[profile] could not start the sampling thread: {e}");
    }
}

fn env_parsed<T: std::str::FromStr>(key: &str, fallback: T) -> T {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn run(path: &str, hz: i32, secs: u64) {
    // The blocklist keeps the unwinder out of frames whose own stack
    // walking can deadlock against the sampling signal.
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(hz)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build();
    let guard = match guard {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("[profile] could not start sampling: {e}");
            return;
        }
    };
    tracing::info!("[profile] sampling at {hz}Hz for {secs}s, writing {path}");

    std::thread::sleep(Duration::from_secs(secs));

    let report = match guard.report().build() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[profile] could not build the report: {e}");
            return;
        }
    };
    // Rendered before the file exists so a run that sampled nothing leaves
    // no 0-byte SVG to be mistaken for a profile.
    let mut svg = Vec::new();
    if let Err(e) = report.flamegraph(&mut svg) {
        tracing::error!("[profile] could not render the flamegraph: {e}");
        return;
    }
    if svg.is_empty() {
        tracing::warn!("[profile] no samples collected, nothing written");
        return;
    }
    match std::fs::write(path, &svg) {
        Ok(()) => tracing::info!("[profile] wrote {path}"),
        Err(e) => tracing::error!("[profile] could not write {path}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An operator who sets the variable gets a flamegraph, which is the
    /// whole of what the gate promises. Every failure inside `run` is
    /// logged rather than propagated, so a broken sampler would otherwise
    /// show up as a missing file long after the run it was meant to cover.
    #[test]
    fn a_short_window_writes_a_flamegraph() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cpu.svg");
        // Arithmetic between clock reads, not a clock read per iteration.
        // `Instant::now()` lands in the vDSO, which the blocklist drops
        // whole samples for, so a loop that spins on it collects nothing
        // on Linux while passing on macOS, where there is no vDSO to match.
        let burn = std::thread::spawn(|| {
            let end = std::time::Instant::now() + Duration::from_millis(2500);
            let mut n: u64 = 0;
            loop {
                for i in 0..1_000_000u64 {
                    n = n.wrapping_add(i).rotate_left(7);
                }
                if std::time::Instant::now() >= end {
                    return n;
                }
            }
        });

        run(&path.to_string_lossy(), 99, 2);

        let _ = burn.join();
        let svg = std::fs::read_to_string(&path).expect("flamegraph written");
        assert!(
            svg.contains("<svg"),
            "not an svg: {}",
            &svg[..svg.len().min(80)]
        );
        // A profiler that samples nothing still writes a valid empty SVG,
        // so name a frame the burn loop had to be inside.
        assert!(
            svg.contains("cpu_profile"),
            "no sampled frame from this test in the flamegraph"
        );
    }
}
