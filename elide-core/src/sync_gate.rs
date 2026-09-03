//! The WAL sync gate: one fdatasync round serves every durability request
//! whose writes landed before the round started.
//!
//! A request carries a generation, a point in the append order. A round
//! records the generation at its start, and a request is satisfied by any
//! round whose start is at or after its generation, because the round began
//! after the request's bytes were in the page cache. One round runs at a
//! time, and a request that finds the gate idle runs the round on its own
//! thread. See `docs/design/wal-sync-gate.md`.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::{Condvar, Mutex};

/// What kind of guest request asked for the sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Flush,
    Fua,
}

#[derive(Default)]
struct GateState {
    /// Start generation of the last completed round.
    completed: u64,
    /// The failure of the round that set `completed`, when it failed.
    failure: Option<(io::ErrorKind, String)>,
    /// Start generation of the round in flight.
    running: Option<u64>,
    /// Requests parked on the running round, satisfied by its completion.
    joined: u64,
}

impl GateState {
    fn outcome(&self) -> io::Result<()> {
        match &self.failure {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }
}

/// Counters over the requests and rounds, read for the `[flush …]` line.
#[derive(Default)]
struct GateCounters {
    flush_requests: AtomicU64,
    fua_requests: AtomicU64,
    /// Requests a completed round already covered on arrival.
    free_requests: AtomicU64,
    rounds: AtomicU64,
    /// Rounds that synced a rotated WAL beside the current one.
    rotated_rounds: AtomicU64,
    window_max_batch: AtomicU64,
    wait_nanos: AtomicU64,
    window_max_wait_nanos: AtomicU64,
    sync_nanos: AtomicU64,
    window_max_sync_nanos: AtomicU64,
}

pub struct SyncGate {
    state: Mutex<GateState>,
    done: Condvar,
    counters: GateCounters,
}

impl Default for SyncGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            done: Condvar::new(),
            counters: GateCounters::default(),
        }
    }
}

impl SyncGate {
    /// Return once a round that started at or after `gen` has completed,
    /// with that round's outcome.
    ///
    /// `now` reads the current generation, and `round` syncs every WAL
    /// file and returns how many it synced. Both run on the calling
    /// thread, with the gate released, when this request leads a round.
    pub fn sync_through(
        &self,
        generation: u64,
        kind: RequestKind,
        now: impl FnOnce() -> u64,
        round: impl FnOnce() -> io::Result<usize>,
    ) -> io::Result<()> {
        let arrived = Instant::now();
        match kind {
            RequestKind::Flush => &self.counters.flush_requests,
            RequestKind::Fua => &self.counters.fua_requests,
        }
        .fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.lock();
        if state.completed >= generation {
            self.counters.free_requests.fetch_add(1, Ordering::Relaxed);
            return state.outcome();
        }
        loop {
            match state.running {
                Some(start) if start >= generation => {
                    state.joined += 1;
                    self.done.wait(&mut state);
                    self.record_wait(arrived);
                    return state.outcome();
                }
                Some(_) => {
                    self.done.wait(&mut state);
                    if state.completed >= generation {
                        self.record_wait(arrived);
                        return state.outcome();
                    }
                }
                None => break,
            }
        }

        let start = now();
        state.running = Some(start);
        state.joined = 0;
        drop(state);

        let synced_at = Instant::now();
        let outcome = round();
        let sync = synced_at.elapsed();

        let mut state = self.state.lock();
        state.completed = start;
        state.running = None;
        state.failure = outcome.as_ref().err().map(|e| (e.kind(), e.to_string()));
        let batch = state.joined + 1;
        self.done.notify_all();
        drop(state);

        self.counters.rounds.fetch_add(1, Ordering::Relaxed);
        if matches!(outcome, Ok(files) if files > 1) {
            self.counters.rotated_rounds.fetch_add(1, Ordering::Relaxed);
        }
        self.counters
            .window_max_batch
            .fetch_max(batch, Ordering::Relaxed);
        let sync_nanos = sync.as_nanos() as u64;
        self.counters
            .sync_nanos
            .fetch_add(sync_nanos, Ordering::Relaxed);
        self.counters
            .window_max_sync_nanos
            .fetch_max(sync_nanos, Ordering::Relaxed);
        self.record_wait(arrived);
        outcome.map(|_| ())
    }

    fn record_wait(&self, arrived: Instant) {
        let nanos = arrived.elapsed().as_nanos() as u64;
        self.counters.wait_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.counters
            .window_max_wait_nanos
            .fetch_max(nanos, Ordering::Relaxed);
    }

    /// Read the counters and reset the window maxima.
    pub fn take_window(&self) -> GateSnapshot {
        self.read(true)
    }

    /// Read the counters and leave the window maxima in place.
    pub fn snapshot(&self) -> GateSnapshot {
        self.read(false)
    }

    fn read(&self, close_window: bool) -> GateSnapshot {
        let c = &self.counters;
        let window = |max: &AtomicU64| {
            if close_window {
                max.swap(0, Ordering::Relaxed)
            } else {
                max.load(Ordering::Relaxed)
            }
        };
        GateSnapshot {
            flush_requests: c.flush_requests.load(Ordering::Relaxed),
            fua_requests: c.fua_requests.load(Ordering::Relaxed),
            free_requests: c.free_requests.load(Ordering::Relaxed),
            rounds: c.rounds.load(Ordering::Relaxed),
            rotated_rounds: c.rotated_rounds.load(Ordering::Relaxed),
            max_batch: window(&c.window_max_batch),
            wait_nanos: c.wait_nanos.load(Ordering::Relaxed),
            max_wait_nanos: window(&c.window_max_wait_nanos),
            sync_nanos: c.sync_nanos.load(Ordering::Relaxed),
            max_sync_nanos: window(&c.window_max_sync_nanos),
        }
    }
}

/// The gate's counters read at an instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateSnapshot {
    pub flush_requests: u64,
    pub fua_requests: u64,
    pub free_requests: u64,
    pub rounds: u64,
    pub rotated_rounds: u64,
    /// Most requests one round served, within the window.
    pub max_batch: u64,
    /// A request's time from arrival to return, summed, and the longest.
    pub wait_nanos: u64,
    pub max_wait_nanos: u64,
    /// A round's sync time, summed, and the longest.
    pub sync_nanos: u64,
    pub max_sync_nanos: u64,
}

impl GateSnapshot {
    /// The counts since `earlier`, with this snapshot's window maxima.
    pub fn since(&self, earlier: &GateSnapshot) -> GateSnapshot {
        GateSnapshot {
            flush_requests: self.flush_requests.saturating_sub(earlier.flush_requests),
            fua_requests: self.fua_requests.saturating_sub(earlier.fua_requests),
            free_requests: self.free_requests.saturating_sub(earlier.free_requests),
            rounds: self.rounds.saturating_sub(earlier.rounds),
            rotated_rounds: self.rotated_rounds.saturating_sub(earlier.rotated_rounds),
            max_batch: self.max_batch,
            wait_nanos: self.wait_nanos.saturating_sub(earlier.wait_nanos),
            max_wait_nanos: self.max_wait_nanos,
            sync_nanos: self.sync_nanos.saturating_sub(earlier.sync_nanos),
            max_sync_nanos: self.max_sync_nanos,
        }
    }

    pub fn requests(&self) -> u64 {
        self.flush_requests + self.fua_requests
    }

    /// One line for the log, `None` when the window saw no request.
    pub fn report(&self) -> Option<String> {
        let requests = self.requests();
        if requests == 0 {
            return None;
        }
        let mean = |nanos: u64, n: u64| {
            if n == 0 {
                0.0
            } else {
                nanos as f64 / 1e6 / n as f64
            }
        };
        Some(format!(
            "flush n={} fua n={} free n={} rounds={} batch max={} \
             wait mean={:.2}ms max={:.1}ms sync mean={:.2}ms max={:.1}ms rotated={}",
            self.flush_requests,
            self.fua_requests,
            self.free_requests,
            self.rounds,
            self.max_batch,
            mean(self.wait_nanos, requests),
            self.max_wait_nanos as f64 / 1e6,
            mean(self.sync_nanos, self.rounds),
            self.max_sync_nanos as f64 / 1e6,
            self.rotated_rounds,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::{Receiver, Sender, bounded};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::thread;
    use std::time::Duration;

    /// A round that blocks until the test releases it, so the test drives
    /// the order of arrivals against the round in flight.
    struct Harness {
        gate: Arc<SyncGate>,
        generation: Arc<AtomicU64>,
        rounds: Arc<AtomicU64>,
        release_tx: Sender<io::Result<usize>>,
        release_rx: Receiver<io::Result<usize>>,
        started_tx: Sender<()>,
        started_rx: Receiver<()>,
    }

    impl Harness {
        fn new() -> Self {
            let (release_tx, release_rx) = bounded(8);
            let (started_tx, started_rx) = bounded(8);
            Self {
                gate: Arc::new(SyncGate::default()),
                generation: Arc::new(AtomicU64::new(0)),
                rounds: Arc::new(AtomicU64::new(0)),
                release_tx,
                release_rx,
                started_tx,
                started_rx,
            }
        }

        /// A request at `gen` on its own thread; the receiver carries its
        /// outcome.
        fn request(&self, generation: u64) -> Receiver<io::Result<()>> {
            let (tx, rx) = bounded(1);
            let gate = Arc::clone(&self.gate);
            let now = Arc::clone(&self.generation);
            let rounds = Arc::clone(&self.rounds);
            let release = self.release_rx.clone();
            let started = self.started_tx.clone();
            thread::spawn(move || {
                let r = gate.sync_through(
                    generation,
                    RequestKind::Flush,
                    || now.load(Ordering::SeqCst),
                    || {
                        rounds.fetch_add(1, Ordering::SeqCst);
                        let _ = started.send(());
                        release.recv().unwrap_or(Ok(1))
                    },
                );
                let _ = tx.send(r);
            });
            rx
        }

        fn round_started(&self) {
            self.started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("a round started");
        }

        fn release(&self, outcome: io::Result<usize>) {
            self.release_tx.send(outcome).expect("the round is waiting");
        }
    }

    fn settled(rx: &Receiver<io::Result<()>>) -> io::Result<()> {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the request returned")
    }

    fn pending(rx: &Receiver<io::Result<()>>) -> bool {
        rx.recv_timeout(Duration::from_millis(50)).is_err()
    }

    /// A request whose generation a completed round already covers
    /// returns at once, and a request with a later generation than the
    /// round in flight waits for that round and then leads the next one.
    #[test]
    fn a_later_request_waits_for_the_round_in_flight_and_then_leads_the_next() {
        let h = Harness::new();
        h.generation.store(1, Ordering::SeqCst);
        let first = h.request(1);
        h.round_started();

        h.generation.store(2, Ordering::SeqCst);
        let later = h.request(2);
        let joiner = h.request(1);
        assert!(pending(&later), "the later request waits");
        assert!(pending(&joiner), "the joiner waits for the round in flight");
        assert_eq!(h.rounds.load(Ordering::SeqCst), 1);

        h.release(Ok(1));
        settled(&first).expect("the leader's round succeeded");
        settled(&joiner).expect("the joiner rode the first round");
        h.round_started();
        assert_eq!(
            h.rounds.load(Ordering::SeqCst),
            2,
            "the later request led a round"
        );
        assert!(pending(&later));

        let free = h.request(1);
        settled(&free).expect("a covered generation returns at once");

        h.release(Ok(2));
        settled(&later).expect("the second round succeeded");

        let snap = h.gate.snapshot();
        assert_eq!(snap.rounds, 2);
        assert_eq!(snap.free_requests, 1);
        assert_eq!(snap.rotated_rounds, 1);
        assert_eq!(
            snap.max_batch, 2,
            "the first round served its leader and the joiner"
        );
        assert_eq!(snap.flush_requests, 4);
    }

    /// A failed round fails every request it served, and the next round
    /// starts clean.
    #[test]
    fn a_failed_round_fails_every_request_it_served_and_the_next_starts_clean() {
        let h = Harness::new();
        h.generation.store(3, Ordering::SeqCst);
        let leader = h.request(3);
        h.round_started();
        let joiner = h.request(2);
        assert!(pending(&joiner));

        h.release(Err(io::Error::other("disk gone")));
        let e = settled(&leader).expect_err("the leader saw the failure");
        assert_eq!(e.to_string(), "disk gone");
        let e = settled(&joiner).expect_err("the joiner saw the same failure");
        assert_eq!(e.to_string(), "disk gone");
        let e = settled(&h.request(1)).expect_err("a covered generation carries the outcome");
        assert_eq!(e.to_string(), "disk gone");

        h.generation.store(4, Ordering::SeqCst);
        let next = h.request(4);
        h.round_started();
        h.release(Ok(1));
        settled(&next).expect("the next round succeeded");
        settled(&h.request(4)).expect("its generation is now covered clean");
    }

    /// The report names the window, and a window with no request has none.
    #[test]
    fn the_report_names_the_window() {
        let gate = SyncGate::default();
        assert!(gate.take_window().report().is_none());
        gate.sync_through(1, RequestKind::Fua, || 1, || Ok(1))
            .expect("one round");
        gate.sync_through(1, RequestKind::Flush, || 1, || Ok(1))
            .expect("covered");
        let window = gate.take_window();
        let report = window.report().expect("two requests");
        assert!(
            report.starts_with("flush n=1 fua n=1 free n=1 rounds=1 batch max=1 wait mean="),
            "got: {report}"
        );
        assert!(report.ends_with("rotated=0"), "got: {report}");
        assert_eq!(gate.snapshot().max_batch, 0, "the window maximum reset");
        assert_eq!(gate.snapshot().since(&window).requests(), 0);
    }
}
