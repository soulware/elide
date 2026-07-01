pub mod bins;
pub mod bucket_position;
pub mod config;
pub mod control;
pub mod eligibility;
pub mod event_journal;
pub mod gc;
pub mod gc_cycle;
pub mod identity;
pub mod ipc;
pub mod key_shadow;
pub mod lifecycle;
pub mod local_cond_store;
pub mod log_init;
pub mod log_relay;
pub mod macaroon;
pub mod name_claims;
pub mod name_store;
pub mod park;
pub mod peer_discovery;
pub mod portable;
pub mod prefetch;
pub mod pull;
pub mod range_fetcher;
pub mod rehome;
pub mod role;
pub mod segment_head;
pub mod stores;
pub mod tasks;
pub mod ublk_sweep;
pub mod upload;
pub mod volume_data;
pub mod volume_state;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use ulid::Ulid;

/// Registry of per-fork eviction channels.
///
/// Maps each fork directory path to its evict request sender.  The coordinator
/// daemon populates this on fork discovery; the inbound handler looks up the
/// sender to forward eviction requests into the fork's task loop.
pub type EvictRegistry =
    Arc<Mutex<HashMap<PathBuf, mpsc::Sender<(Option<String>, tasks::EvictReply)>>>>;

/// Registry of per-fork snapshot locks.
///
/// The outer `Mutex` guards the HashMap and is never held across `.await`.
/// The inner `AsyncMutex` is held by the snapshot inbound handler for the
/// full duration of a snapshot sequence (flush → inline drain → sign
/// manifest → upload) across multiple `.await`s, so it must be a tokio
/// mutex. The per-volume tick loop `try_lock`s the inner mutex before
/// running drain/GC/eviction and skips the volume for that tick if held.
///
/// The lock exists only to keep the coordinator's own background tick loop
/// off a volume mid-snapshot. Volume-actor commands are already serialised
/// through the actor channel, so intra-volume commands never race regardless
/// of this lock.
pub type SnapshotLockRegistry = Arc<Mutex<HashMap<PathBuf, Arc<AsyncMutex<()>>>>>;

/// Construct an empty `SnapshotLockRegistry`.
pub fn new_snapshot_lock_registry() -> SnapshotLockRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Get or create the per-fork snapshot lock for `fork_dir`.
pub fn snapshot_lock_for(
    registry: &SnapshotLockRegistry,
    fork_dir: &std::path::Path,
) -> Arc<AsyncMutex<()>> {
    let mut map = registry.lock().expect("snapshot lock registry poisoned");
    map.entry(fork_dir.to_owned())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// Per-fork prefetch state. `None` means prefetch is still running; `Some(Ok(()))`
/// means prefetch completed successfully; `Some(Err(_))` means prefetch failed and
/// the fork is not safe to open. Future-tense state lets late subscribers see the
/// terminal value via `Sender::subscribe()` without missing the publisher's send.
pub type PrefetchState = Option<Result<(), String>>;

/// Tracker exposing per-fork prefetch completion to the inbound IPC.
///
/// The tracker stores an `Arc<watch::Sender>` per ULID. Both the volume-
/// creating IPC handler (`fork_create_op` pre-registers before returning to
/// the CLI) and the daemon's discovery loop (which spawns
/// `run_volume_tasks`) obtain the same sender via [`register_prefetch_or_get`]
/// — whichever runs first inserts; the other gets the same handle. This
/// closes the race where the CLI's `await-prefetch` could hit the
/// "untracked → ok" path before the daemon registered the entry.
///
/// Subscribers obtain a fresh receiver via [`subscribe_prefetch`]
/// (`tx.subscribe()` under the lock).
///
/// The "task exited unexpectedly" signal is preserved by the per-fork task
/// removing its tracker entry on exit (via a Drop guard in
/// `run_volume_tasks`). When both the tracker's `Arc<Sender>` and the
/// task's local `Arc<Sender>` are dropped, the underlying watch channel
/// has no more senders, and pending subscribers' `changed().await`
/// returns `Err` — surfaced by the IPC as "task exited without
/// publishing a result".
pub type PrefetchTracker = Arc<Mutex<HashMap<Ulid, Arc<watch::Sender<PrefetchState>>>>>;

/// Construct an empty [`PrefetchTracker`].
pub fn new_prefetch_tracker() -> PrefetchTracker {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Idempotent: insert an entry for `vol_ulid` if absent, or return the
/// existing sender. Used both by `fork_create_op` (pre-registering on
/// volume creation, so the CLI's subsequent `await-prefetch` always finds
/// an entry) and by the daemon's first-time discovery — whichever path
/// runs first inserts; the other gets the same `Arc`.
pub fn register_prefetch_or_get(
    tracker: &PrefetchTracker,
    vol_ulid: Ulid,
) -> Arc<watch::Sender<PrefetchState>> {
    let mut guard = tracker.lock().expect("prefetch tracker poisoned");
    guard
        .entry(vol_ulid)
        .or_insert_with(|| {
            let (tx, _rx) = watch::channel(None);
            Arc::new(tx)
        })
        .clone()
}

/// Force-replace the entry for `vol_ulid`, returning the new sender. Used
/// on delete-and-recreate at the same ULID (inode-change rediscovery in
/// the daemon): any prior subscribers see the dropped previous sender via
/// `changed().await -> Err` and can retry.
pub fn replace_prefetch(
    tracker: &PrefetchTracker,
    vol_ulid: Ulid,
) -> Arc<watch::Sender<PrefetchState>> {
    let mut guard = tracker.lock().expect("prefetch tracker poisoned");
    let (tx, _rx) = watch::channel(None);
    let new = Arc::new(tx);
    guard.insert(vol_ulid, new.clone());
    new
}

/// Subscribe to the per-fork prefetch state. Returns `None` when the fork
/// is not tracked (caller treats this as "ready"), or a fresh receiver
/// pinned to the current state.
pub fn subscribe_prefetch(
    tracker: &PrefetchTracker,
    vol_ulid: &Ulid,
) -> Option<watch::Receiver<PrefetchState>> {
    tracker
        .lock()
        .expect("prefetch tracker poisoned")
        .get(vol_ulid)
        .map(|tx| tx.subscribe())
}

/// Remove the entry for `vol_ulid`. Called by the per-fork task on exit
/// (via a Drop guard in `run_volume_tasks`) so the tracker's
/// `Arc<Sender>` is released; combined with the task dropping its own
/// local `Arc<Sender>`, this leaves the watch channel with no senders
/// and unblocks pending subscribers with `changed() -> Err`.
pub fn unregister_prefetch(tracker: &PrefetchTracker, vol_ulid: &Ulid) {
    if let Ok(mut guard) = tracker.lock() {
        guard.remove(vol_ulid);
    }
}

/// Per-fork daemon-readiness flag.
///
/// `false` until the volume binary sends `NotifyVolumeReady` (i.e.
/// `Volume::open` succeeded and the control socket is bound), then
/// `true`. `start_volume_op` registers an entry before triggering
/// rescan and awaits the flip with a bounded timeout, so the IPC reply
/// doesn't lie about the daemon being ready to serve.
pub type ReadinessTracker = Arc<Mutex<HashMap<Ulid, Arc<watch::Sender<bool>>>>>;

/// Construct an empty [`ReadinessTracker`].
pub fn new_readiness_tracker() -> ReadinessTracker {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Insert (or fetch) the readiness sender for `vol_ulid`, resetting the
/// channel to `false`. Used by `start_volume_op` immediately before
/// kicking the supervisor — the reset is what makes a second start of a
/// previously-ready volume wait again rather than seeing the prior
/// `true`.
pub fn arm_readiness(tracker: &ReadinessTracker, vol_ulid: Ulid) -> Arc<watch::Sender<bool>> {
    let mut guard = tracker.lock().expect("readiness tracker poisoned");
    let sender = guard
        .entry(vol_ulid)
        .or_insert_with(|| {
            let (tx, _rx) = watch::channel(false);
            Arc::new(tx)
        })
        .clone();
    sender.send_replace(false);
    sender
}

/// Flip the readiness flag for `vol_ulid` to `true`. Idempotent;
/// creates the entry if absent so a notify that arrives before
/// `arm_readiness` (degenerate but possible if the order ever inverts)
/// still leaves a `true` for the subsequent subscriber.
pub fn signal_ready(tracker: &ReadinessTracker, vol_ulid: Ulid) {
    let mut guard = tracker.lock().expect("readiness tracker poisoned");
    guard
        .entry(vol_ulid)
        .or_insert_with(|| {
            let (tx, _rx) = watch::channel(true);
            Arc::new(tx)
        })
        .send_replace(true);
}

/// Subscribe to the per-fork readiness flag. Returns `None` if no
/// entry exists.
pub fn subscribe_readiness(
    tracker: &ReadinessTracker,
    vol_ulid: &Ulid,
) -> Option<watch::Receiver<bool>> {
    tracker
        .lock()
        .expect("readiness tracker poisoned")
        .get(vol_ulid)
        .map(|tx| tx.subscribe())
}

/// Remove the entry for `vol_ulid`. Called on volume teardown so the
/// channel doesn't outlive the fork.
pub fn unregister_readiness(tracker: &ReadinessTracker, vol_ulid: &Ulid) {
    if let Ok(mut guard) = tracker.lock() {
        guard.remove(vol_ulid);
    }
}

#[cfg(test)]
mod prefetch_tracker_tests {
    use super::*;

    fn vol() -> Ulid {
        Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap()
    }

    /// `register_prefetch_or_get` is idempotent: repeated calls for the
    /// same ULID return the *same* underlying sender. This is the
    /// invariant `fork_create_op` (pre-register) and the daemon's
    /// discovery path (post-register) rely on to converge on a single
    /// channel without races.
    #[test]
    fn register_prefetch_or_get_returns_same_sender_on_second_call() {
        let tracker = new_prefetch_tracker();
        let v = vol();
        let tx1 = register_prefetch_or_get(&tracker, v);
        let tx2 = register_prefetch_or_get(&tracker, v);
        assert!(
            Arc::ptr_eq(&tx1, &tx2),
            "second call must return the same Arc<Sender>"
        );
        // Sanity: a subscriber sees publishes through *either* handle.
        let mut rx = subscribe_prefetch(&tracker, &v).expect("entry must be registered");
        tx1.send_replace(Some(Ok(())));
        assert_eq!(rx.borrow_and_update().clone(), Some(Ok(())));
    }

    /// `replace_prefetch` deliberately abandons the previous channel:
    /// any pre-existing subscriber sees `changed().await -> Err` because
    /// the previous Arc<Sender> drops when the tracker entry is replaced.
    /// This is the inode-change rediscovery path in the daemon.
    #[tokio::test]
    async fn replace_prefetch_drops_previous_channel_for_subscribers() {
        let tracker = new_prefetch_tracker();
        let v = vol();
        let _tx1 = register_prefetch_or_get(&tracker, v);
        let mut rx = subscribe_prefetch(&tracker, &v).expect("entry must be registered");

        // Force-replace; drop the previous local Arc to ensure the
        // tracker held the only other reference.
        let _tx2 = replace_prefetch(&tracker, v);
        drop(_tx1);

        // Old subscriber: previous channel has no senders → Err.
        let result = rx.changed().await;
        assert!(result.is_err(), "previous subscriber must see Err");
    }

    /// `unregister_prefetch` drops the tracker's `Arc<Sender>`. Combined
    /// with the per-fork task dropping its own local Arc<Sender> (the
    /// `prefetch_done` parameter), pending subscribers see Err — the
    /// "task exited unexpectedly" signal.
    #[tokio::test]
    async fn unregister_prefetch_with_dropped_local_unblocks_subscribers() {
        let tracker = new_prefetch_tracker();
        let v = vol();
        let tx = register_prefetch_or_get(&tracker, v);
        let mut rx = subscribe_prefetch(&tracker, &v).expect("entry must be registered");

        unregister_prefetch(&tracker, &v);
        drop(tx);

        let result = rx.changed().await;
        assert!(result.is_err(), "subscriber must see Err after exit");
        // After unregister, late subscribers find no entry.
        assert!(subscribe_prefetch(&tracker, &v).is_none());
    }
}

#[cfg(test)]
mod readiness_tracker_tests {
    use super::*;

    fn vol() -> Ulid {
        Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAB").unwrap()
    }

    /// `arm_readiness` is idempotent on the channel identity (same
    /// `Arc<Sender>` per ULID), but resets the value to `false` —
    /// so a second start of a previously-ready volume waits again
    /// rather than seeing the prior `true`.
    #[tokio::test]
    async fn arm_resets_value_but_keeps_channel() {
        let tracker = new_readiness_tracker();
        let v = vol();
        let tx1 = arm_readiness(&tracker, v);
        tx1.send_replace(true);
        let mut rx = subscribe_readiness(&tracker, &v).expect("entry must be registered");
        assert!(*rx.borrow_and_update());

        let tx2 = arm_readiness(&tracker, v);
        assert!(Arc::ptr_eq(&tx1, &tx2), "arm must reuse the existing Arc");
        // The reset to false is visible to existing subscribers.
        rx.changed().await.expect("re-arm must publish a change");
        assert!(!*rx.borrow_and_update());
    }

    /// `signal_ready` flips the flag for subscribers waiting on
    /// `changed().await`. Mirrors the start→notify path.
    #[tokio::test]
    async fn signal_ready_unblocks_subscriber() {
        let tracker = new_readiness_tracker();
        let v = vol();
        arm_readiness(&tracker, v);
        let mut rx = subscribe_readiness(&tracker, &v).expect("entry must be registered");
        assert!(!*rx.borrow_and_update());

        signal_ready(&tracker, v);
        rx.changed().await.expect("signal_ready must publish");
        assert!(*rx.borrow_and_update());
    }

    /// `signal_ready` arriving before `arm_readiness` (degenerate but
    /// possible if the order ever inverts) still leaves a `true` flag
    /// for the subsequent subscriber — no signal is lost.
    #[tokio::test]
    async fn signal_before_arm_is_durable() {
        let tracker = new_readiness_tracker();
        let v = vol();
        signal_ready(&tracker, v);
        let mut rx = subscribe_readiness(&tracker, &v).expect("entry must exist after signal");
        assert!(*rx.borrow_and_update());
    }
}
