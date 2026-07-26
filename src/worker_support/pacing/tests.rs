use super::{GlobalSyncPacer, SYNC_BEST_EFFORT_POLL_CAP};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn global_sync_pacer_is_immediately_due_without_prior_send() {
    let now = Instant::now();
    let pacer = GlobalSyncPacer::new(Duration::from_millis(10));
    assert!(pacer.is_due(now));
    assert!(pacer.try_acquire_send(now));
    assert!(!pacer.is_due(now));
}

#[test]
fn global_sync_pacer_waits_for_interval_and_never_catches_up_more_than_once() {
    let pacer = GlobalSyncPacer::new(Duration::from_millis(100));
    let now = Instant::now();
    assert!(pacer.try_acquire_send(now));
    assert!(!pacer.try_acquire_send(now));
    assert!(!pacer.try_acquire_send(now + Duration::from_millis(99)));
    assert!(pacer.try_acquire_send(now + Duration::from_millis(100)));
}

#[test]
fn global_sync_pacer_poll_wait_is_bounded() {
    let pacer = GlobalSyncPacer::new(Duration::from_secs(1));
    assert_eq!(pacer.poll_wait(), SYNC_BEST_EFFORT_POLL_CAP);
    let short = GlobalSyncPacer::new(Duration::from_millis(2));
    assert_eq!(short.poll_wait(), Duration::from_millis(2));
}

#[test]
fn global_sync_pacer_allows_only_one_worker_per_interval() {
    let pacer = Arc::new(GlobalSyncPacer::new(Duration::from_millis(100)));
    let barrier = Arc::new(Barrier::new(8));
    let now = Instant::now();
    let mut joins = Vec::new();
    for _ in 0..8 {
        let pacer = Arc::clone(&pacer);
        let barrier = Arc::clone(&barrier);
        joins.push(thread::spawn(move || {
            barrier.wait();
            pacer.try_acquire_send(now)
        }));
    }
    let winners = joins
        .into_iter()
        .filter_map(|join| join.join().expect("join").then_some(()))
        .count();
    assert_eq!(winners, 1);
}
