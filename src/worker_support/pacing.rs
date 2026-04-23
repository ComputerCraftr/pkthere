use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

pub(crate) const SYNC_BEST_EFFORT_POLL_CAP: Duration = Duration::from_millis(5);

pub(crate) struct GlobalSyncPacer {
    base: Instant,
    interval: Duration,
    last_send_ns: AtomicU64,
}

impl GlobalSyncPacer {
    const NEVER_SENT: u64 = u64::MAX;

    #[inline]
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            base: Instant::now(),
            interval,
            last_send_ns: AtomicU64::new(Self::NEVER_SENT),
        }
    }

    #[inline]
    pub(crate) fn try_acquire_send(&self, now: Instant) -> bool {
        let now_ns = now
            .saturating_duration_since(self.base)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let interval_ns = self.interval.as_nanos().min(u64::MAX as u128) as u64;
        let mut prev = self.last_send_ns.load(AtomOrdering::Relaxed);
        loop {
            if prev != Self::NEVER_SENT && now_ns.saturating_sub(prev) < interval_ns {
                return false;
            }
            match self.last_send_ns.compare_exchange_weak(
                prev,
                now_ns,
                AtomOrdering::Relaxed,
                AtomOrdering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => prev = current,
            }
        }
    }

    #[inline]
    pub(crate) fn poll_wait(&self) -> Duration {
        self.interval.min(SYNC_BEST_EFFORT_POLL_CAP)
    }
}

#[cfg(test)]
mod tests {
    use super::{GlobalSyncPacer, SYNC_BEST_EFFORT_POLL_CAP};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn global_sync_pacer_is_immediately_due_without_prior_send() {
        let now = Instant::now();
        let pacer = GlobalSyncPacer::new(Duration::from_millis(10));
        assert!(pacer.try_acquire_send(now));
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
}
