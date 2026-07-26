use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

pub(crate) const SYNC_BEST_EFFORT_POLL_CAP: Duration = Duration::from_millis(5);

pub(crate) struct GlobalSyncPacer {
    base: Instant,
    interval: Duration,
    core: crate::atomic_core::PacingCore<
        crate::authority::AuthorityAtomic<crate::authority::tags::Pacing, AtomicU64>,
    >,
}

impl GlobalSyncPacer {
    #[inline]
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            base: Instant::now(),
            interval,
            core: crate::atomic_core::PacingCore::new(crate::authority::AuthorityAtomic::new_u64(
                crate::atomic_core::NEVER_PACED,
                crate::authority::AtomicProtocolId::PacingDeadline,
            )),
        }
    }

    #[inline]
    pub(crate) fn is_due(&self, now: Instant) -> bool {
        let now_ns = self.tick(now);
        self.core.is_due(now_ns, self.interval_ns())
    }

    #[inline]
    pub(crate) fn try_acquire_send(&self, now: Instant) -> bool {
        let now_ns = self.tick(now);
        self.core.try_claim(now_ns, self.interval_ns())
    }

    #[inline]
    fn tick(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.base)
            .as_nanos()
            .min(u64::MAX as u128) as u64
    }

    #[inline]
    fn interval_ns(&self) -> u64 {
        self.interval.as_nanos().min(u64::MAX as u128) as u64
    }

    #[inline]
    pub(crate) fn poll_wait(&self) -> Duration {
        self.interval.min(SYNC_BEST_EFFORT_POLL_CAP)
    }
}

#[cfg(test)]
mod tests;
