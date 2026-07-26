pub(crate) const NEVER_PACED: u64 = u64::MAX;

pub(crate) trait PacingAtomic {
    fn load_relaxed(&self) -> u64;
    fn compare_relaxed_weak(&self, current: u64, next: u64) -> Result<u64, u64>;
}

pub(crate) struct PacingCore<Atomic> {
    last_send_tick: Atomic,
}

impl<Atomic> PacingCore<Atomic> {
    pub(crate) const fn new(last_send_tick: Atomic) -> Self {
        Self { last_send_tick }
    }
}

impl<Atomic: PacingAtomic> PacingCore<Atomic> {
    #[inline]
    pub(crate) fn is_due(&self, now_tick: u64, interval_ticks: u64) -> bool {
        let previous = self.last_send_tick.load_relaxed();
        previous == NEVER_PACED || now_tick.saturating_sub(previous) >= interval_ticks
    }

    #[inline]
    pub(crate) fn try_claim(&self, now_tick: u64, interval_ticks: u64) -> bool {
        let mut previous = self.last_send_tick.load_relaxed();
        loop {
            if previous != NEVER_PACED && now_tick.saturating_sub(previous) < interval_ticks {
                return false;
            }
            match self.last_send_tick.compare_relaxed_weak(previous, now_tick) {
                Ok(_) => return true,
                Err(current) => previous = current,
            }
        }
    }

    #[cfg(all(test, not(miri), not(target_env = "musl")))]
    pub(crate) fn last_send_tick(&self) -> u64 {
        self.last_send_tick.load_relaxed()
    }
}
