use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

pub struct FlowRuntimeState {
    locked: AtomicBool,
    last_seen_s: AtomicU64,
}

impl FlowRuntimeState {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            last_seen_s: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(AtomOrdering::Relaxed)
    }

    #[inline]
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, AtomOrdering::Relaxed);
        if !locked {
            self.last_seen_s.store(0, AtomOrdering::Relaxed);
        }
    }

    #[inline]
    pub fn record_activity(&self, t_start: Instant, t_recv: Instant) {
        let last_seen = t_recv.saturating_duration_since(t_start).as_secs().max(1);
        self.last_seen_s.store(last_seen, AtomOrdering::Relaxed);
    }

    #[inline]
    pub fn last_seen_s(&self) -> u64 {
        self.last_seen_s.load(AtomOrdering::Relaxed)
    }

    #[inline]
    pub fn reset(&self) {
        self.set_locked(false);
    }
}
