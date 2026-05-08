use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

pub(crate) struct FlowRuntimeState {
    locked: AtomicBool,
    last_seen_s: AtomicU64,
    upstream_reply_id_acked: AtomicBool,
    listener_reply_id_acked: AtomicBool,
}

impl FlowRuntimeState {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            last_seen_s: AtomicU64::new(0),
            upstream_reply_id_acked: AtomicBool::new(false),
            listener_reply_id_acked: AtomicBool::new(false),
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
            self.upstream_reply_id_acked
                .store(false, AtomOrdering::Relaxed);
            self.listener_reply_id_acked
                .store(false, AtomOrdering::Relaxed);
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
    pub fn upstream_reply_id_acked(&self) -> bool {
        self.upstream_reply_id_acked.load(AtomOrdering::Relaxed)
    }

    #[inline]
    pub fn listener_reply_id_acked(&self) -> bool {
        self.listener_reply_id_acked.load(AtomOrdering::Relaxed)
    }

    #[inline]
    pub fn ack_upstream_reply_id(&self) {
        self.upstream_reply_id_acked
            .store(true, AtomOrdering::Relaxed);
    }

    #[inline]
    pub fn ack_listener_reply_id(&self) {
        self.listener_reply_id_acked
            .store(true, AtomOrdering::Relaxed);
    }

    #[inline]
    pub fn reset(&self) {
        self.set_locked(false);
    }
}
