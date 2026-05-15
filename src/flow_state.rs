use crate::net::payload::BufferedPayload;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

pub(crate) struct FlowRuntimeState {
    locked: AtomicBool,
    last_seen_s: AtomicU64,
    upstream_reply_id_acked: AtomicBool,
    listener_reply_id_acked: AtomicBool,
    upstream_reply_id_handshake: Mutex<ReplyIdHandshake>,
    listener_reply_id_handshake: Mutex<ReplyIdHandshake>,
}

impl FlowRuntimeState {
    pub fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            last_seen_s: AtomicU64::new(0),
            upstream_reply_id_acked: AtomicBool::new(false),
            listener_reply_id_acked: AtomicBool::new(false),
            upstream_reply_id_handshake: Mutex::new(ReplyIdHandshake::NotRequired),
            listener_reply_id_handshake: Mutex::new(ReplyIdHandshake::NotRequired),
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
            *self.upstream_reply_id_handshake.lock().unwrap() = ReplyIdHandshake::NotRequired;
            *self.listener_reply_id_handshake.lock().unwrap() = ReplyIdHandshake::NotRequired;
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
    pub fn begin_upstream_reply_id_handshake(
        &self,
        expected_id: u16,
        started_s: u64,
        payload: BufferedPayload,
    ) -> bool {
        begin_handshake(
            &self.upstream_reply_id_handshake,
            self.upstream_reply_id_acked(),
            expected_id,
            started_s,
            payload,
        )
    }

    #[inline]
    pub fn begin_listener_reply_id_handshake(
        &self,
        expected_id: u16,
        started_s: u64,
        payload: BufferedPayload,
    ) -> bool {
        begin_handshake(
            &self.listener_reply_id_handshake,
            self.listener_reply_id_acked(),
            expected_id,
            started_s,
            payload,
        )
    }

    #[inline]
    pub fn ack_upstream_reply_id_handshake(&self, reply_id: u16) -> Option<BufferedPayload> {
        ack_handshake(&self.upstream_reply_id_handshake, reply_id, || {
            self.ack_upstream_reply_id()
        })
    }

    #[inline]
    pub fn ack_listener_reply_id_handshake(&self, reply_id: u16) -> Option<BufferedPayload> {
        ack_handshake(&self.listener_reply_id_handshake, reply_id, || {
            self.ack_listener_reply_id()
        })
    }

    #[inline]
    pub fn expire_reply_id_handshakes(&self, now_s: u64, timeout_s: u64) -> bool {
        let upstream_expired =
            expire_handshake(&self.upstream_reply_id_handshake, now_s, timeout_s);
        let listener_expired =
            expire_handshake(&self.listener_reply_id_handshake, now_s, timeout_s);
        upstream_expired || listener_expired
    }

    #[inline]
    pub fn reset(&self) {
        self.set_locked(false);
    }
}

enum ReplyIdHandshake {
    NotRequired,
    Pending {
        expected_id: u16,
        started_s: u64,
        payload: BufferedPayload,
    },
    Acked,
}

fn begin_handshake(
    state: &Mutex<ReplyIdHandshake>,
    already_acked: bool,
    expected_id: u16,
    started_s: u64,
    payload: BufferedPayload,
) -> bool {
    if already_acked || expected_id == 0 {
        return false;
    }
    let mut guard = state.lock().unwrap();
    if matches!(*guard, ReplyIdHandshake::Acked) {
        return false;
    }
    match *guard {
        ReplyIdHandshake::Pending { .. } => return true,
        ReplyIdHandshake::NotRequired => {
            *guard = ReplyIdHandshake::Pending {
                expected_id,
                started_s,
                payload,
            };
        }
        ReplyIdHandshake::Acked => return false,
    }
    true
}

fn ack_handshake(
    state: &Mutex<ReplyIdHandshake>,
    reply_id: u16,
    mark_acked: impl FnOnce(),
) -> Option<BufferedPayload> {
    let mut guard = state.lock().unwrap();
    match std::mem::replace(&mut *guard, ReplyIdHandshake::NotRequired) {
        ReplyIdHandshake::Pending {
            expected_id,
            payload,
            ..
        } if expected_id == reply_id => {
            *guard = ReplyIdHandshake::Acked;
            mark_acked();
            Some(payload)
        }
        other => {
            *guard = other;
            None
        }
    }
}

fn expire_handshake(state: &Mutex<ReplyIdHandshake>, now_s: u64, timeout_s: u64) -> bool {
    let mut guard = state.lock().unwrap();
    let expired = match &*guard {
        ReplyIdHandshake::Pending { started_s, .. } => {
            now_s.saturating_sub(*started_s) >= timeout_s
        }
        ReplyIdHandshake::NotRequired | ReplyIdHandshake::Acked => false,
    };
    if expired {
        *guard = ReplyIdHandshake::NotRequired;
    }
    expired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::SupportedProtocol;
    use crate::net::payload::PayloadEvent;

    fn buffered_payload(bytes: &'static [u8]) -> BufferedPayload {
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes);
        BufferedPayload::from_event(&event)
    }

    #[test]
    fn reply_id_handshake_buffers_until_matching_ack() {
        let state = FlowRuntimeState::new();
        assert!(state.begin_upstream_reply_id_handshake(2002, 1, buffered_payload(b"first")));
        assert!(state.ack_upstream_reply_id_handshake(3003).is_none());
        assert!(!state.upstream_reply_id_acked());

        let flushed = state
            .ack_upstream_reply_id_handshake(2002)
            .expect("matching ack flushes buffered payload");
        assert!(state.upstream_reply_id_acked());
        assert!(matches!(
            flushed.as_event(),
            PayloadEvent::UserPayload { data, .. } if data.bytes == b"first"
        ));
    }

    #[test]
    fn reply_id_handshake_timeout_drops_buffered_payload() {
        let state = FlowRuntimeState::new();
        assert!(state.begin_listener_reply_id_handshake(3003, 2, buffered_payload(b"first")));
        assert!(!state.expire_reply_id_handshakes(11, 10));
        assert!(state.expire_reply_id_handshakes(12, 10));
        assert!(state.ack_listener_reply_id_handshake(3003).is_none());
        assert!(!state.listener_reply_id_acked());
    }
}
