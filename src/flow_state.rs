use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::payload::BufferedPayload;
use crate::packet_trace::PacketTraceId;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

pub(crate) struct FlowRuntimeState {
    locked: AtomicBool,
    last_seen_s: AtomicU64,
    upstream_reply_id_acked: AtomicBool,
    upstream_reply_id_handshake: Mutex<ReplyIdHandshake>,
    pending_icmp_client_lock: Mutex<Option<PendingIcmpClientLock>>,
}

impl FlowRuntimeState {
    pub fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            last_seen_s: AtomicU64::new(0),
            upstream_reply_id_acked: AtomicBool::new(false),
            upstream_reply_id_handshake: Mutex::new(ReplyIdHandshake::NotRequired),
            pending_icmp_client_lock: Mutex::new(None),
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
            *self.upstream_reply_id_handshake.lock().unwrap() = ReplyIdHandshake::NotRequired;
            *self.pending_icmp_client_lock.lock().unwrap() = None;
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
    pub fn ack_upstream_reply_id(&self) {
        self.upstream_reply_id_acked
            .store(true, AtomOrdering::Relaxed);
    }

    #[inline]
    pub fn begin_upstream_reply_id_handshake(
        &self,
        expected_ack_destination_id: u16,
        started_s: u64,
        payload: BufferedPayload,
    ) -> ReplyIdHandshakeBegin {
        begin_handshake(
            &self.upstream_reply_id_handshake,
            self.upstream_reply_id_acked(),
            expected_ack_destination_id,
            started_s,
            payload,
        )
    }

    #[inline]
    pub fn ack_upstream_reply_id_handshake(
        &self,
        observed_ack_destination_id: u16,
        trigger_trace: Option<PacketTraceId>,
    ) -> ReplyIdHandshakeAck {
        ack_handshake(
            &self.upstream_reply_id_handshake,
            observed_ack_destination_id,
            trigger_trace,
            || self.ack_upstream_reply_id(),
        )
    }

    #[inline]
    pub fn expire_reply_id_handshake(
        &self,
        now_s: u64,
        timeout_s: u64,
    ) -> Option<ExpiredReplyIdHandshake> {
        expire_handshake(&self.upstream_reply_id_handshake, now_s, timeout_s)
    }

    #[inline]
    pub fn reset(&self) -> Option<DroppedReplyIdHandshake> {
        let dropped = take_pending_handshake(&self.upstream_reply_id_handshake);
        self.set_locked(false);
        dropped
    }

    #[inline]
    pub(crate) fn pending_icmp_client_lock(&self) -> Option<PendingIcmpClientLock> {
        *self.pending_icmp_client_lock.lock().unwrap()
    }

    #[inline]
    pub(crate) fn set_pending_icmp_client_lock(
        &self,
        pending: PendingIcmpClientLock,
    ) -> Result<(), PendingIcmpClientLockMismatch> {
        let mut guard = self.pending_icmp_client_lock.lock().unwrap();
        match *guard {
            Some(existing) if existing != pending => Err(PendingIcmpClientLockMismatch),
            _ => {
                *guard = Some(pending);
                Ok(())
            }
        }
    }

    #[inline]
    pub(crate) fn clear_pending_icmp_client_lock(&self) {
        *self.pending_icmp_client_lock.lock().unwrap() = None;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingIcmpClientLock {
    pub(crate) flow_key: ClientFlowKey,
    pub(crate) listener_flow: SocketLegFlow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingIcmpClientLockMismatch;

enum ReplyIdHandshake {
    NotRequired,
    Pending {
        expected_ack_destination_id: u16,
        started_s: u64,
        payload: BufferedPayload,
    },
    Acked,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeBegin {
    Started {
        expected_ack_destination_id: u16,
        buffered_len: usize,
        buffered_trace: Option<PacketTraceId>,
    },
    PendingReused {
        expected_ack_destination_id: u16,
        started_s: u64,
        buffered_len: usize,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    Ignored,
}

impl ReplyIdHandshakeBegin {
    #[inline]
    pub(crate) const fn should_send_control(&self) -> bool {
        matches!(self, Self::Started { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeAckIgnored {
    NoPending {
        trigger_trace: Option<PacketTraceId>,
    },
    AlreadyAcked {
        trigger_trace: Option<PacketTraceId>,
    },
    WrongDestinationId {
        expected_ack_destination_id: u16,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeAck {
    Matched {
        expected_ack_destination_id: u16,
        payload: BufferedPayload,
        trigger_trace: Option<PacketTraceId>,
    },
    Ignored(ReplyIdHandshakeAckIgnored),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredReplyIdHandshake {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) started_s: u64,
    pub(crate) buffered_len: usize,
    pub(crate) buffered_trace: Option<PacketTraceId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DroppedReplyIdHandshake {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) buffered_len: usize,
    pub(crate) buffered_trace: Option<PacketTraceId>,
}

fn begin_handshake(
    state: &Mutex<ReplyIdHandshake>,
    already_acked: bool,
    expected_ack_destination_id: u16,
    started_s: u64,
    payload: BufferedPayload,
) -> ReplyIdHandshakeBegin {
    if already_acked || expected_ack_destination_id == 0 {
        return ReplyIdHandshakeBegin::Ignored;
    }
    let mut guard = state.lock().unwrap();
    if matches!(*guard, ReplyIdHandshake::Acked) {
        return ReplyIdHandshakeBegin::Ignored;
    }
    match *guard {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id: old_expected_ack_destination_id,
            started_s: old_started_s,
            payload: ref old_payload,
        } => ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id: old_expected_ack_destination_id,
            started_s: old_started_s,
            buffered_len: old_payload.payload_len(),
            buffered_trace: old_payload.trace(),
            trigger_trace: payload.trace(),
        },
        ReplyIdHandshake::NotRequired => {
            let buffered_len = payload.payload_len();
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                started_s,
                payload,
            };
            ReplyIdHandshakeBegin::Started {
                expected_ack_destination_id,
                buffered_len,
                buffered_trace,
            }
        }
        ReplyIdHandshake::Acked => ReplyIdHandshakeBegin::Ignored,
    }
}

fn ack_handshake(
    state: &Mutex<ReplyIdHandshake>,
    observed_ack_destination_id: u16,
    trigger_trace: Option<PacketTraceId>,
    mark_acked: impl FnOnce(),
) -> ReplyIdHandshakeAck {
    let mut guard = state.lock().unwrap();
    match std::mem::replace(&mut *guard, ReplyIdHandshake::NotRequired) {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            payload,
            ..
        } if expected_ack_destination_id == observed_ack_destination_id => {
            *guard = ReplyIdHandshake::Acked;
            mark_acked();
            ReplyIdHandshakeAck::Matched {
                expected_ack_destination_id,
                payload,
                trigger_trace,
            }
        }
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            payload,
            started_s,
        } => {
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                payload,
                started_s,
            };
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id,
                buffered_trace,
                trigger_trace,
            })
        }
        ReplyIdHandshake::Acked => {
            *guard = ReplyIdHandshake::Acked;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { trigger_trace })
        }
        ReplyIdHandshake::NotRequired => {
            *guard = ReplyIdHandshake::NotRequired;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::NoPending { trigger_trace })
        }
    }
}

fn expire_handshake(
    state: &Mutex<ReplyIdHandshake>,
    now_s: u64,
    timeout_s: u64,
) -> Option<ExpiredReplyIdHandshake> {
    let mut guard = state.lock().unwrap();
    let expired = match &*guard {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            started_s,
            payload,
        } if now_s.saturating_sub(*started_s) >= timeout_s => Some(ExpiredReplyIdHandshake {
            expected_ack_destination_id: *expected_ack_destination_id,
            started_s: *started_s,
            buffered_len: payload.payload_len(),
            buffered_trace: payload.trace(),
        }),
        ReplyIdHandshake::Pending { .. }
        | ReplyIdHandshake::NotRequired
        | ReplyIdHandshake::Acked => None,
    };
    if expired.is_some() {
        *guard = ReplyIdHandshake::NotRequired;
    }
    expired
}

fn take_pending_handshake(state: &Mutex<ReplyIdHandshake>) -> Option<DroppedReplyIdHandshake> {
    let mut guard = state.lock().unwrap();
    let previous = std::mem::replace(&mut *guard, ReplyIdHandshake::NotRequired);
    match previous {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            payload,
            ..
        } => Some(DroppedReplyIdHandshake {
            expected_ack_destination_id,
            buffered_len: payload.payload_len(),
            buffered_trace: payload.trace(),
        }),
        ReplyIdHandshake::NotRequired | ReplyIdHandshake::Acked => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BufferedPayload, FlowRuntimeState, ReplyIdHandshakeAck, ReplyIdHandshakeAckIgnored,
        ReplyIdHandshakeBegin,
    };
    use crate::cli::SupportedProtocol;
    use crate::net::payload::PayloadEvent;
    use crate::packet_trace::PacketTraceId;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn buffered_payload(bytes: &'static [u8]) -> BufferedPayload {
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes);
        BufferedPayload::from_event(&event, None)
    }

    fn traced_payload(bytes: &'static [u8], packet_id: u64) -> BufferedPayload {
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes);
        BufferedPayload::from_event(
            &event,
            Some(PacketTraceId {
                worker_id: 2,
                c2u: true,
                packet_id,
            }),
        )
    }

    #[test]
    fn reply_id_handshake_buffers_until_matching_ack() {
        let state = FlowRuntimeState::new();
        assert_eq!(
            state.begin_upstream_reply_id_handshake(2002, 1, buffered_payload(b"first")),
            ReplyIdHandshakeBegin::Started {
                expected_ack_destination_id: 2002,
                buffered_len: 5,
                buffered_trace: None,
            }
        );
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(3003, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id: 2002,
                ..
            })
        ));
        assert!(!state.upstream_reply_id_acked());
        assert!(!state.is_locked());

        let ReplyIdHandshakeAck::Matched {
            payload: flushed, ..
        } = state.ack_upstream_reply_id_handshake(2002, None)
        else {
            panic!("matching ack must flush buffered payload");
        };
        assert!(state.upstream_reply_id_acked());
        assert!(matches!(
            flushed.as_event(),
            PayloadEvent::UserPayload { bytes, .. } if bytes == b"first"
        ));
    }

    #[test]
    fn reply_id_handshake_preserves_zero_length_first_payload_until_ack() {
        let state = FlowRuntimeState::new();
        assert!(matches!(
            state.begin_upstream_reply_id_handshake(2002, 1, buffered_payload(b"")),
            ReplyIdHandshakeBegin::Started {
                buffered_len: 0,
                ..
            }
        ));
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(3003, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId { .. })
        ));
        assert!(!state.upstream_reply_id_acked());

        let ReplyIdHandshakeAck::Matched {
            payload: flushed, ..
        } = state.ack_upstream_reply_id_handshake(2002, None)
        else {
            panic!("matching ack must flush zero-length buffered payload");
        };
        assert!(matches!(
            flushed.as_event(),
            PayloadEvent::UserPayload { bytes, .. } if bytes.is_empty()
        ));
    }

    #[test]
    fn reply_id_handshake_timeout_drops_buffered_payload() {
        let state = FlowRuntimeState::new();
        assert!(matches!(
            state.begin_upstream_reply_id_handshake(3003, 2, buffered_payload(b"first")),
            ReplyIdHandshakeBegin::Started { .. }
        ));
        assert_eq!(state.expire_reply_id_handshake(11, 10), None);
        assert_eq!(
            state.expire_reply_id_handshake(12, 10),
            Some(super::ExpiredReplyIdHandshake {
                expected_ack_destination_id: 3003,
                started_s: 2,
                buffered_len: 5,
                buffered_trace: None,
            })
        );
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(3003, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::NoPending { .. })
        ));
        assert!(!state.upstream_reply_id_acked());
    }

    #[test]
    fn handshake_preserves_origin_trace_through_ack_and_timeout() {
        let state = FlowRuntimeState::new();
        state.begin_upstream_reply_id_handshake(3003, 2, traced_payload(b"ack", 41));
        let ReplyIdHandshakeAck::Matched { payload, .. } =
            state.ack_upstream_reply_id_handshake(3003, None)
        else {
            panic!("matching ACK must release payload");
        };
        assert_eq!(payload.trace().map(|trace| trace.packet_id), Some(41));

        let state = FlowRuntimeState::new();
        state.begin_upstream_reply_id_handshake(3003, 2, traced_payload(b"timeout", 42));
        let expired = state
            .expire_reply_id_handshake(12, 10)
            .expect("handshake expires");
        assert_eq!(
            expired.buffered_trace.map(|trace| trace.packet_id),
            Some(42)
        );
    }

    #[test]
    fn reply_id_handshake_preserves_first_payload_while_pending() {
        let state = FlowRuntimeState::new();
        let started = state.begin_upstream_reply_id_handshake(2002, 1, buffered_payload(b"first"));
        assert!(matches!(started, ReplyIdHandshakeBegin::Started { .. }));
        assert!(started.should_send_control());

        let reused = state.begin_upstream_reply_id_handshake(2002, 2, buffered_payload(b"second"));
        assert!(matches!(
            reused,
            ReplyIdHandshakeBegin::PendingReused {
                expected_ack_destination_id: 2002,
                started_s: 1,
                buffered_len: 5,
                ..
            }
        ));
        assert!(!reused.should_send_control());

        let ReplyIdHandshakeAck::Matched { payload, .. } =
            state.ack_upstream_reply_id_handshake(2002, None)
        else {
            panic!("matching ack must flush the first payload");
        };
        assert!(matches!(
            payload.as_event(),
            PayloadEvent::UserPayload { bytes, .. } if bytes == b"first"
        ));
    }

    #[test]
    fn concurrent_handshake_burst_emits_one_control_and_flushes_once() {
        const BURST_SIZE: usize = 16;
        const EXPECTED_ACK_ID: u16 = 2002;

        let state = Arc::new(FlowRuntimeState::new());
        let barrier = Arc::new(Barrier::new(BURST_SIZE));
        let workers = (0..BURST_SIZE)
            .map(|index| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let bytes = format!("burst-payload-{index}").into_bytes();
                    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, &bytes);
                    let payload = BufferedPayload::from_event(&event, None);
                    barrier.wait();
                    state.begin_upstream_reply_id_handshake(
                        EXPECTED_ACK_ID,
                        index as u64 + 1,
                        payload,
                    )
                })
            })
            .collect::<Vec<_>>();

        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("join handshake burst worker"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReplyIdHandshakeBegin::Started { .. }))
                .count(),
            1,
            "exactly one burst payload must own the pending handshake"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.should_send_control())
                .count(),
            1,
            "a pending burst must emit exactly one negotiation control frame"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReplyIdHandshakeBegin::PendingReused { .. }))
                .count(),
            BURST_SIZE - 1
        );

        assert!(matches!(
            state.ack_upstream_reply_id_handshake(EXPECTED_ACK_ID + 1, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId { .. })
        ));
        assert!(!state.upstream_reply_id_acked());

        let ReplyIdHandshakeAck::Matched { payload, .. } =
            state.ack_upstream_reply_id_handshake(EXPECTED_ACK_ID, None)
        else {
            panic!("matching ACK must flush the one preserved burst payload");
        };
        let PayloadEvent::UserPayload { bytes, .. } = payload.as_event() else {
            panic!("buffered burst payload must remain user data");
        };
        assert!(
            (0..BURST_SIZE).any(|index| bytes == format!("burst-payload-{index}").as_bytes()),
            "flushed payload must be the exact bytes from one burst sender"
        );
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(EXPECTED_ACK_ID, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { .. })
        ));
    }

    #[test]
    fn reply_id_handshake_reports_ack_after_completion_as_already_acked() {
        let state = FlowRuntimeState::new();
        assert!(matches!(
            state.begin_upstream_reply_id_handshake(2002, 1, buffered_payload(b"first")),
            ReplyIdHandshakeBegin::Started { .. }
        ));
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(2002, None),
            ReplyIdHandshakeAck::Matched { .. }
        ));
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(2002, None),
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { .. })
        ));
    }
}
