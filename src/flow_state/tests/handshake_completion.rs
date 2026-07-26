use super::{
    BufferedPayload, FlowRuntimeState, PacketTraceId, PayloadEvent, ReplyIdHandshakeAck,
    ReplyIdHandshakeAckIgnored, ReplyIdHandshakeBegin, SessionId, SessionKey, SupportedProtocol,
    ack_for_test, buffered_payload, pending_client_lock,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

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

    let active_instance = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ReplyIdHandshakeBegin::Started { instance, .. } => Some(*instance),
            _ => None,
        })
        .expect("one burst sender owns the handshake instance");

    assert!(matches!(
        ack_for_test(&state, EXPECTED_ACK_ID + 1, active_instance),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId { .. })
    ));
    assert!(!state.upstream_reply_id_acked());

    let ReplyIdHandshakeAck::Matched { token, .. } =
        ack_for_test(&state, EXPECTED_ACK_ID, active_instance)
    else {
        panic!("matching ACK must flush the one preserved burst payload");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching burst ACK leases the preserved payload");
    let PayloadEvent::UserPayload { bytes, .. } = payload.as_event() else {
        panic!("buffered burst payload must remain user data");
    };
    assert!(
        (0..BURST_SIZE).any(|index| bytes == format!("burst-payload-{index}").as_bytes()),
        "flushed payload must be the exact bytes from one burst sender"
    );
    assert!(matches!(
        ack_for_test(&state, EXPECTED_ACK_ID, active_instance),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::CommitInProgress { .. })
    ));
}

#[test]
fn reply_id_handshake_reports_ack_after_completion_as_already_acked() {
    const INSTANCE: u64 = 23;
    let state = FlowRuntimeState::new();
    assert!(matches!(
        state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"first")),
        ReplyIdHandshakeBegin::Started { .. }
    ));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("matching ACK enters commit");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching send lease");
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(payload)
            .expect("matching send lease")
    );
    assert!(matches!(
        ack_for_test(&state, 2002, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { .. })
    ));
}

#[test]
fn old_session_ack_cannot_complete_reused_ids() {
    const CURRENT_INSTANCE: u64 = 31;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(
        2002,
        CURRENT_INSTANCE,
        1,
        buffered_payload(b"current"),
    );

    assert!(matches!(
        ack_for_test(&state, 2002, CURRENT_INSTANCE - 1),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongInstance {
            expected_instance: CURRENT_INSTANCE,
            observed_instance: 30,
            ..
        })
    ));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, CURRENT_INSTANCE)
    else {
        panic!("current handshake instance must still be pending");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("current ACK leases current payload");
    assert!(matches!(
        payload.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"current"
    ));
}

#[test]
fn full_session_key_prevents_stale_generation_ack_with_reused_session_id() {
    let state = FlowRuntimeState::new();
    let session_id = SessionId::new(31).expect("test session");
    let current_key = SessionKey::new(2, 0, session_id).expect("current key");
    let stale_key = SessionKey::new(1, 0, session_id).expect("stale key");
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        current_key,
        1,
        Instant::now() + Duration::from_secs(10),
        buffered_payload(b"current"),
    );
    let lease = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("current negotiation lease");
    state
        .record_upstream_negotiation_sequence(&lease, 7)
        .expect("record sent negotiation");

    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(2002, stale_key, 7, 0, Instant::now(), None,),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongInstance { .. })
    ));
    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(2002, current_key, 7, 0, Instant::now(), None,),
        ReplyIdHandshakeAck::Matched { .. }
    ));
}
#[test]
fn send_failure_retries_from_internal_state_without_duplicate_ack() {
    const INSTANCE: u64 = 33;
    let state = FlowRuntimeState::new();
    let (buffered, initial_copies) =
        crate::allocation_test_support::count_payload_copies(|| buffered_payload(b"retry-send"));
    assert_eq!(initial_copies, 1);
    let retained_storage = buffered.clone();
    let (_, handshake_store_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered)
    });
    assert_eq!(handshake_store_copies, 0);
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("ACK starts commit");
    };
    let first_attempt = state
        .commit_upstream_reply_id_handshake(token)
        .expect("commit retains the buffered payload");
    assert_eq!(first_attempt.payload_len(), b"retry-send".len());
    assert!(matches!(
        ack_for_test(&state, 2002, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::CommitInProgress { .. })
    ));
    let (released, failure_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .release_upstream_reply_id_payload_send(first_attempt)
            .expect("failed send releases the exclusive reservation")
    });
    assert!(!released);
    assert_eq!(failure_copies, 0);
    assert!(matches!(
        ack_for_test(&state, 2002, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { .. })
    ));

    let (retry, retry_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .lease_due_upstream_reply_id_payload(Instant::now() + Duration::from_secs(1))
            .expect("internal retry leases the retained payload")
    });
    assert_eq!(retry_copies, 0);
    assert!(retry.payload().shares_payload_storage(&retained_storage));
    assert!(matches!(
        retry.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"retry-send"
    ));
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(retry)
            .expect("retry owns matching send lease")
    );
}

#[test]
fn unlocked_pending_client_negotiation_expires_without_deadline_refresh() {
    let state = FlowRuntimeState::new();
    let candidate = pending_client_lock();
    let first_trace = PacketTraceId {
        worker_id: 0,
        c2u: true,
        packet_id: 1,
    };
    let duplicate_trace = PacketTraceId {
        packet_id: 2,
        ..first_trace
    };
    assert_eq!(
        state
            .set_pending_icmp_client_lock(candidate, 2, first_trace, 7)
            .expect("first negotiation"),
        super::PendingIcmpClientLockSet::Started
    );
    assert_eq!(
        state
            .set_pending_icmp_client_lock(candidate, 9, duplicate_trace, 8)
            .expect("duplicate negotiation"),
        super::PendingIcmpClientLockSet::Reused
    );
    assert!(!state.is_locked());

    let expired = state
        .expire_pending_icmp_client_lock(Instant::now() + Duration::from_secs(11))
        .expect("original pending deadline expires while unlocked");
    assert_eq!(expired.started_s, 2);
    assert_eq!(expired.trace, first_trace);
    assert_eq!(state.pending_icmp_client_lock(), None);
}

#[test]
fn only_the_exact_pending_client_control_transaction_can_delay_expiry() {
    const EXPECTED_SEQUENCE: u16 = 17;
    let exercise = |observed_sequence, should_block| {
        let state = FlowRuntimeState::new();
        let candidate = pending_client_lock();
        let inbound = candidate
            .listener_flow
            .inbound
            .expect("test pending flow has an inbound tuple");
        let observed_at = Instant::now();
        let deadline = observed_at + Duration::from_millis(10);
        state
            .set_pending_icmp_client_lock_until(
                candidate,
                1,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 1,
                },
                EXPECTED_SEQUENCE,
                observed_at,
                deadline,
            )
            .expect("install exact pending client transaction");
        let observation = state
            .reserve_control_observation(0, state.flow_epoch(), true)
            .expect("reserve control observation")
            .observe(observed_at)
            .finish(Some(super::ControlTransactionKey::new(
                state.flow_epoch(),
                true,
                Some(candidate.flow_key),
                crate::net::payload::IcmpPayloadMeta::new_control(
                    inbound.src.id(),
                    inbound.dst.id(),
                    observed_sequence,
                    candidate
                        .full_observed_control()
                        .expect("pending ICMP candidate carries its observed control"),
                ),
            )))
            .expect("publish observed transaction")
            .expect("control observation remains owned through disposition");
        let expired = state.expire_pending_icmp_client_lock(deadline + Duration::from_nanos(1));
        assert_eq!(
            expired.is_none(),
            should_block,
            "only a complete matching control transaction may delay expiry"
        );
        drop(observation);
        if should_block {
            assert!(
                state
                    .expire_pending_icmp_client_lock(Instant::now() + Duration::from_secs(1))
                    .is_some(),
                "releasing the exact observation permits expiry"
            );
        }
    };

    exercise(EXPECTED_SEQUENCE + 1, false);
    exercise(EXPECTED_SEQUENCE, true);
}
