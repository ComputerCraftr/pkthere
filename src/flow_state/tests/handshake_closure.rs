use super::{
    Duration, FlowRuntimeState, Instant, PayloadEvent, ReplyIdHandshakeAck,
    ReplyIdHandshakeAckIgnored, SessionId, SessionKey, ack_for_test, buffered_payload,
    pending_client_lock, thread,
};
use std::sync::Arc;

#[test]
fn delayed_ack_cancels_an_unsequenced_retry_without_reporting_lease_corruption() {
    const INSTANCE: u64 = 0xbeef;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"first"));
    let first_due = Instant::now();
    let first = state
        .lease_due_upstream_reply_id_negotiation(first_due)
        .expect("first negotiation lease");
    state
        .record_upstream_negotiation_sequence(&first, 7)
        .expect("record first negotiation sequence");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(first, 7, true, first_due),
        super::ReplyIdControlSendCompletion::RetryScheduled
    );

    let retry = state
        .lease_due_upstream_reply_id_negotiation(first_due + Duration::from_secs(1))
        .expect("retry lease");
    let ReplyIdHandshakeAck::Matched { .. } =
        state.ack_upstream_reply_id_handshake(2002, INSTANCE, 7, None)
    else {
        panic!("the delayed ACK for the sent attempt must advance the handshake");
    };

    assert_eq!(
        state
            .record_upstream_negotiation_sequence(&retry, 8)
            .expect("an ACK-winning retry race is not ownership corruption"),
        crate::flow_state::ReplyIdControlSequenceRecord::HandshakeAdvanced
    );
}

#[test]
fn corrupted_pending_control_identity_fails_before_leasing_or_mutating_retry_state() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    state.begin_upstream_reply_id_handshake(2002, 41, 1, buffered_payload(b"pending"));
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.control.upstream_pending_key = None;
    }

    assert!(
        state
            .try_lease_due_upstream_reply_id_negotiation(now + Duration::from_secs(1))
            .is_err()
    );
    let sessions = state.sessions.lock().unwrap();
    let super::ReplyIdHandshake::Pending { control, .. } =
        &sessions.control.upstream_reply_id_handshake
    else {
        panic!("handshake remains pending");
    };
    assert!(!control.in_flight());
}

#[test]
fn duplicate_sent_control_accounting_is_an_invariant_error_not_stale_traffic() {
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(2002, 42, 1, buffered_payload(b"pending"));
    let now = Instant::now();
    let lease = state
        .try_lease_due_upstream_reply_id_negotiation(now)
        .expect("coherent lease result")
        .expect("due control lease");
    state
        .record_upstream_negotiation_sequence(&lease, 17)
        .expect("record in-flight sequence");
    assert_eq!(
        state
            .try_complete_upstream_reply_id_negotiation_send(lease, 17, true, now)
            .expect("first send completion"),
        super::ReplyIdControlSendCompletion::RetryScheduled
    );
    let retry = state
        .try_lease_due_upstream_reply_id_negotiation(now + Duration::from_secs(1))
        .expect("coherent retry lease")
        .expect("retry is due");
    assert_eq!(
        state.record_upstream_negotiation_sequence(&retry, 17),
        Err(super::ReplyIdHandshakeInvariantError)
    );
}

#[test]
fn manager_failure_rollback_keeps_payload_retryable() {
    const INSTANCE: u64 = 32;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"retry"));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("ACK starts transactional commit");
    };
    let (rollback, allocations) = crate::allocation_test_support::count_allocations(|| {
        state.rollback_upstream_reply_id_handshake(token, Instant::now())
    });
    rollback.expect("matching rollback token");
    assert_eq!(
        allocations, 0,
        "rollback must retain the transaction-owned control storage"
    );

    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("rolled-back handshake must accept a later ACK");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("rolled-back ACK leases payload");
    assert!(matches!(
        payload.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"retry"
    ));
}

#[test]
fn initial_ack_uses_packet_observation_time_and_preserves_expired_state() {
    let state = FlowRuntimeState::new();
    let session = SessionId::new(34).expect("test session");
    let key = SessionKey::initial(session).expect("test session reserves a response identity");
    let lease_time = Instant::now();
    let initial_deadline = lease_time + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        initial_deadline,
        buffered_payload(b"deadline"),
    );
    let lease_time = Instant::now();
    let lease = state
        .lease_due_upstream_reply_id_negotiation(lease_time)
        .expect("negotiation before deadline");
    state
        .record_upstream_negotiation_sequence(&lease, 7)
        .expect("record negotiation");
    state.complete_upstream_reply_id_negotiation_send(lease, 7, true, lease_time);
    let deadline = Instant::now() - Duration::from_secs(1);
    let mut sessions = state.sessions.lock().unwrap();
    let super::ReplyIdHandshake::Pending {
        absolute_deadline, ..
    } = &mut sessions.control.upstream_reply_id_handshake
    else {
        panic!("test handshake remains pending");
    };
    *absolute_deadline = deadline;
    drop(sessions);

    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(2002, key, 7, 0, deadline, None),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::Expired { .. })
    ));
    assert!(
        matches!(
            state.ack_upstream_reply_id_handshake_key(
                2002,
                key,
                7,
                0,
                deadline - Duration::from_nanos(1),
                None,
            ),
            ReplyIdHandshakeAck::Matched { .. }
        ),
        "an ACK observed before the deadline remains valid when processed later"
    );
}

#[test]
fn initial_control_cannot_be_leased_at_its_deadline() {
    let state = FlowRuntimeState::new();
    let session = SessionId::new(35).expect("test session");
    let now = Instant::now();
    let deadline = now + Duration::from_millis(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        SessionKey::initial(session).expect("test session reserves a response identity"),
        1,
        deadline,
        buffered_payload(b"deadline"),
    );

    assert!(
        state
            .lease_due_upstream_reply_id_negotiation(deadline)
            .is_none()
    );
}

#[test]
fn stale_commit_and_rollback_tokens_are_typed_errors() {
    let state = FlowRuntimeState::new();
    assert!(matches!(
        state.commit_upstream_reply_id_handshake(super::ReplyIdHandshakeCommitToken {
            instance: 99
        }),
        Err(super::ReplyIdHandshakeTransitionError::InvalidPhase)
    ));
    assert!(matches!(
        state.rollback_upstream_reply_id_handshake(
            super::ReplyIdHandshakeCommitToken { instance: 99 },
            Instant::now(),
        ),
        Err(super::ReplyIdHandshakeTransitionError::InvalidPhase)
    ));
}

#[test]
fn pre_deadline_receive_observation_prevents_maintenance_reclamation() {
    let state = FlowRuntimeState::new();
    let session = SessionId::new(36).expect("session");
    let key = SessionKey::initial(session).expect("test session reserves a response identity");
    let deadline = Instant::now() + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        deadline,
        buffered_payload(b"observed-before-expiry"),
    );
    let observed_at = Instant::now();
    let lease = state
        .lease_due_upstream_reply_id_negotiation(observed_at)
        .expect("control lease before deadline");
    state
        .record_upstream_negotiation_sequence(&lease, 9)
        .expect("record control sequence");
    state.complete_upstream_reply_id_negotiation_send(lease, 9, true, observed_at);
    let expired_deadline = Instant::now() - Duration::from_nanos(1);
    let mut sessions = state.sessions.lock().unwrap();
    let super::ReplyIdHandshake::Pending {
        absolute_deadline, ..
    } = &mut sessions.control.upstream_reply_id_handshake
    else {
        panic!("test handshake remains pending");
    };
    *absolute_deadline = expired_deadline;
    drop(sessions);

    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve received packet")
        .observe(observed_at)
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            false,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                2002,
                2002,
                9,
                crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(
                    crate::net::framing_shim::ReplyIdNegotiation::acknowledge_key_and_challenge(
                        2002, key, 0,
                    )
                    .expect("valid ACK metadata"),
                ),
            ),
        )))
        .expect("announce exact received packet")
        .expect("pre-deadline ACK needs a control observation");
    assert_eq!(
        state.expire_reply_id_handshake(expired_deadline + Duration::from_secs(1)),
        None
    );
    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(2002, key, 9, 0, observed_at, None),
        ReplyIdHandshakeAck::Matched { .. }
    ));
    drop(observation);
}

#[test]
fn pre_deadline_observation_is_reserved_before_waiting_for_session_state() {
    let state = Arc::new(FlowRuntimeState::new());
    let session = SessionId::new(40).expect("session");
    let key = SessionKey::initial(session).expect("test session reserves a response identity");
    let deadline = Instant::now() + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        deadline,
        buffered_payload(b"mutex-contention"),
    );
    let observed_at = Instant::now();
    let lease = state
        .lease_due_upstream_reply_id_negotiation(observed_at)
        .expect("control lease before session mutex contention");
    state
        .record_upstream_negotiation_sequence(&lease, 9)
        .expect("record control sequence before receive");
    state.complete_upstream_reply_id_negotiation_send(lease, 9, true, observed_at);
    let sessions = state.sessions.lock().unwrap();
    let (guard_ready_tx, guard_ready_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let receiver_state = Arc::clone(&state);
    let receiver = thread::spawn(move || {
        let observation = receiver_state
            .reserve_control_observation(0, receiver_state.flow_epoch(), false)
            .expect("reserve pre-deadline receive")
            .observe(observed_at)
            .finish(Some(super::ControlTransactionKey::new(
                receiver_state.flow_epoch(),
                false,
                None,
                crate::net::payload::IcmpPayloadMeta::new_control(
                    2002,
                    2002,
                    9,
                    crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(
                        crate::net::framing_shim::ReplyIdNegotiation::acknowledge_key_and_challenge(
                            2002, key, 0,
                        )
                        .expect("valid ACK metadata"),
                    ),
                ),
            )))
            .expect("publish exact received transaction")
            .expect("pre-deadline packet has timed state");
        guard_ready_tx
            .send(())
            .expect("publish acquired observation guard");
        release_rx.recv().expect("release observation guard");
        drop(observation);
    });

    let count_deadline = Instant::now() + Duration::from_secs(1);
    while state.control_observation_count_for_tests() == 0 && Instant::now() < count_deadline {
        thread::yield_now();
    }
    assert_eq!(
        state.control_observation_count_for_tests(),
        1,
        "the receive announces itself before waiting for the session mutex"
    );
    drop(sessions);
    guard_ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("receive observation guard before deadline");
    assert_eq!(
        state.expire_reply_id_handshake(deadline + Duration::from_secs(1)),
        None,
        "maintenance cannot reclaim state while the received packet is classified"
    );
    release_tx.send(()).expect("release receive observation");
    receiver.join().expect("join receive observer");
    assert!(
        state
            .expire_reply_id_handshake(deadline + Duration::from_secs(1))
            .is_some(),
        "maintenance reclaims the transaction after classification releases it"
    );
}

#[test]
fn post_deadline_receive_attempt_cannot_pin_expired_control_state() {
    let state = FlowRuntimeState::new();
    let session = SessionId::new(39).expect("session");
    let key = SessionKey::initial(session).expect("test session reserves a response identity");
    let now = Instant::now();
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        now,
        buffered_payload(b"already-expired"),
    );

    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), true)
        .expect("reserve observation")
        .observe(now)
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            true,
            None,
            crate::net::payload::IcmpPayloadMeta::new(1, 1, 0, session, None),
        )))
        .expect("publish exact observation")
        .expect("the lane records exact receive evidence even at the deadline");
    assert!(
        state
            .expire_reply_id_handshake(now + Duration::from_nanos(1))
            .is_some(),
        "an observation at the deadline cannot retain expired control state"
    );
    drop(observation);
}

#[test]
fn observation_for_an_unrelated_session_cannot_pin_expired_handshake() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    let handshake_session = SessionId::new(401).expect("handshake session");
    let handshake_key =
        SessionKey::initial(handshake_session).expect("handshake response identity");
    let handshake_deadline = now + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        handshake_key,
        1,
        handshake_deadline,
        buffered_payload(b"expires-independently"),
    );

    let observed_session = SessionId::new(402).expect("independent session");
    let pending = super::pending_client_lock_with_session(
        pending_client_lock(),
        SessionKey::initial(observed_session).expect("independent response identity"),
    );
    state
        .set_pending_icmp_client_lock_until(
            pending,
            1,
            crate::diagnostics::PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            1,
            now,
            now + Duration::from_secs(10),
        )
        .expect("install independent pending receive session");

    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), true)
        .expect("reserve observation")
        .observe(now)
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            true,
            None,
            crate::net::payload::IcmpPayloadMeta::new(1, 1, 0, observed_session, None),
        )))
        .expect("classify observation")
        .expect("independent session has a deadline");
    assert!(
        state
            .expire_reply_id_handshake(handshake_deadline + Duration::from_nanos(1))
            .is_some(),
        "a guard for another session must not postpone this handshake"
    );
    drop(observation);
}

#[test]
fn unrelated_control_for_the_same_session_cannot_pin_expired_handshake() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    let session = SessionId::new(404).expect("handshake session");
    let key = SessionKey::initial(session).expect("handshake response identity");
    let deadline = now + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        deadline,
        buffered_payload(b"same-session-unrelated-control"),
    );
    let lease_time = Instant::now();
    let lease = state
        .try_lease_due_upstream_reply_id_negotiation(lease_time)
        .expect("coherent control lease")
        .expect("control lease");
    state
        .record_upstream_negotiation_sequence(&lease, 17)
        .expect("record expected ACK sequence");
    state.complete_upstream_reply_id_negotiation_send(lease, 17, true, lease_time);

    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve observation")
        .observe(now)
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            false,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                2002,
                2002,
                17,
                crate::net::framing_shim::IcmpTunnelControl::SessionActivated(
                    crate::net::framing_shim::SessionActivated::new(key, 17),
                ),
            ),
        )))
        .expect("publish unrelated same-session control")
        .expect("candidate traffic receives an observation guard");
    assert!(
        state
            .expire_reply_id_handshake(deadline + Duration::from_nanos(1))
            .is_some(),
        "only the exact ACK transaction may retain an expired handshake"
    );
    drop(observation);
}

#[test]
fn post_deadline_reservation_cannot_pin_expired_handshake() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    let session = SessionId::new(403).expect("handshake session");
    let key = SessionKey::initial(session).expect("handshake response identity");
    let deadline = now + Duration::from_secs(1);
    state.begin_upstream_reply_id_handshake_with_key(
        2002,
        key,
        1,
        deadline,
        buffered_payload(b"expires-under-post-deadline-traffic"),
    );

    let reservation = state
        .reserve_control_observation(0, state.flow_epoch(), true)
        .expect("reserve post-deadline observation");
    let reservation = reservation.observe(deadline);
    assert!(
        state
            .expire_reply_id_handshake(deadline + Duration::from_nanos(1))
            .is_some(),
        "traffic observed at or after the deadline cannot postpone expiry"
    );
    drop(reservation);
}

#[test]
fn rollback_applies_timeout_or_reset_that_won_during_manager_publication() {
    for reset in [false, true] {
        let state = FlowRuntimeState::new();
        let session = if reset { 38 } else { 37 };
        state.begin_upstream_reply_id_handshake(
            2002,
            session,
            1,
            buffered_payload(b"rollback-race"),
        );
        let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, session) else {
            panic!("ACK starts commit");
        };
        if reset {
            state.reset();
        } else {
            let mut sessions = state.sessions.lock().unwrap();
            let super::ReplyIdHandshake::Committing { commit, .. } =
                &mut sessions.control.upstream_reply_id_handshake
            else {
                panic!("handshake remains committing");
            };
            commit.request_timeout();
        }
        let outcome = state
            .rollback_upstream_reply_id_handshake(token, Instant::now())
            .expect("matching token restores payload ownership");
        assert!(matches!(
            (reset, outcome),
            (false, super::HandshakeRollbackOutcome::TimedOut { .. })
                | (true, super::HandshakeRollbackOutcome::ResetApplied { .. })
        ));
        assert!(
            state
                .lease_due_upstream_reply_id_negotiation(Instant::now())
                .is_none(),
            "authoritative timeout/reset cannot return payload to negotiation retry"
        );
    }
}

#[test]
fn unsequenced_control_lease_returns_after_socket_admission_failure() {
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(2002, 42, 1, buffered_payload(b"pending"));
    let now = Instant::now();
    let first = state
        .try_lease_due_upstream_reply_id_negotiation(now)
        .expect("coherent first control lease")
        .expect("first control is due");
    let first_session_key = first.session_key;
    let first_session_id = first.session_id;
    let first_attempt = first.attempt.number();

    state
        .release_unsequenced_upstream_negotiation(first, now)
        .expect("return unsequenced lease");

    let second = state
        .try_lease_due_upstream_reply_id_negotiation(now)
        .expect("coherent retried control lease")
        .expect("returned control is immediately retryable");
    assert_eq!(second.session_key, first_session_key);
    assert_eq!(second.session_id, first_session_id);
    assert_ne!(
        second.attempt.number(),
        first_attempt,
        "retry must consume a fresh control-attempt token"
    );
}
