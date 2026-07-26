use super::tests::activate_upstream_session;
use super::{
    FlowRuntimeState, ReplyIdControlSendCompletion, ReplyIdHandshakeAck, ReplyIdHandshakeAckIgnored,
};
use std::num::NonZeroU64;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn session_pool_starts_two_candidates_without_blocking_active_session() {
    let state = FlowRuntimeState::with_session_pool_size(4);
    activate_upstream_session(&state, 17);

    assert_eq!(
        state
            .maintain_upstream_session_pool(2002)
            .expect("create reserve candidates"),
        2
    );
    assert_eq!(state.upstream_session_id().map(|id| id.get()), Some(17));
    let snapshot = state.session_pool_snapshot();
    assert_eq!(
        snapshot.pool.active, 2,
        "one negotiated key installs distinct transmit and receive sessions"
    );
    assert_eq!(snapshot.pool.ready, 0);
    assert_eq!(snapshot.pool.negotiating, 2);
    assert_eq!(snapshot.pool.target, 4);
}

#[test]
fn lost_reserve_ack_does_not_interrupt_active_data() {
    use crate::net::icmp_sequence::{
        SharedIcmpSequenceState, publish_outbound_request_seq, reserve_outbound_request_seq,
    };

    let state = FlowRuntimeState::with_session_pool_size(4);
    let sequences = SharedIcmpSequenceState::new();
    let mut cache = sequences.cache();
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidates");

    let lost = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("reserve candidate lease");
    let control = reserve_outbound_request_seq(&sequences, &mut cache, lost.session_id)
        .expect("reserve control sequence");
    state
        .record_upstream_negotiation_sequence(&lost, control.sequence())
        .expect("record sent reserve negotiation");
    publish_outbound_request_seq(&sequences, &control);
    let control_sequence = control.sequence();
    drop(control);
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(
            lost,
            control_sequence,
            true,
            Instant::now(),
        ),
        ReplyIdControlSendCompletion::RetryScheduled
    );

    let data = reserve_outbound_request_seq(&sequences, &mut cache, active)
        .expect("active traffic remains sendable while reserve ACK is lost");
    assert_eq!(data.sequence(), 0);
    assert_eq!(state.upstream_session_id(), Some(active));
}

#[test]
fn delayed_reserve_ack_cancels_an_unsequenced_retry_without_corruption() {
    let state = FlowRuntimeState::with_session_pool_size(4);
    activate_upstream_session(&state, 17);
    state
        .maintain_upstream_session_pool(2002)
        .expect("create one reserve candidate");
    let now = Instant::now();
    let first = state
        .lease_due_upstream_reply_id_negotiation(now)
        .expect("first reserve lease");
    let first_session_key = first.session_key;
    let first_session_id = first.session_id;
    state
        .record_upstream_negotiation_sequence(&first, 11)
        .expect("record sent reserve negotiation");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(first, 11, true, now),
        ReplyIdControlSendCompletion::RetryScheduled
    );

    let other_candidate = state
        .lease_due_upstream_reply_id_negotiation(now)
        .expect("hold the other candidate lease");
    let retry = state
        .lease_due_upstream_reply_id_negotiation(now + Duration::from_secs(1))
        .expect("reserve retry lease");
    assert_eq!(retry.session_key, first_session_key);
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, first_session_id.get(), 11, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));
    assert_eq!(
        state
            .record_upstream_negotiation_sequence(&retry, 12)
            .expect("an ACK-winning reserve retry is not ownership corruption"),
        super::ReplyIdControlSequenceRecord::HandshakeAdvanced
    );
    state
        .release_unsequenced_upstream_negotiation(other_candidate, now)
        .expect("release the unrelated candidate lease");
}

#[test]
fn acknowledged_session_allows_later_data_while_first_payload_is_in_flight() {
    use crate::cli::SupportedProtocol;
    use crate::net::icmp_sequence::{SharedIcmpSequenceState, reserve_outbound_request_seq};
    use crate::net::payload::{BufferedPayload, PayloadEvent};

    let state = FlowRuntimeState::with_session_pool_size(4);
    let session = crate::net::framing_shim::SessionId::new(41).expect("active session");
    let first = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"first");
    state.begin_upstream_reply_id_handshake(
        2002,
        session.get(),
        1,
        BufferedPayload::from_event(&first, None),
    );
    let control_lease = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("initial negotiation lease");
    state
        .record_upstream_negotiation_sequence(&control_lease, 0)
        .expect("record initial negotiation sequence");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(control_lease, 0, true, Instant::now(),),
        ReplyIdControlSendCompletion::RetryScheduled
    );
    let ReplyIdHandshakeAck::Matched { token, .. } =
        state.ack_upstream_reply_id_handshake(2002, session.get(), 0, None)
    else {
        panic!("initial session ACK must match");
    };
    let first_payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("claim initial payload send");

    assert!(state.upstream_reply_id_acked());
    assert_eq!(state.upstream_session_id(), Some(session));
    let sequences = SharedIcmpSequenceState::new();
    let mut cache = sequences.cache();
    let later = reserve_outbound_request_seq(&sequences, &mut cache, session)
        .expect("later payload must not wait for the first payload syscall");
    assert_eq!(later.sequence(), 0);
    drop(later);

    assert!(
        !state
            .release_upstream_reply_id_payload_send(first_payload)
            .expect("return first payload to bounded retry ownership")
    );
}

#[test]
fn session_pool_replenishes_to_target_without_exceeding_two_negotiations() {
    let state = FlowRuntimeState::with_session_pool_size(4);
    activate_upstream_session(&state, 17);

    for _ in 0..4 {
        state
            .maintain_upstream_session_pool(2002)
            .expect("maintain bounded reserve pool");
        while let Some(lease) = state.lease_due_upstream_reply_id_negotiation(Instant::now()) {
            let sequence =
                u16::try_from(lease.attempt.number() - 1).expect("test attempt fits u16");
            let session_id = lease.session_id;
            state
                .record_upstream_negotiation_sequence(&lease, sequence)
                .expect("record reserve negotiate");
            state.complete_upstream_reply_id_negotiation_send(
                lease,
                sequence,
                true,
                Instant::now(),
            );
            assert!(matches!(
                state.ack_upstream_reply_id_handshake(2002, session_id.get(), sequence, None,),
                ReplyIdHandshakeAck::ReserveReady { .. }
            ));
        }
    }

    let snapshot = state.session_pool_snapshot();
    assert_eq!(snapshot.pool.ready, 4);
    assert_eq!(snapshot.pool.negotiating, 0);
    assert_eq!(snapshot.pool.target, 4);
    assert_eq!(
        state
            .maintain_upstream_session_pool(2002)
            .expect("a full pool is a no-op"),
        0
    );
}

#[cfg(not(miri))]
#[test]
fn full_session_pool_maintenance_does_not_publish_a_spurious_wake() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    activate_upstream_session(&state, 17);
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidate");
    let candidate = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("reserve candidate lease");
    let candidate_session_id = candidate.session_id;
    state
        .record_upstream_negotiation_sequence(&candidate, 0)
        .expect("record reserve negotiation");
    state.complete_upstream_reply_id_negotiation_send(candidate, 0, true, Instant::now());
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, candidate_session_id.get(), 0, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));

    let wake = state
        .register_maintenance_wake(super::FlowReaderLane::for_worker(
            0,
            crate::cli::WorkerFlowMode::SharedFlow,
        ))
        .expect("register maintenance wake after the pool is full");
    let epoch_before = state
        .maintenance_epoch
        .load(std::sync::atomic::Ordering::Acquire);
    assert_eq!(
        state
            .maintain_upstream_session_pool(2002)
            .expect("maintain a full pool"),
        0
    );
    assert_eq!(
        state
            .maintenance_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        epoch_before,
        "a no-op pool pass must not invalidate the maintenance schedule"
    );
    assert_eq!(
        wake.receiver()
            .recv(&mut [0_u8; 1])
            .expect_err("a no-op pool pass must not wake workers")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn session_pool_grants_exactly_two_cross_worker_candidate_leases() {
    let state = Arc::new(FlowRuntimeState::with_session_pool_size(4));
    activate_upstream_session(&state, 17);
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidates");
    let barrier = Arc::new(Barrier::new(8));
    let leases = (0..8)
        .map(|_| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state.lease_due_upstream_reply_id_negotiation(Instant::now())
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|worker| worker.join().expect("join candidate worker"))
        .collect::<Vec<_>>();
    assert_eq!(leases.len(), 2);
    assert_ne!(leases[0].session_id, leases[1].session_id);
}

#[test]
fn reserve_acks_preserve_issuance_order_for_normal_handoff() {
    let state = FlowRuntimeState::with_session_pool_size(2);
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidates");

    let first = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("first candidate lease");
    let first_session_id = first.session_id;
    state
        .record_upstream_negotiation_sequence(&first, 11)
        .expect("record first control");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(first, 11, true, Instant::now()),
        ReplyIdControlSendCompletion::RetryScheduled
    );

    let second = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("second candidate lease");
    let second_session_id = second.session_id;
    state
        .record_upstream_negotiation_sequence(&second, 19)
        .expect("record second control");
    state.complete_upstream_reply_id_negotiation_send(second, 19, true, Instant::now());

    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, second_session_id.get(), 19, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, first_session_id.get(), 11, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));

    let promoted = state
        .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
        .expect("atomic handoff")
        .expect("ready session");
    assert_eq!(
        promoted, first_session_id,
        "ready order follows candidate issuance rather than reordered ACK arrival"
    );
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 1);
}

#[test]
fn failed_handoff_precheck_does_not_consume_a_ready_session() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    let ready = crate::net::framing_shim::SessionKey::new(
        17,
        1,
        crate::net::framing_shim::SessionId::new(19).expect("ready session"),
    )
    .expect("valid ready key");
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.authority.upstream_leg.transmit = Some(active);
        sessions.upstream_pool.upstream_active_key = None;
        sessions
            .upstream_pool
            .upstream_ready_sessions
            .push_back(super::ReadySession { session_key: ready });
    }

    assert!(
        state
            .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
            .is_err()
    );
    let sessions = state.sessions.lock().unwrap();
    assert_eq!(sessions.upstream_pool.upstream_ready_sessions.len(), 1);
    assert_eq!(
        sessions
            .upstream_pool
            .upstream_ready_sessions
            .front()
            .map(|entry| entry.session_key),
        Some(ready)
    );
    assert_eq!(sessions.upstream_pool.upstream_pool_epoch, 0);
}

#[test]
fn handoff_uses_an_existing_flow_writer_without_nested_reservation() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    let active_key = crate::net::framing_shim::SessionKey::new(
        17,
        0,
        crate::net::framing_shim::SessionId::new(17).expect("active session"),
    )
    .expect("active key");
    let ready_key = crate::net::framing_shim::SessionKey::new(
        17,
        1,
        crate::net::framing_shim::SessionId::new(19).expect("ready session"),
    )
    .expect("ready key");
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.authority.upstream_leg.transmit = Some(active_key.session_id());
        sessions.authority.upstream_leg.receive = Some(active_key.response_session_id());
        sessions.upstream_pool.upstream_active_key = Some(active_key);
        sessions.control.upstream_reply_id_handshake = super::ReplyIdHandshake::Acked {
            instance: active_key.session_id().get(),
        };
        sessions
            .upstream_pool
            .upstream_ready_sessions
            .push_back(super::ReadySession {
                session_key: ready_key,
            });
    }

    let transition = state.reserve_client_flow();
    let promoted = state
        .handoff_upstream_session_under(
            &transition,
            active_key.session_id(),
            Instant::now() + Duration::from_secs(3),
        )
        .expect("handoff under existing writer");
    assert_eq!(promoted, Some(ready_key.session_id()));
}

#[test]
fn reserve_ack_deadline_uses_observation_time_without_removing_candidate() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    activate_upstream_session(&state, 17);
    let lease_time = Instant::now();
    let deadline = lease_time + Duration::from_millis(500);
    state
        .maintain_upstream_session_pool_until(2002, lease_time, deadline)
        .expect("create reserve candidate");
    let lease = state
        .lease_due_upstream_reply_id_negotiation(lease_time)
        .expect("reserve negotiation");
    state
        .record_upstream_negotiation_sequence(&lease, 11)
        .expect("record reserve negotiation");
    let session_key = lease.session_key;
    state.complete_upstream_reply_id_negotiation_send(lease, 11, true, lease_time);
    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(2002, session_key, 11, 0, deadline, None,),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::Expired { .. })
    ));
    assert_eq!(state.session_pool_snapshot().pool.negotiating, 1);
    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve pre-deadline reserve ACK")
        .observe(deadline - Duration::from_nanos(1))
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            false,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                2002,
                2002,
                11,
                crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(
                    crate::net::framing_shim::ReplyIdNegotiation::acknowledge_key_and_challenge(
                        2002,
                        session_key,
                        0,
                    )
                    .expect("valid reserve ACK"),
                ),
            ),
        )))
        .expect("announce exact pre-deadline reserve ACK")
        .expect("reserve ACK needs a control observation");
    state
        .maintain_upstream_session_pool_until(
            2002,
            deadline + Duration::from_secs(1),
            deadline + Duration::from_secs(2),
        )
        .expect("maintenance retains candidate observed by another worker");
    assert!(
        matches!(
            state.ack_upstream_reply_id_handshake_key(
                2002,
                session_key,
                11,
                0,
                deadline - Duration::from_nanos(1),
                None,
            ),
            ReplyIdHandshakeAck::ReserveReady { .. }
        ),
        "a reserve ACK observed before its deadline remains valid when processed later"
    );
    drop(observation);
}

#[test]
fn duplicate_generation_advance_uses_receive_time_not_processing_time() {
    let state = FlowRuntimeState::new();
    let current = crate::net::framing_shim::SessionKey::for_tests();
    let proposed =
        crate::net::framing_shim::PoolGeneration::new(2).expect("nonzero proposed generation");
    let advance = crate::net::framing_shim::GenerationAdvance::new(current, proposed);
    let observed_at = Instant::now();
    let deadline = observed_at + Duration::from_secs(1);
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.authority.flow = super::FlowPhase::Active;
        sessions.client_pool.client_active_key = Some(current);
    }

    assert!(state.authorize_client_generation_advance(advance, observed_at, deadline));
    assert!(
        state.authorize_client_generation_advance(
            advance,
            deadline - Duration::from_nanos(1),
            deadline + Duration::from_secs(1),
        ),
        "a duplicate observed before the original deadline remains valid"
    );
    assert!(
        !state.authorize_client_generation_advance(
            advance,
            deadline,
            deadline + Duration::from_secs(1),
        ),
        "a duplicate observed at the original deadline is expired"
    );
}

#[test]
fn reserve_accounting_snapshot_detects_concurrent_handoff_without_false_invariant() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    let active = crate::net::framing_shim::SessionId::new(91).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve");
    let candidate = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("reserve candidate");
    let candidate_session_id = candidate.session_id;
    state
        .record_upstream_negotiation_sequence(&candidate, 0)
        .expect("record negotiation");
    state.complete_upstream_reply_id_negotiation_send(candidate, 0, true, Instant::now());
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, candidate_session_id.get(), 0, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));
    let (snapshot, allocations) =
        crate::allocation_test_support::count_allocations(|| state.session_pool_snapshot());
    assert_eq!(
        allocations, 0,
        "diagnostic snapshot allocated while flow-session authority was held"
    );
    assert!(state.reserve_accounting_snapshot_is_current(
        snapshot.pool.pool_epoch,
        &snapshot.pool.ready_session_ids,
    ));

    state
        .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
        .expect("handoff")
        .expect("ready session");
    assert!(
        !state.reserve_accounting_snapshot_is_current(
            snapshot.pool.pool_epoch,
            &snapshot.pool.ready_session_ids,
        ),
        "a reporting race is detected as an unstable snapshot, not fabricated capacity"
    );
}

// Native coverage owns the full 16-bit traversal. Miri exercises the same
// handoff through targeted allocator-boundary tests in `net::icmp_sequence`.
#[cfg(not(miri))]
#[test]
fn exhausted_active_session_hands_off_without_buffering_the_triggering_frame() {
    use crate::net::icmp_sequence::{
        SharedIcmpSequenceState, publish_outbound_request_seq, reserve_outbound_request_seq,
    };

    let state = FlowRuntimeState::with_session_pool_size(1);
    let sequences = SharedIcmpSequenceState::new();
    let mut cache = sequences.cache();
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidate");

    let candidate = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("reserve candidate lease");
    let candidate_session_id = candidate.session_id;
    let candidate_control =
        reserve_outbound_request_seq(&sequences, &mut cache, candidate.session_id)
            .expect("candidate negotiate sequence");
    state
        .record_upstream_negotiation_sequence(&candidate, candidate_control.sequence())
        .expect("record candidate control");
    publish_outbound_request_seq(&sequences, &candidate_control);
    let candidate_control_sequence = candidate_control.sequence();
    drop(candidate_control);
    state.complete_upstream_reply_id_negotiation_send(
        candidate,
        candidate_control_sequence,
        true,
        Instant::now(),
    );
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(
            2002,
            candidate_session_id.get(),
            candidate_control_sequence,
            None,
        ),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));

    for expected in 0..=u16::MAX {
        let reservation = reserve_outbound_request_seq(&sequences, &mut cache, active)
            .expect("active session owns every sequence once");
        assert_eq!(reservation.sequence(), expected);
        publish_outbound_request_seq(&sequences, &reservation);
    }
    assert!(crate::net::icmp_sequence::outbound_session_requires_rekey(
        &sequences, &cache, active
    ));

    let next = state
        .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
        .expect("handoff state remains coherent")
        .expect("a ready session avoids exceptional buffering");
    assert_eq!(next, candidate_session_id);
    let triggering_data = reserve_outbound_request_seq(&sequences, &mut cache, next)
        .expect("triggering data uses the ready session immediately");
    assert_eq!(
        triggering_data.sequence(),
        1,
        "candidate data follows its negotiate sequence without wrapping the old session"
    );
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 1);
    assert_eq!(state.session_pool_snapshot().metrics.pool_empty_stalls, 0);
}

// This is a throughput/regression traversal across three complete sequence
// spaces, not a useful interpreter workload.
#[cfg(not(miri))]
#[test]
fn more_than_two_sequence_spaces_cross_without_a_normal_path_gap() {
    use crate::net::icmp_sequence::{
        SharedIcmpSequenceState, publish_outbound_request_seq, reserve_outbound_request_seq,
    };

    let state = FlowRuntimeState::with_session_pool_size(2);
    let sequences = SharedIcmpSequenceState::new();
    let mut cache = sequences.cache();
    let mut active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create two reserve candidates");

    while let Some(candidate) = state.lease_due_upstream_reply_id_negotiation(Instant::now()) {
        let candidate_session_id = candidate.session_id;
        let control = reserve_outbound_request_seq(&sequences, &mut cache, candidate.session_id)
            .expect("candidate control sequence");
        state
            .record_upstream_negotiation_sequence(&candidate, control.sequence())
            .expect("record candidate control");
        publish_outbound_request_seq(&sequences, &control);
        let control_sequence = control.sequence();
        drop(control);
        state.complete_upstream_reply_id_negotiation_send(
            candidate,
            control_sequence,
            true,
            Instant::now(),
        );
        assert!(matches!(
            state.ack_upstream_reply_id_handshake(
                2002,
                candidate_session_id.get(),
                control_sequence,
                None,
            ),
            ReplyIdHandshakeAck::ReserveReady { .. }
        ));
    }

    let mut sent = 0_u64;
    for handoff in 0..=2 {
        while let Ok(reservation) = reserve_outbound_request_seq(&sequences, &mut cache, active) {
            publish_outbound_request_seq(&sequences, &reservation);
            sent += 1;
        }
        if handoff < 2 {
            active = state
                .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
                .expect("session handoff remains coherent")
                .expect("pre-negotiated session prevents a normal-path stall");
        }
    }

    assert!(sent > 131_072, "crossed multiple 16-bit sequence spaces");
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 2);
    assert_eq!(state.session_pool_snapshot().metrics.pool_empty_stalls, 0);
}

#[test]
fn concurrent_handoff_promotes_once_and_all_workers_observe_the_same_session() {
    let state = Arc::new(FlowRuntimeState::with_session_pool_size(1));
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidate");
    let candidate = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("candidate lease");
    let candidate_session_id = candidate.session_id;
    state
        .record_upstream_negotiation_sequence(&candidate, 0)
        .expect("record candidate sequence");
    state.complete_upstream_reply_id_negotiation_send(candidate, 0, true, Instant::now());
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, candidate_session_id.get(), 0, None),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));

    let barrier = Arc::new(Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state
                    .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
                    .expect("concurrent handoff is idempotent")
                    .expect("ready session")
            })
        })
        .collect::<Vec<_>>();
    let observed = workers
        .into_iter()
        .map(|worker| worker.join().expect("join handoff worker"))
        .collect::<Vec<_>>();

    assert_eq!(observed, vec![candidate_session_id; 2]);
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 1);
    assert_eq!(state.session_pool_snapshot().metrics.pool_empty_stalls, 0);
}

#[test]
fn pool_empty_handoff_retains_the_critical_buffer_path() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    let active = crate::net::framing_shim::SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());

    assert_eq!(
        state
            .handoff_upstream_session(active, Instant::now() + Duration::from_secs(3))
            .expect("handoff state"),
        None
    );
    assert_eq!(state.session_pool_snapshot().metrics.pool_empty_stalls, 1);
}

#[test]
fn ordinal_headroom_starts_background_generation_rollover_without_wrapping() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    activate_upstream_session(&state, 17);
    let active_generation = state
        .sessions
        .lock()
        .unwrap()
        .upstream_pool
        .upstream_active_key
        .expect("active key")
        .generation();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.upstream_pool.next_session_ordinal =
            u32::MAX - super::MAX_RECEIVE_SESSION_CANDIDATES as u32 + 2;
    }
    assert_eq!(
        state
            .maintain_upstream_session_pool(2002)
            .expect("ordinal headroom starts generation authorization"),
        1
    );
    let sessions = state.sessions.lock().unwrap();
    assert!(
        sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .is_empty()
    );
    let rollover = sessions
        .upstream_pool
        .upstream_generation_advance
        .as_ref()
        .expect("generation advance is staged");
    assert_eq!(rollover.proposed_key.ordinal(), 0);
    assert_ne!(rollover.proposed_key.generation(), active_generation);
    assert_eq!(
        sessions.upstream_pool.next_session_ordinal,
        u32::MAX - super::MAX_RECEIVE_SESSION_CANDIDATES as u32 + 2
    );
}

#[test]
fn pre_deadline_generation_ack_survives_concurrent_expiry_maintenance() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    activate_upstream_session(&state, 17);
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.upstream_pool.next_session_ordinal = u32::MAX;
    }
    let now = Instant::now();
    let deadline = now + Duration::from_millis(500);
    state
        .maintain_upstream_session_pool_until(2002, now, deadline)
        .expect("stage generation advance");
    let lease = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("lease generation advance");
    let crate::net::framing_shim::IcmpTunnelControl::GenerationAdvance(advance) = lease.control
    else {
        panic!("expected generation advance");
    };
    state
        .record_upstream_negotiation_sequence(&lease, 31)
        .expect("record generation sequence");
    state.complete_upstream_reply_id_negotiation_send(lease, 31, true, now);
    let observed_at = now;
    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve pre-deadline generation ACK")
        .observe(observed_at)
        .finish(Some(super::ControlTransactionKey::new(
            state.flow_epoch(),
            false,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                2002,
                2002,
                31,
                crate::net::framing_shim::IcmpTunnelControl::GenerationAdvanceAck(advance),
            ),
        )))
        .expect("announce exact pre-deadline generation ACK")
        .expect("generation ACK needs a control observation");
    state
        .maintain_upstream_session_pool_until(
            2002,
            deadline + Duration::from_secs(1),
            deadline + Duration::from_secs(2),
        )
        .expect("maintenance retains observed generation transaction");
    assert!(
        state
            .accept_upstream_generation_advance_ack(
                advance,
                31,
                observed_at,
                observed_at + Duration::from_secs(1),
            )
            .expect("accept generation ACK observed before deadline")
    );
    drop(observation);
}

#[test]
fn conflicting_rollover_candidate_retries_with_receiver_challenge() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    activate_upstream_session(&state, 17);
    let active_generation = state
        .sessions
        .lock()
        .unwrap()
        .upstream_pool
        .upstream_active_key
        .expect("active key")
        .generation();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.upstream_pool.next_session_ordinal = u32::MAX;
    }
    state
        .maintain_upstream_session_pool(2002)
        .expect("start rollover");
    let advance_lease = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("generation advance lease");
    let crate::net::framing_shim::IcmpTunnelControl::GenerationAdvance(advance) =
        advance_lease.control
    else {
        panic!("rollover starts with GenerationAdvance");
    };
    state
        .record_upstream_negotiation_sequence(&advance_lease, 7)
        .expect("record generation advance");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(advance_lease, 7, true, Instant::now(),),
        ReplyIdControlSendCompletion::RetryScheduled
    );
    let now = Instant::now();
    assert!(
        state
            .accept_upstream_generation_advance_ack(advance, 7, now, now + Duration::from_secs(3),)
            .expect("accept generation advance ACK")
    );
    let conflicting = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("authorized ordinal-zero negotiation");
    let conflicting_session_key = conflicting.session_key;
    state
        .record_upstream_negotiation_sequence(&conflicting, 8)
        .expect("record conflicting negotiate");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(conflicting, 8, true, Instant::now(),),
        ReplyIdControlSendCompletion::RetryScheduled
    );

    let challenge = NonZeroU64::new(91).expect("nonzero challenge");
    let reset = crate::net::framing_shim::ResetRequired::for_evidence(
        crate::net::framing_shim::RejectedFrameEvidence::Negotiate {
            candidate: conflicting_session_key,
            sequence: 8,
        },
        Some(active_generation),
        challenge,
    );
    assert!(
        state
            .accept_upstream_rollover_challenge(reset, 2002, now, now + Duration::from_secs(3),)
            .expect("accept rollover challenge")
    );
    let challenged = state
        .lease_due_upstream_reply_id_negotiation(Instant::now())
        .expect("challenge-authorized lease");
    assert_ne!(challenged.session_key, conflicting_session_key);
    let challenged_session_key = challenged.session_key;
    assert_eq!(challenged.session_key.ordinal(), 0);
    assert_eq!(challenged.reset_challenge, challenge.get());
    state
        .record_upstream_negotiation_sequence(&challenged, 9)
        .expect("record challenged negotiate");
    state.complete_upstream_reply_id_negotiation_send(challenged, 9, true, Instant::now());
    assert!(matches!(
        state.ack_upstream_reply_id_handshake_key(
            2002,
            challenged_session_key,
            9,
            challenge.get(),
            Instant::now(),
            None,
        ),
        ReplyIdHandshakeAck::ReserveReady { .. }
    ));
    assert_eq!(state.upstream_session_id().map(|id| id.get()), Some(17));
    assert_eq!(state.session_pool_snapshot().pool.ready, 1);
}
