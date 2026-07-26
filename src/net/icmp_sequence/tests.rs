use super::{
    SharedIcmpSequenceState, TransmitSequenceWindow, activate_receive_session,
    admit_inbound_sequence, claim_prepared_outbound_session, current_reply_seq,
    install_outbound_request_session, publish_outbound_request_seq, register_receive_candidate,
    remember_request_seq, reserve_outbound_reply_seq, reserve_outbound_request_seq,
    reset_sequence_pair_for_client_lock, reset_sequence_state_and_seed_receive,
    retain_admitted_receive_sessions, unregister_receive_candidate,
};
use crate::flow_state::SessionAdmissionSnapshot;
use crate::net::framing_shim::{SessionActivated, SessionId, SessionKey};
use crate::net::payload::IcmpPayloadMeta;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[test]
fn outbound_reservation_requires_an_exact_prepared_cache_capability() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session = SessionId::for_tests();

    assert!(claim_prepared_outbound_session(&state, &cache, session).is_err());
    install_outbound_request_session(&state, &mut cache, session)
        .expect("install exact transmit session");
    let prepared = claim_prepared_outbound_session(&state, &cache, session)
        .expect("claim exact prepared-session capability");
    let stable = crate::worker_support::StableSendCore::new(())
        .acquire_socket(())
        .reserve_protocol(prepared)
        .expect("reserve through stable-send capability");
    assert_eq!(stable.protocol().sequence(), 0);
}

#[test]
fn receive_publication_atomics_use_the_receive_replay_contract() {
    let registry =
        Arc::new(crate::authority::WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = crate::authority::WorkerAuditIdentity {
        worker: 0,
        direction: crate::authority::AuditDirection::ClientToUpstream,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);

    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let state = SharedIcmpSequenceState::new();
        assert_eq!(state.generation.load(Ordering::Acquire), 1);
        assert_eq!(state.reply_icmp_seq.load(Ordering::Acquire), 0);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");

    let records = registry.records().expect("terminal worker record");
    assert_eq!(records.len(), 1);
    records[0]
        .validate()
        .expect("receive publication atomics match their registered protocol");
}

#[test]
fn receive_candidate_registration_reports_ownership_and_rolls_back_exactly_once() {
    let state = SharedIcmpSequenceState::new();
    let candidate = crate::net::framing_shim::SessionId::new(17).expect("candidate session");
    assert!(
        register_receive_candidate(&state, candidate).expect("register candidate"),
        "the caller owns rollback only for a newly inserted candidate"
    );
    assert!(
        !register_receive_candidate(&state, candidate)
            .expect("duplicate registration is idempotent")
    );
    assert!(unregister_receive_candidate(&state, candidate));
    assert!(!unregister_receive_candidate(&state, candidate));

    let mut cache = state.cache();
    activate_receive_session(&state, &mut cache, candidate);
    assert!(
        !unregister_receive_candidate(&state, candidate),
        "candidate rollback can never remove the active replay authority"
    );
}

#[test]
fn valid_active_session_data_is_not_rate_limited_at_4096_frames() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    activate_receive_session(
        &state,
        &mut cache,
        crate::net::framing_shim::SessionId::for_tests(),
    );
    for sequence in 0..=4096 {
        let icmp = IcmpPayloadMeta::new(
            1,
            2,
            sequence as u16,
            crate::net::framing_shim::SessionId::for_tests(),
            None,
        );
        admit_inbound_sequence(false, &state, &icmp, None)
            .expect("valid active-session data is not abuse-budget traffic");
    }
}

#[test]
fn distant_sequence_cannot_evict_an_older_replay_claim() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    activate_receive_session(
        &state,
        &mut cache,
        crate::net::framing_shim::SessionId::for_tests(),
    );
    let first = IcmpPayloadMeta::new(
        1,
        2,
        7,
        crate::net::framing_shim::SessionId::for_tests(),
        None,
    );
    let distant = IcmpPayloadMeta::new(
        1,
        2,
        7 + 2048,
        crate::net::framing_shim::SessionId::for_tests(),
        None,
    );
    admit_inbound_sequence(false, &state, &first, None).expect("admit first sequence");
    admit_inbound_sequence(false, &state, &distant, None).expect("advance replay window");

    let error = admit_inbound_sequence(false, &state, &first, None)
        .expect_err("an old replay must remain rejected after a 2048-step advance");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(state.rejection_counters().stale, 1);
}

#[test]
fn rejected_ranges_are_classified_without_a_valid_traffic_rate_limit() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    activate_receive_session(
        &state,
        &mut cache,
        crate::net::framing_shim::SessionId::for_tests(),
    );
    let session_id = crate::net::framing_shim::SessionId::for_tests();
    for expected in 0..=10 {
        let reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
            .expect("test sequence remains allocatable");
        assert_eq!(reservation.sequence(), expected);
        publish_outbound_request_seq(&state, &reservation);
    }
    let future = IcmpPayloadMeta::new(
        1,
        2,
        11,
        crate::net::framing_shim::SessionId::for_tests(),
        None,
    );
    let error = admit_inbound_sequence(false, &state, &future, Some(0))
        .expect_err("future sequence must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(state.rejection_counters().future, 1);
}

#[test]
fn user_data_cannot_choose_an_inactive_receive_session() {
    let state = SharedIcmpSequenceState::new();
    let frame = IcmpPayloadMeta::new(
        1,
        2,
        0,
        crate::net::framing_shim::SessionId::for_tests(),
        None,
    );

    let error = admit_inbound_sequence(false, &state, &frame, None)
        .expect_err("data must not activate an unnegotiated receive session");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn only_published_reservations_advance_the_latest_sequence() {
    let state = std::sync::Arc::new(SharedIcmpSequenceState::new());
    let mut cache = state.cache();
    let session_id = crate::net::framing_shim::SessionId::for_tests();
    activate_receive_session(&state, &mut cache, session_id);
    let delayed_state = std::sync::Arc::clone(&state);
    let (reserved_tx, reserved_rx) = std::sync::mpsc::sync_channel(1);
    let (publish_tx, publish_rx) = std::sync::mpsc::sync_channel(1);
    let delayed = std::thread::spawn(move || {
        let mut delayed_cache = delayed_state.cache();
        let first = reserve_outbound_request_seq(&delayed_state, &mut delayed_cache, session_id)
            .expect("first reservation");
        reserved_tx
            .send(first.sequence())
            .expect("publish delayed sequence");
        publish_rx.recv().expect("release delayed publisher");
        publish_outbound_request_seq(&delayed_state, &first);
    });
    let first_sequence = reserved_rx.recv().expect("receive delayed sequence");
    let second =
        reserve_outbound_request_seq(&state, &mut cache, session_id).expect("second reservation");

    assert_eq!(state.latest_for_tests(), None);
    publish_outbound_request_seq(&state, &second);
    assert_eq!(state.latest_for_tests(), Some(second.sequence()));
    let second_sequence = second.sequence();
    drop(second);

    publish_tx.send(()).expect("release delayed publisher");
    delayed.join().expect("delayed publisher");
    assert_eq!(
        state.latest_for_tests(),
        Some(second_sequence),
        "a delayed publisher must not move the admission window backward"
    );
    assert!(first_sequence < second_sequence);
    let second_reply = IcmpPayloadMeta::new(1, 2, second_sequence, session_id, None);
    admit_inbound_sequence(false, &state, &second_reply, Some(0))
        .expect("per-session publication also ignores the delayed older publisher");
}

#[test]
fn retired_session_rejects_a_cached_reservation_without_consuming_a_sequence() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let first =
        reserve_outbound_request_seq(&state, &mut cache, session_id).expect("initial reservation");
    assert_eq!(first.sequence(), 0);
    drop(first);
    assert_eq!(state.retire_outbound_sessions(&[session_id]), 1);

    assert!(
        reserve_outbound_request_seq(&state, &mut cache, session_id).is_err(),
        "a stale cached session must reject allocation after retirement"
    );
    let window = state.transmit.lock().unwrap();
    assert!(window.transmit_sessions.is_empty());
}

#[cfg(not(miri))]
#[test]
fn activation_recovery_has_exactly_one_atomic_owner() {
    let state = std::sync::Arc::new(SharedIcmpSequenceState::new());
    let session_id = SessionId::for_tests();
    let start = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let state = std::sync::Arc::clone(&state);
        let start = std::sync::Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            let mut cache = state.cache();
            let reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
                .expect("reserve directional sequence");
            start.wait();
            reservation
                .claim_activation_recovery()
                .expect("reservation cache remains current")
        }));
    }
    start.wait();
    let owners = workers
        .into_iter()
        .map(|worker| worker.join().expect("claim worker"))
        .filter(|claimed| *claimed)
        .count();
    assert_eq!(owners, 1);
}

#[test]
fn catchup_validation_uses_the_frame_session_not_another_sessions_watermark() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let active = crate::net::framing_shim::SessionId::for_tests();
    let reserve = crate::net::framing_shim::SessionId::new(2).expect("reserve session");

    let active_first =
        reserve_outbound_request_seq(&state, &mut cache, active).expect("active first sequence");
    publish_outbound_request_seq(&state, &active_first);
    drop(active_first);
    let reserve_control = reserve_outbound_request_seq(&state, &mut cache, reserve)
        .expect("reserve control sequence");
    publish_outbound_request_seq(&state, &reserve_control);
    let reserve_sequence = reserve_control.sequence();
    drop(reserve_control);
    let active_second =
        reserve_outbound_request_seq(&state, &mut cache, active).expect("active second sequence");
    publish_outbound_request_seq(&state, &active_second);
    drop(active_second);

    activate_receive_session(&state, &mut cache, reserve);
    let reserve_reply = IcmpPayloadMeta::new(1, 2, reserve_sequence, reserve, None);
    admit_inbound_sequence(false, &state, &reserve_reply, Some(0))
        .expect("another session's later global publication cannot make this reserve reply stale");
}

#[test]
fn directional_response_uses_its_request_sessions_echo_sequence_watermark() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let request_session = SessionId::new(41).expect("request session");
    let response_session = request_session
        .response_session_id()
        .expect("paired response session");
    let request = reserve_outbound_request_seq(&state, &mut cache, request_session)
        .expect("request sequence");
    publish_outbound_request_seq(&state, &request);
    let request_sequence = request.sequence();
    drop(request);
    activate_receive_session(&state, &mut cache, response_session);

    let response = IcmpPayloadMeta::new(1, 2, request_sequence, response_session, None);
    admit_inbound_sequence(false, &state, &response, Some(0))
        .expect("paired response echoes the base session's request sequence");
}

#[test]
fn negotiating_candidates_own_independent_sequence_spaces() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let first_session = crate::net::framing_shim::SessionId::for_tests();
    let second_session = crate::net::framing_shim::SessionId::new(2).expect("second session");

    let first_control = reserve_outbound_request_seq(&state, &mut cache, first_session)
        .expect("first candidate control");
    let first_control_sequence = first_control.sequence();
    drop(first_control);
    let second_control = reserve_outbound_request_seq(&state, &mut cache, second_session)
        .expect("second candidate control");
    let second_control_sequence = second_control.sequence();
    drop(second_control);
    let first_data = reserve_outbound_request_seq(&state, &mut cache, first_session)
        .expect("first candidate data");

    assert_eq!(first_control_sequence, 0);
    assert_eq!(second_control_sequence, 0);
    assert_eq!(
        first_data.sequence(),
        1,
        "data starts after sequences reserved by that candidate's controls"
    );
}

#[test]
fn ordinary_data_completion_has_no_deferred_control_work() {
    let window = TransmitSequenceWindow::new(SessionId::for_tests(), 0);
    let sequence = window.reserve().expect("reserve sequence");
    window
        .reserve_data(sequence)
        .expect("reserve data evidence");
    assert_eq!(
        window
            .completion
            .state_for_test(sequence)
            .expect("in-flight completion state"),
        super::send_completion::SendCompletionState::InFlight,
    );
    assert!(
        window
            .complete_data(sequence, true)
            .expect("complete data")
            .is_none()
    );
    assert_eq!(
        window
            .completion
            .state_for_test(sequence)
            .expect("sent completion state"),
        super::send_completion::SendCompletionState::Sent,
    );
}

#[test]
fn send_completion_returns_deferred_control_without_a_flow_writer() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let mut reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
        .expect("reserve request sequence");
    let sequence = reservation.sequence();
    let evidence = reservation
        .arm_data_evidence()
        .expect("reserve in-flight data evidence");
    let key = SessionKey::new(1, 0, session_id).expect("session key");
    let deferred = crate::flow_state::DeferredPeerControl::SessionActivated {
        control: SessionActivated::new(key, sequence),
        observed_at: std::time::Instant::now(),
    };
    assert_eq!(
        state.defer_outbound_data_control(session_id, deferred),
        super::DeferredDataControlOutcome::Deferred
    );
    assert_eq!(
        evidence.complete(true).expect("complete data evidence"),
        Some(deferred)
    );
}

#[test]
fn dropping_unexposed_sequence_reservation_cancels_the_production_slot() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
        .expect("reserve request sequence");
    let sequence = reservation.sequence();

    drop(reservation);

    let session = cache
        .transmit_session
        .as_deref()
        .expect("cached transmit session");
    assert_eq!(
        session
            .completion
            .state_for_test(sequence)
            .expect("cancelled reservation state"),
        super::send_completion::SendCompletionState::Retired
    );
    assert_eq!(
        reserve_outbound_request_seq(&state, &mut cache, session_id)
            .expect("abandoning one sequence does not strand the allocator")
            .sequence(),
        sequence
            .checked_add(1)
            .expect("test sequence has a successor")
    );
}

#[test]
fn dropping_armed_data_evidence_rejects_deferred_control_exactly_once() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let mut reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
        .expect("reserve request sequence");
    let sequence = reservation.sequence();
    let evidence = reservation
        .arm_data_evidence()
        .expect("arm production data evidence");
    let key = SessionKey::new(1, 0, session_id).expect("session key");
    let control = crate::flow_state::DeferredPeerControl::SessionActivated {
        control: SessionActivated::new(key, sequence),
        observed_at: std::time::Instant::now(),
    };
    assert_eq!(
        state.defer_outbound_data_control(session_id, control),
        super::DeferredDataControlOutcome::Deferred
    );

    drop(evidence);
    drop(reservation);

    assert_eq!(
        cache
            .transmit_session
            .as_deref()
            .expect("cached transmit session")
            .completion
            .state_for_test(sequence)
            .expect("terminal completion state"),
        super::send_completion::SendCompletionState::ConsumedFailed
    );
    assert_eq!(
        state.defer_outbound_data_control(session_id, control),
        super::DeferredDataControlOutcome::Rejected
    );
}

#[test]
fn control_arriving_after_success_is_returned_to_the_control_owner() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let mut reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
        .expect("reserve request sequence");
    let sequence = reservation.sequence();
    let evidence = reservation
        .arm_data_evidence()
        .expect("reserve in-flight data evidence");
    assert!(
        evidence
            .complete(true)
            .expect("complete successful data evidence")
            .is_none()
    );
    let key = SessionKey::new(1, 0, session_id).expect("session key");
    let control = crate::flow_state::DeferredPeerControl::SessionActivated {
        control: SessionActivated::new(key, sequence),
        observed_at: std::time::Instant::now(),
    };
    assert_eq!(
        state.defer_outbound_data_control(session_id, control),
        super::DeferredDataControlOutcome::Apply(control)
    );
}

#[test]
fn control_arriving_after_failed_send_is_rejected_by_the_completion_core() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session_id = SessionId::for_tests();
    let mut reservation = reserve_outbound_request_seq(&state, &mut cache, session_id)
        .expect("reserve request sequence");
    let sequence = reservation.sequence();
    let evidence = reservation
        .arm_data_evidence()
        .expect("reserve in-flight data evidence");
    assert!(
        evidence
            .complete(false)
            .expect("complete failed data evidence")
            .is_none()
    );
    let key = SessionKey::new(1, 0, session_id).expect("session key");
    let control = crate::flow_state::DeferredPeerControl::SessionActivated {
        control: SessionActivated::new(key, sequence),
        observed_at: std::time::Instant::now(),
    };
    assert_eq!(
        state.defer_outbound_data_control(session_id, control),
        super::DeferredDataControlOutcome::Rejected
    );
}

#[test]
fn transmit_session_storage_is_allocated_before_session_control_locking() {
    let state = SharedIcmpSequenceState::new();
    let allocation_before_cache =
        crate::authority::allocation_violation_count_for_authority_for_test(
            crate::authority::AuthorityId::SessionControl,
        );
    let receive_acquisitions_before = crate::authority::acquisition_count_for_test(
        crate::authority::AuthorityId::ProtocolReceive,
    );
    let mut cache = state.cache();
    assert_eq!(
        crate::authority::allocation_violation_count_for_authority_for_test(
            crate::authority::AuthorityId::SessionControl,
        ),
        allocation_before_cache,
        "worker-cache construction must not allocate beneath transmit authority"
    );
    assert_eq!(
        crate::authority::acquisition_count_for_test(
            crate::authority::AuthorityId::ProtocolReceive
        ),
        receive_acquisitions_before,
        "worker-cache construction does not depend on receive/replay authority"
    );
    let before = crate::authority::allocation_violation_count_for_authority_for_test(
        crate::authority::AuthorityId::SessionControl,
    );
    install_outbound_request_session(&state, &mut cache, SessionId::for_tests())
        .expect("prepare first transmit session");
    assert_eq!(
        crate::authority::allocation_violation_count_for_authority_for_test(
            crate::authority::AuthorityId::SessionControl,
        ),
        before,
        "first-session allocation must occur before session-control authority is held"
    );
}

#[test]
fn sequence_authorities_are_prewarmed_before_grouped_reset() {
    let client = SharedIcmpSequenceState::new();
    let upstream = SharedIcmpSequenceState::new();
    let mut client_cache = client.cache();
    let mut upstream_cache = upstream.cache();
    let session = SessionId::for_tests();
    let before = crate::authority::allocation_violation_count_for_test();
    reset_sequence_pair_for_client_lock(
        false,
        &client,
        &mut client_cache,
        None,
        &upstream,
        &mut upstream_cache,
    )
    .expect("reset prewarmed sequence authorities");
    assert_eq!(
        crate::authority::allocation_violation_count_for_test(),
        before,
        "grouped sequence reset must not lazily allocate synchronization backing"
    );
    install_outbound_request_session(&client, &mut client_cache, session)
        .expect("prepare session after reset");
}

#[test]
fn opposite_direction_reply_lookup_does_not_take_the_replay_lock() {
    let state = std::sync::Arc::new(SharedIcmpSequenceState::new());
    let mut cache = state.cache();
    let request = IcmpPayloadMeta::new(1, 2, 37, SessionId::for_tests(), None);
    remember_request_seq(&state, &mut cache, &request);
    let mut reader_cache = state.cache();
    let replay_guard = state.receive.lock().expect("hold replay authority");
    let reader = std::sync::Arc::clone(&state);
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        completed_tx
            .send(current_reply_seq(&reader, &mut reader_cache))
            .expect("publish reply sequence");
    });
    assert_eq!(
        completed_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .expect("reply lookup must not wait for replay admission"),
        37
    );
    drop(replay_guard);
    worker.join().expect("reply lookup worker");
}

#[test]
fn client_lock_sequence_reset_preflights_both_directions_before_mutation() {
    assert!(super::preflight_sequence_generations([1, 2]).is_ok());
    assert!(
        super::preflight_sequence_generations([1, super::MAX_SEQUENCE_GENERATION]).is_err(),
        "generation exhaustion must be detected before either direction mutates"
    );
}

#[test]
fn client_lock_sequence_reset_rejects_a_duplicated_authority_without_deadlocking() {
    let shared = SharedIcmpSequenceState::new();
    let mut client_cache = shared.cache();
    let mut upstream_cache = shared.cache();

    let error = reset_sequence_pair_for_client_lock(
        false,
        &shared,
        &mut client_cache,
        None,
        &shared,
        &mut upstream_cache,
    )
    .expect_err("one mutex cannot represent both directional sequence authorities");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn outbound_reservation_retains_protocol_authority_through_evidence_completion() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session = SessionId::new(71).expect("transmit session");
    let mut reservation =
        reserve_outbound_request_seq(&state, &mut cache, session).expect("reserve sequence");

    assert!(crate::authority::is_held_for_test(
        crate::authority::AuthorityId::ProtocolTransmit
    ));
    let evidence = reservation
        .arm_data_evidence()
        .expect("reserve in-flight evidence");
    evidence.complete(true).expect("complete send evidence");
    assert!(crate::authority::is_held_for_test(
        crate::authority::AuthorityId::ProtocolTransmit
    ));

    drop(reservation);
    assert!(!crate::authority::is_held_for_test(
        crate::authority::AuthorityId::ProtocolTransmit
    ));
}

#[test]
fn outbound_reply_retains_protocol_authority_through_send_scope() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session = SessionId::new(72).expect("reply session");
    let request = IcmpPayloadMeta::new(1, 2, 91, session, None);
    remember_request_seq(&state, &mut cache, &request);

    let reservation = reserve_outbound_reply_seq(&state, &mut cache, session);
    assert_eq!(reservation.sequence(), 91);
    assert!(crate::authority::is_held_for_test(
        crate::authority::AuthorityId::ProtocolTransmit
    ));

    drop(reservation);
    assert!(!crate::authority::is_held_for_test(
        crate::authority::AuthorityId::ProtocolTransmit
    ));
}

#[test]
fn reserve_capacity_is_derived_from_the_allocator_state() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let first = SessionId::new(23).expect("first reserve");
    let second = SessionId::new(24).expect("second reserve");

    for _ in 0..3 {
        drop(
            reserve_outbound_request_seq(&state, &mut cache, first).expect("first reserve control"),
        );
    }
    drop(reserve_outbound_request_seq(&state, &mut cache, second).expect("second reserve control"));

    assert_eq!(
        state.remaining_outbound_sequences([first, second]),
        Some((u16::MAX as u64 + 1 - 3) + (u16::MAX as u64 + 1 - 1))
    );
    assert_eq!(
        state.remaining_outbound_sequences([first, SessionId::new(25).expect("missing reserve")]),
        None,
        "missing allocator state must not fabricate reserve capacity"
    );
}

#[cfg(not(miri))]
#[test]
fn every_sequence_is_allocated_exactly_once_before_rekey() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session = crate::net::framing_shim::SessionId::for_tests();

    for expected in 0..=u16::MAX {
        let mut reservation = reserve_outbound_request_seq(&state, &mut cache, session)
            .expect("the session owns each sequence exactly once");
        assert_eq!(reservation.sequence(), expected);
        if expected == u16::MAX {
            let evidence = reservation
                .arm_data_evidence()
                .expect("the exhausting sequence owns in-flight evidence");
            assert!(
                evidence
                    .complete(true)
                    .expect("complete final data evidence")
                    .is_none()
            );
        }
    }
    assert!(
        reserve_outbound_request_seq(&state, &mut cache, session).is_err(),
        "the sequence allocator must not wrap"
    );

    let next_session = crate::net::framing_shim::SessionId::new(2).expect("valid session");
    let rekeyed = reserve_outbound_request_seq(&state, &mut cache, next_session)
        .expect("a new session restarts sequence allocation");
    assert_eq!(rekeyed.sequence(), 0);
}

#[test]
fn receive_rekey_rejects_the_old_session_even_when_sequence_is_reused() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let old_session = crate::net::framing_shim::SessionId::for_tests();
    let new_session = crate::net::framing_shim::SessionId::new(2).expect("valid session");
    activate_receive_session(&state, &mut cache, old_session);
    let old_frame = IcmpPayloadMeta::new(1, 2, 0, old_session, None);
    admit_inbound_sequence(false, &state, &old_frame, None).expect("old session starts active");

    activate_receive_session(&state, &mut cache, new_session);
    let new_frame = IcmpPayloadMeta::new(1, 2, 0, new_session, None);
    admit_inbound_sequence(false, &state, &new_frame, None)
        .expect("new session may reuse sequence zero");
    assert!(
        admit_inbound_sequence(false, &state, &old_frame, None).is_err(),
        "the retired session must not reclaim the replay window"
    );
}

#[test]
fn receive_sequence_space_never_wraps_within_one_session() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let first_session = SessionId::new(21).expect("first session");
    let second_session = SessionId::new(22).expect("second session");
    activate_receive_session(&state, &mut cache, first_session);

    admit_inbound_sequence(
        false,
        &state,
        &IcmpPayloadMeta::new(1, 2, u16::MAX - 1, first_session, None),
        None,
    )
    .expect("sequence 65534 is admitted");
    admit_inbound_sequence(
        false,
        &state,
        &IcmpPayloadMeta::new(1, 2, u16::MAX, first_session, None),
        None,
    )
    .expect("sequence 65535 is admitted");
    assert!(
        admit_inbound_sequence(
            false,
            &state,
            &IcmpPayloadMeta::new(1, 2, 0, first_session, None),
            None,
        )
        .is_err(),
        "sequence zero cannot synthesize a second epoch for the same session"
    );

    activate_receive_session(&state, &mut cache, second_session);
    admit_inbound_sequence(
        false,
        &state,
        &IcmpPayloadMeta::new(1, 2, 0, second_session, None),
        None,
    )
    .expect("a new session owns a fresh sequence-zero value");
}

#[test]
fn admission_pruning_releases_stale_candidate_replay_windows() {
    let state = SharedIcmpSequenceState::new();
    let first = SessionId::new(17).expect("first candidate");
    let second = SessionId::new(18).expect("second candidate");
    register_receive_candidate(&state, first).expect("register first candidate");
    register_receive_candidate(&state, second).expect("register second candidate");
    assert_eq!(state.tracked_receive_session_count_for_tests(), 2);

    retain_admitted_receive_sessions(&state, SessionAdmissionSnapshot::empty());
    assert_eq!(state.tracked_receive_session_count_for_tests(), 0);

    register_receive_candidate(&state, second)
        .expect("released capacity accepts a later candidate");
    assert_eq!(state.tracked_receive_session_count_for_tests(), 1);
}

#[test]
fn first_candidate_data_is_admitted_before_activation_and_keeps_its_replay_state() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let candidate = SessionId::new(19).expect("candidate session");
    register_receive_candidate(&state, candidate).expect("register receive candidate");
    let first_data = IcmpPayloadMeta::new(1, 2, 7, candidate, None);

    admit_inbound_sequence(false, &state, &first_data, None)
        .expect("first candidate data may trigger session activation");
    activate_receive_session(&state, &mut cache, candidate);
    assert!(
        admit_inbound_sequence(false, &state, &first_data, None).is_err(),
        "activation must preserve the candidate replay window"
    );
}

#[test]
fn transactional_lock_initialization_preserves_the_first_data_replay_claim() {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    let session = SessionId::new(20).expect("session");
    let first_data = IcmpPayloadMeta::new(1, 2, 37, session, None);

    reset_sequence_state_and_seed_receive(false, &state, &mut cache, Some(&first_data))
        .expect("initialize lock sequence state");

    let duplicate = admit_inbound_sequence(false, &state, &first_data, None)
        .expect_err("the lock-triggering data sequence remains claimed");
    assert_eq!(duplicate.kind(), std::io::ErrorKind::InvalidData);

    let next_data = IcmpPayloadMeta::new(1, 2, 38, session, None);
    admit_inbound_sequence(false, &state, &next_data, None)
        .expect("the next sequence remains admissible");
}
