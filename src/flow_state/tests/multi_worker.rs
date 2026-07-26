use super::super::FlowRuntimeState;
use super::{activate_upstream_session, pending_client_lock, reserve_data_send};
use crate::cli::SupportedProtocol;
use crate::diagnostics::PacketTraceId;
use crate::net::framing_shim::{SessionActivated, SessionId, SessionKey};
use crate::net::icmp_sequence::{
    DataSequenceEvidenceState, SharedIcmpSequenceState, activate_receive_session,
    register_receive_candidate,
};
use crate::net::payload::PayloadEvent;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

fn promote_ready_with_replay(
    state: &FlowRuntimeState,
    session_id: SessionId,
    drain_until: Instant,
    sequence_state: &SharedIcmpSequenceState,
    sequence_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
) -> Result<bool, super::super::PendingIcmpClientLockMismatch> {
    let transition = state.reserve_client_flow();
    match state.promote_ready_icmp_client_session_with_replay_under(
        &transition,
        session_id,
        drain_until,
        sequence_state,
        sequence_cache,
    ) {
        Ok(promoted) => Ok(promoted),
        Err(super::super::FlowMutationError::Operation(error)) => Err(error),
        Err(super::super::FlowMutationError::Authority(error)) => {
            panic!("test ready-session promotion lost flow authority: {error}")
        }
    }
}

#[test]
fn admission_snapshot_never_mixes_pending_and_active_flow_state() {
    let state = FlowRuntimeState::new();
    let pending = pending_client_lock();
    state
        .set_pending_icmp_client_lock(
            pending,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            1,
        )
        .expect("install pending flow");

    let pending_snapshot = state.admission_snapshot(Instant::now());
    assert!(!pending_snapshot.locked);
    assert_eq!(pending_snapshot.client_flow, None);
    assert_eq!(pending_snapshot.pending_icmp_client_lock, Some(pending));
    assert_eq!(pending_snapshot.client_receive_session_id, None);

    state
        .reserve_client_flow()
        .publish_locked(pending.flow_key)
        .expect("publish pending flow");
    let active_snapshot = state.admission_snapshot(Instant::now());
    assert!(active_snapshot.locked);
    assert_eq!(active_snapshot.client_flow, Some(pending.flow_key));
    assert_eq!(active_snapshot.pending_icmp_client_lock, None);
    assert_eq!(
        active_snapshot.client_receive_session_id,
        pending.session_id()
    );
}

#[test]
fn competing_receive_promotions_keep_flow_and_replay_authorities_aligned() {
    let state = Arc::new(FlowRuntimeState::new());
    let sequence_state = Arc::new(SharedIcmpSequenceState::new());
    let initial = pending_client_lock();
    let initial_session = initial.session_id().expect("initial receive session");
    state
        .set_pending_icmp_client_lock(
            initial,
            1,
            crate::diagnostics::PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install initial receive session");
    state
        .reserve_client_flow()
        .publish_locked(initial.flow_key)
        .expect("publish initial flow");
    activate_receive_session(
        &sequence_state,
        &mut sequence_state.cache(),
        initial_session,
    );

    let mut candidates = Vec::new();
    for (offset, raw_session) in [99_u64, 101].into_iter().enumerate() {
        let session_id = SessionId::new(raw_session).expect("candidate session");
        let session_key = SessionKey::for_tests_with(
            session_id,
            u32::try_from(offset + 1).expect("candidate ordinal"),
        );
        let candidate = super::pending_client_lock_with_session(initial, session_key);
        state
            .set_pending_icmp_client_lock(
                candidate,
                2,
                crate::diagnostics::PacketTraceId {
                    worker_id: offset + 1,
                    c2u: true,
                    packet_id: u64::try_from(offset + 2).expect("packet ID"),
                },
                u16::try_from(offset + 1).expect("ACK sequence"),
            )
            .expect("install receive candidate");
        state
            .mark_client_candidate_acknowledged(session_key, Instant::now())
            .expect("mark candidate ready");
        register_receive_candidate(&sequence_state, session_id)
            .expect("register candidate replay state");
        candidates.push(session_id);
    }

    let barrier = Arc::new(Barrier::new(candidates.len()));
    let mut workers = Vec::new();
    for session_id in candidates {
        let state = Arc::clone(&state);
        let sequence_state = Arc::clone(&sequence_state);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let mut cache = sequence_state.cache();
            barrier.wait();
            promote_ready_with_replay(
                &state,
                session_id,
                Instant::now() + Duration::from_secs(1),
                &sequence_state,
                &mut cache,
            )
        }));
    }
    let mut successful_promotions = 0;
    for worker in workers {
        if worker
            .join()
            .expect("promotion worker did not panic")
            .is_ok()
        {
            successful_promotions += 1;
        }
    }
    assert!(
        successful_promotions >= 1,
        "at least one competing candidate must become authoritative"
    );

    assert_eq!(
        state.client_receive_session_id(),
        sequence_state.receive_session_id_for_tests(),
        "flow admission and replay authority must commit the same receive session"
    );
    assert_eq!(
        state.client_receive_session_id(),
        SessionId::new(101),
        "the highest ready ordinal is the only possible final promotion"
    );
}

fn active_receive_state_with_candidate(
    candidate_session: SessionId,
) -> (FlowRuntimeState, SharedIcmpSequenceState, SessionKey) {
    let state = FlowRuntimeState::new();
    let sequence_state = SharedIcmpSequenceState::new();
    let initial = pending_client_lock();
    let initial_session = initial.session_id().expect("initial session");
    state
        .set_pending_icmp_client_lock(
            initial,
            1,
            crate::diagnostics::PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install initial session");
    state
        .reserve_client_flow()
        .publish_locked(initial.flow_key)
        .expect("publish initial flow");
    activate_receive_session(
        &sequence_state,
        &mut sequence_state.cache(),
        initial_session,
    );
    let candidate_key = SessionKey::for_tests_with(candidate_session, 1);
    state
        .set_pending_icmp_client_lock(
            super::pending_client_lock_with_session(initial, candidate_key),
            2,
            crate::diagnostics::PacketTraceId {
                worker_id: 1,
                c2u: true,
                packet_id: 2,
            },
            1,
        )
        .expect("install reserve candidate");
    register_receive_candidate(&sequence_state, candidate_session)
        .expect("register reserve replay state");
    (state, sequence_state, candidate_key)
}

#[test]
fn first_data_may_promote_while_the_ack_syscall_is_still_in_flight() {
    let candidate_session = SessionId::new(111).expect("candidate session");
    let (state, sequence_state, candidate_key) =
        active_receive_state_with_candidate(candidate_session);
    let ack_lease = state
        .begin_client_candidate_ack_send(candidate_key, Instant::now())
        .expect("begin ACK send")
        .expect("new candidate needs an ACK lease");

    let mut cache = sequence_state.cache();
    assert_eq!(
        promote_ready_with_replay(
            &state,
            candidate_session,
            Instant::now() + Duration::from_secs(1),
            &sequence_state,
            &mut cache,
        ),
        Ok(true),
        "peer data proves that an ACK reached it before the local syscall returned"
    );
    state
        .complete_client_candidate_ack_send(ack_lease, false)
        .expect("a promoted candidate wins over the late local send result");
    assert_eq!(
        state.client_receive_session_id(),
        sequence_state.receive_session_id_for_tests()
    );
}

#[test]
fn one_successful_duplicate_ack_prevents_another_worker_from_rolling_back_readiness() {
    let candidate_session = SessionId::new(113).expect("candidate session");
    let (state, sequence_state, candidate_key) =
        active_receive_state_with_candidate(candidate_session);
    let first = state
        .begin_client_candidate_ack_send(candidate_key, Instant::now())
        .expect("begin first ACK")
        .expect("first ACK lease");
    let second = state
        .begin_client_candidate_ack_send(candidate_key, Instant::now())
        .expect("begin duplicate ACK")
        .expect("duplicate ACK lease");

    state
        .complete_client_candidate_ack_send(second, true)
        .expect("duplicate ACK succeeds");
    state
        .complete_client_candidate_ack_send(first, false)
        .expect("later failure cannot undo an observed ACK success");
    let mut cache = sequence_state.cache();
    assert_eq!(
        promote_ready_with_replay(
            &state,
            candidate_session,
            Instant::now() + Duration::from_secs(1),
            &sequence_state,
            &mut cache,
        ),
        Ok(true)
    );
}

#[test]
fn reset_during_recovery_send_waits_for_payload_ownership_to_return() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 47);
    let session = SessionId::new(47).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"timeout-race");
    let now = Instant::now();
    assert!(
        state
            .retain_first_upstream_recovery_payload(
                session,
                7,
                &event,
                None,
                now,
                now + Duration::from_secs(5),
            )
            .owns_recovery()
    );
    state
        .record_upstream_recovery_send_result(session, 7, false, now)
        .expect("record failed first send");
    let lease = state
        .lease_due_upstream_recovery_payload(now + Duration::from_secs(1))
        .expect("recovery state remains coherent")
        .expect("retry lease");
    state
        .prepare_upstream_recovery_payload_send(&lease.token, 8)
        .expect("publish in-flight retry sequence");
    assert_eq!(state.reset(), None);
    let completion = state
        .complete_upstream_recovery_payload_send(lease, true, now + Duration::from_secs(1))
        .expect("return ownership after timeout");
    assert!(completion.timeout_requested);
    assert_eq!(completion.pending_reset, None);
    assert!(
        !state
            .observe_upstream_session_activated(
                SessionActivated::new(
                    SessionKey::initial(session).expect("retired session key"),
                    8,
                ),
                now + Duration::from_secs(1),
                DataSequenceEvidenceState::Sent,
            )
            .expect("production recognition transition remains coherent after reset")
    );
}

#[test]
fn maintenance_timeout_cannot_destroy_an_in_flight_recovery_lease() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 49);
    let session = SessionId::new(49).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"maintenance-race");
    let now = Instant::now();
    assert!(
        state
            .retain_first_upstream_recovery_payload(
                session,
                7,
                &event,
                None,
                now,
                now + Duration::from_secs(1),
            )
            .owns_recovery()
    );
    state
        .record_upstream_recovery_send_result(session, 7, false, now)
        .expect("schedule payload retry");
    let lease = state
        .lease_due_upstream_recovery_payload(now + Duration::from_millis(20))
        .expect("recovery state remains coherent")
        .expect("lease retry");
    state
        .prepare_upstream_recovery_payload_send(&lease.token, 8)
        .expect("record leased sequence");

    state
        .maintain_upstream_session_pool_until(
            2002,
            now + Duration::from_secs(2),
            now + Duration::from_secs(3),
        )
        .expect("run maintenance after recovery deadline");
    let completion = state
        .complete_upstream_recovery_payload_send(lease, true, now + Duration::from_secs(2))
        .expect("leased worker retains ownership until completion");
    assert!(completion.timeout_requested);
}

#[test]
fn pre_deadline_activation_observation_survives_concurrent_maintenance() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 51);
    let sequences = SharedIcmpSequenceState::new();
    let session = SessionId::new(51).expect("active session");
    let key = state
        .sessions
        .lock()
        .unwrap()
        .upstream_pool
        .upstream_active_key
        .expect("active key");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"activation-race");
    let observed_at = Instant::now();
    let deadline = observed_at + Duration::from_secs(1);
    assert!(state.retain_first_upstream_recovery_payload(
        session,
        7,
        &event,
        None,
        observed_at,
        deadline,
    )
    .owns_recovery());
    let mut sequence_cache = sequences.cache();
    assert_eq!(
        reserve_data_send(&sequences, &mut sequence_cache, session, 7).complete(true),
        None
    );
    state
        .record_upstream_recovery_send_result(session, 7, true, observed_at)
        .expect("record local send result");

    let observation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve activation control")
        .observe(observed_at)
        .finish(Some(crate::flow_state::ControlTransactionKey::new(
            state.flow_epoch(),
            false,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                1,
                1,
                7,
                crate::net::framing_shim::IcmpTunnelControl::SessionActivated(
                    SessionActivated::new(key, 7),
                ),
            ),
        )))
        .expect("announce exact activation control")
        .expect("activation needs a control observation");
    state
        .maintain_upstream_session_pool_until(
            2002,
            deadline + Duration::from_secs(1),
            deadline + Duration::from_secs(2),
        )
        .expect("maintenance cannot reclaim observed activation state");
    assert_eq!(
        state.observe_upstream_session_activated(
            SessionActivated::new(key, 7),
            observed_at,
            crate::net::icmp_sequence::DataSequenceEvidenceState::Sent,
        ),
        Ok(true)
    );
    drop(observation);
}

#[test]
fn separate_flow_observation_uses_direction_lane_not_global_worker_id() {
    let state = FlowRuntimeState::with_session_pool_size_and_reader_lanes(1, 4);
    let c2u_lane =
        crate::flow_state::FlowReaderLane::for_worker(4, crate::cli::WorkerFlowMode::SingleFlow);
    let u2c_lane =
        crate::flow_state::FlowReaderLane::for_worker(5, crate::cli::WorkerFlowMode::SingleFlow);

    assert_eq!(c2u_lane.index(), 0);
    assert_eq!(u2c_lane.index(), 1);

    let c2u = state
        .reserve_control_observation(c2u_lane.index(), state.flow_epoch(), true)
        .expect("third pair C2U uses its flow-local direction lane");
    let u2c = state
        .reserve_control_observation(u2c_lane.index(), state.flow_epoch(), false)
        .expect("third pair U2C uses its flow-local direction lane");

    assert_eq!(state.control_observation_count_for_tests(), 2);
    drop(c2u);
    drop(u2c);
    assert_eq!(state.control_observation_count_for_tests(), 0);
}
