use super::{promote_ready_with_replay, recover_upstream_session};
use crate::cli::SupportedProtocol;
use crate::diagnostics::PacketTraceId;
use crate::flow_state::tests::{activate_upstream_session, pending_client_lock, reserve_data_send};
use crate::flow_state::{FlowRuntimeState, ReplyIdHandshakeBegin, UpstreamSessionRecovery};
use crate::net::framing_shim::{
    PoolGeneration, ResetRequired, SessionActivated, SessionId, SessionKey,
};
use crate::net::icmp_sequence::{DataSequenceEvidenceState, SharedIcmpSequenceState};
use crate::net::payload::PayloadEvent;
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

#[test]
fn forged_reset_for_an_unsent_data_sequence_cannot_mutate_the_session() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 41);
    let sequences = SharedIcmpSequenceState::new();
    let session = SessionId::new(41).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"retained");
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
    let forged = ResetRequired::new(
        session,
        7,
        Some(PoolGeneration::new(1).expect("receiver generation")),
        NonZeroU64::new(55).expect("challenge"),
    );
    assert!(
        recover_upstream_session(
            &state,
            &sequences,
            forged,
            2002,
            now,
            now + Duration::from_secs(1),
            1,
        )
        .is_err()
    );
    assert_eq!(state.upstream_session_id(), Some(session));
    assert_eq!(
        state
            .session_pool_snapshot()
            .reset_recovery
            .reset_responses_accepted,
        0
    );
}

#[test]
fn failed_first_session_send_retries_with_fresh_sequences_and_one_payload_owner() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 43);
    let session = SessionId::new(43).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"retry-me");
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

    let first = state
        .lease_due_upstream_recovery_payload(now + Duration::from_secs(1))
        .expect("recovery state remains coherent")
        .expect("first retry lease");
    let PayloadEvent::UserPayload { bytes, .. } = first.payload.as_event() else {
        panic!("recovery lease must retain user data");
    };
    assert_eq!(bytes, b"retry-me");
    state
        .prepare_upstream_recovery_payload_send(&first.token, 8)
        .expect("reserve fresh retry sequence");
    assert_eq!(
        state
            .complete_upstream_recovery_payload_send(first, false, now + Duration::from_secs(1),)
            .expect("return retry ownership")
            .pending_reset,
        None
    );

    let second = state
        .lease_due_upstream_recovery_payload(now + Duration::from_secs(3))
        .expect("recovery state remains coherent")
        .expect("second retry lease");
    state
        .prepare_upstream_recovery_payload_send(&second.token, 9)
        .expect("reserve another fresh retry sequence");
    assert_eq!(
        state
            .complete_upstream_recovery_payload_send(second, true, now + Duration::from_secs(3),)
            .expect("complete retry")
            .pending_reset,
        None
    );
    assert!(
        state
            .observe_upstream_session_activated(
                SessionActivated::new(
                    SessionKey::initial(session).expect("active session key"),
                    9,
                ),
                now + Duration::from_secs(3),
                DataSequenceEvidenceState::Sent,
            )
            .expect("production recognition transition")
    );
    assert!(
        state
            .lease_due_upstream_recovery_payload(now + Duration::from_secs(4))
            .expect("recognition leaves coherent recovery state")
            .is_none(),
        "production recognition must consume completed recovery ownership"
    );
}

#[test]
fn reset_during_first_payload_retry_defers_recovery_until_ownership_returns() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 45);
    let sequences = SharedIcmpSequenceState::new();
    let session = SessionId::new(45).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"race-recovery");
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
    let mut sequence_cache = sequences.cache();
    let in_flight = reserve_data_send(&sequences, &mut sequence_cache, session, 8);
    let reset = ResetRequired::new(
        session,
        8,
        state
            .sessions
            .lock()
            .unwrap()
            .upstream_pool
            .upstream_active_key
            .map(SessionKey::generation),
        NonZeroU64::new(57).expect("challenge"),
    );
    assert!(matches!(
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    recover_upstream_session(
                        &state,
                        &sequences,
                        reset,
                        2002,
                        now,
                        now + Duration::from_secs(2),
                        2,
                    )
                })
                .join()
                .expect("deferred recovery worker completes")
        }),
        Ok(UpstreamSessionRecovery::Deferred)
    ));
    let completion = state
        .complete_upstream_recovery_payload_send(lease, true, now + Duration::from_secs(1))
        .expect("return ownership after reset race");
    assert_eq!(completion.pending_reset, None);
    assert!(!completion.timeout_requested);
    assert!(matches!(
        in_flight.complete(true),
        Some(super::DeferredPeerControl::ResetRequired {
            control,
            observed_at,
        }) if control == reset && observed_at == now
    ));
    assert!(matches!(
        recover_upstream_session(
            &state,
            &sequences,
            reset,
            2002,
            now + Duration::from_secs(1),
            now + Duration::from_secs(2),
            2,
        ),
        Ok(UpstreamSessionRecovery::Recovered {
            handshake: ReplyIdHandshakeBegin::Started {
                buffered_len: 13,
                ..
            },
            ..
        })
    ));
}

#[test]
fn receive_candidate_promotes_by_session_id_and_drains_previous_session_absolutely() {
    let state = FlowRuntimeState::new();
    let first = pending_client_lock();
    let first_session = first.session_id().expect("first session");
    state
        .set_pending_icmp_client_lock(
            first,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install first receive session");
    state
        .reserve_client_flow()
        .publish_locked(first.flow_key)
        .expect("publish first flow");

    let second_session = crate::net::framing_shim::SessionId::new(99).expect("second session");
    let second = super::pending_with_session(
        first,
        crate::net::framing_shim::SessionKey::for_tests_with(second_session, 1),
    );
    state
        .set_pending_icmp_client_lock(
            second,
            2,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 2,
            },
            7,
        )
        .expect("install reserve receive candidate");
    state
        .mark_client_candidate_acknowledged(
            second.session_key.expect("second session key"),
            Instant::now(),
        )
        .expect("mark reserve ACK sent");
    assert!(
        state
            .client_session_admission(Instant::now())
            .contains(second_session)
    );

    let drain_until = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        promote_ready_with_replay(&state, second_session, drain_until),
        Ok(true)
    );
    let draining = state.client_session_admission(Instant::now());
    assert!(
        draining.contains(first_session) && draining.is_draining(first_session),
        "previous active session remains in the bounded drain set"
    );
    assert!(
        !state
            .client_session_admission(drain_until + Duration::from_millis(1))
            .contains(first_session),
        "drain expiry is absolute and is not refreshed by admission"
    );
    assert_eq!(
        state
            .session_pool_snapshot()
            .metrics
            .stale_session_evictions,
        1
    );
}
