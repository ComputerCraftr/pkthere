use super::tests::{activate_upstream_session, pending_client_lock, reserve_data_send};
use super::{
    DeferredPeerControl, FlowMutationError, FlowRuntimeState, PendingIcmpClientLock,
    ReplyIdHandshakeAck, ReplyIdHandshakeBegin, ReplyIdHandshakeInvariantError, ResetChallenge,
    UpstreamRecoveryRequest, UpstreamSessionRecovery,
};
use crate::cli::SupportedProtocol;
use crate::diagnostics::PacketTraceId;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::ClientFlowKey;
use crate::net::framing_shim::{
    PoolGeneration, RejectedFrameEvidence, ResetRequired, SessionId, SessionKey,
};
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::payload::PayloadEvent;
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

fn pending_with_session(
    mut pending: PendingIcmpClientLock,
    session_key: SessionKey,
) -> PendingIcmpClientLock {
    let reply_id = pending
        .listener_flow
        .inbound
        .map_or(1, |flow| flow.src.id());
    pending.session_key = Some(session_key);
    pending.observed_control = Some(super::PendingClientControl::Negotiate { reply_id });
    pending.reset_challenge = 0;
    pending.reset_evidence = None;
    pending
}

fn pending_with_challenge(
    mut pending: PendingIcmpClientLock,
    session_key: SessionKey,
    challenge: ResetChallenge,
) -> PendingIcmpClientLock {
    let reply_id = pending
        .listener_flow
        .inbound
        .map_or(1, |flow| flow.src.id());
    pending.session_key = Some(session_key);
    pending.observed_control = Some(super::PendingClientControl::ChallengeNegotiate {
        reply_id,
        receiver_generation: challenge.receiver_generation,
    });
    pending.reset_challenge = challenge.challenge.get();
    pending.reset_evidence = Some(challenge.context);
    pending
}

fn recover_upstream_session(
    state: &FlowRuntimeState,
    sequences: &SharedIcmpSequenceState,
    reset: ResetRequired,
    expected_ack_destination_id: u16,
    now: Instant,
    absolute_deadline: Instant,
    started_s: u64,
) -> Result<UpstreamSessionRecovery, ReplyIdHandshakeInvariantError> {
    let transition = state.reserve_client_flow();
    let result = match state.recover_upstream_session_under(
        &transition,
        UpstreamRecoveryRequest {
            sequences,
            reset,
            expected_ack_destination_id,
            observed_at: now,
            absolute_deadline,
            started_s,
        },
    ) {
        Ok(recovery) => Ok(recovery),
        Err(FlowMutationError::Operation(error)) => Err(error),
        Err(FlowMutationError::Authority(_)) => Err(ReplyIdHandshakeInvariantError),
    };
    if let Ok(UpstreamSessionRecovery::Recovered {
        retired_sessions, ..
    }) = &result
    {
        sequences.retire_outbound_sessions(retired_sessions);
    }
    result
}

fn promote_ready_with_replay(
    state: &FlowRuntimeState,
    session_id: SessionId,
    drain_until: Instant,
) -> Result<bool, super::PendingIcmpClientLockMismatch> {
    let sequence_state = SharedIcmpSequenceState::new();
    let mut sequence_cache = sequence_state.cache();
    let transition = state.reserve_client_flow();
    match state.promote_ready_icmp_client_session_with_replay_under(
        &transition,
        session_id,
        drain_until,
        &sequence_state,
        &mut sequence_cache,
    ) {
        Ok(promoted) => Ok(promoted),
        Err(FlowMutationError::Operation(error)) => Err(error),
        Err(FlowMutationError::Authority(error)) => {
            panic!("test ready-session promotion lost flow authority: {error}")
        }
    }
}

#[test]
fn stateless_receiver_restart_challenge_is_bounded_and_consumed_by_recovery_negotiation() {
    let state = FlowRuntimeState::new();
    let peer = pending_client_lock();
    let rejected = RejectedFrameEvidence::Data {
        session: SessionId::new(77).expect("rejected session"),
        sequence: 12,
    };
    let now = Instant::now();
    let super::ResetChallengeIssue::Created(challenge) = state
        .issue_client_reset_challenge(peer.flow_key, rejected, now, now + Duration::from_secs(1))
        .expect("create stateless reset challenge")
    else {
        panic!("unlocked receiver creates a stateless challenge");
    };
    assert_eq!(
        state
            .issue_client_reset_challenge(
                peer.flow_key,
                rejected,
                now,
                now + Duration::from_secs(1),
            )
            .expect("reuse stateless reset challenge"),
        super::ResetChallengeIssue::Reused(challenge)
    );

    let recovery = pending_with_challenge(
        peer,
        SessionKey::new(2, 0, SessionId::new(78).expect("replacement session"))
            .expect("replacement key"),
        challenge,
    );
    assert_eq!(
        state
            .set_pending_icmp_client_lock_until(
                recovery,
                1,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 1,
                },
                13,
                now,
                now + Duration::from_secs(1),
            )
            .expect("challenge-authorized recovery negotiation"),
        super::PendingIcmpClientLockSet::Started
    );
    assert!(
        state
            .sessions
            .lock()
            .unwrap()
            .reset_recovery
            .stateless_client_reset_challenges
            .is_empty(),
        "consumed stateless challenges cannot authorize a second generation"
    );
}

#[test]
fn stateless_receiver_restart_challenge_table_never_exceeds_protocol_capacity() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    for index in 0..=super::MAX_STATELESS_RESET_CHALLENGES {
        let endpoint_id = u16::try_from(index + 1).expect("test endpoint ID");
        let peer_flow = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            std::net::Ipv4Addr::LOCALHOST,
            endpoint_id,
        ));
        let rejected = RejectedFrameEvidence::Data {
            session: SessionId::new(u64::try_from(index + 1).expect("test session ID"))
                .expect("nonzero test session"),
            sequence: endpoint_id,
        };
        assert!(matches!(
            state
                .issue_client_reset_challenge(
                    peer_flow,
                    rejected,
                    now,
                    now + Duration::from_secs(1),
                )
                .expect("create bounded stateless challenge"),
            super::ResetChallengeIssue::Created(_)
        ));
    }
    assert_eq!(
        state
            .sessions
            .lock()
            .unwrap()
            .reset_recovery
            .stateless_client_reset_challenges
            .len(),
        super::MAX_STATELESS_RESET_CHALLENGES
    );
}

#[test]
fn conflicting_generation_challenge_is_reused_and_consumed_once() {
    let state = FlowRuntimeState::new();
    let initial = pending_client_lock();
    state
        .set_pending_icmp_client_lock(
            initial,
            1,
            PacketTraceId {
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

    let rejected_session = SessionId::new(99).expect("rejected session");
    let rejected_generation = PoolGeneration::new(2).expect("rejected generation");
    let rejected_key =
        SessionKey::new(rejected_generation.get(), 0, rejected_session).expect("rejected key");
    let rejected = RejectedFrameEvidence::Negotiate {
        candidate: rejected_key,
        sequence: 7,
    };
    let now = Instant::now();
    let first = state
        .issue_client_reset_challenge(
            initial.flow_key,
            rejected,
            now,
            now + Duration::from_secs(1),
        )
        .expect("create reset challenge");
    let super::ResetChallengeIssue::Created(challenge) = first else {
        panic!("first conflict creates a challenge");
    };
    assert_eq!(
        state
            .issue_client_reset_challenge(
                initial.flow_key,
                rejected,
                now,
                now + Duration::from_secs(1),
            )
            .expect("reuse reset challenge"),
        super::ResetChallengeIssue::Reused(challenge)
    );

    let replacement_session = SessionId::new(100).expect("replacement session");
    let replacement = pending_with_challenge(
        initial,
        SessionKey::new(3, 0, replacement_session).expect("replacement key"),
        challenge,
    );
    assert_eq!(
        state
            .set_pending_icmp_client_lock_until(
                replacement,
                2,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 2,
                },
                0,
                now,
                now + Duration::from_secs(1),
            )
            .expect("challenge-authorized replacement"),
        super::PendingIcmpClientLockSet::Started
    );
    assert_eq!(
        state
            .set_pending_icmp_client_lock_until(
                replacement,
                2,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 3,
                },
                0,
                now,
                now + Duration::from_secs(1),
            )
            .expect("known staged replacement is idempotent"),
        super::PendingIcmpClientLockSet::Reused
    );
    let snapshot = state.session_pool_snapshot();
    assert_eq!(snapshot.reset_recovery.reset_challenges_created, 1);
    assert_eq!(snapshot.reset_recovery.reset_challenges_reused, 1);
    assert_eq!(snapshot.reset_recovery.reset_challenges_consumed, 1);
    assert_eq!(state.client_receive_session_id(), initial.session_id());
    state
        .mark_client_candidate_acknowledged(
            replacement.session_key.expect("replacement session key"),
            now,
        )
        .expect("mark replacement ACK sent");
    assert_eq!(
        promote_ready_with_replay(&state, replacement_session, now + Duration::from_secs(1)),
        Ok(true)
    );
    assert_eq!(
        state.client_receive_session_id(),
        Some(replacement_session),
        "the old generation remains active until first valid replacement data"
    );
}

#[test]
fn reset_response_budget_is_independently_packet_and_byte_bounded() {
    let state = FlowRuntimeState::new();
    let peer_flow = pending_client_lock().flow_key;
    let now = Instant::now();
    let response_bytes =
        u32::try_from(crate::net::framing_shim::ICMP_TUNNEL_EXPLICIT_RESET_REQUIRED_LEN)
            .expect("reset-required length fits u32");
    assert!(state.reserve_client_reset_response(peer_flow, now, response_bytes));
    assert!(state.reserve_client_reset_response(peer_flow, now, response_bytes));
    assert!(!state.reserve_client_reset_response(peer_flow, now, response_bytes));
    assert!(state.reserve_client_reset_response(peer_flow, now + Duration::from_secs(1), 128));
    assert!(!state.reserve_client_reset_response(peer_flow, now + Duration::from_secs(1), 453));
    assert_eq!(
        state
            .session_pool_snapshot()
            .reset_recovery
            .reset_responses_rate_limited,
        2
    );
}

#[test]
fn reset_response_budget_reservation_is_all_or_nothing() {
    let now = Instant::now();
    let mut global = super::ResetResponseBudget::with_limits(2, 0, 128, 0);
    let mut peer = super::ResetResponseBudget::with_limits(0, 0, 128, 0);

    assert!(!super::ResetResponseBudget::reserve_with(
        &mut global,
        &mut peer,
        now,
        64
    ));
    assert_eq!(global.packet_tokens, 2);
    assert_eq!(global.byte_tokens, 128);
    assert_eq!(peer.packet_tokens, 0);
    assert_eq!(peer.byte_tokens, 128);
}

#[test]
fn reset_response_budget_contention_suppresses_without_waiting() {
    let state = FlowRuntimeState::new();
    let peer_flow = pending_client_lock().flow_key;
    let now = Instant::now();
    let session_guard = state.sessions.lock().expect("hold session authority");
    assert!(!state.reserve_client_reset_response(peer_flow, now, 64));
    drop(session_guard);

    let global_guard = super::global_reset_response_budget()
        .lock()
        .expect("hold global reset budget");
    assert!(!state.reserve_client_reset_response(peer_flow, now, 64));
    drop(global_guard);
}

#[test]
fn reset_response_budget_retains_subsecond_refill_remainder() {
    let mut budget = super::ResetResponseBudget::with_limits(1, 1, 64, 64);
    let origin = budget.last_refill;

    assert!(budget.reserve(origin, 1));
    assert!(budget.reserve(origin + Duration::from_millis(1_100), 1));
    assert!(
        budget.reserve(origin + Duration::from_millis(2_001), 1),
        "whole-token publication must retain the unused 100 ms refill remainder"
    );
}

#[test]
fn reset_challenge_rng_failures_are_typed_and_zero_is_rejected() {
    let failure = super::fresh_nonzero_challenge_with(|_| Err("injected failure".to_owned()))
        .expect_err("RNG failure must not create a challenge");
    assert!(failure.to_string().contains("injected failure"));

    let zero = super::fresh_nonzero_challenge_with(|bytes| {
        bytes.fill(0);
        Ok(())
    })
    .expect_err("zero challenge must be rejected");
    assert!(zero.to_string().contains("produced zero"));
}

#[test]
fn reset_challenge_expiry_is_absolute_and_allows_a_fresh_challenge() {
    let state = FlowRuntimeState::new();
    let initial = pending_client_lock();
    state
        .set_pending_icmp_client_lock(
            initial,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install client flow");
    state
        .reserve_client_flow()
        .publish_locked(initial.flow_key)
        .expect("publish initial flow");
    let rejected = SessionId::new(99).expect("rejected session");
    let rejected = RejectedFrameEvidence::Data {
        session: rejected,
        sequence: 9,
    };
    let now = Instant::now();
    let first = state
        .issue_client_reset_challenge(
            initial.flow_key,
            rejected,
            now,
            now + Duration::from_millis(1),
        )
        .expect("first challenge");
    assert!(matches!(first, super::ResetChallengeIssue::Created(_)));
    let second = state
        .issue_client_reset_challenge(
            initial.flow_key,
            rejected,
            now + Duration::from_millis(1),
            now + Duration::from_secs(1),
        )
        .expect("expired challenge replacement");
    assert!(matches!(second, super::ResetChallengeIssue::Created(_)));
    assert_eq!(
        state
            .session_pool_snapshot()
            .reset_recovery
            .reset_challenges_expired,
        1
    );
}

#[test]
fn sparse_candidate_expiry_does_not_retire_a_lower_ready_ordinal() {
    let state = FlowRuntimeState::new();
    let now = Instant::now();
    let generation = PoolGeneration::new(1).expect("test generation");
    let lower = SessionKey::new(
        generation.get(),
        7,
        SessionId::new(70).expect("lower session"),
    )
    .expect("lower key");
    let expired = SessionKey::new(
        generation.get(),
        8,
        SessionId::new(80).expect("expired session"),
    )
    .expect("expired key");
    let transaction_key = |session_key| {
        super::ControlTransactionKey::new(
            state.flow_epoch(),
            true,
            None,
            crate::net::payload::IcmpPayloadMeta::new_control(
                1,
                1,
                0,
                crate::net::framing_shim::IcmpTunnelControl::Negotiate(
                    crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key(
                        1,
                        session_key,
                    )
                    .expect("test candidate negotiation"),
                ),
            ),
        )
    };
    {
        let mut sessions = state.sessions.lock().unwrap();
        let mut ready = super::ReceiveCandidate::negotiating(
            lower,
            transaction_key(lower),
            now + Duration::from_secs(1),
        );
        let mut next_installation_order = 0;
        let permit = ready
            .begin_ack_send(now, &mut next_installation_order)
            .expect("lease candidate ACK")
            .expect("candidate ACK lease");
        ready
            .complete_ack_send(permit, true)
            .expect("complete candidate ACK");
        sessions.client_pool.client_ready_sessions.push(ready);
        sessions
            .client_pool
            .client_ready_sessions
            .push(super::ReceiveCandidate::negotiating(
                expired,
                transaction_key(expired),
                now,
            ));
    }

    state.client_session_admission(now);
    let sessions = state.sessions.lock().unwrap();
    assert!(
        !sessions
            .client_pool
            .client_retired_ordinals
            .is_retired(lower.ordinal())
    );
    assert!(
        sessions
            .client_pool
            .client_retired_ordinals
            .is_retired(expired.ordinal())
    );
    assert_eq!(sessions.client_pool.client_ready_sessions.len(), 1);
    assert_eq!(
        sessions.client_pool.client_ready_sessions[0].session_key,
        lower
    );
}

#[test]
fn duplicate_candidate_negotiation_does_not_refresh_its_absolute_deadline() {
    let state = FlowRuntimeState::new();
    let initial = pending_client_lock();
    state
        .set_pending_icmp_client_lock(
            initial,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install client flow");
    state
        .reserve_client_flow()
        .publish_locked(initial.flow_key)
        .expect("publish initial flow");

    let candidate = pending_with_session(
        initial,
        SessionKey::for_tests_with(SessionId::new(99).expect("candidate session"), 1),
    );
    let now = Instant::now();
    let first_deadline = now + Duration::from_secs(1);
    assert_eq!(
        state
            .set_pending_icmp_client_lock_until(
                candidate,
                2,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 2,
                },
                0,
                now,
                first_deadline,
            )
            .expect("install candidate"),
        super::PendingIcmpClientLockSet::Started
    );
    assert_eq!(
        state
            .set_pending_icmp_client_lock_until(
                candidate,
                3,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 3,
                },
                0,
                now,
                now + Duration::from_secs(10),
            )
            .expect("duplicate candidate"),
        super::PendingIcmpClientLockSet::Reused
    );
    let sessions = state.sessions.lock().unwrap();
    assert!(sessions.client_pool.client_ready_sessions[0].is_negotiating());
    assert_eq!(
        sessions.client_pool.client_ready_sessions[0].absolute_deadline(),
        first_deadline
    );
}

#[test]
fn draining_overflow_evicts_the_earliest_absolute_expiry() {
    let now = Instant::now();
    let mut draining = std::collections::VecDeque::new();
    let earliest =
        SessionKey::new(1, 1, SessionId::new(1).expect("earliest session")).expect("earliest key");
    assert!(!super::push_draining_session(
        &mut draining,
        earliest,
        now + Duration::from_secs(1)
    ));
    for ordinal in 2..=super::MAX_DRAINING_SESSIONS as u32 {
        let key = SessionKey::new(
            1,
            ordinal,
            SessionId::new(u64::from(ordinal)).expect("draining session"),
        )
        .expect("draining key");
        assert!(!super::push_draining_session(
            &mut draining,
            key,
            now + Duration::from_secs(100)
        ));
    }
    let replacement = SessionKey::new(
        1,
        super::MAX_DRAINING_SESSIONS as u32 + 1,
        SessionId::new(super::MAX_DRAINING_SESSIONS as u64 + 1).expect("replacement session"),
    )
    .expect("replacement key");
    assert!(super::push_draining_session(
        &mut draining,
        replacement,
        now + Duration::from_secs(50)
    ));
    assert_eq!(draining.len(), super::MAX_DRAINING_SESSIONS);
    assert!(
        draining
            .iter()
            .all(|session| session.session_key != earliest)
    );
    assert!(
        draining
            .iter()
            .any(|session| session.session_key == replacement)
    );
}

#[test]
fn reset_required_recovers_retained_first_payload_without_echoing_it() {
    let state = FlowRuntimeState::new();
    activate_upstream_session(&state, 41);
    let sequences = SharedIcmpSequenceState::new();
    let session = SessionId::new(41).expect("active session");
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"recover-me");
    let now = Instant::now();
    let (retention, payload_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state.retain_first_upstream_recovery_payload(
            session,
            7,
            &event,
            None,
            now,
            now + Duration::from_secs(1),
        )
    });
    assert!(retention.owns_recovery());
    assert_eq!(payload_copies, 1);
    let mut sequence_cache = sequences.cache();
    assert_eq!(
        reserve_data_send(&sequences, &mut sequence_cache, session, 7).complete(true),
        None
    );
    let reset = ResetRequired::new(
        session,
        7,
        Some(PoolGeneration::new(1).expect("receiver generation")),
        NonZeroU64::new(55).expect("challenge"),
    );
    let (recovery, recovery_copies) = crate::allocation_test_support::count_payload_copies(|| {
        recover_upstream_session(
            &state,
            &sequences,
            reset,
            2002,
            now,
            now + Duration::from_secs(2),
            2,
        )
    });
    assert_eq!(recovery_copies, 0);
    assert!(matches!(
        recovery,
        Ok(UpstreamSessionRecovery::Recovered {
            handshake: ReplyIdHandshakeBegin::Started {
                buffered_len: 10,
                ..
            },
            ..
        })
    ));
    let lease = state
        .lease_due_upstream_reply_id_negotiation(now)
        .expect("recovery negotiation lease");
    assert_eq!(lease.reset_challenge, 55);
    assert_ne!(lease.session_id, session);
}

#[test]
fn reset_required_skips_rejected_active_session_with_same_generation_reserve() {
    let state = FlowRuntimeState::with_session_pool_size(2);
    activate_upstream_session(&state, 41);
    let sequences = SharedIcmpSequenceState::new();
    let rejected = SessionId::new(41).expect("active session");
    state
        .maintain_upstream_session_pool(2002)
        .expect("create same-generation reserves");
    let mut ready = Vec::new();
    while let Some(candidate) = state.lease_due_upstream_reply_id_negotiation(Instant::now()) {
        let candidate_session_id = candidate.session_id;
        let sequence = u16::try_from(ready.len()).expect("test sequence");
        state
            .record_upstream_negotiation_sequence(&candidate, sequence)
            .expect("record reserve negotiation");
        state.complete_upstream_reply_id_negotiation_send(
            candidate,
            sequence,
            true,
            Instant::now(),
        );
        assert!(matches!(
            state
                .ack_upstream_reply_id_handshake(2002, candidate_session_id.get(), sequence, None,),
            ReplyIdHandshakeAck::ReserveReady { .. }
        ));
        ready.push(candidate_session_id);
    }
    assert_eq!(ready.len(), 2);

    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"owned");
    let now = Instant::now();
    assert!(
        state
            .retain_first_upstream_recovery_payload(
                rejected,
                7,
                &event,
                None,
                now,
                now + Duration::from_secs(1),
            )
            .owns_recovery()
    );
    let mut sequence_cache = sequences.cache();
    assert_eq!(
        reserve_data_send(&sequences, &mut sequence_cache, rejected, 7).complete(true),
        None
    );
    let in_flight = reserve_data_send(&sequences, &mut sequence_cache, rejected, 8);
    let reset = ResetRequired::new(
        rejected,
        7,
        state
            .sessions
            .lock()
            .unwrap()
            .upstream_pool
            .upstream_active_key
            .map(SessionKey::generation),
        NonZeroU64::new(55).expect("challenge"),
    );

    let first_recovery = std::thread::scope(|scope| {
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
            .expect("recovery worker completes")
    })
    .expect("same-generation recovery");
    assert_eq!(
        in_flight.complete(true),
        None,
        "superseded-session completion remains valid after fallback"
    );
    assert!(
        matches!(
            &first_recovery,
            UpstreamSessionRecovery::Recovered {
                handshake: ReplyIdHandshakeBegin::Ignored,
                retired_sessions,
            } if retired_sessions == &vec![rejected]
        ),
        "retirement supersedes new allocations while the existing Arc-backed lease remains valid"
    );
    assert_eq!(state.upstream_session_id(), Some(ready[0]));
    assert_eq!(state.session_pool_snapshot().pool.ready, 1);
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 1);
    assert!(
        state.lease_due_upstream_reply_id_negotiation(now).is_none(),
        "same-generation fallback must not start a replacement generation"
    );
    let retry = state
        .lease_due_upstream_recovery_payload(now)
        .expect("recovery state remains coherent")
        .expect("owned payload follows the selected reserve");
    assert_eq!(retry.token.session, ready[0]);
    assert_eq!(retry.payload.payload_len(), b"owned".len());
    state
        .prepare_upstream_recovery_payload_send(&retry.token, 8)
        .expect("reserve the fallback sequence");
    let fallback_send = reserve_data_send(&sequences, &mut sequence_cache, ready[0], 8);
    state
        .complete_upstream_recovery_payload_send(retry, true, now)
        .expect("complete fallback payload send");
    assert_eq!(fallback_send.complete(true), None);

    let second_reset = ResetRequired::new(
        ready[0],
        8,
        state
            .sessions
            .lock()
            .unwrap()
            .upstream_pool
            .upstream_active_key
            .map(SessionKey::generation),
        NonZeroU64::new(56).expect("second challenge"),
    );
    assert!(matches!(
        recover_upstream_session(
            &state,
            &sequences,
            second_reset,
            2002,
            now,
            now + Duration::from_secs(2),
            2,
        )
        .expect("second same-generation recovery"),
        UpstreamSessionRecovery::Recovered {
            handshake: ReplyIdHandshakeBegin::Ignored,
            retired_sessions,
        } if retired_sessions == vec![ready[0]]
    ));
    assert_eq!(state.upstream_session_id(), Some(ready[1]));
    assert_eq!(state.session_pool_snapshot().pool.ready, 0);
    assert_eq!(state.session_pool_snapshot().metrics.normal_handoffs, 2);
}

mod capacity_tests;
mod session_fallback;
