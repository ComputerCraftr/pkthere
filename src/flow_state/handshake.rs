use super::session_lifecycles::ControlSendCore;
use super::{
    BufferedPayload, FlowSessionState, HANDSHAKE_RETRY_BASE, HANDSHAKE_RETRY_MAX,
    MAX_HANDSHAKE_RETRY_ATTEMPTS, PacketTraceId, ReplyIdControlSendCompletion,
    ReplyIdControlSendLease, ReplyIdHandshake, ReplyIdHandshakeAck, ReplyIdHandshakeAckIgnored,
    ReplyIdHandshakeActivationLease, ReplyIdHandshakeBegin, ReplyIdHandshakeCommitToken,
    ReplyIdHandshakeInvariantError, ReplyIdHandshakeManagerReceipt,
    ReplyIdHandshakeTransitionError, ReplyIdPayloadSendLease, SessionId, SessionKey,
};
type SessionAuthority =
    crate::authority::AuthorityMutex<crate::authority::tags::SessionControl, FlowSessionState>;
use std::time::{Duration, Instant};

pub(super) mod commit_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod commit_core_loom;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod control_send_core_loom;
mod payload_send;
mod sequence_record;

pub(super) use payload_send::{
    complete_handshake_send, lease_due_handshake_payload, release_handshake_send,
};
pub(super) use sequence_record::record_handshake_control_sequence;

pub(crate) struct PreparedControlSend {
    pub(super) core: ControlSendCore,
}

impl PreparedControlSend {
    pub(crate) fn new(now: Instant, deadline: Instant) -> Self {
        Self {
            core: ControlSendCore::new(now, deadline),
        }
    }
}

pub(crate) struct PreparedReplyIdHandshake {
    pub(super) expected_ack_destination_id: u16,
    pub(super) session_key: SessionKey,
    pub(super) started_s: u64,
    pub(super) absolute_deadline: Instant,
    pub(super) control: PreparedControlSend,
}

impl PreparedReplyIdHandshake {
    pub(crate) fn new(
        expected_ack_destination_id: u16,
        session_key: SessionKey,
        started_s: u64,
        absolute_deadline: Instant,
        now: Instant,
    ) -> Self {
        Self {
            expected_ack_destination_id,
            session_key,
            started_s,
            absolute_deadline,
            control: PreparedControlSend::new(now, absolute_deadline),
        }
    }
}

pub(super) struct HandshakeStart {
    pub(super) expected_ack_destination_id: u16,
    pub(super) session_key: SessionKey,
    pub(super) started_s: u64,
    pub(super) absolute_deadline: Instant,
    pub(super) trigger_trace: Option<PacketTraceId>,
    pub(super) control: ControlSendCore,
}

pub(super) fn begin_handshake(
    state: &SessionAuthority,
    start: HandshakeStart,
    payload: &mut Option<BufferedPayload>,
) -> ReplyIdHandshakeBegin {
    let HandshakeStart {
        expected_ack_destination_id,
        session_key,
        started_s,
        absolute_deadline,
        trigger_trace,
        control,
    } = start;
    let instance = session_key.session_id().get();
    if expected_ack_destination_id == 0 {
        return ReplyIdHandshakeBegin::Ignored;
    }
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let guard = &mut sessions.control.upstream_reply_id_handshake;
    if matches!(
        *guard,
        ReplyIdHandshake::Sending { .. }
            | ReplyIdHandshake::AckedRetryable { .. }
            | ReplyIdHandshake::Acked { .. }
    ) {
        return ReplyIdHandshakeBegin::Ignored;
    }
    match *guard {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id: old_expected_ack_destination_id,
            instance: old_instance,
            started_s: old_started_s,
            payload: ref old_payload,
            ..
        } => ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id: old_expected_ack_destination_id,
            instance: old_instance,
            started_s: old_started_s,
            buffered_len: old_payload.payload_len(),
            buffered_trace: old_payload.trace(),
            trigger_trace,
        },
        ReplyIdHandshake::NotRequired => {
            let payload = payload.take().unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "reply-ID handshake payload ownership disappeared before session commit"
                ))
            });
            let buffered_len = payload.payload_len();
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
                payload,
                control,
            };
            sessions.control.upstream_pending_key = Some(session_key);
            sessions.control.upstream_pending_challenge = None;
            ReplyIdHandshakeBegin::Started {
                expected_ack_destination_id,
                instance,
                buffered_len,
                buffered_trace,
            }
        }
        ReplyIdHandshake::Committing { .. }
        | ReplyIdHandshake::Sending { .. }
        | ReplyIdHandshake::AckedRetryable { .. }
        | ReplyIdHandshake::Acked { .. } => ReplyIdHandshakeBegin::Ignored,
    }
}

pub(super) fn ack_handshake(
    state: &SessionAuthority,
    observed_ack_destination_id: u16,
    observed_key: SessionKey,
    observed_sequence: u16,
    observed_challenge: Option<crate::net::framing_shim::ChallengeControl>,
    observed_at: Instant,
    trigger_trace: Option<PacketTraceId>,
) -> ReplyIdHandshakeAck {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let observed_instance = observed_key.session_id().get();
    if let Some(index) = sessions
        .upstream_pool
        .upstream_reserve_handshakes
        .iter()
        .position(|candidate| candidate.session_key == observed_key)
    {
        let candidate = &sessions.upstream_pool.upstream_reserve_handshakes[index];
        if candidate.expected_ack_destination_id != observed_ack_destination_id {
            return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id: candidate.expected_ack_destination_id,
                buffered_trace: None,
                trigger_trace,
            });
        }
        if candidate.challenge != observed_challenge {
            return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongInstance {
                expected_instance: candidate.session_key.session_id().get(),
                observed_instance,
                buffered_trace: None,
                trigger_trace,
            });
        }
        if observed_at >= candidate.control.deadline() {
            return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::Expired {
                buffered_trace: None,
                trigger_trace,
            });
        }
        if !candidate.control.acknowledges(observed_sequence) {
            return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::UnsentSequence {
                observed_sequence,
                buffered_trace: None,
                trigger_trace,
            });
        }
        let candidate = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .remove(index);
        let super::ReserveReplyIdHandshake {
            expected_ack_destination_id,
            session_key,
            started_at,
            control,
            ..
        } = candidate;
        sessions.upstream_pool.recycle_control_send(control);
        sessions.metrics.candidate_negotiation_latency_ns_total = sessions
            .metrics
            .candidate_negotiation_latency_ns_total
            .saturating_add(observed_at.saturating_duration_since(started_at).as_nanos());
        sessions.metrics.candidate_negotiations_completed = sessions
            .metrics
            .candidate_negotiations_completed
            .saturating_add(1);
        let ready = super::ReadySession { session_key };
        let insert_at = sessions
            .upstream_pool
            .upstream_ready_sessions
            .iter()
            .position(|existing| existing.session_key.ordinal() > ready.session_key.ordinal())
            .unwrap_or(sessions.upstream_pool.upstream_ready_sessions.len());
        sessions
            .upstream_pool
            .upstream_ready_sessions
            .insert(insert_at, ready);
        sessions.publish_upstream_pool_change();
        return ReplyIdHandshakeAck::ReserveReady {
            instance: session_key.session_id().get(),
            expected_ack_destination_id,
            trigger_trace,
        };
    }
    if sessions
        .upstream_pool
        .upstream_ready_sessions
        .iter()
        .any(|session| session.session_key == observed_key)
    {
        return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked {
            trigger_trace,
        });
    }
    let expected_pending_key = sessions.control.upstream_pending_key;
    let expected_pending_challenge = sessions.control.upstream_pending_challenge;
    if let ReplyIdHandshake::Pending {
        expected_ack_destination_id,
        instance,
        absolute_deadline,
        payload,
        ..
    } = &sessions.control.upstream_reply_id_handshake
        && *expected_ack_destination_id == observed_ack_destination_id
        && *instance == observed_instance
        && expected_pending_key == Some(observed_key)
        && expected_pending_challenge == observed_challenge
        && observed_at >= *absolute_deadline
    {
        return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::Expired {
            buffered_trace: payload.trace(),
            trigger_trace,
        });
    }
    let guard = &mut sessions.control.upstream_reply_id_handshake;
    match std::mem::replace(guard, ReplyIdHandshake::NotRequired) {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            payload,
            started_s,
            absolute_deadline,
            control,
            ..
        } if expected_ack_destination_id == observed_ack_destination_id
            && instance == observed_instance
            && expected_pending_key == Some(observed_key)
            && expected_pending_challenge == observed_challenge
            && control.acknowledges(observed_sequence) =>
        {
            let token = ReplyIdHandshakeCommitToken { instance };
            let buffered_len = payload.payload_len();
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Committing {
                commit: commit_core::HandshakeCommitCore::new(instance, payload),
                control,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
            };
            ReplyIdHandshakeAck::Matched {
                token,
                instance,
                expected_ack_destination_id,
                buffered_len,
                buffered_trace,
                trigger_trace,
            }
        }
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            payload,
            started_s,
            absolute_deadline,
            control,
        } if expected_ack_destination_id != observed_ack_destination_id => {
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                instance,
                payload,
                started_s,
                absolute_deadline,
                control,
            };
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id,
                buffered_trace,
                trigger_trace,
            })
        }
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            payload,
            started_s,
            absolute_deadline,
            control,
        } => {
            let buffered_trace = payload.trace();
            *guard = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                instance,
                payload,
                started_s,
                absolute_deadline,
                control,
            };
            if instance == observed_instance
                && expected_pending_key == Some(observed_key)
                && expected_pending_challenge == observed_challenge
            {
                ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::UnsentSequence {
                    observed_sequence,
                    buffered_trace,
                    trigger_trace,
                })
            } else {
                ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongInstance {
                    expected_instance: instance,
                    observed_instance,
                    buffered_trace,
                    trigger_trace,
                })
            }
        }
        committing @ ReplyIdHandshake::Committing { .. } => {
            *guard = committing;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::CommitInProgress {
                trigger_trace,
            })
        }
        pending_send @ ReplyIdHandshake::Sending { .. } => {
            *guard = pending_send;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::CommitInProgress {
                trigger_trace,
            })
        }
        acked @ (ReplyIdHandshake::AckedRetryable { .. } | ReplyIdHandshake::Acked { .. }) => {
            *guard = acked;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::AlreadyAcked { trigger_trace })
        }
        ReplyIdHandshake::NotRequired => {
            *guard = ReplyIdHandshake::NotRequired;
            ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::NoPending { trigger_trace })
        }
    }
}

pub(super) fn mark_handshake_manager_published(
    state: &SessionAuthority,
    token: ReplyIdHandshakeCommitToken,
) -> Result<ReplyIdHandshakeManagerReceipt, ReplyIdHandshakeTransitionError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    match &mut sessions.control.upstream_reply_id_handshake {
        ReplyIdHandshake::Committing { commit, .. } => commit
            .manager_published(token.instance)
            .map_err(map_commit_transition_error),
        _ => Err(ReplyIdHandshakeTransitionError::InvalidPhase),
    }
}

struct HandshakeSessionPublication<'a> {
    sessions: &'a mut super::FlowSessionState,
}

impl commit_core::HandshakeSessionPublication for HandshakeSessionPublication<'_> {
    type Output = ();

    fn publish_session(&mut self, instance: u64) {
        self.sessions.authority.upstream_leg.transmit = SessionId::new(instance);
        self.sessions
            .upstream_recovery
            .upstream_activation_confirmed = false;
        self.sessions.upstream_pool.upstream_active_key =
            self.sessions.control.upstream_pending_key.take();
        self.sessions.authority.upstream_leg.receive = self
            .sessions
            .upstream_pool
            .upstream_active_key
            .map(SessionKey::response_session_id);
        self.sessions.control.upstream_pending_challenge = None;
        self.sessions.upstream_pool.upstream_pool_generation = self
            .sessions
            .upstream_pool
            .upstream_active_key
            .map(SessionKey::generation);
    }

    fn finish(self) {}
}

pub(super) fn commit_handshake_session(
    state: &SessionAuthority,
    receipt: ReplyIdHandshakeManagerReceipt,
) -> Result<ReplyIdHandshakeActivationLease, ReplyIdHandshakeTransitionError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let previous = std::mem::replace(
        &mut sessions.control.upstream_reply_id_handshake,
        ReplyIdHandshake::NotRequired,
    );
    match previous {
        ReplyIdHandshake::Committing {
            mut commit,
            control,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            ..
        } => {
            let publication = HandshakeSessionPublication {
                sessions: &mut sessions,
            };
            let activation = match commit.commit_session(receipt, publication) {
                Ok((activation, ())) => activation,
                Err(error) => {
                    sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Committing {
                        commit,
                        control,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                    };
                    return Err(map_commit_transition_error(error));
                }
            };
            sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Committing {
                commit,
                control,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
            };
            Ok(activation)
        }
        other => {
            sessions.control.upstream_reply_id_handshake = other;
            Err(ReplyIdHandshakeTransitionError::InvalidPhase)
        }
    }
}

pub(super) fn complete_handshake_activation(
    state: &SessionAuthority,
    activation: ReplyIdHandshakeActivationLease,
) -> Result<ReplyIdPayloadSendLease, ReplyIdHandshakeTransitionError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let previous = std::mem::replace(
        &mut sessions.control.upstream_reply_id_handshake,
        ReplyIdHandshake::NotRequired,
    );
    match previous {
        ReplyIdHandshake::Committing {
            mut commit,
            control,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
        } => {
            let lease = match commit.begin_send(activation) {
                Ok(lease) => lease,
                Err(error) => {
                    sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Committing {
                        commit,
                        control,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                    };
                    return Err(map_commit_transition_error(error));
                }
            };
            sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Sending {
                commit,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
                attempts: 1,
            };
            drop(sessions);
            drop(control);
            Ok(lease)
        }
        other => {
            sessions.control.upstream_reply_id_handshake = other;
            Err(ReplyIdHandshakeTransitionError::InvalidPhase)
        }
    }
}

pub(super) fn poison_handshake_activation(
    state: &SessionAuthority,
    activation: ReplyIdHandshakeActivationLease,
) -> Result<(), ReplyIdHandshakeTransitionError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    match &mut sessions.control.upstream_reply_id_handshake {
        ReplyIdHandshake::Committing { commit, .. } => commit
            .poison_after_session_commit(activation)
            .map_err(map_commit_transition_error),
        _ => Err(ReplyIdHandshakeTransitionError::InvalidPhase),
    }
}

pub(super) fn rollback_handshake(
    state: &SessionAuthority,
    token: ReplyIdHandshakeCommitToken,
    now: Instant,
) -> Result<super::HandshakeRollbackOutcome, ReplyIdHandshakeTransitionError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let guard = &mut sessions.control.upstream_reply_id_handshake;
    let previous = std::mem::replace(guard, ReplyIdHandshake::NotRequired);
    match previous {
        ReplyIdHandshake::Committing {
            mut commit,
            mut control,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            ..
        } => {
            let decision = match commit.rollback(token.instance, now >= absolute_deadline) {
                Ok(decision) => decision,
                Err(error) => {
                    *guard = ReplyIdHandshake::Committing {
                        commit,
                        control,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                    };
                    return Err(map_commit_transition_error(error));
                }
            };
            match decision {
                commit_core::HandshakeRollbackDecision::ResetApplied(payload) => {
                    sessions.authority.upstream_leg.transmit = None;
                    drop(sessions);
                    drop(control);
                    Ok(super::HandshakeRollbackOutcome::ResetApplied { payload })
                }
                commit_core::HandshakeRollbackDecision::TimedOut(payload) => {
                    sessions.authority.upstream_leg.transmit = None;
                    drop(sessions);
                    drop(control);
                    Ok(super::HandshakeRollbackOutcome::TimedOut { payload })
                }
                commit_core::HandshakeRollbackDecision::Retryable(payload) => {
                    control.reset_for_new_transaction(now, absolute_deadline);
                    *guard = ReplyIdHandshake::Pending {
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                        payload,
                        control,
                    };
                    Ok(super::HandshakeRollbackOutcome::Retryable)
                }
            }
        }
        other => {
            *guard = other;
            Err(ReplyIdHandshakeTransitionError::InvalidPhase)
        }
    }
}

fn map_commit_transition_error(
    error: commit_core::HandshakeCommitCoreError,
) -> ReplyIdHandshakeTransitionError {
    match error {
        commit_core::HandshakeCommitCoreError::InvalidPhase => {
            ReplyIdHandshakeTransitionError::InvalidPhase
        }
        commit_core::HandshakeCommitCoreError::StaleToken => {
            ReplyIdHandshakeTransitionError::StaleToken
        }
    }
}

pub(super) fn lease_due_handshake_control(
    state: &SessionAuthority,
    now: Instant,
) -> Result<Option<ReplyIdControlSendLease>, ReplyIdHandshakeInvariantError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    if sessions.control.control_lease_epoch_exhausted {
        return Err(ReplyIdHandshakeInvariantError);
    }
    let control_lease_epoch = sessions.control.control_lease_epoch;
    let pending_session_key = sessions.control.upstream_pending_key;
    let pending_challenge = sessions.control.upstream_pending_challenge;
    if let ReplyIdHandshake::Pending {
        expected_ack_destination_id,
        instance,
        control,
        ..
    } = &mut sessions.control.upstream_reply_id_handshake
    {
        let session_id = SessionId::new(*instance).ok_or(ReplyIdHandshakeInvariantError)?;
        let session_key = pending_session_key.ok_or(ReplyIdHandshakeInvariantError)?;
        if session_key.session_id() != session_id {
            return Err(ReplyIdHandshakeInvariantError);
        }
        let wire_control = pending_challenge.map_or_else(
            || {
                crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key(
                    *expected_ack_destination_id,
                    session_key,
                )
                .map(crate::net::framing_shim::IcmpTunnelControl::Negotiate)
            },
            |challenge| {
                Some(crate::net::framing_shim::IcmpTunnelControl::ChallengeNegotiate(challenge))
            },
        );
        let wire_control = wire_control.ok_or(ReplyIdHandshakeInvariantError)?;
        if let Some(attempt) = control.lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)? {
            return Ok(Some(ReplyIdControlSendLease {
                expected_ack_destination_id: *expected_ack_destination_id,
                session_key,
                session_id,
                reset_challenge: pending_challenge
                    .map_or(0, |challenge| challenge.challenge().get()),
                control: wire_control,
                control_lease_epoch,
                attempt,
                reserve: false,
                generation_advance: false,
            }));
        }
    }
    if let Some(advance) = sessions.upstream_pool.upstream_generation_advance.as_mut()
        && let Some(attempt) = advance
            .control
            .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)?
    {
        let control = crate::net::framing_shim::IcmpTunnelControl::GenerationAdvance(
            crate::net::framing_shim::GenerationAdvance::new(
                advance.current,
                advance.proposed_key.generation(),
            ),
        );
        return Ok(Some(ReplyIdControlSendLease {
            expected_ack_destination_id: advance.expected_ack_destination_id,
            session_key: advance.current,
            session_id: advance.current.session_id(),
            reset_challenge: 0,
            control,
            control_lease_epoch,
            attempt,
            reserve: false,
            generation_advance: true,
        }));
    }
    let Some(candidate_index) = sessions
        .upstream_pool
        .upstream_reserve_handshakes
        .iter()
        .position(|candidate| candidate.control.is_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS))
    else {
        return Ok(None);
    };
    let candidate = &mut sessions.upstream_pool.upstream_reserve_handshakes[candidate_index];
    let wire_control = candidate.challenge.map_or_else(
        || {
            crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key(
                candidate.expected_ack_destination_id,
                candidate.session_key,
            )
            .map(crate::net::framing_shim::IcmpTunnelControl::Negotiate)
        },
        |challenge| {
            Some(crate::net::framing_shim::IcmpTunnelControl::ChallengeNegotiate(challenge))
        },
    );
    let wire_control = wire_control.ok_or(ReplyIdHandshakeInvariantError)?;
    let attempt = candidate
        .control
        .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)?
        .ok_or(ReplyIdHandshakeInvariantError)?;
    let lease = ReplyIdControlSendLease {
        expected_ack_destination_id: candidate.expected_ack_destination_id,
        session_key: candidate.session_key,
        session_id: candidate.session_key.session_id(),
        reset_challenge: candidate
            .challenge
            .map_or(0, |challenge| challenge.challenge().get()),
        control: wire_control,
        control_lease_epoch,
        attempt,
        reserve: true,
        generation_advance: false,
    };
    sessions.metrics.candidate_retry_attempts =
        sessions.metrics.candidate_retry_attempts.saturating_add(1);
    Ok(Some(lease))
}

pub(super) fn complete_handshake_control_send(
    state: &SessionAuthority,
    lease: ReplyIdControlSendLease,
    sequence: u16,
    sent: bool,
    completed_at: Instant,
) -> Result<ReplyIdControlSendCompletion, ReplyIdHandshakeInvariantError> {
    let attempt_number = lease.attempt.number();
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    if sessions.control.control_lease_epoch_exhausted
        || lease.control_lease_epoch != sessions.control.control_lease_epoch
    {
        return Ok(ReplyIdControlSendCompletion::ResetWon);
    }
    if lease.generation_advance {
        let Some(advance) = sessions.upstream_pool.upstream_generation_advance.as_mut() else {
            return Ok(ReplyIdControlSendCompletion::Stale);
        };
        if advance.current != lease.session_key {
            return Ok(ReplyIdControlSendCompletion::Stale);
        }
        if !advance.control.complete_sequence(
            lease.attempt,
            sequence,
            sent,
            completed_at + retry_backoff(attempt_number),
        )? {
            return Ok(ReplyIdControlSendCompletion::Stale);
        }
        return Ok(ReplyIdControlSendCompletion::RetryScheduled);
    }
    if lease.reserve {
        let candidate_index = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter()
            .position(|candidate| candidate.session_key == lease.session_key);
        if let Some(index) = candidate_index {
            let matches = sessions.upstream_pool.upstream_reserve_handshakes[index]
                .expected_ack_destination_id
                == lease.expected_ack_destination_id;
            if matches {
                let candidate = &mut sessions.upstream_pool.upstream_reserve_handshakes[index];
                if !candidate.control.complete_sequence(
                    lease.attempt,
                    sequence,
                    sent,
                    completed_at + retry_backoff(attempt_number),
                )? {
                    return Ok(ReplyIdControlSendCompletion::Stale);
                }
                return Ok(ReplyIdControlSendCompletion::RetryScheduled);
            }
            return Ok(ReplyIdControlSendCompletion::Stale);
        }
        return Ok(
            if sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .any(|session| session.session_key == lease.session_key)
            {
                ReplyIdControlSendCompletion::HandshakeAdvanced
            } else {
                ReplyIdControlSendCompletion::Stale
            },
        );
    }
    Ok(match &mut sessions.control.upstream_reply_id_handshake {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            control,
            ..
        } if *instance == lease.session_id.get()
            && *expected_ack_destination_id == lease.expected_ack_destination_id =>
        {
            if !control.complete_sequence(
                lease.attempt,
                sequence,
                sent,
                completed_at + retry_backoff(attempt_number),
            )? {
                return Ok(ReplyIdControlSendCompletion::Stale);
            }
            ReplyIdControlSendCompletion::RetryScheduled
        }
        ReplyIdHandshake::Committing { instance, .. }
        | ReplyIdHandshake::Sending { instance, .. }
        | ReplyIdHandshake::AckedRetryable { instance, .. }
        | ReplyIdHandshake::Acked { instance }
            if *instance == lease.session_id.get() =>
        {
            ReplyIdControlSendCompletion::HandshakeAdvanced
        }
        _ => ReplyIdControlSendCompletion::Stale,
    })
}

pub(super) fn release_unsequenced_handshake_control(
    state: &SessionAuthority,
    lease: ReplyIdControlSendLease,
    retry_at: Instant,
) -> Result<(), ReplyIdHandshakeInvariantError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    if sessions.control.control_lease_epoch_exhausted
        || lease.control_lease_epoch != sessions.control.control_lease_epoch
    {
        return Ok(());
    }
    if lease.generation_advance {
        let advance = sessions
            .upstream_pool
            .upstream_generation_advance
            .as_mut()
            .ok_or(ReplyIdHandshakeInvariantError)?;
        if advance.current != lease.session_key {
            return Err(ReplyIdHandshakeInvariantError);
        }
        return advance.control.release_unsequenced(lease.attempt, retry_at);
    }
    if lease.reserve {
        let candidate = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter_mut()
            .find(|candidate| candidate.session_key == lease.session_key);
        let Some(candidate) = candidate else {
            return if sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .any(|session| session.session_key == lease.session_key)
            {
                Ok(())
            } else {
                Err(ReplyIdHandshakeInvariantError)
            };
        };
        return candidate
            .control
            .release_unsequenced(lease.attempt, retry_at);
    }
    match &mut sessions.control.upstream_reply_id_handshake {
        ReplyIdHandshake::Pending {
            instance, control, ..
        } if *instance == lease.session_id.get() => {
            control.release_unsequenced(lease.attempt, retry_at)
        }
        ReplyIdHandshake::Committing { instance, .. }
        | ReplyIdHandshake::Sending { instance, .. }
        | ReplyIdHandshake::AckedRetryable { instance, .. }
        | ReplyIdHandshake::Acked { instance }
            if *instance == lease.session_id.get() =>
        {
            Ok(())
        }
        _ => Err(ReplyIdHandshakeInvariantError),
    }
}

pub(super) fn retry_backoff(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(6);
    HANDSHAKE_RETRY_BASE
        .saturating_mul(1_u32 << exponent)
        .min(HANDSHAKE_RETRY_MAX)
}

mod expiry;
pub(super) use expiry::{expire_handshake, take_pending_handshake_locked};
