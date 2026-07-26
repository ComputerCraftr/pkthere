use super::{
    BufferedPayload, ClientFlowKey, FlowRuntimeState, FlowSessionState, Instant,
    PendingIcmpClientLock, RecoveryPayload, RecoveryPayloadSendCompletion,
    RecoveryPayloadSendLease, RecoveryPayloadSendToken, ReplyIdHandshake, ReplyIdHandshakeBegin,
    ReplyIdHandshakeInvariantError, ResetChallenge, ResetChallengeIssue, ResetRequired, SessionId,
    SessionKey, fresh_nonzero_challenge, handshake, inspect_existing_reset_challenge,
    inspect_stateless_reset_challenge, upstream_reset_matches,
};
#[cfg(test)]
use super::{PacketTraceId, PayloadEvent};

pub(crate) struct UpstreamRecoveryRequest<'a> {
    pub(crate) sequences: &'a crate::net::icmp_sequence::SharedIcmpSequenceState,
    pub(crate) reset: ResetRequired,
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) observed_at: Instant,
    pub(crate) absolute_deadline: Instant,
    pub(crate) started_s: u64,
}

impl FlowRuntimeState {
    #[cfg(test)]
    pub(crate) fn retain_first_upstream_recovery_payload(
        &self,
        session: SessionId,
        sequence: u16,
        event: &PayloadEvent<'_>,
        trace: Option<PacketTraceId>,
        received_at: Instant,
        deadline: Instant,
    ) -> super::RecoveryPayloadRetention {
        if !event.is_user_payload() {
            return super::RecoveryPayloadRetention::Occupied;
        }
        self.retain_owned_upstream_recovery_payload(
            session,
            sequence,
            BufferedPayload::from_event_at(event, trace, received_at),
            deadline,
        )
    }

    pub(crate) fn retain_owned_upstream_recovery_payload(
        &self,
        session: SessionId,
        sequence: u16,
        payload: BufferedPayload,
        deadline: Instant,
    ) -> super::RecoveryPayloadRetention {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if sessions.authority.upstream_leg.transmit != Some(session) {
            return super::RecoveryPayloadRetention::StaleSession;
        }
        if let Some(existing) = sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_ref()
        {
            return if existing.session == session && existing.sequence == sequence {
                super::RecoveryPayloadRetention::AlreadyRetained
            } else {
                super::RecoveryPayloadRetention::Occupied
            };
        }
        if sessions.upstream_recovery.upstream_activation_confirmed {
            return super::RecoveryPayloadRetention::ActivationConfirmed;
        }
        sessions.upstream_recovery.upstream_recovery_payload = Some(RecoveryPayload {
            session,
            sequence,
            deadline,
            send: super::super::recovery_core::RecoverySendCore::new(payload),
        });
        drop(sessions);
        self.invalidate_maintenance_schedule();
        super::RecoveryPayloadRetention::Retained
    }

    pub(crate) fn record_upstream_recovery_send_result(
        &self,
        session: SessionId,
        sequence: u16,
        sent: bool,
        completed_at: Instant,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(recovery) = sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_mut()
        else {
            return Ok(());
        };
        if recovery.session != session || recovery.sequence != sequence {
            return Err(ReplyIdHandshakeInvariantError);
        }
        recovery
            .send
            .record_initial_send_result(sent, completed_at + handshake::retry_backoff(1))?;
        drop(sessions);
        self.invalidate_maintenance_schedule();
        Ok(())
    }

    pub(crate) fn lease_due_upstream_recovery_payload(
        &self,
        now: Instant,
    ) -> Result<Option<RecoveryPayloadSendLease>, ReplyIdHandshakeInvariantError> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(recovery) = sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_mut()
        else {
            return Ok(None);
        };
        if now >= recovery.deadline {
            sessions.upstream_recovery.upstream_recovery_payload = None;
            return Ok(None);
        }
        let Some(lease) = recovery.send.lease_due(recovery.session, now)? else {
            return Ok(None);
        };
        Ok(Some(lease))
    }

    pub(crate) fn prepare_upstream_recovery_payload_send(
        &self,
        token: &RecoveryPayloadSendToken,
        sequence: u16,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(recovery) = sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_mut()
        else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        recovery.sequence = sequence;
        recovery.send.prepare_sequence(token, sequence)
    }

    pub(crate) fn complete_upstream_recovery_payload_send(
        &self,
        lease: RecoveryPayloadSendLease,
        sent: bool,
        completed_at: Instant,
    ) -> Result<RecoveryPayloadSendCompletion, ReplyIdHandshakeInvariantError> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(recovery) = sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_mut()
        else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        let retry = if sent {
            None
        } else {
            let attempt = lease
                .token
                .attempt
                .checked_add(1)
                .ok_or(ReplyIdHandshakeInvariantError)?;
            Some((attempt, completed_at + handshake::retry_backoff(attempt)))
        };
        let decision = recovery.send.complete_send(lease, sent, retry)?;
        if decision.remove {
            sessions.upstream_recovery.upstream_recovery_payload = None;
        }
        Ok(RecoveryPayloadSendCompletion {
            pending_reset: decision.pending_reset,
            timeout_requested: decision.timeout_requested,
        })
    }

    pub(crate) fn issue_client_reset_challenge(
        &self,
        peer_flow: ClientFlowKey,
        context: crate::net::framing_shim::RejectedFrameEvidence,
        now: Instant,
        expires_at: Instant,
    ) -> std::io::Result<ResetChallengeIssue> {
        {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            if expires_at <= now {
                return Ok(ResetChallengeIssue::DifferentConflictPending);
            }
            if sessions.authority.client_flow == Some(peer_flow) {
                if let Some(result) =
                    inspect_existing_reset_challenge(&mut sessions, peer_flow, context, now)
                {
                    return Ok(result);
                }
            } else if sessions.authority.client_flow.is_none() {
                if let Some(result) =
                    inspect_stateless_reset_challenge(&mut sessions, peer_flow, context, now)
                {
                    return Ok(result);
                }
            } else {
                return Ok(ResetChallengeIssue::DifferentConflictPending);
            }
        }

        let fresh_challenge = fresh_nonzero_challenge()?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if expires_at <= now {
            return Ok(ResetChallengeIssue::DifferentConflictPending);
        }
        let challenge = ResetChallenge {
            peer_flow,
            receiver_generation: sessions
                .client_pool
                .client_active_key
                .map(SessionKey::generation),
            context,
            challenge: fresh_challenge,
            expires_at,
            consumed: false,
        };
        if sessions.authority.client_flow == Some(peer_flow) {
            if let Some(result) =
                inspect_existing_reset_challenge(&mut sessions, peer_flow, context, now)
            {
                return Ok(result);
            }
            sessions.reset_recovery.client_reset_challenge = Some(challenge);
        } else if sessions.authority.client_flow.is_none() {
            if let Some(result) =
                inspect_stateless_reset_challenge(&mut sessions, peer_flow, context, now)
            {
                return Ok(result);
            }
            if sessions
                .reset_recovery
                .stateless_client_reset_challenges
                .len()
                == super::MAX_STATELESS_RESET_CHALLENGES
            {
                let Some(earliest) = sessions
                    .reset_recovery
                    .stateless_client_reset_challenges
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, existing)| existing.expires_at)
                    .map(|(index, _)| index)
                else {
                    return Err(std::io::Error::other(
                        "full stateless challenge table had no eviction candidate",
                    ));
                };
                sessions
                    .reset_recovery
                    .stateless_client_reset_challenges
                    .remove(earliest);
            }
            sessions
                .reset_recovery
                .stateless_client_reset_challenges
                .push_back(challenge);
        } else {
            return Ok(ResetChallengeIssue::DifferentConflictPending);
        }
        sessions.reset_recovery.reset_challenges_created = sessions
            .reset_recovery
            .reset_challenges_created
            .saturating_add(1);
        Ok(ResetChallengeIssue::Created(challenge))
    }

    pub(crate) fn reserve_client_reset_response(
        &self,
        peer_flow: ClientFlowKey,
        now: Instant,
        bytes: u32,
    ) -> bool {
        let mut global_budget = match super::global_reset_response_budget().try_lock() {
            Ok(budget) => budget,
            Err(crate::authority::AuthorityTryLockError::WouldBlock) => return false,
            Err(crate::authority::AuthorityTryLockError::Authority(_)) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "global reset-response budget authority is poisoned"
                ));
                return false;
            }
        };
        let mut sessions = match self.sessions.try_lock() {
            Ok(sessions) => sessions,
            Err(crate::authority::AuthorityTryLockError::WouldBlock) => return false,
            Err(crate::authority::AuthorityTryLockError::Authority(_)) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "flow session authority is poisoned during reset-response admission"
                ));
                return false;
            }
        };
        let reserved = if sessions.authority.client_flow == Some(peer_flow) {
            super::ResetResponseBudget::reserve_with(
                &mut global_budget,
                &mut sessions.reset_recovery.client_reset_response_budget,
                now,
                bytes,
            )
        } else if sessions.authority.client_flow.is_none() {
            if let Some(index) = sessions
                .reset_recovery
                .stateless_reset_response_budgets
                .iter()
                .position(|entry| entry.peer_flow == peer_flow)
            {
                let Some(entry) = sessions
                    .reset_recovery
                    .stateless_reset_response_budgets
                    .get_mut(index)
                else {
                    sessions.reset_recovery.reset_responses_rate_limited = sessions
                        .reset_recovery
                        .reset_responses_rate_limited
                        .saturating_add(1);
                    return false;
                };
                let reserved = super::ResetResponseBudget::reserve_with(
                    &mut global_budget,
                    &mut entry.budget,
                    now,
                    bytes,
                );
                if reserved {
                    entry.last_used = now;
                }
                reserved
            } else {
                let eviction = if sessions
                    .reset_recovery
                    .stateless_reset_response_budgets
                    .len()
                    == super::MAX_STATELESS_RESET_CHALLENGES
                {
                    sessions
                        .reset_recovery
                        .stateless_reset_response_budgets
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, entry)| entry.last_used)
                        .map(|(index, _)| index)
                } else {
                    None
                };
                if sessions
                    .reset_recovery
                    .stateless_reset_response_budgets
                    .len()
                    >= super::MAX_STATELESS_RESET_CHALLENGES
                    && eviction.is_none()
                {
                    sessions.reset_recovery.reset_responses_rate_limited = sessions
                        .reset_recovery
                        .reset_responses_rate_limited
                        .saturating_add(1);
                    return false;
                }
                let mut peer_budget = super::ResetResponseBudget::new_at(now);
                let reserved = super::ResetResponseBudget::reserve_with(
                    &mut global_budget,
                    &mut peer_budget,
                    now,
                    bytes,
                );
                if reserved {
                    if let Some(oldest) = eviction {
                        sessions
                            .reset_recovery
                            .stateless_reset_response_budgets
                            .remove(oldest);
                    }
                    sessions
                        .reset_recovery
                        .stateless_reset_response_budgets
                        .push_back(super::StatelessResetResponseBudget {
                            peer_flow,
                            budget: peer_budget,
                            last_used: now,
                        });
                }
                reserved
            }
        } else {
            false
        };
        if reserved {
            true
        } else {
            sessions.reset_recovery.reset_responses_rate_limited = sessions
                .reset_recovery
                .reset_responses_rate_limited
                .saturating_add(1);
            false
        }
    }

    pub(super) fn consume_client_reset_challenge_locked(
        sessions: &mut FlowSessionState,
        pending: PendingIcmpClientLock,
        now: Instant,
    ) -> bool {
        let Some(session_key) = pending.session_key else {
            return false;
        };
        let challenge_location = if sessions
            .reset_recovery
            .client_reset_challenge
            .is_some_and(|challenge| challenge.peer_flow == pending.flow_key)
        {
            None
        } else {
            sessions
                .reset_recovery
                .stateless_client_reset_challenges
                .iter()
                .position(|challenge| challenge.peer_flow == pending.flow_key)
        };
        let Some(mut challenge) =
            challenge_location.map_or(sessions.reset_recovery.client_reset_challenge, |index| {
                sessions
                    .reset_recovery
                    .stateless_client_reset_challenges
                    .get(index)
                    .copied()
            })
        else {
            return false;
        };
        if challenge.consumed
            || now >= challenge.expires_at
            || pending.reset_challenge == 0
            || challenge.challenge.get() != pending.reset_challenge
            || challenge.peer_flow != pending.flow_key
            || pending.reset_evidence != Some(challenge.context)
            || session_key.ordinal() != 0
            || challenge.receiver_generation == Some(session_key.generation())
            || challenge.context.session_id() == session_key.session_id()
        {
            return false;
        }
        challenge.consumed = true;
        match challenge_location {
            None => sessions.reset_recovery.client_reset_challenge = Some(challenge),
            Some(index) => {
                sessions
                    .reset_recovery
                    .stateless_client_reset_challenges
                    .remove(index);
            }
        }
        sessions.client_pool.client_staged_generation = Some(session_key);
        sessions.reset_recovery.reset_challenges_consumed = sessions
            .reset_recovery
            .reset_challenges_consumed
            .saturating_add(1);
        true
    }

    fn preflight_upstream_recovery(
        &self,
        upstream_sequences: &crate::net::icmp_sequence::SharedIcmpSequenceState,
        reset: ResetRequired,
        expected_ack_destination_id: u16,
        now: Instant,
    ) -> Result<
        Option<super::UpstreamSessionRecovery>,
        super::FlowMutationError<ReplyIdHandshakeInvariantError>,
    > {
        {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            if reset.rejected_kind() != crate::net::framing_shim::RejectedFrameKind::Data {
                sessions.reset_recovery.reset_responses_ignored = sessions
                    .reset_recovery
                    .reset_responses_ignored
                    .saturating_add(1);
                return Err(super::FlowMutationError::Operation(
                    ReplyIdHandshakeInvariantError,
                ));
            }
            let evidence = super::upstream_data_evidence(&sessions, upstream_sequences, reset);
            if evidence == crate::net::icmp_sequence::DataSequenceEvidenceState::InFlight {
                let deferred = super::DeferredPeerControl::ResetRequired {
                    control: reset,
                    observed_at: now,
                };
                match upstream_sequences
                    .defer_outbound_data_control(reset.rejected_session(), deferred)
                {
                    crate::net::icmp_sequence::DeferredDataControlOutcome::Deferred => {
                        return Ok(Some(super::UpstreamSessionRecovery::Deferred));
                    }
                    crate::net::icmp_sequence::DeferredDataControlOutcome::Apply(_) => {}
                    crate::net::icmp_sequence::DeferredDataControlOutcome::Rejected => {
                        sessions.reset_recovery.reset_responses_ignored = sessions
                            .reset_recovery
                            .reset_responses_ignored
                            .saturating_add(1);
                        return Ok(Some(super::UpstreamSessionRecovery::Ignored));
                    }
                }
            }
            if !upstream_reset_matches(
                &sessions,
                upstream_sequences,
                reset,
                now,
                expected_ack_destination_id,
            ) {
                sessions.reset_recovery.reset_responses_ignored = sessions
                    .reset_recovery
                    .reset_responses_ignored
                    .saturating_add(1);
                return Err(super::FlowMutationError::Operation(
                    ReplyIdHandshakeInvariantError,
                ));
            }
        }
        Ok(None)
    }

    pub(crate) fn recover_upstream_session_under(
        &self,
        transition: &super::ClientFlowReservation<'_>,
        request: UpstreamRecoveryRequest<'_>,
    ) -> Result<
        super::UpstreamSessionRecovery,
        super::FlowMutationError<ReplyIdHandshakeInvariantError>,
    > {
        let UpstreamRecoveryRequest {
            sequences: upstream_sequences,
            reset,
            expected_ack_destination_id,
            observed_at: now,
            absolute_deadline,
            started_s,
        } = request;
        transition.assert_current().map_err(|error| {
            super::FlowMutationError::Authority(super::FlowAuthorityError::from(error))
        })?;
        if let Some(outcome) = self.preflight_upstream_recovery(
            upstream_sequences,
            reset,
            expected_ack_destination_id,
            now,
        )? {
            return Ok(outcome);
        }
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if !upstream_reset_matches(
            &sessions,
            upstream_sequences,
            reset,
            now,
            expected_ack_destination_id,
        ) {
            sessions.reset_recovery.reset_responses_ignored = sessions
                .reset_recovery
                .reset_responses_ignored
                .saturating_add(1);
            return Err(super::FlowMutationError::Operation(
                ReplyIdHandshakeInvariantError,
            ));
        }
        let Some(mut recovery) = sessions.upstream_recovery.upstream_recovery_payload.take() else {
            return Err(super::FlowMutationError::Operation(
                ReplyIdHandshakeInvariantError,
            ));
        };
        let Some(payload) = recovery.send.take_available_payload() else {
            if !recovery.send.defer_reset(reset) {
                return Err(super::FlowMutationError::Operation(
                    ReplyIdHandshakeInvariantError,
                ));
            }
            sessions.upstream_recovery.upstream_recovery_payload = Some(recovery);
            return Ok(super::UpstreamSessionRecovery::Deferred);
        };
        let rejected_key = sessions
            .upstream_pool
            .upstream_active_key
            .filter(|key| key.session_id() == reset.rejected_session())
            .ok_or(ReplyIdHandshakeInvariantError)?;
        let receiver_generation_matches =
            reset.receiver_generation() == Some(rejected_key.generation());
        if receiver_generation_matches
            && sessions
                .upstream_recovery
                .upstream_same_generation_fallback
                .is_none()
        {
            sessions.upstream_recovery.upstream_same_generation_fallback =
                Some(super::SameGenerationFallback {
                    original_reset: reset,
                    rejected_sessions: vec![rejected_key.session_id()],
                    attempts_remaining: sessions.upstream_pool.session_pool_target,
                    expires_at: absolute_deadline,
                });
        }
        if let Some(fallback) = sessions
            .upstream_recovery
            .upstream_same_generation_fallback
            .as_mut()
            && receiver_generation_matches
            && now < fallback.expires_at
            && fallback.attempts_remaining != 0
            && !fallback
                .rejected_sessions
                .contains(&rejected_key.session_id())
        {
            fallback.rejected_sessions.push(rejected_key.session_id());
        }
        let rejected_sessions = sessions
            .upstream_recovery
            .upstream_same_generation_fallback
            .as_ref()
            .map(|fallback| fallback.rejected_sessions.clone())
            .unwrap_or_default();
        let next_index = receiver_generation_matches
            .then(|| {
                sessions
                    .upstream_recovery
                    .upstream_same_generation_fallback
                    .as_ref()
                    .is_some_and(|fallback| {
                        now < fallback.expires_at && fallback.attempts_remaining != 0
                    })
            })
            .filter(|eligible| *eligible)
            .and_then(|_| {
                sessions
                    .upstream_pool
                    .upstream_ready_sessions
                    .iter()
                    .enumerate()
                    .filter(|(_, ready)| {
                        ready.session_key.generation() == rejected_key.generation()
                            && ready.session_key.ordinal() > rejected_key.ordinal()
                            && !rejected_sessions.contains(&ready.session_key.session_id())
                    })
                    .min_by_key(|(_, ready)| ready.session_key.ordinal())
                    .map(|(index, _)| index)
            });
        if let Some(index) = next_index {
            let next = sessions
                .upstream_pool
                .upstream_ready_sessions
                .remove(index)
                .ok_or(ReplyIdHandshakeInvariantError)?;
            sessions.publish_upstream_pool_change();
            if let Some(fallback) = sessions
                .upstream_recovery
                .upstream_same_generation_fallback
                .as_mut()
            {
                fallback.attempts_remaining = fallback.attempts_remaining.saturating_sub(1);
            }
            recovery.session = next.session_key.session_id();
            recovery.send.restart_retry(payload, now);
            sessions.upstream_recovery.upstream_recovery_payload = Some(recovery);
            sessions.authority.upstream_leg.transmit = Some(next.session_key.session_id());
            sessions.authority.upstream_leg.receive = Some(next.session_key.response_session_id());
            sessions.upstream_pool.upstream_active_key = Some(next.session_key);
            sessions.upstream_recovery.upstream_activation_confirmed = false;
            sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Acked {
                instance: next.session_key.session_id().get(),
            };
            sessions.metrics.normal_handoffs = sessions.metrics.normal_handoffs.saturating_add(1);
            sessions.reset_recovery.reset_responses_accepted = sessions
                .reset_recovery
                .reset_responses_accepted
                .saturating_add(1);
            drop(sessions);
            self.invalidate_flow_authority_under(transition)
                .map_err(super::FlowMutationError::Authority)?;
            return Ok(super::UpstreamSessionRecovery::Recovered {
                handshake: ReplyIdHandshakeBegin::Ignored,
                retired_sessions: vec![rejected_key.session_id()],
            });
        }
        let reset = sessions
            .upstream_recovery
            .upstream_same_generation_fallback
            .as_ref()
            .filter(|fallback| now < fallback.expires_at)
            .map_or(reset, |fallback| fallback.original_reset);
        let mut retired_sessions = Vec::with_capacity(
            1 + sessions.upstream_pool.upstream_ready_sessions.len()
                + sessions.upstream_pool.upstream_reserve_handshakes.len(),
        );
        retired_sessions.push(rejected_key.session_id());
        retired_sessions.extend(
            sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .map(|ready| ready.session_key.session_id()),
        );
        retired_sessions.extend(
            sessions
                .upstream_pool
                .upstream_reserve_handshakes
                .iter()
                .map(|candidate| candidate.session_key.session_id()),
        );
        retired_sessions.sort_unstable_by_key(|session| session.get());
        retired_sessions.dedup();
        let replacement =
            SessionKey::fresh_initial().map_err(|_| ReplyIdHandshakeInvariantError)?;
        let control = sessions
            .upstream_pool
            .take_control_send(now, absolute_deadline)
            .map_err(|_| ReplyIdHandshakeInvariantError)?;
        let buffered_len = payload.payload_len();
        let buffered_trace = payload.trace();
        sessions.invalidate_control_leases();
        sessions.upstream_pool.upstream_ready_sessions.clear();
        sessions.publish_upstream_pool_change();
        sessions.upstream_pool.clear_reserve_handshakes();
        sessions.upstream_pool.upstream_draining_sessions.clear();
        sessions.authority.upstream_leg.transmit = None;
        sessions.upstream_pool.upstream_active_key = None;
        sessions.upstream_recovery.upstream_activation_confirmed = false;
        sessions.upstream_recovery.upstream_same_generation_fallback = None;
        sessions.control.upstream_pending_key = Some(replacement);
        sessions.control.upstream_pending_challenge =
            crate::net::framing_shim::ChallengeControl::new(
                expected_ack_destination_id,
                reset.challenge(),
                reset.receiver_generation(),
                crate::net::framing_shim::RejectedFrameEvidence::Data {
                    session: reset.rejected_session(),
                    sequence: reset.rejected_sequence(),
                },
                replacement,
            );
        sessions.upstream_pool.upstream_pool_generation = Some(replacement.generation());
        sessions.upstream_pool.next_session_ordinal = 1;
        sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance: replacement.session_id().get(),
            started_s,
            absolute_deadline,
            payload,
            control,
        };
        sessions.metrics.generation_rollovers =
            sessions.metrics.generation_rollovers.saturating_add(1);
        sessions.reset_recovery.reset_responses_accepted = sessions
            .reset_recovery
            .reset_responses_accepted
            .saturating_add(1);
        drop(sessions);
        self.invalidate_flow_authority_under(transition)
            .map_err(super::FlowMutationError::Authority)?;
        Ok(super::UpstreamSessionRecovery::Recovered {
            handshake: ReplyIdHandshakeBegin::Started {
                expected_ack_destination_id,
                instance: replacement.session_id().get(),
                buffered_len,
                buffered_trace,
            },
            retired_sessions,
        })
    }
}
