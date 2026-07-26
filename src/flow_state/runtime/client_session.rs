use super::{
    ExpiredPendingIcmpClientLock, FlowPhase, FlowRuntimeState, Instant,
    MAX_RECEIVE_SESSION_CANDIDATES, PacketTraceId, PendingIcmpClientLock,
    PendingIcmpClientLockMismatch, PendingIcmpClientLockSet, ReceiveCandidate, SessionId,
    SessionKey, TimedPendingIcmpClientLock, push_draining_session,
};
use crate::flow_state::ControlTransactionKey;

impl FlowRuntimeState {
    pub(crate) fn set_pending_icmp_client_lock_until(
        &self,
        pending: PendingIcmpClientLock,
        started_s: u64,
        trace: PacketTraceId,
        acknowledge_sequence: u16,
        observed_at: Instant,
        deadline: Instant,
    ) -> Result<PendingIcmpClientLockSet, PendingIcmpClientLockMismatch> {
        let Some(inbound) = pending.listener_flow.inbound else {
            return Err(PendingIcmpClientLockMismatch);
        };
        let observed_control = pending
            .full_observed_control()
            .ok_or(PendingIcmpClientLockMismatch)?;
        if observed_control.session_id()
            != pending.session_id().ok_or(PendingIcmpClientLockMismatch)?
        {
            return Err(PendingIcmpClientLockMismatch);
        }
        let transaction_key = ControlTransactionKey::new(
            self.flow_epoch(),
            true,
            Some(pending.flow_key),
            crate::net::payload::IcmpPayloadMeta::new_control(
                inbound.src.id(),
                inbound.dst.id(),
                acknowledge_sequence,
                observed_control,
            ),
        );
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if sessions.authority.flow == FlowPhase::Active {
            super::session_pool::expire_receive_candidates(
                &mut sessions,
                self.flow_epoch(),
                observed_at,
                &self.control_observations,
            );
            let Some(session_key) = pending.session_key else {
                return Err(PendingIcmpClientLockMismatch);
            };
            let session_id = session_key.session_id();
            if sessions.authority.client_leg.receive == Some(session_id)
                || sessions
                    .client_pool
                    .client_ready_sessions
                    .iter()
                    .any(|candidate| {
                        candidate.session_key == session_key && candidate.is_live_at(observed_at)
                    })
                || sessions
                    .client_pool
                    .client_draining_sessions
                    .iter()
                    .any(|draining| draining.session_key == session_key)
            {
                return Ok(PendingIcmpClientLockSet::Reused);
            }
            let conflicting_generation = sessions
                .client_pool
                .client_active_key
                .is_some_and(|active| active.generation() != session_key.generation());
            let generation_advance_authorized = conflicting_generation
                && session_key.ordinal() == 0
                && sessions
                    .client_pool
                    .client_generation_authorization
                    .is_some_and(|authorization| {
                        observed_at < authorization.expires_at
                            && sessions.client_pool.client_active_key == Some(authorization.current)
                            && session_key.generation() == authorization.proposed_generation
                    });
            if (conflicting_generation
                && !generation_advance_authorized
                && !Self::consume_client_reset_challenge_locked(
                    &mut sessions,
                    pending,
                    observed_at,
                ))
                || sessions
                    .client_pool
                    .client_active_key
                    .is_some_and(|active| {
                        active.generation() == session_key.generation()
                            && session_key.ordinal() <= active.ordinal()
                    })
                || sessions
                    .client_pool
                    .client_retired_ordinals
                    .is_retired(session_key.ordinal())
            {
                return Err(PendingIcmpClientLockMismatch);
            }
            if generation_advance_authorized {
                sessions.client_pool.client_generation_authorization = None;
                sessions.client_pool.client_staged_generation = Some(session_key);
            }
            if sessions.client_pool.client_ready_sessions.len() == MAX_RECEIVE_SESSION_CANDIDATES {
                let Some((oldest_index, _)) = sessions
                    .client_pool
                    .client_ready_sessions
                    .iter()
                    .enumerate()
                    .filter_map(|(index, candidate)| {
                        candidate
                            .ready_installation_order()
                            .map(|order| (index, order))
                    })
                    .min_by_key(|(_, order)| *order)
                else {
                    return Err(PendingIcmpClientLockMismatch);
                };
                let evicted = sessions
                    .client_pool
                    .client_ready_sessions
                    .swap_remove(oldest_index);
                if sessions
                    .client_pool
                    .client_retired_ordinals
                    .retire_exact(evicted.session_key.ordinal())
                    .is_err()
                {
                    sessions.metrics.sparse_retirement_exhaustions = sessions
                        .metrics
                        .sparse_retirement_exhaustions
                        .saturating_add(1);
                    return Err(PendingIcmpClientLockMismatch);
                }
                sessions.metrics.stale_session_evictions =
                    sessions.metrics.stale_session_evictions.saturating_add(1);
            }
            sessions
                .client_pool
                .client_ready_sessions
                .push(ReceiveCandidate::negotiating(
                    session_key,
                    transaction_key,
                    deadline,
                ));
            return Ok(PendingIcmpClientLockSet::Started);
        }
        match &mut sessions.authority.pending_icmp_client_lock {
            Some(existing) if existing.candidate != pending => Err(PendingIcmpClientLockMismatch),
            Some(existing) if observed_at < existing.deadline => {
                Ok(PendingIcmpClientLockSet::Reused)
            }
            Some(_) => Err(PendingIcmpClientLockMismatch),
            None => {
                if pending.reset_challenge != 0
                    && !Self::consume_client_reset_challenge_locked(
                        &mut sessions,
                        pending,
                        observed_at,
                    )
                {
                    return Err(PendingIcmpClientLockMismatch);
                }
                sessions.authority.pending_icmp_client_lock = Some(TimedPendingIcmpClientLock {
                    candidate: pending,
                    transaction_key,
                    started_s,
                    trace,
                    deadline,
                });
                Ok(PendingIcmpClientLockSet::Started)
            }
        }
    }

    pub(crate) fn begin_client_candidate_ack_send(
        &self,
        session_key: SessionKey,
        observed_at: Instant,
    ) -> Result<Option<super::ClientCandidateAckLease>, PendingIcmpClientLockMismatch> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(index) = sessions
            .client_pool
            .client_ready_sessions
            .iter()
            .position(|candidate| candidate.session_key == session_key)
        else {
            return if sessions.client_pool.client_active_key == Some(session_key) {
                Ok(None)
            } else {
                Err(PendingIcmpClientLockMismatch)
            };
        };
        let pool = &mut sessions.client_pool;
        let permit = pool.client_ready_sessions[index]
            .begin_ack_send(observed_at, &mut pool.next_receive_installation_order)?;
        Ok(permit.map(|permit| super::ClientCandidateAckLease {
            session_key,
            permit,
        }))
    }

    pub(crate) fn complete_client_candidate_ack_send(
        &self,
        lease: super::ClientCandidateAckLease,
        sent: bool,
    ) -> Result<(), PendingIcmpClientLockMismatch> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let Some(index) = sessions
            .client_pool
            .client_ready_sessions
            .iter()
            .position(|candidate| candidate.session_key == lease.session_key)
        else {
            return if sessions.client_pool.client_active_key == Some(lease.session_key) {
                Ok(())
            } else {
                Err(PendingIcmpClientLockMismatch)
            };
        };
        sessions.client_pool.client_ready_sessions[index].complete_ack_send(lease.permit, sent)
    }

    #[inline]
    pub(crate) fn clear_pending_icmp_client_lock_under(
        &self,
        transition: &super::ClientFlowReservation<'_>,
    ) -> Result<Option<SessionId>, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let session =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
                .authority
                .pending_icmp_client_lock
                .take()
                .and_then(|pending| pending.candidate.session_id());
        if session.is_some() {
            self.invalidate_flow_authority_under(transition)?;
        }
        Ok(session)
    }

    fn promote_pending_icmp_client_session(
        &self,
        candidate: PendingIcmpClientLock,
        drain_until: Instant,
    ) -> Result<SessionId, PendingIcmpClientLockMismatch> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if sessions.authority.flow != FlowPhase::Active {
            return Err(PendingIcmpClientLockMismatch);
        }
        let Some(session_key) = candidate.session_key else {
            return Err(PendingIcmpClientLockMismatch);
        };
        let session_id = session_key.session_id();
        let pending_matches = sessions
            .authority
            .pending_icmp_client_lock
            .is_some_and(|pending| pending.candidate == candidate);
        let Some(ready_index) = sessions
            .client_pool
            .client_ready_sessions
            .iter()
            .position(|ready| ready.session_key == session_key)
        else {
            if !pending_matches {
                return Err(PendingIcmpClientLockMismatch);
            }
            if let Some(previous) = sessions.client_pool.client_active_key
                && previous != session_key
                && push_draining_session(
                    &mut sessions.client_pool.client_draining_sessions,
                    previous,
                    drain_until,
                )
            {
                sessions.metrics.stale_session_evictions =
                    sessions.metrics.stale_session_evictions.saturating_add(1);
            }
            sessions.authority.client_leg.receive = Some(session_id);
            sessions.authority.client_leg.transmit = Some(session_key.response_session_id());
            sessions.client_pool.client_active_key = Some(session_key);
            sessions.authority.pending_icmp_client_lock = None;
            return Ok(session_id);
        };
        sessions
            .client_pool
            .client_ready_sessions
            .swap_remove(ready_index);
        if let Some(previous) = sessions.client_pool.client_active_key
            && previous != session_key
            && push_draining_session(
                &mut sessions.client_pool.client_draining_sessions,
                previous,
                drain_until,
            )
        {
            sessions.metrics.stale_session_evictions =
                sessions.metrics.stale_session_evictions.saturating_add(1);
        }
        sessions.authority.client_leg.receive = Some(session_id);
        sessions.authority.client_leg.transmit = Some(session_key.response_session_id());
        sessions.client_pool.client_active_key = Some(session_key);
        Ok(session_id)
    }

    pub(crate) fn promote_pending_icmp_client_session_with_replay_under(
        &self,
        transition: &super::ClientFlowReservation<'_>,
        candidate: PendingIcmpClientLock,
        drain_until: Instant,
        sequence_state: &crate::net::icmp_sequence::SharedIcmpSequenceState,
        sequence_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    ) -> Result<SessionId, super::FlowMutationError<PendingIcmpClientLockMismatch>> {
        transition.assert_current().map_err(|error| {
            super::FlowMutationError::Authority(super::FlowAuthorityError::from(error))
        })?;
        let session_id = self
            .promote_pending_icmp_client_session(candidate, drain_until)
            .map_err(super::FlowMutationError::Operation)?;
        crate::net::icmp_sequence::activate_receive_session(
            sequence_state,
            sequence_cache,
            session_id,
        );
        self.invalidate_flow_authority_under(transition)
            .map_err(super::FlowMutationError::Authority)?;
        Ok(session_id)
    }

    #[cfg(test)]
    pub(crate) fn expire_pending_icmp_client_lock(
        &self,
        now: Instant,
    ) -> Option<ExpiredPendingIcmpClientLock> {
        self.expire_pending_icmp_client_lock_inner(now)
    }

    pub(crate) fn expire_pending_icmp_client_lock_under(
        &self,
        transition: &super::ClientFlowReservation<'_>,
        now: Instant,
    ) -> Result<Option<ExpiredPendingIcmpClientLock>, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let expired = self.expire_pending_icmp_client_lock_inner(now);
        if expired.is_some() {
            self.invalidate_flow_authority_under(transition)?;
        }
        Ok(expired)
    }

    fn expire_pending_icmp_client_lock_inner(
        &self,
        now: Instant,
    ) -> Option<ExpiredPendingIcmpClientLock> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let pending = sessions.authority.pending_icmp_client_lock?;
        if now < pending.deadline {
            return None;
        }
        if self
            .control_observations
            .blocks_exact_key(pending.transaction_key, pending.deadline)
        {
            return None;
        }
        sessions.authority.pending_icmp_client_lock = None;
        Some(ExpiredPendingIcmpClientLock {
            candidate: pending.candidate,
            started_s: pending.started_s,
            trace: pending.trace,
        })
    }
}
