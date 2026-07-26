use super::{
    ClientFlowReservation, FlowAdmissionSnapshot, FlowPhase, FlowRuntimeState,
    MAX_CONCURRENT_SESSION_CANDIDATES, PendingIcmpClientLockMismatch, ReplyIdHandshake,
    ReplyIdHandshakeInvariantError, ReserveReplyIdHandshake, SessionAdmissionSnapshot, SessionId,
    SessionKey, SessionPoolSnapshot, active_session_count, expire_draining_sessions,
    push_draining_session, session_admission_snapshot,
};
use std::io;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;
mod evidence;
pub(super) use evidence::expire_receive_candidates;
use evidence::{rollover_challenge_is_in_flight, rollover_challenge_matches};

const ORDINAL_ROLLOVER_HEADROOM: u32 =
    (crate::cli::MAX_ICMP_SESSION_POOL_SIZE + MAX_CONCURRENT_SESSION_CANDIDATES) as u32;

impl FlowRuntimeState {
    #[cfg(test)]
    pub(crate) fn admission_snapshot(&self, now: Instant) -> FlowAdmissionSnapshot {
        self.admission_snapshot_under(now)
    }

    pub(crate) fn admission_snapshot_with_read<'cache>(
        &self,
        lease: &super::FlowTopologyReadLease<'_>,
        cache: &'cache mut super::FlowSnapshotCache,
        _now: Instant,
    ) -> Result<&'cache FlowAdmissionSnapshot, super::FlowTopologyError> {
        if !lease.is_current() {
            return Err(super::FlowTopologyError::Busy);
        }
        if cache
            .published
            .as_ref()
            .is_some_and(|published| published.epoch == lease.transaction_epoch())
        {
            return cache
                .published
                .as_ref()
                .map(|published| &published.admission)
                .ok_or(super::FlowTopologyError::OwnershipLost);
        }
        let published = crate::runtime_support::lock_authority_or_shutdown(
            &self.published_admission,
            "published flow admission snapshot",
        );
        if published.epoch != lease.transaction_epoch() {
            let observed_epoch = published.epoch;
            drop(published);
            crate::runtime_support::publish_process_fatal(format_args!(
                "published flow snapshot epoch {observed_epoch} does not match admitted read epoch {}",
                lease.transaction_epoch()
            ));
            return Err(super::FlowTopologyError::OwnershipLost);
        }
        cache.published = Some(*published);
        #[cfg(test)]
        {
            cache.refreshes = cache.refreshes.saturating_add(1);
        }
        drop(published);
        if !lease.is_current() {
            return Err(super::FlowTopologyError::Busy);
        }
        cache
            .published
            .as_ref()
            .map(|published| &published.admission)
            .ok_or(super::FlowTopologyError::OwnershipLost)
    }

    pub(super) fn admission_snapshot_under(&self, _now: Instant) -> FlowAdmissionSnapshot {
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");

        FlowAdmissionSnapshot {
            locked: sessions.authority.flow == FlowPhase::Active,
            client_flow: sessions.authority.client_flow,
            flow_claim_generation: sessions.authority.flow_claim_generation,
            pending_icmp_client_lock: sessions
                .authority
                .pending_icmp_client_lock
                .map(|pending| pending.candidate),
            pending_icmp_client_deadline: sessions
                .authority
                .pending_icmp_client_lock
                .map(|pending| pending.deadline),
            client_active_session_key: sessions.client_pool.client_active_key,
            client_transmit_session_id: sessions.authority.client_leg.transmit,
            client_receive_session_id: sessions.authority.client_leg.receive,
            upstream_receive_session_id: sessions
                .authority
                .upstream_leg
                .receive
                .or(sessions.authority.upstream_leg.transmit),
            upstream_transmit_session_id: sessions.authority.upstream_leg.transmit,
            upstream_reply_id_acked: matches!(
                sessions.control.upstream_reply_id_handshake,
                ReplyIdHandshake::Sending { .. }
                    | ReplyIdHandshake::AckedRetryable { .. }
                    | ReplyIdHandshake::Acked { .. }
            ),
            upstream_handshake_deadline: match sessions.control.upstream_reply_id_handshake {
                ReplyIdHandshake::Pending {
                    absolute_deadline, ..
                }
                | ReplyIdHandshake::Committing {
                    absolute_deadline, ..
                }
                | ReplyIdHandshake::Sending {
                    absolute_deadline, ..
                }
                | ReplyIdHandshake::AckedRetryable {
                    absolute_deadline, ..
                } => Some(absolute_deadline),
                ReplyIdHandshake::NotRequired | ReplyIdHandshake::Acked { .. } => None,
            },
            client_sessions: session_admission_snapshot(
                sessions.authority.client_leg.receive,
                &sessions.client_pool.client_ready_sessions,
                &sessions.client_pool.client_draining_sessions,
            ),
            upstream_sessions: session_admission_snapshot(
                sessions
                    .authority
                    .upstream_leg
                    .receive
                    .or(sessions.authority.upstream_leg.transmit),
                &[],
                &sessions.upstream_pool.upstream_draining_sessions,
            ),
        }
    }

    pub(crate) fn packet_snapshot_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        session_id: Option<SessionId>,
        now: Instant,
    ) -> Result<super::PacketFlowSnapshot, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        Ok(self.admission_snapshot_under(now).for_packet(session_id))
    }

    /// Revalidates a tentative watchdog timeout after the flow gate has closed
    /// and all admitted packet readers have drained.
    pub(crate) fn timeout_due_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        t_start: Instant,
        now: Instant,
        idle_timeout: std::time::Duration,
    ) -> Result<bool, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let snapshot = self.admission_snapshot_under(now);
        Ok(snapshot.locked
            && (snapshot
                .upstream_handshake_deadline
                .is_some_and(|deadline| now >= deadline)
                || self.idle_timeout_reached(t_start, now, idle_timeout)))
    }

    pub(crate) fn authorize_client_generation_advance(
        &self,
        advance: crate::net::framing_shim::GenerationAdvance,
        observed_at: Instant,
        expires_at: Instant,
    ) -> bool {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if sessions.authority.flow != FlowPhase::Active
            || sessions.client_pool.client_active_key != Some(advance.current())
            || advance.proposed_generation() == advance.current().generation()
        {
            return false;
        }
        let requested = super::GenerationAuthorization {
            current: advance.current(),
            proposed_generation: advance.proposed_generation(),
            expires_at,
        };
        match sessions.client_pool.client_generation_authorization {
            Some(existing)
                if existing.current == requested.current
                    && existing.proposed_generation == requested.proposed_generation =>
            {
                observed_at < existing.expires_at
            }
            Some(existing) if observed_at < existing.expires_at => false,
            _ => {
                sessions
                    .client_pool
                    .client_ready_sessions
                    .retain(|candidate| {
                        candidate.session_key.generation() == advance.current().generation()
                            && !candidate.is_negotiating()
                    });
                sessions.client_pool.client_generation_authorization = Some(requested);
                true
            }
        }
    }

    pub(crate) fn accept_upstream_generation_advance_ack(
        &self,
        advance: crate::net::framing_shim::GenerationAdvance,
        sequence: u16,
        now: Instant,
        candidate_deadline: Instant,
    ) -> Result<bool, ReplyIdHandshakeInvariantError> {
        let result = (|| {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            let Some(pending) = sessions.upstream_pool.upstream_generation_advance.as_ref() else {
                return Ok(false);
            };
            if now >= pending.control.deadline()
                || pending.current != advance.current()
                || pending.proposed_key.generation() != advance.proposed_generation()
                || !pending.control.acknowledges(sequence)
            {
                return Ok(false);
            }
            let pending = sessions
                .upstream_pool
                .upstream_generation_advance
                .take()
                .ok_or(ReplyIdHandshakeInvariantError)?;
            let mut control = pending.control;
            control.reset_for_new_transaction(now, candidate_deadline);
            sessions
                .upstream_pool
                .upstream_reserve_handshakes
                .push(ReserveReplyIdHandshake::new(
                    pending.expected_ack_destination_id,
                    pending.proposed_key,
                    None,
                    now,
                    control,
                ));
            Ok(true)
        })();
        self.invalidate_maintenance_schedule();
        result
    }

    #[cfg(test)]
    pub(crate) fn maintain_upstream_session_pool(
        &self,
        expected_ack_destination_id: u16,
    ) -> Result<usize, io::Error> {
        let now = Instant::now();
        self.maintain_upstream_session_pool_until(
            expected_ack_destination_id,
            now,
            now + Duration::from_secs(3),
        )
    }

    pub(crate) fn maintain_upstream_session_pool_until(
        &self,
        expected_ack_destination_id: u16,
        now: Instant,
        candidate_deadline: Instant,
    ) -> Result<usize, io::Error> {
        if expected_ack_destination_id == 0 {
            return Ok(0);
        }
        let flow_epoch = self.flow_epoch();
        let result = (|| {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            let mut changed = false;
            if sessions
                .upstream_recovery
                .upstream_recovery_payload
                .as_ref()
                .is_some_and(|recovery| now >= recovery.deadline)
                && sessions
                    .upstream_recovery
                    .upstream_recovery_payload
                    .as_ref()
                    .is_some_and(|recovery| {
                        let active_key = sessions.upstream_pool.upstream_active_key;
                        !active_key.is_some_and(|key| {
                            key.session_id() == recovery.session
                                && self.control_observations.blocks_exact_key(
                                    super::ControlTransactionKey::new(
                                        flow_epoch,
                                        false,
                                        sessions.authority.client_flow,
                                        crate::net::payload::IcmpPayloadMeta::new_control(
                                            expected_ack_destination_id,
                                            expected_ack_destination_id,
                                            recovery.sequence,
                                            crate::net::framing_shim::IcmpTunnelControl::SessionActivated(
                                                crate::net::framing_shim::SessionActivated::new(
                                                    key,
                                                    recovery.sequence,
                                                ),
                                            ),
                                        ),
                                    ),
                                    recovery.deadline,
                                )
                        })
                    })
            {
                let awaiting_completion = sessions
                    .upstream_recovery
                    .upstream_recovery_payload
                    .as_mut()
                    .is_some_and(|recovery| {
                        matches!(
                            recovery.send.request_timeout(),
                            super::recovery_core::RecoveryTimeoutDecision::AwaitCompletion
                        )
                    });
                if !awaiting_completion {
                    sessions.upstream_recovery.upstream_recovery_payload = None;
                }
                changed = true;
            }
            if sessions.authority.upstream_leg.transmit.is_none() {
                return Ok((0, changed));
            }
            let peer_flow = sessions.authority.client_flow;
            let mut candidate_index = 0;
            let mut expired_candidates = 0_u64;
            while candidate_index < sessions.upstream_pool.upstream_reserve_handshakes.len() {
                let retain = {
                    let candidate =
                        &sessions.upstream_pool.upstream_reserve_handshakes[candidate_index];
                    candidate.control.in_flight()
                        || now < candidate.control.deadline()
                        || self.control_observations.blocks_exact_control_variants(
                            super::observations::ExactControlObservation {
                                flow_epoch,
                                c2u: false,
                                peer_flow,
                                remote_source_id: candidate.expected_ack_destination_id,
                                local_destination_id: candidate.expected_ack_destination_id,
                                deadline: candidate.control.deadline(),
                            },
                            |sequence| {
                                if !candidate.control.acknowledges(sequence) {
                                    return [None, None];
                                }
                                if let Some(challenge) = candidate.challenge {
                                    return [
                                        Some(
                                            crate::net::framing_shim::IcmpTunnelControl::ChallengeAck(
                                                challenge,
                                            ),
                                        ),
                                        None,
                                    ];
                                }
                                let acknowledged =
                                    crate::net::framing_shim::ReplyIdNegotiation::acknowledge_key_and_challenge(
                                        candidate.expected_ack_destination_id,
                                        candidate.session_key,
                                        0,
                                    )
                                    .map(crate::net::framing_shim::IcmpTunnelControl::NegotiateAck);
                                let reflected =
                                    crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key(
                                        candidate.expected_ack_destination_id,
                                        candidate.session_key,
                                    )
                                    .map(crate::net::framing_shim::IcmpTunnelControl::Negotiate);
                                [acknowledged, reflected]
                            },
                        )
                };
                if retain {
                    candidate_index += 1;
                } else {
                    let candidate = sessions
                        .upstream_pool
                        .upstream_reserve_handshakes
                        .swap_remove(candidate_index);
                    sessions
                        .upstream_pool
                        .recycle_control_send(candidate.control);
                    expired_candidates = expired_candidates.saturating_add(1);
                }
            }
            changed |= expired_candidates != 0;
            sessions.metrics.candidate_expirations = sessions
                .metrics
                .candidate_expirations
                .saturating_add(expired_candidates);
            let generation = sessions
                .upstream_pool
                .upstream_pool_generation
                .or_else(|| {
                    sessions
                        .upstream_pool
                        .upstream_active_key
                        .map(SessionKey::generation)
                })
                .ok_or_else(|| io::Error::other("active ICMP session has no pool generation"))?;
            let mut added = 0;
            if sessions.upstream_pool.next_session_ordinal
                > u32::MAX - (ORDINAL_ROLLOVER_HEADROOM - 1)
            {
                if sessions
                    .upstream_pool
                    .upstream_generation_advance
                    .as_ref()
                    .is_some_and(|advance| {
                        now >= advance.control.deadline()
                            && !advance.control.in_flight()
                            && !self.control_observations.blocks_exact_control_variants(
                                super::observations::ExactControlObservation {
                                    flow_epoch,
                                    c2u: false,
                                    peer_flow: sessions.authority.client_flow,
                                    remote_source_id: advance.expected_ack_destination_id,
                                    local_destination_id: advance.expected_ack_destination_id,
                                    deadline: advance.control.deadline(),
                                },
                                |sequence| {
                                    if !advance.control.acknowledges(sequence) {
                                        return [None, None];
                                    }
                                    [
                                        Some(
                                            crate::net::framing_shim::IcmpTunnelControl::GenerationAdvanceAck(
                                                crate::net::framing_shim::GenerationAdvance::new(
                                                    advance.current,
                                                    advance.proposed_key.generation(),
                                                ),
                                            ),
                                        ),
                                        None,
                                    ]
                                },
                            )
                    })
                {
                    sessions.upstream_pool.clear_generation_advance();
                    sessions.metrics.candidate_expirations =
                        sessions.metrics.candidate_expirations.saturating_add(1);
                    changed = true;
                }
                if sessions.upstream_pool.upstream_generation_advance.is_none()
                    && !sessions
                        .upstream_pool
                        .upstream_reserve_handshakes
                        .iter()
                        .any(|candidate| candidate.control.in_flight())
                {
                    sessions.upstream_pool.clear_reserve_handshakes();
                    let current = sessions.upstream_pool.upstream_active_key.ok_or_else(|| {
                        io::Error::other("rollover requires an active session key")
                    })?;
                    let proposed_key = SessionKey::fresh_initial()?;
                    let control = sessions
                        .upstream_pool
                        .take_control_send(now, candidate_deadline)
                        .map_err(|_| io::Error::other("ICMP control-send pool exhausted"))?;
                    sessions.upstream_pool.upstream_generation_advance =
                        Some(super::GenerationAdvanceHandshake::new(
                            current,
                            proposed_key,
                            expected_ack_destination_id,
                            control,
                        ));
                    added += 1;
                    changed = true;
                }
                return Ok((added, changed));
            }
            while sessions.upstream_pool.upstream_ready_sessions.len()
                + sessions.upstream_pool.upstream_reserve_handshakes.len()
                < sessions.upstream_pool.session_pool_target
                && sessions.upstream_pool.upstream_reserve_handshakes.len()
                    < MAX_CONCURRENT_SESSION_CANDIDATES
            {
                let ordinal = sessions.upstream_pool.next_session_ordinal;
                sessions.upstream_pool.next_session_ordinal = sessions
                    .upstream_pool
                    .next_session_ordinal
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("ICMP session ordinal exhausted"))?;
                let session_key = SessionKey::fresh_in_generation(generation, ordinal)?;
                let control = sessions
                    .upstream_pool
                    .take_control_send(now, candidate_deadline)
                    .map_err(|_| io::Error::other("ICMP control-send pool exhausted"))?;
                sessions.upstream_pool.upstream_reserve_handshakes.push(
                    ReserveReplyIdHandshake::new(
                        expected_ack_destination_id,
                        session_key,
                        None,
                        now,
                        control,
                    ),
                );
                added += 1;
                changed = true;
            }
            Ok((added, changed))
        })();
        match result {
            Ok((added, changed)) => {
                if changed {
                    self.invalidate_maintenance_schedule();
                }
                Ok(added)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn accept_upstream_rollover_challenge(
        &self,
        reset: crate::net::framing_shim::ResetRequired,
        expected_ack_destination_id: u16,
        now: Instant,
        candidate_deadline: Instant,
    ) -> io::Result<bool> {
        if reset.rejected_kind() != crate::net::framing_shim::RejectedFrameKind::Negotiate {
            return Ok(false);
        }
        {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            if !rollover_challenge_matches(&sessions, reset, expected_ack_destination_id, now) {
                return Ok(false);
            }
            if rollover_challenge_is_in_flight(&sessions, reset, expected_ack_destination_id, now) {
                let deferred = super::DeferredPeerControl::ResetRequired {
                    control: reset,
                    observed_at: now,
                };
                if !sessions.defer_peer_control(deferred) {
                    return Ok(false);
                }
                return Ok(true);
            }
        }

        let replacement = SessionKey::fresh_initial()?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if !rollover_challenge_matches(&sessions, reset, expected_ack_destination_id, now) {
            return Ok(false);
        }
        if let Some(rejected_key) = sessions
            .control
            .upstream_pending_key
            .filter(|key| key.session_id() == reset.rejected_session())
        {
            let previous = std::mem::replace(
                &mut sessions.control.upstream_reply_id_handshake,
                ReplyIdHandshake::NotRequired,
            );
            let ReplyIdHandshake::Pending {
                expected_ack_destination_id: pending_destination,
                started_s,
                absolute_deadline,
                payload,
                mut control,
                ..
            } = previous
            else {
                sessions.control.upstream_reply_id_handshake = previous;
                return Ok(false);
            };
            if pending_destination != expected_ack_destination_id
                || !control.was_sent(reset.rejected_sequence())
            {
                control.restart(now).map_err(|_| {
                    io::Error::other("cannot restart an in-flight handshake control")
                })?;
                sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Pending {
                    expected_ack_destination_id: pending_destination,
                    instance: reset.rejected_session().get(),
                    started_s,
                    absolute_deadline,
                    payload,
                    control,
                };
                return Ok(false);
            }
            let Some(challenge) = crate::net::framing_shim::ChallengeControl::new(
                expected_ack_destination_id,
                reset.challenge(),
                reset.receiver_generation(),
                crate::net::framing_shim::RejectedFrameEvidence::Negotiate {
                    candidate: rejected_key,
                    sequence: reset.rejected_sequence(),
                },
                replacement,
            ) else {
                control.restart(now).map_err(|_| {
                    io::Error::other("cannot restart an in-flight handshake control")
                })?;
                sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Pending {
                    expected_ack_destination_id: pending_destination,
                    instance: rejected_key.session_id().get(),
                    started_s,
                    absolute_deadline,
                    payload,
                    control,
                };
                return Err(io::Error::other(
                    "challenge negotiation requires nonzero reply ID",
                ));
            };
            if !sessions.upstream_pool.upstream_ready_sessions.is_empty() {
                sessions.upstream_pool.upstream_ready_sessions.clear();
                sessions.publish_upstream_pool_change();
            }
            sessions.invalidate_control_leases();
            sessions.upstream_pool.clear_reserve_handshakes();
            sessions.upstream_pool.clear_generation_advance();
            sessions.control.upstream_pending_key = Some(replacement);
            sessions.control.upstream_pending_challenge = Some(challenge);
            control.reset_for_new_transaction(now, absolute_deadline);
            sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Pending {
                expected_ack_destination_id,
                instance: replacement.session_id().get(),
                started_s,
                absolute_deadline,
                payload,
                control,
            };
            sessions.reset_recovery.reset_responses_accepted = sessions
                .reset_recovery
                .reset_responses_accepted
                .saturating_add(1);
            return Ok(true);
        }
        let Some(index) = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter()
            .position(|candidate| {
                candidate.session_key.session_id() == reset.rejected_session()
                    && candidate.control.was_sent(reset.rejected_sequence())
            })
        else {
            return Ok(false);
        };
        let rejected_key = sessions.upstream_pool.upstream_reserve_handshakes[index].session_key;
        let challenge = crate::net::framing_shim::ChallengeControl::new(
            expected_ack_destination_id,
            reset.challenge(),
            reset.receiver_generation(),
            crate::net::framing_shim::RejectedFrameEvidence::Negotiate {
                candidate: rejected_key,
                sequence: reset.rejected_sequence(),
            },
            replacement,
        )
        .ok_or_else(|| io::Error::other("challenge negotiation requires nonzero reply ID"))?;
        let mut control = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .swap_remove(index)
            .control;
        control.reset_for_new_transaction(now, candidate_deadline);
        sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .push(ReserveReplyIdHandshake::new(
                expected_ack_destination_id,
                replacement,
                Some(challenge),
                now,
                control,
            ));
        Ok(true)
    }

    pub(crate) fn handoff_upstream_session(
        &self,
        exhausted_session: SessionId,
        drain_until: Instant,
    ) -> Result<Option<SessionId>, super::FlowMutationError<ReplyIdHandshakeInvariantError>> {
        let transition = self
            .try_reserve_client_flow()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        self.handoff_upstream_session_under(&transition, exhausted_session, drain_until)
    }

    pub(crate) fn handoff_upstream_session_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        exhausted_session: SessionId,
        drain_until: Instant,
    ) -> Result<Option<SessionId>, super::FlowMutationError<ReplyIdHandshakeInvariantError>> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        let result: Result<_, super::FlowMutationError<ReplyIdHandshakeInvariantError>> = (|| {
            let mut sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            if sessions.authority.upstream_leg.transmit != Some(exhausted_session) {
                // Another worker may have linearized the same exhaustion or a
                // reset fallback first. The current active session is the
                // authoritative retry target; stale callers must not pop a
                // second ready entry or fail a legitimate packet.
                return Ok(sessions.authority.upstream_leg.transmit);
            }
            let exhausted_key = sessions
                .upstream_pool
                .upstream_active_key
                .filter(|key| key.session_id() == exhausted_session)
                .ok_or(ReplyIdHandshakeInvariantError)?;
            let Some(next) = sessions.upstream_pool.upstream_ready_sessions.pop_front() else {
                sessions.metrics.pool_empty_stalls =
                    sessions.metrics.pool_empty_stalls.saturating_add(1);
                return Ok(None);
            };
            sessions.publish_upstream_pool_change();
            if push_draining_session(
                &mut sessions.upstream_pool.upstream_draining_sessions,
                exhausted_key.response_key(),
                drain_until,
            ) {
                sessions.metrics.stale_session_evictions =
                    sessions.metrics.stale_session_evictions.saturating_add(1);
            }
            sessions.authority.upstream_leg.transmit = Some(next.session_key.session_id());
            sessions.authority.upstream_leg.receive = Some(next.session_key.response_session_id());
            sessions.upstream_pool.upstream_active_key = Some(next.session_key);
            sessions.upstream_recovery.upstream_activation_confirmed = false;
            if next.session_key.generation() != exhausted_key.generation() {
                let ready_before = sessions.upstream_pool.upstream_ready_sessions.len();
                sessions
                    .upstream_pool
                    .upstream_ready_sessions
                    .retain(|ready| {
                        ready.session_key.generation() == next.session_key.generation()
                    });
                if sessions.upstream_pool.upstream_ready_sessions.len() != ready_before {
                    sessions.publish_upstream_pool_change();
                }
                sessions
                    .upstream_pool
                    .upstream_reserve_handshakes
                    .retain(|candidate| {
                        candidate.session_key.generation() == next.session_key.generation()
                    });
                sessions.upstream_pool.upstream_pool_generation =
                    Some(next.session_key.generation());
                sessions.upstream_pool.next_session_ordinal =
                    next.session_key.ordinal().saturating_add(1);
                sessions.metrics.generation_rollovers =
                    sessions.metrics.generation_rollovers.saturating_add(1);
            }
            sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Acked {
                instance: next.session_key.session_id().get(),
            };
            sessions.metrics.normal_handoffs = sessions.metrics.normal_handoffs.saturating_add(1);
            Ok(Some(next.session_key.session_id()))
        })(
        );
        if result
            .as_ref()
            .is_ok_and(|session| session.is_some_and(|session| session != exhausted_session))
        {
            self.invalidate_flow_authority_under(transition)
                .map_err(super::FlowMutationError::Authority)?;
        } else {
            self.invalidate_maintenance_schedule();
        }
        result
    }

    pub(crate) fn session_pool_snapshot(&self) -> SessionPoolSnapshot {
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        SessionPoolSnapshot {
            pool: crate::flow_state::SessionPoolStateSnapshot {
                pool_epoch: sessions.upstream_pool.upstream_pool_epoch,
                pool_epoch_exhausted: sessions.upstream_pool.upstream_pool_epoch_exhausted,
                active: active_session_count(&sessions),
                client_transmit_session_id: sessions.authority.client_leg.transmit,
                client_receive_session_id: sessions.authority.client_leg.receive,
                upstream_transmit_session_id: sessions.authority.upstream_leg.transmit,
                upstream_receive_session_id: sessions.authority.upstream_leg.receive,
                ready: sessions.upstream_pool.upstream_ready_sessions.len()
                    + sessions.client_pool.client_ready_sessions.len(),
                negotiating: sessions.upstream_pool.upstream_reserve_handshakes.len()
                    + usize::from(matches!(
                        sessions.control.upstream_reply_id_handshake,
                        ReplyIdHandshake::Pending { .. } | ReplyIdHandshake::Committing { .. }
                    ))
                    + usize::from(sessions.authority.pending_icmp_client_lock.is_some()),
                draining: sessions.client_pool.client_draining_sessions.len()
                    + sessions.upstream_pool.upstream_draining_sessions.len(),
                target: sessions.upstream_pool.session_pool_target,
                ready_session_ids:
                    crate::flow_state::session_state::ReadySessionIdSnapshot::from_ready_sessions(
                        &sessions.upstream_pool.upstream_ready_sessions,
                    ),
            },
            metrics: crate::flow_state::SessionPoolMetricsSnapshot {
                candidate_retry_attempts: sessions.metrics.candidate_retry_attempts,
                candidate_expirations: sessions.metrics.candidate_expirations,
                candidate_negotiation_latency_ns_total: sessions
                    .metrics
                    .candidate_negotiation_latency_ns_total,
                candidate_negotiations_completed: sessions.metrics.candidate_negotiations_completed,
                normal_handoffs: sessions.metrics.normal_handoffs,
                pool_empty_stalls: sessions.metrics.pool_empty_stalls,
                stale_session_evictions: sessions.metrics.stale_session_evictions,
                sparse_retirement_exhaustions: sessions.metrics.sparse_retirement_exhaustions,
                generation_rollovers: sessions.metrics.generation_rollovers,
            },
            reset_recovery: crate::flow_state::ResetRecoveryMetricsSnapshot {
                reset_challenges_created: sessions.reset_recovery.reset_challenges_created,
                reset_challenges_reused: sessions.reset_recovery.reset_challenges_reused,
                reset_challenges_consumed: sessions.reset_recovery.reset_challenges_consumed,
                reset_challenges_expired: sessions.reset_recovery.reset_challenges_expired,
                reset_responses_rate_limited: sessions.reset_recovery.reset_responses_rate_limited,
                reset_responses_accepted: sessions.reset_recovery.reset_responses_accepted,
                reset_responses_ignored: sessions.reset_recovery.reset_responses_ignored,
            },
            maintenance_wake_failures: self
                .maintenance_wake_failures
                .load(std::sync::atomic::Ordering::Acquire),
        }
    }

    pub(crate) fn reserve_accounting_snapshot_is_current(
        &self,
        pool_epoch: u64,
        ready_session_ids: &crate::flow_state::session_state::ReadySessionIdSnapshot,
    ) -> bool {
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        !sessions.upstream_pool.upstream_pool_epoch_exhausted
            && sessions.upstream_pool.upstream_pool_epoch == pool_epoch
            && sessions.upstream_pool.upstream_ready_sessions.len() == ready_session_ids.len()
            && sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .map(|ready| ready.session_key.session_id())
                .eq(ready_session_ids.iter())
    }

    fn promote_ready_icmp_client_session(
        &self,
        session_id: SessionId,
        drain_until: Instant,
    ) -> Result<bool, PendingIcmpClientLockMismatch> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        expire_receive_candidates(
            &mut sessions,
            self.flow_epoch(),
            Instant::now(),
            &self.control_observations,
        );
        if sessions.authority.flow != FlowPhase::Active {
            return Err(PendingIcmpClientLockMismatch);
        }
        if sessions.authority.client_leg.receive == Some(session_id) {
            return Ok(false);
        }
        let Some(index) = sessions
            .client_pool
            .client_ready_sessions
            .iter()
            .position(|ready| {
                ready.session_key.session_id() == session_id && ready.is_promotable()
            })
        else {
            return Err(PendingIcmpClientLockMismatch);
        };
        let next = sessions
            .client_pool
            .client_ready_sessions
            .swap_remove(index);
        if sessions
            .client_pool
            .client_retired_ordinals
            .is_retired(next.session_key.ordinal())
        {
            return Err(PendingIcmpClientLockMismatch);
        }
        if let Some(active) = sessions.client_pool.client_active_key {
            if active.generation() != next.session_key.generation() {
                if sessions.client_pool.client_staged_generation != Some(next.session_key) {
                    return Err(PendingIcmpClientLockMismatch);
                }
                sessions.client_pool.client_retired_ordinals = Default::default();
                sessions.client_pool.client_staged_generation = None;
                sessions.reset_recovery.client_reset_challenge = None;
            } else {
                if next.session_key.ordinal() <= active.ordinal() {
                    return Err(PendingIcmpClientLockMismatch);
                }
                // Valid higher-ordinal data proves that same-generation
                // fallback succeeded, so the challenge bound to the original
                // rejected session is no longer needed.
                sessions.reset_recovery.client_reset_challenge = None;
                sessions
                    .client_pool
                    .client_retired_ordinals
                    .retire_through(next.session_key.ordinal().saturating_sub(1));
            }
        }
        sessions
            .client_pool
            .client_ready_sessions
            .retain(|candidate| {
                candidate.session_key.generation() == next.session_key.generation()
                    && candidate.session_key.ordinal() > next.session_key.ordinal()
            });
        if let Some(previous) = sessions.client_pool.client_active_key
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
        sessions.authority.client_leg.transmit = Some(next.session_key.response_session_id());
        sessions.client_pool.client_active_key = Some(next.session_key);
        Ok(true)
    }

    pub(crate) fn promote_ready_icmp_client_session_with_replay_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        session_id: SessionId,
        drain_until: Instant,
        sequence_state: &crate::net::icmp_sequence::SharedIcmpSequenceState,
        sequence_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    ) -> Result<bool, super::FlowMutationError<PendingIcmpClientLockMismatch>> {
        transition.assert_current().map_err(|error| {
            super::FlowMutationError::Authority(super::FlowAuthorityError::from(error))
        })?;
        let promoted = self
            .promote_ready_icmp_client_session(session_id, drain_until)
            .map_err(super::FlowMutationError::Operation)?;
        if promoted {
            crate::net::icmp_sequence::activate_receive_session(
                sequence_state,
                sequence_cache,
                session_id,
            );
            self.invalidate_flow_authority_under(transition)
                .map_err(super::FlowMutationError::Authority)?;
        }
        Ok(promoted)
    }

    pub(crate) fn client_session_admission(&self, now: Instant) -> SessionAdmissionSnapshot {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        expire_receive_candidates(
            &mut sessions,
            self.flow_epoch(),
            now,
            &self.control_observations,
        );
        let previous_len = sessions.client_pool.client_draining_sessions.len();
        expire_draining_sessions(&mut sessions.client_pool.client_draining_sessions, now);
        sessions.metrics.stale_session_evictions =
            sessions.metrics.stale_session_evictions.saturating_add(
                (previous_len - sessions.client_pool.client_draining_sessions.len()) as u64,
            );
        session_admission_snapshot(
            sessions.authority.client_leg.receive,
            &sessions.client_pool.client_ready_sessions,
            &sessions.client_pool.client_draining_sessions,
        )
    }
}
