use super::{
    BufferedPayload, ClientFlowReservation, ExpiredReplyIdHandshake, FlowRuntimeState,
    HandshakeStart, Instant, PacketTraceId, PoolGeneration, ReplyIdControlSendCompletion,
    ReplyIdControlSendLease, ReplyIdHandshake, ReplyIdHandshakeAck, ReplyIdHandshakeAckIgnored,
    ReplyIdHandshakeActivationLease, ReplyIdHandshakeBegin, ReplyIdHandshakeCommitToken,
    ReplyIdHandshakeInvariantError, ReplyIdHandshakeManagerReceipt, ReplyIdPayloadSendLease,
    SessionId, SessionKey, ack_handshake, begin_handshake, commit_handshake_session,
    complete_handshake_activation, complete_handshake_control_send, complete_handshake_send,
    expire_handshake, handshake, lease_due_handshake_control, lease_due_handshake_payload,
    mark_handshake_manager_published, poison_handshake_activation, release_handshake_send,
    release_unsequenced_handshake_control, rollback_handshake,
};
#[cfg(test)]
use super::{Duration, PayloadEvent, PendingIcmpClientLock};
use crate::flow_state::{PreparedControlSend, PreparedReplyIdHandshake};

impl FlowRuntimeState {
    #[inline]
    pub fn upstream_reply_id_acked(&self) -> bool {
        matches!(
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
                .control
                .upstream_reply_id_handshake,
            ReplyIdHandshake::Sending { .. }
                | ReplyIdHandshake::AckedRetryable { .. }
                | ReplyIdHandshake::Acked { .. }
        )
    }

    #[inline]
    pub(crate) fn upstream_session_id(&self) -> Option<crate::net::framing_shim::SessionId> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .upstream_leg
            .transmit
    }

    pub(crate) fn use_reflected_upstream_session_for_debug_under(
        &self,
        transition: &ClientFlowReservation<'_>,
    ) -> Result<(), super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let changed =
            sessions.authority.upstream_leg.receive != sessions.authority.upstream_leg.transmit;
        sessions.authority.upstream_leg.receive = sessions.authority.upstream_leg.transmit;
        drop(sessions);
        if changed {
            self.invalidate_flow_authority_under(transition)?;
        }
        Ok(())
    }

    #[inline]
    #[cfg(test)]
    pub fn begin_upstream_reply_id_handshake(
        &self,
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        payload: BufferedPayload,
    ) -> ReplyIdHandshakeBegin {
        let session_id = SessionId::new(instance)
            .expect("reply-ID handshake instance must be a nonzero session ID");
        let absolute_deadline =
            payload.received_at() + Duration::from_secs(crate::cli::DEFAULT_TIMEOUT_SECS);
        self.begin_upstream_reply_id_handshake_with_key(
            expected_ack_destination_id,
            SessionKey::initial(session_id)
                .expect("test handshake session reserves a response identity"),
            started_s,
            absolute_deadline,
            payload,
        )
    }

    #[cfg(test)]
    pub(crate) fn begin_upstream_reply_id_handshake_with_key(
        &self,
        expected_ack_destination_id: u16,
        session_key: SessionKey,
        started_s: u64,
        absolute_deadline: Instant,
        payload: BufferedPayload,
    ) -> ReplyIdHandshakeBegin {
        let trigger_trace = payload.trace();
        let started_at = payload.received_at();
        let prepared = PreparedControlSend::new(started_at, absolute_deadline);
        let mut payload = Some(payload);
        let result = begin_handshake(
            &self.sessions,
            HandshakeStart {
                expected_ack_destination_id,
                session_key,
                started_s,
                absolute_deadline,
                trigger_trace,
                control: prepared.core,
            },
            &mut payload,
        );
        self.invalidate_maintenance_schedule();
        result
    }

    pub(crate) fn begin_upstream_reply_id_handshake_with_owned_payload_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        prepared: PreparedReplyIdHandshake,
        payload: &mut Option<BufferedPayload>,
    ) -> Result<ReplyIdHandshakeBegin, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let Some(buffered) = payload.as_ref() else {
            return Err(super::FlowAuthorityError::Reservation(
                crate::net::sock_mgr::transaction_lock::ReservationError::OwnershipLost,
            ));
        };
        let trigger_trace = buffered.trace();
        let PreparedReplyIdHandshake {
            expected_ack_destination_id,
            session_key,
            started_s,
            absolute_deadline,
            control,
        } = prepared;
        let result = begin_handshake(
            &self.sessions,
            HandshakeStart {
                expected_ack_destination_id,
                session_key,
                started_s,
                absolute_deadline,
                trigger_trace,
                control: control.core,
            },
            payload,
        );
        if matches!(result, ReplyIdHandshakeBegin::Started { .. }) {
            self.invalidate_flow_authority_under(transition)?;
        }
        self.invalidate_maintenance_schedule();
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn begin_upstream_rekey_from_event(
        &self,
        old_session_id: SessionId,
        new_session_id: SessionId,
        expected_ack_destination_id: u16,
        started_s: u64,
        absolute_deadline: Instant,
        event: &PayloadEvent<'_>,
        trace: Option<PacketTraceId>,
        received_at: Instant,
    ) -> Result<ReplyIdHandshakeBegin, super::FlowMutationError<ReplyIdHandshakeInvariantError>>
    {
        self.begin_upstream_rekey(
            old_session_id,
            new_session_id,
            expected_ack_destination_id,
            started_s,
            absolute_deadline,
            BufferedPayload::from_event_at(event, trace, received_at),
        )
    }

    pub(crate) fn begin_upstream_rekey(
        &self,
        old_session_id: SessionId,
        new_session_id: SessionId,
        expected_ack_destination_id: u16,
        started_s: u64,
        absolute_deadline: Instant,
        payload: BufferedPayload,
    ) -> Result<ReplyIdHandshakeBegin, super::FlowMutationError<ReplyIdHandshakeInvariantError>>
    {
        let prepared = PreparedControlSend::new(payload.received_at(), absolute_deadline);
        let transition = self
            .try_reserve_client_flow()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        self.begin_upstream_rekey_under(
            &transition,
            old_session_id,
            new_session_id,
            expected_ack_destination_id,
            started_s,
            absolute_deadline,
            payload,
            prepared,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_upstream_rekey_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        old_session_id: SessionId,
        new_session_id: SessionId,
        expected_ack_destination_id: u16,
        started_s: u64,
        absolute_deadline: Instant,
        payload: BufferedPayload,
        prepared: PreparedControlSend,
    ) -> Result<ReplyIdHandshakeBegin, super::FlowMutationError<ReplyIdHandshakeInvariantError>>
    {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let ReplyIdHandshake::Acked { instance } = sessions.control.upstream_reply_id_handshake
        else {
            return Err(super::FlowMutationError::Operation(
                ReplyIdHandshakeInvariantError,
            ));
        };
        if instance != old_session_id.get()
            || sessions.authority.upstream_leg.transmit != Some(old_session_id)
        {
            return Err(super::FlowMutationError::Operation(
                ReplyIdHandshakeInvariantError,
            ));
        }
        let buffered_len = payload.payload_len();
        let buffered_trace = payload.trace();
        let new_session_key = SessionKey::with_fresh_generation(new_session_id)
            .map_err(|_| ReplyIdHandshakeInvariantError)?;
        sessions.authority.upstream_leg.transmit = None;
        sessions.control.upstream_pending_key = Some(new_session_key);
        sessions.control.upstream_pending_challenge = None;
        sessions.upstream_pool.upstream_pool_generation = Some(new_session_key.generation());
        sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance: new_session_id.get(),
            started_s,
            absolute_deadline,
            payload,
            control: prepared.core,
        };
        let result = ReplyIdHandshakeBegin::Started {
            expected_ack_destination_id,
            instance: new_session_id.get(),
            buffered_len,
            buffered_trace,
        };
        drop(sessions);
        self.invalidate_flow_authority_under(transition)
            .map_err(super::FlowMutationError::Authority)?;
        Ok(result)
    }

    #[inline]
    pub(crate) fn try_lease_due_upstream_reply_id_negotiation(
        &self,
        now: Instant,
    ) -> Result<Option<ReplyIdControlSendLease>, ReplyIdHandshakeInvariantError> {
        lease_due_handshake_control(&self.sessions, now)
    }

    #[cfg(test)]
    pub(crate) fn lease_due_upstream_reply_id_negotiation(
        &self,
        now: Instant,
    ) -> Option<ReplyIdControlSendLease> {
        self.try_lease_due_upstream_reply_id_negotiation(now)
            .expect("test handshake state must remain internally coherent")
    }

    #[inline]
    pub(crate) fn try_complete_upstream_reply_id_negotiation_send(
        &self,
        lease: ReplyIdControlSendLease,
        sequence: u16,
        sent: bool,
        completed_at: Instant,
    ) -> Result<ReplyIdControlSendCompletion, ReplyIdHandshakeInvariantError> {
        complete_handshake_control_send(&self.sessions, lease, sequence, sent, completed_at)
    }

    pub(crate) fn invalidate_maintenance_after_control_send(&self) {
        self.invalidate_maintenance_schedule();
    }

    #[cfg(test)]
    pub(crate) fn complete_upstream_reply_id_negotiation_send(
        &self,
        lease: ReplyIdControlSendLease,
        sequence: u16,
        sent: bool,
        completed_at: Instant,
    ) -> ReplyIdControlSendCompletion {
        let result =
            complete_handshake_control_send(&self.sessions, lease, sequence, sent, completed_at)
                .expect("test control-send accounting must remain internally coherent");
        self.invalidate_maintenance_after_control_send();
        result
    }

    pub(crate) fn complete_deferred_upstream_control_response(
        &self,
        session_id: SessionId,
        sequence: u16,
        sent: bool,
    ) -> Option<super::DeferredPeerControl> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let index = sessions
            .upstream_recovery
            .upstream_deferred_peer_controls
            .iter()
            .position(|deferred| {
                matches!(
                    deferred,
                    super::DeferredPeerControl::ResetRequired { control, .. }
                        if control.rejected_session() == session_id
                            && control.rejected_sequence() == sequence
                )
            })?;
        let deferred = sessions
            .upstream_recovery
            .upstream_deferred_peer_controls
            .remove(index)?;
        sent.then_some(deferred)
    }

    pub(crate) fn record_upstream_negotiation_sequence(
        &self,
        lease: &ReplyIdControlSendLease,
        sequence: u16,
    ) -> Result<super::ReplyIdControlSequenceRecord, ReplyIdHandshakeInvariantError> {
        handshake::record_handshake_control_sequence(&self.sessions, lease, sequence)
    }

    pub(crate) fn release_unsequenced_upstream_negotiation(
        &self,
        lease: ReplyIdControlSendLease,
        retry_at: Instant,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        release_unsequenced_handshake_control(&self.sessions, lease, retry_at)
    }

    #[inline]
    pub(crate) fn ack_upstream_reply_id_handshake_key(
        &self,
        observed_ack_destination_id: u16,
        observed_key: SessionKey,
        observed_sequence: u16,
        observed_reset_challenge: u64,
        observed_at: Instant,
        trigger_trace: Option<PacketTraceId>,
    ) -> ReplyIdHandshakeAck {
        let observed_challenge = {
            let sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            sessions
                .upstream_pool
                .upstream_reserve_handshakes
                .iter()
                .find(|candidate| candidate.session_key == observed_key)
                .and_then(|candidate| candidate.challenge)
                .or_else(|| {
                    (sessions.control.upstream_pending_key == Some(observed_key))
                        .then_some(sessions.control.upstream_pending_challenge)
                        .flatten()
                })
                .filter(|challenge| challenge.challenge().get() == observed_reset_challenge)
        };
        if observed_reset_challenge != 0 && observed_challenge.is_none() {
            return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongInstance {
                expected_instance: observed_key.session_id().get(),
                observed_instance: observed_key.session_id().get(),
                buffered_trace: None,
                trigger_trace,
            });
        }
        ack_handshake(
            &self.sessions,
            observed_ack_destination_id,
            observed_key,
            observed_sequence,
            observed_challenge,
            observed_at,
            trigger_trace,
        )
    }

    pub(crate) fn ack_upstream_icmp_control(
        &self,
        observed_ack_destination_id: u16,
        observed_control: crate::net::framing_shim::IcmpTunnelControl,
        observed_sequence: u16,
        observed_at: Instant,
        trigger_trace: Option<PacketTraceId>,
    ) -> ReplyIdHandshakeAck {
        let (observed_key, observed_challenge) = match observed_control {
            crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(negotiation) => {
                (negotiation.session_key(), None)
            }
            crate::net::framing_shim::IcmpTunnelControl::ChallengeAck(challenge) => {
                (challenge.new_session(), Some(challenge))
            }
            _ => {
                return ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::NoPending {
                    trigger_trace,
                });
            }
        };
        ack_handshake(
            &self.sessions,
            observed_ack_destination_id,
            observed_key,
            observed_sequence,
            observed_challenge,
            observed_at,
            trigger_trace,
        )
    }

    /// Returns whether an ACK belongs to direction-local reserve-pool state.
    ///
    /// Reserve completion does not alter the active route, socket topology, or
    /// admission snapshot. Callers holding a flow read lane may therefore
    /// consume it without closing and reopening the global flow gate.
    pub(crate) fn upstream_ack_key_is_reserve_local(
        &self,
        observed_key: crate::net::framing_shim::SessionKey,
    ) -> bool {
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter()
            .any(|candidate| candidate.session_key == observed_key)
            || sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .any(|ready| ready.session_key == observed_key)
    }

    #[inline]
    pub(crate) fn mark_upstream_reply_id_manager_published_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        token: ReplyIdHandshakeCommitToken,
    ) -> Result<
        ReplyIdHandshakeManagerReceipt,
        super::FlowMutationError<super::ReplyIdHandshakeTransitionError>,
    > {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        mark_handshake_manager_published(&self.sessions, token)
            .map_err(super::FlowMutationError::Operation)
    }

    #[inline]
    pub(crate) fn commit_upstream_reply_id_handshake_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        receipt: ReplyIdHandshakeManagerReceipt,
    ) -> Result<
        ReplyIdHandshakeActivationLease,
        super::FlowMutationError<super::ReplyIdHandshakeTransitionError>,
    > {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)
            .map_err(super::FlowMutationError::Authority)?;
        let result = commit_handshake_session(&self.sessions, receipt)
            .map_err(super::FlowMutationError::Operation);
        if result.is_ok() {
            self.invalidate_flow_authority_under(transition)
                .map_err(super::FlowMutationError::Authority)?;
        }
        result
    }

    #[inline]
    pub(crate) fn complete_upstream_reply_id_handshake_activation(
        &self,
        activation: ReplyIdHandshakeActivationLease,
    ) -> Result<ReplyIdPayloadSendLease, super::ReplyIdHandshakeTransitionError> {
        complete_handshake_activation(&self.sessions, activation)
    }

    #[inline]
    pub(crate) fn poison_upstream_reply_id_handshake_activation(
        &self,
        activation: ReplyIdHandshakeActivationLease,
    ) -> Result<(), super::ReplyIdHandshakeTransitionError> {
        poison_handshake_activation(&self.sessions, activation)
    }

    #[inline]
    pub fn rollback_upstream_reply_id_handshake(
        &self,
        token: ReplyIdHandshakeCommitToken,
        now: Instant,
    ) -> Result<super::HandshakeRollbackOutcome, super::ReplyIdHandshakeTransitionError> {
        rollback_handshake(&self.sessions, token, now)
    }

    #[inline]
    pub fn complete_upstream_reply_id_payload_send(
        &self,
        lease: ReplyIdPayloadSendLease,
    ) -> Result<bool, ReplyIdHandshakeInvariantError> {
        complete_handshake_send(&self.sessions, lease)
    }

    #[inline]
    pub fn release_upstream_reply_id_payload_send(
        &self,
        lease: ReplyIdPayloadSendLease,
    ) -> Result<bool, ReplyIdHandshakeInvariantError> {
        let result = release_handshake_send(&self.sessions, lease);
        self.invalidate_maintenance_schedule();
        result
    }

    #[inline]
    pub fn lease_due_upstream_reply_id_payload(
        &self,
        now: Instant,
    ) -> Option<ReplyIdPayloadSendLease> {
        lease_due_handshake_payload(&self.sessions, now)
    }

    #[inline]
    #[cfg(test)]
    pub fn expire_reply_id_handshake(&self, now: Instant) -> Option<ExpiredReplyIdHandshake> {
        expire_handshake(
            &self.sessions,
            &self.control_observations,
            self.flow_epoch(),
            now,
        )
    }

    pub(crate) fn expire_reply_id_handshake_under(
        &self,
        transition: &ClientFlowReservation<'_>,
        now: Instant,
    ) -> Result<Option<ExpiredReplyIdHandshake>, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let expired = expire_handshake(
            &self.sessions,
            &self.control_observations,
            self.flow_epoch(),
            now,
        );
        if expired.is_some() {
            self.invalidate_flow_authority_under(transition)?;
        }
        Ok(expired)
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn pending_icmp_client_lock(&self) -> Option<PendingIcmpClientLock> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .pending_icmp_client_lock
            .map(|pending| pending.candidate)
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn client_receive_session_id(&self) -> Option<SessionId> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .client_leg
            .receive
    }

    pub(crate) fn client_pool_generation(&self) -> Option<PoolGeneration> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .client_pool
            .client_active_key
            .map(SessionKey::generation)
    }
}
