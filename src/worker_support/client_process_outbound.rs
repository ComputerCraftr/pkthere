use super::client_dispatch::{
    AdmittedWirePacket, C2U, C2uDispatchOutcome, Instant, ManagerError, PacketContext,
    PacketDisposition, PacketTraceId, accept_pending_negotiation, dispatch_c2u_event,
    handle_c2u_session_control, log_packet_disposition,
};
use super::client_process::ClientPacketProcessor;
use crate::stats::StatsSink;

impl<'a, 'context> ClientPacketProcessor<'a, 'context> {
    pub(super) fn handle_outbound_handshake(
        &mut self,
        event: &crate::net::payload::PayloadEvent<'_>,
        trace: PacketTraceId,
        negotiation: crate::net::framing_shim::ReplyIdNegotiation,
    ) -> Result<(), ManagerError> {
        self.release_stable_authority();
        let mut payload = Some(crate::net::payload::BufferedPayload::from_event_at(
            event,
            Some(trace),
            self.received_at,
        ));
        let absolute_deadline = self.received_at
            + std::time::Duration::from_secs(self.context.cfg.icmp_handshake_timeout_secs);
        let prepared = crate::flow_state::PreparedReplyIdHandshake::new(
            negotiation.reply_id(),
            negotiation.session_key(),
            self.received_at
                .saturating_duration_since(self.context.t_start)
                .as_secs()
                .max(1),
            absolute_deadline,
            self.received_at,
        );
        if !self.begin_transition() {
            return Ok(());
        }
        let transition = self.flow_transaction.as_ref().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ICMP handshake lost its flow reservation"
            ))
        });
        let outcome = self
            .context
            .flow_state
            .begin_upstream_reply_id_handshake_with_owned_payload_under(
                transition,
                prepared,
                &mut payload,
            )
            .map_err(ManagerError::from)?;
        drop(self.flow_transaction.take());
        crate::worker_support::handshake_trace::log_handshake_begin(
            self.context.cfg,
            self.context.worker_id,
            Some(trace),
            &outcome,
            event.payload_len(),
        );
        let route = match &outcome {
            crate::flow_state::ReplyIdHandshakeBegin::Started { .. } => {
                crate::worker_support::UserPayloadRoute::BufferFirstHandshakePayload
            }
            crate::flow_state::ReplyIdHandshakeBegin::PendingReused { .. } => {
                crate::worker_support::log_packet_disposition(
                    self.context.cfg,
                    trace,
                    crate::worker_support::PacketDisposition::DropHandshakePending,
                );
                crate::worker_support::UserPayloadRoute::DropHandshakePending
            }
            crate::flow_state::ReplyIdHandshakeBegin::Ignored => {
                crate::worker_support::UserPayloadRoute::DropHandshakePending
            }
        };
        crate::worker_support::record_user_payload_route(
            &mut PacketContext::new(
                self.context.worker_id,
                self.context.t_start,
                self.received_at,
                self.context.cfg,
                self.context.stats,
                self.context.flow_state,
            ),
            route,
        );
        if outcome.should_send_control() {
            crate::worker_support::dispatch::retry_due_upstream_negotiation(
                &mut PacketContext::new(
                    self.context.worker_id,
                    self.context.t_start,
                    Instant::now(),
                    self.context.cfg,
                    self.context.stats,
                    self.context.flow_state,
                ),
                self.handles,
                self.cache,
                self.context.upstream_side_state,
                self.upstream_side_cache,
                Some(negotiation.session_key().session_id()),
            )
            .map_err(|error| ManagerError::io("send initial ICMP negotiation", error))?;
        }
        Ok(())
    }

    pub(super) fn handle_outbound_rekey(
        &mut self,
        event: &crate::net::payload::PayloadEvent<'_>,
        trace: PacketTraceId,
        mut rekey: crate::net::icmp_sequence::RekeyRequired,
    ) -> Result<Option<C2uDispatchOutcome>, ManagerError> {
        let maximum_attempts = self
            .context
            .cfg
            .icmp_session_pool_size
            .checked_add(crate::flow_state::MAX_CONCURRENT_SESSION_CANDIDATES)
            .ok_or_else(|| {
                ManagerError::io(
                    "bound ICMP handoff attempts",
                    std::io::Error::other("ICMP handoff retry bound overflowed"),
                )
            })?;
        for _ in 0..maximum_attempts {
            if !self.begin_transition() {
                return Ok(None);
            }
            let transition = self.flow_transaction.as_ref().unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "ICMP handoff lost its flow reservation"
                ))
            });
            let drain_until = self.received_at
                + std::time::Duration::from_secs(self.context.cfg.icmp_handshake_timeout_secs);
            let next_session = self
                .context
                .flow_state
                .handoff_upstream_session_under(transition, rekey.session_id, drain_until)
                .map_err(|error| {
                    ManagerError::io(
                        "handoff exhausted ICMP session",
                        super::flow_mutation_io_error("ICMP session-pool handoff failed", error),
                    )
                })?;
            if let Some(next_session) = next_session {
                crate::worker_support::dispatch::activate_upstream_receive_session(
                    self.context.cfg,
                    self.context.flow_state,
                    Some(transition),
                    self.context.upstream_side_state,
                    self.upstream_side_cache,
                    next_session,
                )
                .map_err(|error| {
                    ManagerError::io("activate handoff ICMP receive session", error)
                })?;
                self.context
                    .upstream_side_state
                    .retire_outbound_sessions(&[rekey.session_id]);
                if !self.resume_stable_read() {
                    return Ok(None);
                }
                let flow_read =
                    self.take_stable_read("ICMP handoff retry lost its flow-read authority");
                let permit = crate::worker_support::StableForwardPermit::for_upstream_packet(
                    flow_read,
                    &self.flow_snapshot,
                    self.handles,
                );
                let outcome = dispatch_c2u_event(
                    self.context,
                    self.handles,
                    self.cache,
                    self.client_side_cache,
                    self.upstream_side_cache,
                    event,
                    trace,
                    self.received_at,
                    true,
                    permit,
                );
                match outcome {
                    C2uDispatchOutcome::Rekey(next_rekey) => {
                        rekey = next_rekey;
                        continue;
                    }
                    other => return Ok(Some(other)),
                }
            }

            let expected_ack_destination_id = self
                .cache
                .expected_upstream_ack_destination_id(self.handles)
                .map_err(|error| ManagerError::io("resolve ICMP rekey ACK destination", error))?;
            let new_session_id = crate::net::framing_shim::SessionId::fresh()
                .map_err(|error| ManagerError::io("allocate ICMP rekey session", error))?;
            // Payload ownership is prepared outside the exclusive flow
            // transaction. begin_upstream_rekey_under revalidates the old
            // session after the writer is reacquired, so a competing
            // transition cannot consume this stale input.
            drop(self.flow_transaction.take());
            let payload = crate::net::payload::BufferedPayload::from_event_at(
                event,
                Some(trace),
                self.received_at,
            );
            let prepared =
                crate::flow_state::PreparedControlSend::new(self.received_at, drain_until);
            if !self.begin_transition() {
                return Ok(None);
            }
            let transition = self.flow_transaction.as_ref().unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "ICMP rekey lost its reacquired flow reservation"
                ))
            });
            let outcome = self
                .context
                .flow_state
                .begin_upstream_rekey_under(
                    transition,
                    rekey.session_id,
                    new_session_id,
                    expected_ack_destination_id,
                    self.received_at
                        .saturating_duration_since(self.context.t_start)
                        .as_secs()
                        .max(1),
                    drain_until,
                    payload,
                    prepared,
                )
                .map_err(|error| {
                    ManagerError::io(
                        "begin critical ICMP rekey",
                        super::flow_mutation_io_error("ICMP critical rekey failed", error),
                    )
                })?;
            drop(self.flow_transaction.take());
            self.context
                .upstream_side_state
                .retire_outbound_sessions(&[rekey.session_id]);
            crate::worker_support::handshake_trace::log_handshake_begin(
                self.context.cfg,
                self.context.worker_id,
                Some(trace),
                &outcome,
                event.payload_len(),
            );
            crate::worker_support::record_user_payload_route(
                &mut PacketContext::new(
                    self.context.worker_id,
                    self.context.t_start,
                    self.received_at,
                    self.context.cfg,
                    self.context.stats,
                    self.context.flow_state,
                ),
                crate::worker_support::UserPayloadRoute::BufferFirstHandshakePayload,
            );
            crate::worker_support::dispatch::retry_due_upstream_negotiation(
                &mut PacketContext::new(
                    self.context.worker_id,
                    self.context.t_start,
                    Instant::now(),
                    self.context.cfg,
                    self.context.stats,
                    self.context.flow_state,
                ),
                self.handles,
                self.cache,
                self.context.upstream_side_state,
                self.upstream_side_cache,
                Some(new_session_id),
            )
            .map_err(|error| ManagerError::io("send critical ICMP rekey control", error))?;
            return Ok(None);
        }
        Err(ManagerError::io(
            "handoff exhausted ICMP session",
            std::io::Error::other("ICMP session-pool handoff bound exhausted"),
        ))
    }

    pub(super) fn accept_unlocked_negotiation(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        candidate: crate::flow_state::PendingIcmpClientLock,
        trace: PacketTraceId,
    ) {
        let is_locked = match self.flow_transaction().is_locked() {
            Ok(is_locked) => is_locked,
            Err(error) => {
                self.context.stats.invariant_failure(C2U);
                crate::runtime_support::publish_process_fatal(format_args!(
                    "unlocked negotiation lost flow reservation: {error}"
                ));
                return;
            }
        };
        if is_locked {
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            return;
        }
        let flow_transaction = self.flow_transaction.as_ref().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "receive mutation lost its client-flow reservation"
            ))
        });
        let pending_reply = match accept_pending_negotiation(
            &mut *self.context,
            flow_transaction,
            Some(candidate),
            trace,
            admitted.event.icmp_meta().map_or(0, |icmp| icmp.seq()),
            self.received_at,
        ) {
            Ok(Some(reply)) => reply,
            Ok(None) | Err(()) => return,
        };
        if !self.resume_stable_read() {
            return;
        }
        let packet_context = &mut PacketContext::new(
            self.context.worker_id,
            self.context.t_start,
            self.received_at,
            self.context.cfg,
            self.context.stats,
            self.context.flow_state,
        );
        handle_c2u_session_control(
            packet_context,
            self.handles,
            self.context.client_side_state,
            Some(&pending_reply.0),
            false,
            &admitted.event,
            Some(trace),
        );
    }

    pub(super) fn emit_activation(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) {
        if let (Some(route), Some(session_key), Some(icmp)) = (
            self.cache.session_control_reply_route.clone(),
            self.flow_snapshot.client_active_session_key,
            admitted.event.icmp_meta(),
        ) {
            let packet_context = &mut PacketContext::new(
                self.context.worker_id,
                self.context.t_start,
                self.received_at,
                self.context.cfg,
                self.context.stats,
                self.context.flow_state,
            );
            super::sync_buffer::emit_local_session_activated(
                packet_context,
                self.handles,
                &route,
                crate::net::framing_shim::SessionActivated::new(session_key, icmp.seq()),
                Some(trace),
            );
        }
    }
}
