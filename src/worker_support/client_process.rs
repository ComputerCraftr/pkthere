use super::client_dispatch::{
    AdmittedWirePacket, C2U, C2uDispatchOutcome, CachedClientState, ClientWorkerContext,
    IcmpSequenceCache, Instant, ManagerError, PacketContext, PacketDisposition, PacketTraceId,
    SocketHandles, accept_pending_negotiation, dispatch_c2u_event, emit_client_reset_challenge,
    handle_c2u_session_control, log_packet_disposition, prepare_client_lock,
    publish_client_lock_with_transaction, release_prepared_client_lock,
};
use crate::flow_state::ClientFlowReservation;
use crate::stats::StatsSink;

pub(super) struct ClientPacketProcessor<'a, 'context> {
    pub(super) context: &'a mut ClientWorkerContext<'context>,
    pub(super) flow_read: Option<crate::flow_state::FlowTopologyReadLease<'context>>,
    pub(super) flow_transaction: Option<ClientFlowReservation<'context>>,
    pub(super) handles: &'a mut SocketHandles,
    pub(super) cache: &'a mut CachedClientState,
    pub(super) client_side_cache: &'a mut IcmpSequenceCache,
    pub(super) upstream_side_cache: &'a mut IcmpSequenceCache,
    pub(super) was_locked: &'a mut bool,
    pub(super) received_at: Instant,
    pub(super) flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    pub(super) flow_snapshot_cache: crate::flow_state::FlowSnapshotCache,
}

impl<'a, 'context> ClientPacketProcessor<'a, 'context> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        context: &'a mut ClientWorkerContext<'context>,
        mutation_authority: crate::worker_support::ReceiveMutationAuthority<'context>,
        handles: &'a mut SocketHandles,
        cache: &'a mut CachedClientState,
        client_side_cache: &'a mut IcmpSequenceCache,
        upstream_side_cache: &'a mut IcmpSequenceCache,
        was_locked: &'a mut bool,
        received_at: Instant,
        flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    ) -> Self {
        let flow_read = mutation_authority.into_flow();
        Self {
            context,
            flow_read: Some(flow_read),
            flow_transaction: None,
            handles,
            cache,
            client_side_cache,
            upstream_side_cache,
            was_locked,
            received_at,
            flow_snapshot,
            flow_snapshot_cache: crate::flow_state::FlowSnapshotCache::new(),
        }
    }

    pub(super) fn process(&mut self, admitted: AdmittedWirePacket<'_>) -> Result<(), ManagerError> {
        let Some(trace) = admitted.trace else {
            self.context.stats.invariant_failure(C2U);
            return Ok(());
        };
        if self.conflicts_with_published_flow(&admitted) {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            return Ok(());
        }
        if admitted.unknown_session_for_reset() {
            self.handle_unknown_session(&admitted, trace);
            return Ok(());
        }
        if self.flow_snapshot.locked && !self.ensure_upstream_transmit_session() {
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            return Ok(());
        }
        if self.flow_snapshot.locked {
            self.process_locked(admitted, trace)
        } else {
            self.process_unlocked(admitted, trace)
        }
    }

    pub(super) fn flow_transaction(&self) -> &ClientFlowReservation<'context> {
        self.flow_transaction.as_ref().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "receive mutation lost its client-flow reservation"
            ))
        })
    }

    pub(super) fn take_stable_read(
        &mut self,
        missing_context: &'static str,
    ) -> crate::flow_state::FlowTopologyReadLease<'context> {
        self.flow_read.take().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!("{missing_context}"))
        })
    }

    pub(super) fn release_stable_authority(&mut self) {
        drop(self.flow_read.take());
    }

    pub(super) fn begin_transition(&mut self) -> bool {
        if self.flow_transaction.is_some() {
            return true;
        }
        drop(self.flow_read.take());
        match self.context.flow_state.try_reserve_client_flow() {
            Ok(transaction) => {
                self.flow_transaction = Some(transaction);
                true
            }
            Err(error) => {
                if error.class().is_fatal() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "client packet transition reservation failed: {error}"
                    ));
                    self.context.stats.invariant_failure(C2U);
                }
                false
            }
        }
    }

    pub(super) fn resume_stable_read(&mut self) -> bool {
        drop(self.flow_transaction.take());
        match self
            .context
            .flow_state
            .try_topology_read(self.context.flow_lane)
        {
            Ok(read) => {
                let snapshot = match self.context.flow_state.admission_snapshot_with_read(
                    &read,
                    &mut self.flow_snapshot_cache,
                    Instant::now(),
                ) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        if error.class().is_fatal() {
                            crate::runtime_support::publish_process_fatal(format_args!(
                                "client packet could not refresh stable flow snapshot: {error}"
                            ));
                            self.context.stats.invariant_failure(C2U);
                        }
                        return false;
                    }
                };
                self.flow_snapshot = snapshot.for_packet(None);
                self.flow_read = Some(read);
                self.ensure_upstream_transmit_session()
            }
            Err(error) => {
                if error.class().is_fatal() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "client packet could not resume stable flow authority: {error}"
                    ));
                    self.context.stats.invariant_failure(C2U);
                }
                false
            }
        }
    }

    fn ensure_upstream_transmit_session(&mut self) -> bool {
        let Some(session_id) = self.flow_snapshot.upstream_transmit_session_id else {
            return true;
        };
        if crate::net::icmp_sequence::outbound_request_session_is_prepared(
            self.context.upstream_side_state,
            self.upstream_side_cache,
            session_id,
        ) {
            return true;
        }
        let Some(read) = self.flow_read.take() else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "transmit-cache refresh lost its flow-read authority"
            ));
            self.context.stats.invariant_failure(C2U);
            return false;
        };
        match read.run_released(|| {
            crate::net::icmp_sequence::load_installed_outbound_session(
                self.context.upstream_side_state,
                self.upstream_side_cache,
                session_id,
            )
        }) {
            Ok((read, ())) => {
                self.flow_read = Some(read);
                true
            }
            Err(crate::flow_state::ReleasedFlowOperationError::Operation(_)) => false,
            Err(crate::flow_state::ReleasedFlowOperationError::Reacquire(error)) => {
                if error.class().is_fatal() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "transmit-cache installation could not reacquire flow authority: {error}"
                    ));
                    self.context.stats.invariant_failure(C2U);
                }
                false
            }
        }
    }

    pub(super) fn conflicts_with_published_flow(&self, admitted: &AdmittedWirePacket<'_>) -> bool {
        self.handles.listener.flow.is_some_and(|active_flow| {
            admitted
                .candidate_flow_key()
                .is_some_and(|candidate_flow| candidate_flow != active_flow)
        })
    }

    pub(super) fn handle_unknown_session(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) {
        let Some(icmp) = admitted.event.icmp_meta() else {
            self.context.stats.invariant_failure(C2U);
            return;
        };
        let candidate = admitted.reset_candidate();
        let peer_flow = self
            .flow_snapshot
            .client_flow
            .or_else(|| candidate.map(|candidate| candidate.flow_key));
        let route = self.cache.session_control_reply_route.clone().or_else(|| {
            candidate.and_then(super::client_lock::pending_session_control_reply_route)
        });
        if let (Some(peer_flow), Some(route)) = (peer_flow, route.as_ref()) {
            if !self.begin_transition() {
                return;
            }
            emit_client_reset_challenge(
                self.context,
                &mut self.flow_transaction,
                self.handles,
                route,
                peer_flow,
                crate::net::framing_shim::RejectedFrameEvidence::Data {
                    session: icmp.session_id(),
                    sequence: icmp.seq(),
                },
                trace,
                self.received_at,
            );
        } else {
            self.context.stats.invariant_failure(C2U);
        }
    }

    pub(super) fn process_locked(
        &mut self,
        admitted: AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) -> Result<(), ManagerError> {
        if self.handle_locked_control(&admitted, trace) {
            return Ok(());
        }
        let sequence_already_admitted = match self.admit_locked_session(&admitted, trace) {
            Some(admitted) => admitted,
            None => return Ok(()),
        };
        super::pipeline_audit::checkpoint(C2U, super::PipelineStage::ReplayAdmitted);
        if let Some(candidate) = admitted
            .lock_candidate()
            .filter(|candidate| candidate.session_id().is_some())
        {
            if !self.begin_transition() {
                return Ok(());
            }
            let flow_transaction = self.flow_transaction.as_ref().unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "pending-session promotion lost its flow reservation"
                ))
            });
            match self
                .context
                .flow_state
                .promote_pending_icmp_client_session_with_replay_under(
                    flow_transaction,
                    candidate,
                    self.received_at
                        + std::time::Duration::from_secs(
                            self.context.cfg.icmp_handshake_timeout_secs,
                        ),
                    self.context.client_side_state,
                    self.client_side_cache,
                ) {
                Ok(_) => {}
                Err(crate::flow_state::FlowMutationError::Operation(_)) => {
                    log_packet_disposition(
                        self.context.cfg,
                        trace,
                        PacketDisposition::DropFlowConflict,
                    );
                    return Ok(());
                }
                Err(crate::flow_state::FlowMutationError::Authority(error)) => {
                    return Err(error.into());
                }
            }
            if !self.resume_stable_read() {
                return Ok(());
            }
        }
        let flow_read =
            self.take_stable_read("stable client dispatch lost its flow-read authority");
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
            &admitted.event,
            trace,
            self.received_at,
            sequence_already_admitted,
            permit,
        );
        self.finish_dispatch(&admitted.event, trace, outcome)
    }

    pub(super) fn handle_locked_control(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) -> bool {
        if let Some(crate::net::framing_shim::IcmpTunnelControl::GenerationAdvance(advance)) =
            admitted.event.icmp_meta().and_then(|icmp| icmp.control())
        {
            if !self.begin_transition() {
                return true;
            }
            let expires_at = self.received_at
                + std::time::Duration::from_secs(self.context.cfg.icmp_handshake_timeout_secs);
            if !self.context.flow_state.authorize_client_generation_advance(
                advance,
                self.received_at,
                expires_at,
            ) {
                log_packet_disposition(
                    self.context.cfg,
                    trace,
                    PacketDisposition::DropFlowConflict,
                );
                return true;
            }
            if !self.resume_stable_read() {
                return true;
            }
            let packet_context = &mut PacketContext::new(
                self.context.worker_id,
                self.context.t_start,
                self.received_at,
                self.context.cfg,
                self.context.stats,
                self.context.flow_state,
            );
            if !handle_c2u_session_control(
                packet_context,
                self.handles,
                self.context.client_side_state,
                self.cache.session_control_reply_route.as_ref(),
                false,
                &admitted.event,
                Some(trace),
            ) {
                self.context.stats.invariant_failure(C2U);
            }
            return true;
        }
        let Some(candidate) = admitted.pending_negotiation() else {
            return false;
        };
        if !self.begin_transition() {
            return true;
        }
        let Some(candidate_key) = candidate.session_key else {
            self.context.stats.invariant_failure(C2U);
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::Filtered);
            return true;
        };
        if candidate.reset_challenge == 0
            && self
                .context
                .flow_state
                .client_pool_generation()
                .is_some_and(|generation| generation != candidate_key.generation())
        {
            if let Some(route) = super::client_lock::pending_session_control_reply_route(candidate)
            {
                emit_client_reset_challenge(
                    self.context,
                    &mut self.flow_transaction,
                    self.handles,
                    &route,
                    candidate.flow_key,
                    crate::net::framing_shim::RejectedFrameEvidence::Negotiate {
                        candidate: candidate_key,
                        sequence: admitted.event.icmp_meta().map_or(0, |icmp| icmp.seq()),
                    },
                    trace,
                    self.received_at,
                );
            }
            return true;
        }
        self.accept_and_ack_candidate(admitted, candidate, candidate_key, trace);
        true
    }

    pub(super) fn accept_and_ack_candidate(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        candidate: crate::flow_state::PendingIcmpClientLock,
        candidate_key: crate::net::framing_shim::SessionKey,
        trace: PacketTraceId,
    ) {
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
        let ack_lease = match self
            .context
            .flow_state
            .begin_client_candidate_ack_send(candidate_key, self.received_at)
        {
            Ok(lease) => lease,
            Err(_) => {
                self.fail_candidate_ack("lease");
                return;
            }
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
        let ack_sent = handle_c2u_session_control(
            packet_context,
            self.handles,
            self.context.client_side_state,
            Some(&pending_reply.0),
            false,
            &admitted.event,
            Some(trace),
        );
        if let Some(ack_lease) = ack_lease
            && self
                .context
                .flow_state
                .complete_client_candidate_ack_send(ack_lease, ack_sent)
                .is_err()
        {
            self.fail_candidate_ack("completion");
        }
    }

    pub(super) fn fail_candidate_ack(&mut self, operation: &str) {
        log_error_dir!(
            self.context.worker_id,
            C2U,
            "fatal receive-candidate ACK {operation} invariant failure"
        );
        self.context.stats.invariant_failure(C2U);
        self.context.exit_code_set.store(
            crate::runtime_support::FATAL_EXIT,
            std::sync::atomic::Ordering::Release,
        );
    }

    pub(super) fn admit_locked_session(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) -> Option<bool> {
        if admitted.event.is_cadence_packet()
            && admitted.event.icmp_meta().is_some_and(|icmp| {
                self.flow_snapshot.client_receive_session_id != Some(icmp.session_id())
            })
        {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            return None;
        }
        let Some(session_id) = admitted
            .event
            .is_user_payload()
            .then(|| admitted.event.icmp_meta().map(|icmp| icmp.session_id()))
            .flatten()
        else {
            return Some(false);
        };
        if self.flow_snapshot.client_receive_session_id == Some(session_id) {
            return Some(false);
        }
        if self.flow_snapshot.client_packet_session
            == crate::flow_state::PacketSessionAdmission::Candidate
        {
            if let Err(error) = crate::net::payload::classify_c2u_data_or_cadence_event(
                &admitted.event,
                self.context.client_side_state,
                self.client_side_cache,
            ) {
                self.release_stable_authority();
                log_packet_disposition(
                    self.context.cfg,
                    trace,
                    super::record_sequence_rejection(self.context.stats, C2U, &error),
                );
                return None;
            }
            if self
                .promote_ready_session(admitted, trace, session_id)
                .is_err()
            {
                return None;
            }
            Some(true)
        } else if self.flow_snapshot.client_packet_session
            == crate::flow_state::PacketSessionAdmission::Draining
        {
            Some(false)
        } else {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            None
        }
    }

    pub(super) fn promote_ready_session(
        &mut self,
        admitted: &AdmittedWirePacket<'_>,
        trace: PacketTraceId,
        session_id: crate::net::framing_shim::SessionId,
    ) -> Result<(), ()> {
        if !self.begin_transition() {
            return Err(());
        }
        let flow_transaction = self.flow_transaction.as_mut().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ready-session promotion lost its flow reservation"
            ))
        });
        let promoted = self
            .context
            .flow_state
            .promote_ready_icmp_client_session_with_replay_under(
                flow_transaction,
                session_id,
                self.received_at
                    + std::time::Duration::from_secs(self.context.cfg.icmp_handshake_timeout_secs),
                self.context.client_side_state,
                self.client_side_cache,
            );
        match promoted {
            Ok(true) => {
                if !self.resume_stable_read() {
                    return Err(());
                }
                self.emit_activation(admitted, trace);
            }
            Ok(false) => {}
            Err(crate::flow_state::FlowMutationError::Operation(_)) => {
                log_packet_disposition(
                    self.context.cfg,
                    trace,
                    PacketDisposition::DropFlowConflict,
                );
                return Err(());
            }
            Err(crate::flow_state::FlowMutationError::Authority(error)) => {
                self.context.stats.invariant_failure(C2U);
                crate::runtime_support::publish_process_fatal(format_args!(
                    "ready-session promotion lost flow authority: {error}"
                ));
                return Err(());
            }
        }
        Ok(())
    }

    pub(super) fn process_unlocked(
        &mut self,
        admitted: AdmittedWirePacket<'_>,
        trace: PacketTraceId,
    ) -> Result<(), ManagerError> {
        if self.handles.listener_connected() {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropNoActiveFlow);
            return Ok(());
        }
        let Some(source) = admitted.normalized_source else {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropNoActiveFlow);
            return Ok(());
        };
        if admitted.event.is_cadence_packet() {
            self.release_stable_authority();
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::ConsumeCadence);
            return Ok(());
        }
        if let Some(candidate) = admitted.pending_negotiation() {
            if !self.begin_transition() {
                return Ok(());
            }
            self.accept_unlocked_negotiation(&admitted, candidate, trace);
            return Ok(());
        }
        let Some(lock_candidate) = admitted.lock_candidate() else {
            log_packet_disposition(self.context.cfg, trace, PacketDisposition::DropFlowConflict);
            return Ok(());
        };
        let initial_icmp = admitted
            .event
            .is_user_payload()
            .then(|| admitted.event.icmp_meta())
            .flatten();
        let initial_sequence_admitted = initial_icmp.is_some();
        let published_flow = lock_candidate.flow_key;
        self.release_stable_authority();
        let Some(prepared) = prepare_client_lock(self.context, source, lock_candidate, trace)?
        else {
            return Ok(());
        };
        if !self.begin_transition() {
            release_prepared_client_lock(self.context, prepared);
            return Ok(());
        }
        let flow_transaction = self.flow_transaction.as_mut().unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "client lock publication lost its flow reservation"
            ))
        });
        if !publish_client_lock_with_transaction(
            self.context,
            self.handles,
            self.client_side_cache,
            self.upstream_side_cache,
            self.was_locked,
            prepared,
            initial_icmp,
            trace,
            flow_transaction,
        )? {
            return Ok(());
        }
        drop(self.flow_transaction.take());
        log_info!(
            "Locked to single client {} ({})",
            source,
            if self.handles.listener_connected() {
                "connected"
            } else {
                "not connected"
            }
        );
        log_debug_dir!(
            self.context.cfg.debug_logs.handles,
            self.context.worker_id,
            C2U,
            "publish lock: flow={:?} connected={} ver={}",
            published_flow,
            self.handles.listener_connected(),
            self.handles.version
        );
        if !self.resume_stable_read() {
            return Ok(());
        }
        if initial_sequence_admitted {
            self.emit_activation(&admitted, trace);
        }
        let flow_read =
            self.take_stable_read("newly locked client dispatch lost its flow-read authority");
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
            &admitted.event,
            trace,
            self.received_at,
            initial_sequence_admitted,
            permit,
        );
        self.finish_dispatch(&admitted.event, trace, outcome)
    }

    pub(super) fn finish_dispatch(
        &mut self,
        event: &crate::net::payload::PayloadEvent<'_>,
        trace: PacketTraceId,
        mut outcome: C2uDispatchOutcome,
    ) -> Result<(), ManagerError> {
        loop {
            outcome = match outcome {
                C2uDispatchOutcome::Complete => return Ok(()),
                C2uDispatchOutcome::Rekey(rekey) => {
                    let Some(next) = self.handle_outbound_rekey(event, trace, rekey)? else {
                        return Ok(());
                    };
                    next
                }
                C2uDispatchOutcome::AssociationStale(stale) => {
                    let Some(next) = self.handle_stale_association(event, trace, stale)? else {
                        return Ok(());
                    };
                    next
                }
                C2uDispatchOutcome::BeginHandshake(negotiation) => {
                    self.handle_outbound_handshake(event, trace, negotiation)?;
                    return Ok(());
                }
                C2uDispatchOutcome::DeferredControl(control) => {
                    self.handle_deferred_peer_control(control)?;
                    return Ok(());
                }
            }
        }
    }

    pub(super) fn handle_stale_association(
        &mut self,
        event: &crate::net::payload::PayloadEvent<'_>,
        trace: PacketTraceId,
        stale: crate::net::managed_socket::AssociationStale,
    ) -> Result<Option<C2uDispatchOutcome>, ManagerError> {
        let retry = super::stale_association::ObservedStaleRetry::new(
            stale.expected_epoch(),
            self.flow_snapshot,
            event,
        );
        if !self.begin_transition() {
            return Ok(None);
        }
        let current = self.context.flow_state.packet_snapshot_under(
            self.flow_transaction(),
            event.icmp_meta().map(|metadata| metadata.session_id()),
            Instant::now(),
        )?;
        let retry = match retry.authorize_transition(current) {
            Ok(retry) => retry,
            Err(_) => {
                drop(self.flow_transaction.take());
                return Ok(None);
            }
        };
        self.context.sock_mgr.reconcile_stale_send_association(
            self.handles,
            true,
            stale.expected_epoch(),
        )?;
        let retry = retry.reconciled(stale.expected_epoch()).map_err(|error| {
            ManagerError::io(
                "reconcile stale upstream association",
                std::io::Error::other(format!("stale association retry lost authority: {error:?}")),
            )
        })?;
        if !self.resume_stable_read() {
            return Ok(None);
        }
        let retry = match retry.authorize(self.flow_snapshot) {
            Ok(retry) => retry,
            Err(_) => {
                self.release_stable_authority();
                return Ok(None);
            }
        };
        let flow_read = self.take_stable_read("association retry lost its flow-read authority");
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
            retry.payload(),
            trace,
            self.received_at,
            true,
            permit,
        );
        let stale_again = matches!(outcome, C2uDispatchOutcome::AssociationStale(_));
        if retry.complete(stale_again).is_err() {
            return Err(ManagerError::io(
                "retry stale upstream association",
                std::io::Error::other("stale association recurred after one managed retry"),
            ));
        }
        Ok(Some(outcome))
    }

    pub(super) fn handle_deferred_peer_control(
        &mut self,
        control: crate::flow_state::DeferredPeerControl,
    ) -> Result<(), ManagerError> {
        match control {
            crate::flow_state::DeferredPeerControl::SessionActivated {
                control,
                observed_at,
            } => {
                self.context
                    .flow_state
                    .observe_upstream_session_activated(
                        control,
                        observed_at,
                        crate::net::icmp_sequence::DataSequenceEvidenceState::Sent,
                    )
                    .map_err(|_| {
                        ManagerError::io(
                            "apply deferred ICMP activation",
                            std::io::Error::other("deferred ICMP activation became stale"),
                        )
                    })?;
            }
            crate::flow_state::DeferredPeerControl::ResetRequired {
                control: reset,
                observed_at,
            } => {
                if !self.begin_transition() {
                    return Ok(());
                }
                let expected_ack_destination_id = self
                    .cache
                    .expected_upstream_ack_destination_id(self.handles)
                    .map_err(|error| {
                        ManagerError::io("resolve deferred ICMP reset destination", error)
                    })?;
                let recovery = self
                    .context
                    .flow_state
                    .recover_upstream_session_under(
                        self.flow_transaction(),
                        crate::flow_state::UpstreamRecoveryRequest {
                            sequences: self.context.upstream_side_state,
                            reset,
                            expected_ack_destination_id,
                            observed_at,
                            absolute_deadline: observed_at
                                + std::time::Duration::from_secs(
                                    self.context.cfg.icmp_handshake_timeout_secs,
                                ),
                            started_s: observed_at
                                .saturating_duration_since(self.context.t_start)
                                .as_secs()
                                .max(1),
                        },
                    )
                    .map_err(|error| {
                        ManagerError::io(
                            "apply deferred ICMP reset recovery",
                            super::flow_mutation_io_error(
                                "deferred ICMP reset recovery failed",
                                error,
                            ),
                        )
                    })?;
                if let crate::flow_state::UpstreamSessionRecovery::Recovered {
                    retired_sessions,
                    ..
                } = recovery
                {
                    self.context
                        .upstream_side_state
                        .retire_outbound_sessions(&retired_sessions);
                }
            }
        }
        Ok(())
    }
}
