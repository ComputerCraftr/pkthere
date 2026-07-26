use super::upstream_ack::{consume_reply_id_ack, retry_due_reply_id_payload};
use super::{
    CachedClientState, PacketContext, PacketReceiver, RECEIVE_ERROR_BACKOFF, ReceivePacketContext,
    SocketLeg, UPSTREAM_TO_CLIENT as C2U, UserPayloadRoute, record_user_payload_route,
};
use crate::cli::RuntimeConfig;
use crate::flow_state::{FlowReaderLane, FlowRuntimeState};
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::params::MAX_RECEIVE_CAPTURE;
use crate::net::payload::{
    PayloadEvent, classify_u2c_event, reply_id_negotiation_for_u2c_listener_reply,
    send_payload_with_lease,
};
use crate::net::session::{SendOutcome, handle_send_result};
use crate::net::sock_mgr::{ReceiverRole, SocketManager};
use crate::runtime_support::{RuntimeFailure, ShutdownController};
use crate::stats::{StatsRecorder, StatsSink};
use std::io;
use std::sync::Arc;
use std::time::Instant;

pub(super) enum UpstreamForwardOutcome {
    Continue,
    Fatal,
    AssociationStale(crate::net::managed_socket::AssociationStale),
}

struct ListenerPayloadSend<'payload> {
    destination: &'payload socket2::SockAddr,
    policy: pkthere_socket_policy::SocketSendPolicy,
    source_ip: Option<std::net::IpAddr>,
    outbound: &'payload crate::net::payload::OutboundPayloadEvent<'payload>,
}

impl<Flow, Protocol>
    crate::worker_support::context::StableSendTransaction<
        Flow,
        crate::net::managed_socket::ManagedSendLease<'_>,
        Protocol,
    > for ListenerPayloadSend<'_>
{
    type SendResult = io::Result<crate::net::managed_socket::ManagedSendResult>;
    type Output = Self::SendResult;

    fn send(
        &mut self,
        _flow: &mut Flow,
        send_lease: &crate::net::managed_socket::ManagedSendLease<'_>,
        _protocol: &mut Protocol,
    ) -> Self::SendResult {
        super::pipeline_audit::checkpoint(C2U, super::PipelineStage::BeforeSend);
        let result = send_payload_with_lease(
            send_lease,
            self.destination,
            self.policy,
            self.source_ip,
            self.outbound,
        );
        super::pipeline_audit::checkpoint(C2U, super::PipelineStage::AfterSend);
        result
    }

    fn complete(
        self,
        _flow: &mut Flow,
        _socket: &crate::net::managed_socket::ManagedSendLease<'_>,
        _protocol: &mut Protocol,
        send_result: Self::SendResult,
    ) -> Self::Output {
        send_result
    }
}

fn emit_deferred_packet_dump(
    cfg: &RuntimeConfig,
    packet_dump: &mut Option<super::packet_dump::DeferredPacketDump<'_>>,
) {
    if let Some(packet_dump) = packet_dump.take() {
        packet_dump.emit(cfg);
    }
}

fn drop_stale_upstream_packet(
    cfg: &RuntimeConfig,
    stats: &mut dyn StatsSink,
    trace: crate::worker_support::PacketTraceId,
) {
    stats.stale_authority_drop(false);
    crate::worker_support::log_packet_disposition(
        cfg,
        trace,
        crate::worker_support::PacketDisposition::DropStaleAuthority,
    );
}

pub(crate) struct UpstreamWorkerContext<'a> {
    pub(crate) t_start: Instant,
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) sock_mgr: &'a SocketManager,
    pub(crate) all_sock_mgrs: &'a [Arc<SocketManager>],
    pub(crate) worker_id: usize,
    pub(crate) flow_lane: FlowReaderLane,
    pub(crate) flow_state: &'a FlowRuntimeState,
    pub(crate) stats: &'a mut StatsRecorder,
    pub(crate) client_side_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_side_state: &'a SharedIcmpSequenceState,
    pub(crate) exit_code_set: &'a ShutdownController,
}

enum UpstreamIteration<'a> {
    Ready(crate::flow_state::FlowTopologyReadLease<'a>),
    Continue,
    Exit,
}

type UpstreamLoopSetup = (
    crate::net::sock_mgr::SocketHandles,
    PacketReceiver<{ MAX_RECEIVE_CAPTURE }>,
    crate::net::icmp_sequence::IcmpSequenceCache,
    crate::net::icmp_sequence::IcmpSequenceCache,
    CachedClientState,
    CachedClientState,
    crate::flow_state::FlowSnapshotCache,
    crate::flow_state::MaintenanceWakeRegistration,
);

fn initialize_upstream_loop(
    context: &mut UpstreamWorkerContext<'_>,
) -> Result<UpstreamLoopSetup, RuntimeFailure> {
    let handles = context
        .sock_mgr
        .capture_startup_handles()
        .map_err(|error| {
            RuntimeFailure::fatal(format_args!(
                "could not capture initial upstream handles: {error}"
            ))
        })?;
    let receiver = context
        .sock_mgr
        .claim_receiver(ReceiverRole::Upstream, context.worker_id)
        .map(PacketReceiver::<{ MAX_RECEIVE_CAPTURE }>::new)
        .map_err(|error| {
            RuntimeFailure::fatal(format_args!(
                "could not claim upstream receive ownership: {error}"
            ))
        })?;
    let client_side_cache = context.client_side_state.cache();
    let upstream_side_cache = context.upstream_side_state.cache();
    let cache = CachedClientState::new(
        false,
        context.worker_id,
        context.cfg,
        &handles,
        context.cfg.debug_logs.handles,
    )
    .map_err(|error| {
        RuntimeFailure::fatal(format_args!(
            "could not initialize U2C descriptor cache: {error}"
        ))
    })?;
    let auxiliary_lane =
        super::auxiliary_descriptor_cache_lane(context.cfg.workers, context.worker_id).ok_or_else(
            || RuntimeFailure::fatal(format_args!("auxiliary descriptor-cache lane overflow")),
        )?;
    let c2u_cache = CachedClientState::new_with_descriptor_lane(
        true,
        context.worker_id,
        auxiliary_lane,
        context.cfg,
        &handles,
        context.cfg.debug_logs.handles,
    )
    .map_err(|error| {
        RuntimeFailure::fatal(format_args!(
            "could not initialize C2U descriptor cache: {error}"
        ))
    })?;
    let maintenance_wake = context
        .flow_state
        .register_maintenance_wake(context.flow_lane)
        .map_err(|error| {
            RuntimeFailure::fatal(format_args!(
                "could not create ICMP maintenance wake pair: {error}"
            ))
        })?;
    Ok((
        handles,
        receiver,
        client_side_cache,
        upstream_side_cache,
        cache,
        c2u_cache,
        crate::flow_state::FlowSnapshotCache::new(),
        maintenance_wake,
    ))
}

#[allow(clippy::too_many_arguments)]
fn prepare_upstream_iteration<'flow>(
    context: &mut UpstreamWorkerContext<'flow>,
    handles: &mut crate::net::sock_mgr::SocketHandles,
    receiver: &mut PacketReceiver<{ MAX_RECEIVE_CAPTURE }>,
    cache: &mut CachedClientState,
    c2u_cache: &mut CachedClientState,
    client_side_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    upstream_side_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    flow_snapshot_cache: &mut crate::flow_state::FlowSnapshotCache,
    was_locked: &mut bool,
) -> UpstreamIteration<'flow> {
    if context.exit_code_set.is_requested() {
        return UpstreamIteration::Exit;
    }
    for (label, result) in [
        ("client-send", cache.service_descriptor_revocation()),
        ("upstream-send", c2u_cache.service_descriptor_revocation()),
    ] {
        if let Err(error) = result {
            crate::runtime_support::publish_process_fatal(format_args!(
                "upstream worker {label} cache revocation failed: {error}"
            ));
            return UpstreamIteration::Exit;
        }
    }
    if let Err(error) = receiver.prepare_for_receive() {
        if crate::net::managed_socket::descriptor_cache_reconcile_is_retryable(&error) {
            return UpstreamIteration::Continue;
        }
        crate::runtime_support::publish_process_fatal(format_args!(
            "upstream worker receive preparation failed: {error}"
        ));
        return UpstreamIteration::Exit;
    }
    if context.flow_state.repair_maintenance_schedule().is_err() {
        log_error_dir!(
            context.worker_id,
            C2U,
            "ICMP maintenance schedule epoch exhausted"
        );
        context.stats.invariant_failure(C2U);
        context.exit_code_set.store(
            crate::runtime_support::FATAL_EXIT,
            std::sync::atomic::Ordering::Release,
        );
        return UpstreamIteration::Exit;
    }
    context.stats.maintenance();
    let topology_read = match context.flow_state.try_topology_read(context.flow_lane) {
        Ok(read) => read,
        Err(error) => match error.class() {
            crate::runtime_support::FailureClass::Shutdown => return UpstreamIteration::Exit,
            crate::runtime_support::FailureClass::FatalInvariant => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "upstream worker flow-topology authority failed: {error}"
                ));
                return UpstreamIteration::Exit;
            }
            crate::runtime_support::FailureClass::RetryableContention
            | crate::runtime_support::FailureClass::PacketRejected
            | crate::runtime_support::FailureClass::OperationFailed => {
                return UpstreamIteration::Continue;
            }
        },
    };
    super::pipeline_audit::checkpoint(C2U, super::PipelineStage::FlowLaneAcquired);
    let topology_read = match cache.ensure_worker_state(
        context.sock_mgr,
        handles,
        topology_read,
        Some(c2u_cache),
    ) {
        Ok(super::cache::WorkerStateOutcome::Current(read)) => read,
        Ok(super::cache::WorkerStateOutcome::Reconciled(read)) => {
            drop(read);
            return UpstreamIteration::Continue;
        }
        Err(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "upstream worker handle refresh failed: {error}"
                ));
                return UpstreamIteration::Exit;
            }
            return UpstreamIteration::Continue;
        }
    };
    let flow_snapshot = match context.flow_state.admission_snapshot_with_read(
        &topology_read,
        flow_snapshot_cache,
        Instant::now(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "upstream worker flow snapshot refresh failed: {error}"
                ));
                return UpstreamIteration::Exit;
            }
            return UpstreamIteration::Continue;
        }
    };
    *was_locked = flow_snapshot.locked;
    if !topology_read.is_current() {
        return UpstreamIteration::Continue;
    }
    if context.flow_state.maintenance_due(Instant::now()) {
        drop(topology_read);
        let (retry_attempted, deferred_control) = retry_due_reply_id_payload(
            context,
            handles,
            c2u_cache,
            client_side_cache,
            upstream_side_cache,
        );
        if retry_attempted {
            if let Some(control) = deferred_control
                && let Err(error) = super::dispatch::apply_deferred_upstream_control(
                    &mut PacketContext::new(
                        context.worker_id,
                        context.t_start,
                        Instant::now(),
                        context.cfg,
                        context.stats,
                        context.flow_state,
                    ),
                    handles,
                    c2u_cache,
                    context.upstream_side_state,
                    control,
                )
            {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "deferred buffered-send ICMP control failed: {error}"
                ));
                context.stats.invariant_failure(C2U);
                return UpstreamIteration::Exit;
            }
            return UpstreamIteration::Continue;
        }
        return UpstreamIteration::Continue;
    }
    UpstreamIteration::Ready(topology_read)
}

pub(crate) fn run_upstream_to_client_thread(mut context: UpstreamWorkerContext<'_>) {
    let (
        mut handles,
        mut receiver,
        mut client_side_cache,
        mut upstream_side_cache,
        mut cache,
        mut c2u_cache,
        mut flow_snapshot_cache,
        maintenance_wake,
    ) = match initialize_upstream_loop(&mut context) {
        Ok(setup) => setup,
        Err(error) => {
            context.exit_code_set.request_current_fatal(error);
            return;
        }
    };
    super::context::log_worker_ready(context.cfg, context.worker_id, false);
    let mut was_locked = false;
    loop {
        let cfg = context.cfg;
        let sock_mgr = context.sock_mgr;
        let worker_id = context.worker_id;
        let flow_state = context.flow_state;
        super::flush_completed_packet_diagnostics(context.cfg, context.worker_id);
        let flow_read = match prepare_upstream_iteration(
            &mut context,
            &mut handles,
            &mut receiver,
            &mut cache,
            &mut c2u_cache,
            &mut client_side_cache,
            &mut upstream_side_cache,
            &mut flow_snapshot_cache,
            &mut was_locked,
        ) {
            UpstreamIteration::Ready(flow_read) => flow_read,
            UpstreamIteration::Continue => continue,
            UpstreamIteration::Exit => return,
        };
        // Capture admission only after the readiness wait so the packet is
        // never classified with a stale unlocked snapshot.
        let mut outcome = match super::receive::poll_receive_with_checkpoint(
            ReceivePacketContext {
                cfg: context.cfg,
                worker_id: context.worker_id,
                flow_lane: context.flow_lane,
                c2u: false,
                socket_leg: SocketLeg::UpstreamFacing,
                proto: handles.upstream.parser.protocol(),
                receive_policy: handles.upstream.policy,
                stats: context.stats,
                flow_state: context.flow_state,
                wake: maintenance_wake.receiver(),
                wait: context.flow_state.maintenance_wait(Instant::now()),
            },
            &mut receiver,
            &handles,
            context.sock_mgr,
            &flow_read,
            &mut flow_snapshot_cache,
        ) {
            Ok(super::receive::PollReceiveOutcome {
                status: super::receive::PollReceiveStatus::Received,
                outcome,
            }) => outcome,
            Ok(super::receive::PollReceiveOutcome {
                status: super::receive::PollReceiveStatus::Wake,
                ..
            }) => {
                drop(flow_read);
                if let Err(error) = maintenance_wake.drain() {
                    handle_upstream_receive_error(context.worker_id, context.stats, error);
                }
                continue;
            }
            Ok(super::receive::PollReceiveOutcome {
                status: super::receive::PollReceiveStatus::Timeout,
                ..
            }) => {
                drop(flow_read);
                continue;
            }
            Err(ref error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                drop(flow_read);
                handle_upstream_receive_error(worker_id, context.stats, error);
                continue;
            }
        };
        if let Some(mut packet) = outcome.take_packet() {
            let mut packet_dump = packet.take_packet_dump();
            let Some(trace) = packet.admitted.trace else {
                context.stats.invariant_failure(C2U);
                emit_deferred_packet_dump(cfg, &mut packet_dump);
                continue;
            };
            let mut flow_snapshot = packet.flow_snapshot;
            let mut flow_read = Some(flow_read);
            let current_flow_epoch = flow_state.flow_epoch();
            let receiver_generation = match sock_mgr.try_receiver_generation(ReceiverRole::Upstream)
            {
                Ok(generation) => generation,
                Err(error) => {
                    drop(flow_read.take());
                    if error.class().is_fatal() {
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "upstream receiver generation refresh failed: {error}"
                        ));
                    }
                    drop_stale_upstream_packet(cfg, context.stats, trace);
                    emit_deferred_packet_dump(cfg, &mut packet_dump);
                    continue;
                }
            };
            if flow_read
                .as_ref()
                .unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "upstream receive mutation lost its flow read authority"
                    ))
                })
                .transaction_epoch()
                != packet.authority.flow_epoch
                || !packet.authority.matches(
                    &handles,
                    SocketLeg::UpstreamFacing,
                    current_flow_epoch,
                    receiver_generation,
                )
            {
                drop(flow_read.take());
                drop_stale_upstream_packet(cfg, context.stats, trace);
                emit_deferred_packet_dump(cfg, &mut packet_dump);
                continue;
            }
            let locked_now = flow_snapshot.locked;
            was_locked = locked_now;
            if locked_now {
                let event = packet.admitted.event;
                if matches!(event, PayloadEvent::SessionControl { .. }) {
                    let reserve_local = super::dispatch::reply_id_ack_is_reserve_local(
                        cfg, &event, &handles, flow_state,
                    );
                    if reserve_local {
                        drop(flow_read.take());
                        if super::upstream_ack::consume_reserve_reply_id_ack(
                            &mut context,
                            &event,
                            trace,
                            packet.received_at,
                            &handles,
                        ) {
                            emit_deferred_packet_dump(cfg, &mut packet_dump);
                            continue;
                        }
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "reserve-local upstream control was not an ACK"
                        ));
                        context.stats.invariant_failure(C2U);
                        emit_deferred_packet_dump(cfg, &mut packet_dump);
                        continue;
                    }
                    drop(flow_read.take());
                    let mut flow_transaction = match flow_state.try_reserve_client_flow() {
                        Ok(transaction) => Some(transaction),
                        Err(error) => {
                            if error.class().is_fatal() {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "upstream control transition reservation failed: {error}"
                                ));
                            }
                            drop_stale_upstream_packet(cfg, context.stats, trace);
                            emit_deferred_packet_dump(cfg, &mut packet_dump);
                            continue;
                        }
                    };
                    if consume_reply_id_ack(
                        &mut context,
                        &mut flow_transaction,
                        packet.authority.topology_epoch,
                        &event,
                        trace,
                        packet.received_at,
                        &mut handles,
                        &mut cache,
                        &mut c2u_cache,
                        &mut client_side_cache,
                        &mut upstream_side_cache,
                    ) {
                        emit_deferred_packet_dump(cfg, &mut packet_dump);
                        continue;
                    }
                    drop(flow_transaction.take());
                    flow_read = match flow_state.try_topology_read(context.flow_lane) {
                        Ok(read) => Some(read),
                        Err(error) => {
                            if error.class().is_fatal() {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "upstream control could not resume stable flow authority: {error}"
                                ));
                            }
                            emit_deferred_packet_dump(cfg, &mut packet_dump);
                            continue;
                        }
                    };
                    let Some(ref resumed_read) = flow_read else {
                        emit_deferred_packet_dump(cfg, &mut packet_dump);
                        continue;
                    };
                    flow_snapshot = match flow_state.admission_snapshot_with_read(
                        resumed_read,
                        &mut flow_snapshot_cache,
                        Instant::now(),
                    ) {
                        Ok(snapshot) => {
                            snapshot.for_packet(event.icmp_meta().map(|meta| meta.session_id()))
                        }
                        Err(error) => {
                            if error.class().is_fatal() {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "upstream control could not refresh flow snapshot: {error}"
                                ));
                            }
                            emit_deferred_packet_dump(cfg, &mut packet_dump);
                            continue;
                        }
                    };
                }
                if !flow_read.as_ref().is_some_and(|read| read.is_current()) {
                    drop(flow_read.take());
                    drop_stale_upstream_packet(cfg, context.stats, trace);
                    emit_deferred_packet_dump(cfg, &mut packet_dump);
                    continue;
                }
                let flow_read_owned = flow_read.take().unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "upstream forwarding lost its flow-read authority"
                    ))
                });
                let outcome = process_admitted_upstream_event(
                    &mut context,
                    &handles,
                    &mut cache,
                    &mut client_side_cache,
                    flow_read_owned,
                    flow_snapshot,
                    &event,
                    trace,
                    packet.received_at,
                );
                if !(super::upstream_retry::UpstreamOutcomeContext {
                    worker: &mut context,
                    handles: &handles,
                    flow_snapshot_cache: &mut flow_snapshot_cache,
                    cache: &mut cache,
                    client_side_cache: &mut client_side_cache,
                    flow_snapshot,
                    event: &event,
                    trace,
                    received_at: packet.received_at,
                })
                .handle(outcome)
                {
                    emit_deferred_packet_dump(cfg, &mut packet_dump);
                    return;
                }
            } else {
                drop(flow_read.take());
                crate::worker_support::log_packet_disposition(
                    cfg,
                    trace,
                    crate::worker_support::PacketDisposition::DropNoActiveFlow,
                );
            }
            emit_deferred_packet_dump(cfg, &mut packet_dump);
        } else {
            drop(flow_read);
            if let Some(diagnostic) = outcome.take_diagnostic() {
                diagnostic.emit(cfg, context.stats);
            }
        }
    }
}

fn handle_upstream_receive_error(worker_id: usize, stats: &mut StatsRecorder, error: io::Error) {
    log_error_dir!(worker_id, C2U, "recv error: {}", error);
    stats.receive_error(C2U);
    crate::authority::audited_thread_sleep(RECEIVE_ERROR_BACKOFF);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn process_admitted_upstream_event(
    context: &mut UpstreamWorkerContext<'_>,
    handles: &crate::net::sock_mgr::SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    flow_read: crate::flow_state::FlowTopologyReadLease<'_>,
    flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    event: &PayloadEvent<'_>,
    trace: crate::worker_support::PacketTraceId,
    received_at: Instant,
) -> UpstreamForwardOutcome {
    let decision = match classify_u2c_event(context.cfg, event, context.upstream_side_state) {
        Ok(decision) => decision,
        Err(error) => {
            drop(flow_read);
            log_debug_dir!(
                context.cfg.debug_logs.drops,
                context.worker_id,
                C2U,
                "classify_u2c_event rejected packet: {}",
                error
            );
            let disposition =
                crate::worker_support::record_sequence_rejection(context.stats, C2U, &error);
            crate::worker_support::log_packet_disposition(context.cfg, trace, disposition);
            return UpstreamForwardOutcome::Continue;
        }
    };
    if !decision.should_send() {
        drop(flow_read);
        let disposition = match decision {
            crate::net::payload::U2cDecision::ConsumeCadence => {
                crate::worker_support::PacketDisposition::ConsumeCadence
            }
            crate::net::payload::U2cDecision::ConsumeSessionControl => {
                crate::worker_support::PacketDisposition::ConsumeSessionControl
            }
            crate::net::payload::U2cDecision::ForwardPayload
            | crate::net::payload::U2cDecision::ForwardSessionControl => {
                context.stats.invariant_failure(C2U);
                return UpstreamForwardOutcome::Continue;
            }
        };
        crate::worker_support::log_packet_disposition(context.cfg, trace, disposition);
        return UpstreamForwardOutcome::Continue;
    }
    if event.is_user_payload() {
        record_user_payload_route(
            &mut PacketContext::new(
                context.worker_id,
                context.t_start,
                received_at,
                context.cfg,
                context.stats,
                context.flow_state,
            ),
            UserPayloadRoute::ForwardNow,
        );
    }
    let source_id = cache.route.icmp_source_id();
    let reply_id = reply_id_negotiation_for_u2c_listener_reply(
        event,
        context
            .cfg
            .listener_reply_id_request
            .resolved_reply_id(handles.listener.listen_local_filter.id()),
    )
    .filter(|_| context.cfg.listen_proto == crate::cli::SupportedProtocol::ICMP);
    let permit = crate::worker_support::StableForwardPermit::for_listener_packet(
        flow_read,
        &flow_snapshot,
        handles,
    );
    super::pipeline_audit::checkpoint(C2U, super::PipelineStage::ReplayAdmitted);
    forward_upstream_event(
        context,
        handles,
        cache,
        client_side_cache,
        permit,
        event,
        source_id,
        reply_id,
        trace,
        received_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn forward_upstream_event(
    context: &mut UpstreamWorkerContext<'_>,
    handles: &crate::net::sock_mgr::SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
    permit: crate::worker_support::StableForwardPermit<'_>,
    event: &PayloadEvent<'_>,
    source_id: u16,
    reply_id: Option<crate::net::framing_shim::ReplyIdNegotiation>,
    trace: crate::worker_support::PacketTraceId,
    received_at: Instant,
) -> UpstreamForwardOutcome {
    if let Err(error) = permit.validate(context.flow_state, handles) {
        drop(permit);
        log_debug_dir!(
            context.cfg.debug_logs.drops,
            context.worker_id,
            C2U,
            "dropping stale upstream forwarding permit: {}",
            error
        );
        crate::worker_support::log_packet_disposition(
            context.cfg,
            trace,
            crate::worker_support::PacketDisposition::DropStaleAuthority,
        );
        return UpstreamForwardOutcome::Continue;
    }
    let outbound_session = reply_id
        .map(crate::net::framing_shim::ReplyIdNegotiation::instance)
        .or(permit.snapshot().client_transmit_session_id);
    let prepared_outbound = match crate::net::payload::prepare_outbound_payload_event(
        event,
        cache.route.icmp_header_id,
        C2U,
        source_id,
        outbound_session,
        reply_id,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(permit);
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal outbound payload preparation invariant failure: {}",
                error
            );
            context.stats.invariant_failure(C2U);
            context.exit_code_set.store(
                crate::runtime_support::FATAL_EXIT,
                std::sync::atomic::Ordering::Release,
            );
            crate::worker_support::log_packet_disposition(
                context.cfg,
                trace,
                crate::worker_support::PacketDisposition::SendFailed,
            );
            return UpstreamForwardOutcome::Fatal;
        }
    };
    let cached_send = match cache.acquire_prepared_send(handles) {
        Ok(lease) => lease,
        Err(error) => {
            drop(permit);
            log_debug_dir!(
                context.cfg.debug_logs.drops,
                context.worker_id,
                C2U,
                "dropping stale listener socket authority: {}",
                error
            );
            crate::worker_support::log_packet_disposition(
                context.cfg,
                trace,
                crate::worker_support::PacketDisposition::DropStaleAuthority,
            );
            return UpstreamForwardOutcome::Continue;
        }
    };
    let super::cache::CachedSendLease {
        socket: send_lease,
        destination,
        source_ip: send_source_ip,
        ..
    } = cached_send;
    super::pipeline_audit::checkpoint(C2U, super::PipelineStage::DestinationSocketAcquired);
    if let Err(error) = permit.validate(context.flow_state, handles) {
        drop(send_lease);
        drop(permit);
        log_debug_dir!(
            context.cfg.debug_logs.drops,
            context.worker_id,
            C2U,
            "dropping listener send after socket acquisition changed authority: {}",
            error
        );
        crate::worker_support::log_packet_disposition(
            context.cfg,
            trace,
            crate::worker_support::PacketDisposition::DropStaleAuthority,
        );
        return UpstreamForwardOutcome::Continue;
    }
    let sequence_reservation = if event.dst_proto() == crate::cli::SupportedProtocol::ICMP {
        let Some(session_id) = outbound_session else {
            drop(send_lease);
            drop(permit);
            crate::worker_support::log_packet_disposition(
                context.cfg,
                trace,
                crate::worker_support::PacketDisposition::SendFailed,
            );
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal outbound reply is missing its active ICMP session"
            );
            context.stats.invariant_failure(C2U);
            context.exit_code_set.store(
                crate::runtime_support::FATAL_EXIT,
                std::sync::atomic::Ordering::Release,
            );
            return UpstreamForwardOutcome::Fatal;
        };
        Some(crate::net::icmp_sequence::outbound_reply_reservation(
            context.client_side_state,
            client_side_cache,
            session_id,
        ))
    } else {
        None
    };
    let stable_send = crate::worker_support::StableSendCore::new(permit)
        .acquire_socket(send_lease)
        .reserve_protocol(sequence_reservation)
        .unwrap_or_else(|never| match never {});
    let send_sequence = stable_send
        .protocol()
        .as_ref()
        .map(crate::net::icmp_sequence::OutboundReplySequence::sequence);
    super::pipeline_audit::checkpoint(C2U, super::PipelineStage::SequenceReserved);
    let outbound = match prepared_outbound.finish(send_sequence) {
        Ok(outbound) => outbound,
        Err(_) => {
            drop(stable_send);
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal prepared ICMP payload lost its reserved sequence"
            );
            context.stats.invariant_failure(C2U);
            context.exit_code_set.store(
                crate::runtime_support::FATAL_EXIT,
                std::sync::atomic::Ordering::Release,
            );
            return UpstreamForwardOutcome::Fatal;
        }
    };
    let attempted_at = Instant::now();
    let send_result = stable_send.perform(ListenerPayloadSend {
        destination,
        policy: handles.listener.policy.send_policy,
        source_ip: send_source_ip,
        outbound: &outbound,
    });
    let association_stale = send_result
        .as_ref()
        .err()
        .and_then(crate::net::managed_socket::AssociationStale::from_io);
    handle_send_result(
        &mut PacketContext::new(
            context.worker_id,
            context.t_start,
            received_at,
            context.cfg,
            context.stats,
            context.flow_state,
        ),
        C2U,
        event,
        SendOutcome {
            result: &send_result,
            attempted_at,
            completed_at: Instant::now(),
            account_success: true,
            destination,
            trace: Some(trace),
            trace_kind: crate::net::session::SendTraceKind::Forward,
        },
    );
    match association_stale {
        Some(stale) => UpstreamForwardOutcome::AssociationStale(stale),
        None => UpstreamForwardOutcome::Continue,
    }
}

#[cfg(all(test, not(miri)))]
mod tests;
