use super::client::{
    ClientWorkerContext, handle_receive_error, lease_due_sync_send,
    request_fatal_exit_after_client_lock_failure,
};
use super::client_dispatch::{process_client_packet, process_sync_packet};
use super::{
    CLIENT_TO_UPSTREAM as C2U, CachedClientState, GlobalSyncPacer, PacketContext, PacketReceiver,
    RECEIVE_ERROR_BACKOFF, ReceivePacketContext, SocketLeg, perform_sync_session_transition,
    send_sync_payload_or_cadence,
};
use crate::net::icmp_sequence::IcmpSequenceCache;
use crate::net::params::MAX_RECEIVE_CAPTURE;
use crate::net::sock_mgr::{ReceiverRole, SocketHandles};
use crate::runtime_support::FATAL_EXIT;
use crate::stats::StatsSink;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const UNLOCKED_SYNC_BACKOFF: Duration = Duration::from_millis(1);

enum LoopAction {
    Continue,
    Exit,
}

enum RetryAction {
    Proceed,
    Restart,
    Exit,
}

struct ClientLoopState {
    handles: SocketHandles,
    receiver: PacketReceiver<{ MAX_RECEIVE_CAPTURE }>,
    was_locked: bool,
    client_side_cache: IcmpSequenceCache,
    upstream_side_cache: IcmpSequenceCache,
    cache: CachedClientState,
    flow_snapshot_cache: crate::flow_state::FlowSnapshotCache,
    maintenance_wake: crate::flow_state::MaintenanceWakeRegistration,
}

pub(super) fn run(mut context: ClientWorkerContext<'_>) {
    let mut state = match ClientLoopState::new(&mut context) {
        Ok(state) => state,
        Err(error) => {
            log_error_dir!(
                context.worker_id,
                C2U,
                "could not create ICMP maintenance wake pair: {}",
                error
            );
            request_fatal_exit_after_client_lock_failure(context.exit_code_set);
            return;
        }
    };
    super::context::log_worker_ready(context.cfg, context.worker_id, true);
    loop {
        if context.exit_code_set.is_requested() {
            return;
        }
        if matches!(run_iteration(&mut context, &mut state), LoopAction::Exit) {
            return;
        }
    }
}

impl ClientLoopState {
    fn new(context: &mut ClientWorkerContext<'_>) -> std::io::Result<Self> {
        let handles = context
            .sock_mgr
            .capture_startup_handles()
            .map_err(std::io::Error::other)?;
        let receiver = PacketReceiver::new(
            context
                .sock_mgr
                .claim_receiver(ReceiverRole::Listener, context.worker_id)?,
        );
        let cache = CachedClientState::new(
            C2U,
            context.worker_id,
            context.cfg,
            &handles,
            context.cfg.debug_logs.handles,
        )?;
        Ok(Self {
            handles,
            receiver,
            was_locked: false,
            client_side_cache: context.client_side_state.cache(),
            upstream_side_cache: context.upstream_side_state.cache(),
            cache,
            flow_snapshot_cache: crate::flow_state::FlowSnapshotCache::new(),
            maintenance_wake: context
                .flow_state
                .register_maintenance_wake(context.flow_lane)?,
        })
    }
}

fn run_iteration(context: &mut ClientWorkerContext<'_>, state: &mut ClientLoopState) -> LoopAction {
    super::flush_completed_packet_diagnostics(context.cfg, context.worker_id);
    if let Err(error) = state.cache.service_descriptor_revocation() {
        crate::runtime_support::publish_process_fatal(format_args!(
            "client worker send-cache revocation failed: {error}"
        ));
        return LoopAction::Exit;
    }
    if let Err(error) = state.receiver.prepare_for_receive() {
        if crate::net::managed_socket::descriptor_cache_reconcile_is_retryable(&error) {
            return LoopAction::Continue;
        }
        crate::runtime_support::publish_process_fatal(format_args!(
            "client worker receive preparation failed: {error}"
        ));
        return LoopAction::Exit;
    }
    if context.flow_state.repair_maintenance_schedule().is_err() {
        log_error_dir!(
            context.worker_id,
            C2U,
            "ICMP maintenance schedule epoch exhausted"
        );
        context.stats.invariant_failure(C2U);
        request_fatal_exit_after_client_lock_failure(context.exit_code_set);
        return LoopAction::Exit;
    }
    context.stats.maintenance();
    if context.flow_state.maintenance_due(Instant::now()) {
        match retry_due_work(context, state) {
            RetryAction::Proceed => {}
            RetryAction::Restart => return LoopAction::Continue,
            RetryAction::Exit => return LoopAction::Exit,
        }
    }
    let topology_read = match context.flow_state.try_topology_read(context.flow_lane) {
        Ok(read) => read,
        Err(error) => match error.class() {
            crate::runtime_support::FailureClass::Shutdown => return LoopAction::Exit,
            crate::runtime_support::FailureClass::FatalInvariant => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client worker flow-topology authority failed: {error}"
                ));
                return LoopAction::Exit;
            }
            crate::runtime_support::FailureClass::RetryableContention
            | crate::runtime_support::FailureClass::PacketRejected
            | crate::runtime_support::FailureClass::OperationFailed => return LoopAction::Continue,
        },
    };
    super::pipeline_audit::checkpoint(C2U, super::PipelineStage::FlowLaneAcquired);
    let topology_read = match state.cache.ensure_worker_state(
        context.sock_mgr,
        &mut state.handles,
        topology_read,
        None,
    ) {
        Ok(super::cache::WorkerStateOutcome::Current(read)) => read,
        Ok(super::cache::WorkerStateOutcome::Reconciled(read)) => {
            drop(read);
            return LoopAction::Continue;
        }
        Err(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client worker handle refresh failed: {error}"
                ));
                return LoopAction::Exit;
            }
            return LoopAction::Continue;
        }
    };
    let flow_snapshot = match context.flow_state.admission_snapshot_with_read(
        &topology_read,
        &mut state.flow_snapshot_cache,
        Instant::now(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client worker flow snapshot refresh failed: {error}"
                ));
                return LoopAction::Exit;
            }
            return LoopAction::Continue;
        }
    };
    let locked = flow_snapshot.locked;
    state.was_locked = locked;
    if !topology_read.is_current() {
        return LoopAction::Continue;
    }
    if context.cfg.is_icmp_sync_enabled() && locked {
        let sync_snapshot = flow_snapshot.for_packet(None);
        return run_sync_iteration(context, state, topology_read, sync_snapshot);
    }
    if context.cfg.is_icmp_sync_enabled() && state.handles.listener_connected() {
        crate::authority::audited_thread_sleep(UNLOCKED_SYNC_BACKOFF);
        return LoopAction::Continue;
    }
    receive_regular_packet(context, state, topology_read)
}

fn retry_due_work(
    context: &mut ClientWorkerContext<'_>,
    state: &mut ClientLoopState,
) -> RetryAction {
    let recovery = {
        let mut packet_context = PacketContext::new(
            context.worker_id,
            context.t_start,
            Instant::now(),
            context.cfg,
            context.stats,
            context.flow_state,
        );
        super::dispatch::retry_due_upstream_recovery_payload(
            &mut packet_context,
            &state.handles,
            &mut state.cache,
            context.upstream_side_state,
            &mut state.upstream_side_cache,
        )
    };
    match recovery {
        Ok(true) => return RetryAction::Restart,
        Ok(false) => {}
        Err(error) => {
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal ICMP recovery payload retry failure: {}",
                error
            );
            context.stats.invariant_failure(C2U);
            context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
            return RetryAction::Exit;
        }
    }
    let negotiation = {
        let mut packet_context = PacketContext::new(
            context.worker_id,
            context.t_start,
            Instant::now(),
            context.cfg,
            context.stats,
            context.flow_state,
        );
        super::dispatch::retry_due_upstream_negotiation(
            &mut packet_context,
            &state.handles,
            &mut state.cache,
            context.upstream_side_state,
            &mut state.upstream_side_cache,
            None,
        )
    };
    match negotiation {
        Ok(true) => RetryAction::Restart,
        Ok(false) => RetryAction::Proceed,
        Err(error) => {
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal ICMP negotiation retry failure: {}",
                error
            );
            request_fatal_exit_after_client_lock_failure(context.exit_code_set);
            RetryAction::Exit
        }
    }
}

fn run_sync_iteration<'context>(
    context: &mut ClientWorkerContext<'context>,
    state: &mut ClientLoopState,
    flow_read: crate::flow_state::FlowTopologyReadLease<'context>,
    flow_snapshot: crate::flow_state::PacketFlowSnapshot,
) -> LoopAction {
    let Some(pacer) = context.sync_pacer else {
        log_error_dir!(
            context.worker_id,
            C2U,
            "sync pacing state missing while ICMP sync mode is enabled"
        );
        crate::authority::audited_thread_sleep(RECEIVE_ERROR_BACKOFF);
        return LoopAction::Continue;
    };
    let now = Instant::now();
    let due_sync_lease = match lease_due_sync_send(context.flow_state, pacer, now) {
        Ok(lease) => lease,
        Err(_) => return fatal_sync(context, "lease"),
    };
    if let Some(lease) = due_sync_lease {
        return send_due_sync(context, state, lease, now, flow_read, flow_snapshot);
    }
    receive_sync_packet(context, state, pacer, flow_read)
}

fn send_due_sync(
    context: &mut ClientWorkerContext<'_>,
    state: &mut ClientLoopState,
    mut lease: crate::flow_state::SyncSendLease,
    now: Instant,
    flow_read: crate::flow_state::FlowTopologyReadLease<'_>,
    flow_snapshot: crate::flow_state::PacketFlowSnapshot,
) -> LoopAction {
    let (flow_read, flow_snapshot) =
        match ensure_sync_transmit_session(context, state, flow_read, flow_snapshot, now) {
            Ok(prepared) => prepared,
            Err(SyncCacheRefreshError::Retryable) => {
                return if context.flow_state.complete_sync_send(lease, false).is_ok() {
                    LoopAction::Continue
                } else {
                    fatal_sync(context, "cache-refresh rollback")
                };
            }
            Err(SyncCacheRefreshError::Fatal) => {
                let _completion = context.flow_state.complete_sync_send(lease, false);
                return fatal_sync(context, "cache refresh");
            }
        };
    let accounting = lease.payload.as_ref().map(|payload| {
        (
            payload.payload_len(),
            payload.received_at(),
            payload.trace(),
        )
    });
    let attempt = {
        let permit = crate::worker_support::StableForwardPermit::for_upstream_packet(
            flow_read,
            &flow_snapshot,
            &state.handles,
        );
        let permit_snapshot = permit.snapshot();
        send_sync_payload_or_cadence(
            &mut PacketContext::new(
                context.worker_id,
                context.t_start,
                now,
                context.cfg,
                context.stats,
                context.flow_state,
            )
            .with_flow_snapshot(permit_snapshot),
            &state.handles,
            &mut state.cache,
            (context.upstream_side_state, &mut state.upstream_side_cache),
            &mut lease.payload,
            permit,
        )
    };
    let result = match attempt {
        Ok(super::dispatch::SyncSendAttempt::Complete(result)) => Ok(result),
        Ok(super::dispatch::SyncSendAttempt::TransitionRequired(transition)) => {
            perform_sync_session_transition(
                &mut PacketContext::new(
                    context.worker_id,
                    context.t_start,
                    now,
                    context.cfg,
                    context.stats,
                    context.flow_state,
                ),
                &state.handles,
                &mut state.cache,
                (context.upstream_side_state, &mut state.upstream_side_cache),
                &mut lease.payload,
                transition,
            )
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(result) => {
            let deferred_control = result.deferred_control;
            let completion = complete_sync_send(context, lease, accounting, result);
            if !matches!(completion, LoopAction::Exit)
                && let Some(control) = deferred_control
                && let Err(error) = super::dispatch::apply_deferred_upstream_control(
                    &mut PacketContext::new(
                        context.worker_id,
                        context.t_start,
                        now,
                        context.cfg,
                        context.stats,
                        context.flow_state,
                    ),
                    &state.handles,
                    &state.cache,
                    context.upstream_side_state,
                    control,
                )
            {
                log_error_dir!(
                    context.worker_id,
                    C2U,
                    "deferred synchronized ICMP control failed: {}",
                    error
                );
                return fatal_sync(context, "deferred control");
            }
            completion
        }
        Err(error) => {
            if context.flow_state.complete_sync_send(lease, false).is_err() {
                return fatal_sync(context, "rollback");
            }
            if super::dispatch::is_retryable_outbound_session_race(&error) {
                return LoopAction::Continue;
            }
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal synchronized payload state/build failure: {}",
                error
            );
            fatal_sync(context, "state/build")
        }
    }
}

#[derive(Clone, Copy)]
enum SyncCacheRefreshError {
    Retryable,
    Fatal,
}

fn ensure_sync_transmit_session<'flow>(
    context: &ClientWorkerContext<'flow>,
    state: &mut ClientLoopState,
    flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
    flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    now: Instant,
) -> Result<
    (
        crate::flow_state::FlowTopologyReadLease<'flow>,
        crate::flow_state::PacketFlowSnapshot,
    ),
    SyncCacheRefreshError,
> {
    let Some(session_id) = flow_snapshot.upstream_transmit_session_id else {
        return Ok((flow_read, flow_snapshot));
    };
    if crate::net::icmp_sequence::outbound_request_session_is_prepared(
        context.upstream_side_state,
        &state.upstream_side_cache,
        session_id,
    ) {
        return Ok((flow_read, flow_snapshot));
    }

    let (flow_read, ()) = flow_read
        .run_released(|| {
            crate::net::icmp_sequence::load_installed_outbound_session(
                context.upstream_side_state,
                &mut state.upstream_side_cache,
                session_id,
            )
        })
        .map_err(|error| match error {
            crate::flow_state::ReleasedFlowOperationError::Operation(_) => {
                SyncCacheRefreshError::Fatal
            }
            crate::flow_state::ReleasedFlowOperationError::Reacquire(error) => {
                if error.class().is_fatal() {
                    SyncCacheRefreshError::Fatal
                } else {
                    SyncCacheRefreshError::Retryable
                }
            }
        })?;
    let refreshed = context
        .flow_state
        .admission_snapshot_with_read(&flow_read, &mut state.flow_snapshot_cache, now)
        .map_err(|error| {
            if error.class().is_fatal() {
                SyncCacheRefreshError::Fatal
            } else {
                SyncCacheRefreshError::Retryable
            }
        })?
        .for_packet(None);
    if refreshed.upstream_transmit_session_id != Some(session_id) {
        return Err(SyncCacheRefreshError::Fatal);
    }
    Ok((flow_read, refreshed))
}

fn complete_sync_send(
    context: &mut ClientWorkerContext<'_>,
    lease: crate::flow_state::SyncSendLease,
    accounting: Option<(usize, Instant, Option<crate::diagnostics::PacketTraceId>)>,
    result: super::dispatch::PayloadSendResult,
) -> LoopAction {
    let committed = lease.payload.is_none();
    let completion = match context.flow_state.complete_sync_send(lease, committed) {
        Ok(completion) => completion,
        Err(_) => return fatal_sync(context, "completion"),
    };
    if completion != crate::flow_state::SyncSendCompletion::ResetWon
        && let (
            Some((payload_len, received_at, trace)),
            crate::net::session::HandledSendOutcome::Sent {
                used_unconnected, ..
            },
        ) = (accounting, result.outcome)
    {
        if context.cfg.stats_interval_mins != 0 {
            context.stats.send_add(
                C2U,
                payload_len as u64,
                received_at,
                result.attempted_at,
                result.completed_at,
            );
        }
        if let Some(trace) = trace {
            super::log_packet_send_disposition(
                context.cfg,
                trace,
                super::PacketDisposition::Forwarded,
                used_unconnected,
            );
        }
    }
    LoopAction::Continue
}

fn fatal_sync(context: &mut ClientWorkerContext<'_>, operation: &str) -> LoopAction {
    log_error_dir!(
        context.worker_id,
        C2U,
        "fatal sync payload {operation} invariant failure"
    );
    context.stats.invariant_failure(C2U);
    context.exit_code_set.store(FATAL_EXIT, Ordering::Release);
    LoopAction::Exit
}

fn receive_sync_packet<'context>(
    context: &mut ClientWorkerContext<'context>,
    state: &mut ClientLoopState,
    pacer: &GlobalSyncPacer,
    flow_read: crate::flow_state::FlowTopologyReadLease<'context>,
) -> LoopAction {
    let wait = pacer
        .poll_wait()
        .min(context.flow_state.maintenance_wait(Instant::now()));
    let mut outcome = match super::receive::poll_receive_with_checkpoint(
        ReceivePacketContext {
            cfg: context.cfg,
            worker_id: context.worker_id,
            flow_lane: context.flow_lane,
            c2u: C2U,
            socket_leg: SocketLeg::ClientFacing,
            proto: state.handles.listener.parser.protocol(),
            receive_policy: state.handles.listener.policy,
            stats: context.stats,
            flow_state: context.flow_state,
            wake: state.maintenance_wake.receiver(),
            wait,
        },
        &mut state.receiver,
        &state.handles,
        context.sock_mgr,
        &flow_read,
        &mut state.flow_snapshot_cache,
    ) {
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Received,
            outcome,
        }) => outcome,
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Wake,
            ..
        }) => {
            if let Err(error) = state.maintenance_wake.drain() {
                handle_receive_error(context, error);
            }
            return LoopAction::Continue;
        }
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Timeout,
            ..
        }) => return LoopAction::Continue,
        Err(error) => {
            drop(flow_read);
            handle_receive_error(context, error);
            return LoopAction::Continue;
        }
    };
    if let Some(mut packet) = outcome.take_packet() {
        let packet_dump = packet.take_packet_dump();
        if let Some(mutation_authority) =
            validate_received_authority(context, &state.handles, &packet, flow_read)
        {
            process_sync_packet(
                context,
                mutation_authority,
                &mut state.handles,
                &state.cache,
                &mut state.client_side_cache,
                packet.received_at,
                packet.admitted,
            );
        }
        if let Some(packet_dump) = packet_dump {
            packet_dump.emit(context.cfg);
        }
    } else {
        drop(flow_read);
        if let Some(diagnostic) = outcome.take_diagnostic() {
            diagnostic.emit(context.cfg, context.stats);
        }
    }
    LoopAction::Continue
}

fn receive_regular_packet<'context>(
    context: &mut ClientWorkerContext<'context>,
    state: &mut ClientLoopState,
    flow_read: crate::flow_state::FlowTopologyReadLease<'context>,
) -> LoopAction {
    let wait = context.flow_state.maintenance_wait(Instant::now());
    let mut outcome = match super::receive::poll_receive_with_checkpoint(
        ReceivePacketContext {
            cfg: context.cfg,
            worker_id: context.worker_id,
            flow_lane: context.flow_lane,
            c2u: C2U,
            socket_leg: SocketLeg::ClientFacing,
            proto: state.handles.listener.parser.protocol(),
            receive_policy: state.handles.listener.policy,
            stats: context.stats,
            flow_state: context.flow_state,
            wake: state.maintenance_wake.receiver(),
            wait,
        },
        &mut state.receiver,
        &state.handles,
        context.sock_mgr,
        &flow_read,
        &mut state.flow_snapshot_cache,
    ) {
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Received,
            outcome,
        }) => outcome,
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Wake,
            ..
        }) => {
            if let Err(error) = state.maintenance_wake.drain() {
                handle_receive_error(context, error);
            }
            return LoopAction::Continue;
        }
        Ok(super::receive::PollReceiveOutcome {
            status: super::receive::PollReceiveStatus::Timeout,
            ..
        }) => return LoopAction::Continue,
        Err(error) => {
            drop(flow_read);
            handle_receive_error(context, error);
            return LoopAction::Continue;
        }
    };
    if let Some(mut packet) = outcome.take_packet() {
        let packet_dump = packet.take_packet_dump();
        let packet_length = packet.length;
        let processing = if let Some(mutation_authority) =
            validate_received_authority(context, &state.handles, &packet, flow_read)
        {
            process_client_packet(
                context,
                mutation_authority,
                &mut state.handles,
                &mut state.cache,
                &mut state.client_side_cache,
                &mut state.upstream_side_cache,
                &mut state.was_locked,
                packet.received_at,
                packet.flow_snapshot,
                packet.admitted,
            )
        } else {
            Ok(())
        };
        if let Some(packet_dump) = packet_dump {
            packet_dump.emit(context.cfg);
        }
        log_debug!(
            context.cfg.debug_logs.packets,
            "[worker {}] received {} bytes from client socket",
            context.worker_id,
            packet_length
        );
        if let Err(error) = processing {
            log_error_dir!(
                context.worker_id,
                C2U,
                "fatal client-lock transaction failure: {}",
                error
            );
            request_fatal_exit_after_client_lock_failure(context.exit_code_set);
            return LoopAction::Exit;
        }
    } else {
        drop(flow_read);
        if let Some(diagnostic) = outcome.take_diagnostic() {
            diagnostic.emit(context.cfg, context.stats);
        }
    }
    LoopAction::Continue
}

fn validate_received_authority<'a>(
    context: &mut ClientWorkerContext<'a>,
    handles: &SocketHandles,
    packet: &super::receive::ReceivedWirePacket<'_, '_>,
    flow_read: crate::flow_state::FlowTopologyReadLease<'a>,
) -> Option<crate::worker_support::ReceiveMutationAuthority<'a>> {
    let current_flow_epoch = context.flow_state.flow_epoch();
    let receiver_generation = match context
        .sock_mgr
        .try_receiver_generation(ReceiverRole::Listener)
    {
        Ok(generation) => generation,
        Err(error) => {
            drop(flow_read);
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client receiver generation refresh failed: {error}"
                ));
            }
            return None;
        }
    };
    if flow_read.transaction_epoch() == packet.authority.flow_epoch
        && packet.authority.matches(
            handles,
            SocketLeg::ClientFacing,
            current_flow_epoch,
            receiver_generation,
        )
    {
        return Some(crate::worker_support::ReceiveMutationAuthority::new(
            flow_read,
        ));
    }
    drop(flow_read);
    context.stats.stale_authority_drop(C2U);
    if let Some(trace) = packet.admitted.trace {
        super::log_packet_disposition(
            context.cfg,
            trace,
            super::PacketDisposition::DropStaleAuthority,
        );
    }
    None
}
