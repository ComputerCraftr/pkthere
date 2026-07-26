use super::client::ClientWorkerContext;
use super::{
    CLIENT_TO_UPSTREAM as C2U, CachedClientState, CachedSendRoute, PacketDisposition, PacketTraceId,
};
use crate::cli::WorkerFlowMode;
use crate::endpoint::LogicalEndpoint;
use crate::flow_state::{ClientFlowReservation, PendingIcmpClientLock, PendingIcmpClientLockSet};
use crate::net::icmp_sequence::{
    IcmpSequenceCache, register_receive_candidate, reset_sequence_pair_for_client_lock,
    retain_admitted_receive_sessions, unregister_receive_candidate,
};
use crate::net::payload::IcmpPayloadMeta;
use crate::net::sock_mgr::{
    ClientFlowUpdate, ManagerError, PreparedClientFlowGroup, SocketHandles, SocketManager,
};
use crate::stats::StatsSink;

pub(super) fn pending_session_control_reply_route(
    candidate: PendingIcmpClientLock,
) -> Option<CachedSendRoute> {
    let inbound = candidate.listener_flow.inbound?;
    let outbound = candidate.listener_flow.outbound?;
    let destination = candidate.listener_flow.outbound_destination()?;
    Some(
        CachedClientState::build_pending_session_control_reply_route(
            destination,
            outbound.src.id(),
            outbound.src.ip(),
            inbound.dst.id(),
        ),
    )
}

pub(super) fn accept_pending_negotiation(
    context: &mut ClientWorkerContext<'_>,
    flow_transaction: &ClientFlowReservation<'_>,
    candidate: Option<PendingIcmpClientLock>,
    trace: PacketTraceId,
    acknowledge_sequence: u16,
    observed_at: std::time::Instant,
) -> Result<Option<(CachedSendRoute, bool)>, ()> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let Some(session_id) = candidate.session_id() else {
        context.stats.topology_error(C2U);
        return Err(());
    };
    if let Err(error) = flow_transaction.assert_current() {
        match error.class() {
            crate::runtime_support::FailureClass::RetryableContention
            | crate::runtime_support::FailureClass::Shutdown
            | crate::runtime_support::FailureClass::OperationFailed
            | crate::runtime_support::FailureClass::PacketRejected => {
                context.stats.topology_error(C2U);
            }
            crate::runtime_support::FailureClass::FatalInvariant => {
                context.stats.invariant_failure(C2U);
                crate::runtime_support::publish_process_fatal(format_args!(
                    "pending ICMP negotiation lost its flow reservation"
                ));
            }
        }
        return Err(());
    }
    retain_admitted_receive_sessions(
        context.client_side_state,
        context
            .flow_state
            .client_session_admission(std::time::Instant::now()),
    );
    let inserted = match register_receive_candidate(context.client_side_state, session_id) {
        Ok(inserted) => inserted,
        Err(error) => {
            log_error_dir!(
                context.worker_id,
                C2U,
                "failed to register bounded ICMP receive candidate: {}",
                error
            );
            context.stats.invariant_failure(C2U);
            return Err(());
        }
    };
    let set = if let Ok(set) = context.flow_state.set_pending_icmp_client_lock_until(
        candidate,
        observed_at
            .saturating_duration_since(context.t_start)
            .as_secs(),
        trace,
        acknowledge_sequence,
        observed_at,
        observed_at + std::time::Duration::from_secs(context.cfg.icmp_handshake_timeout_secs),
    ) {
        set
    } else {
        if inserted {
            unregister_receive_candidate(context.client_side_state, session_id);
        }
        log_debug_dir!(
            context.cfg.debug_logs.drops,
            context.worker_id,
            C2U,
            "dropping mismatched pre-lock ICMP reply-ID negotiation"
        );
        context.stats.topology_error(C2U);
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Err(());
    };
    Ok(pending_session_control_reply_route(candidate)
        .map(|route| (route, matches!(set, PendingIcmpClientLockSet::Started))))
}

pub(super) struct PreparedClientLock<'manager> {
    group: PreparedClientFlowGroup<'manager>,
    claim: Option<crate::flow_claim::FlowClaim<'manager>>,
}

pub(super) fn prepare_client_lock<'manager>(
    context: &mut ClientWorkerContext<'manager>,
    source: LogicalEndpoint,
    candidate: PendingIcmpClientLock,
    trace: PacketTraceId,
) -> Result<Option<PreparedClientLock<'manager>>, ManagerError> {
    if context.cfg.reresolve_mode.allow_upstream() {
        context.sock_mgr.reresolve(true, false)?;
    }
    let flow = candidate.flow_key;
    let claim = if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow {
        let Some(claims) = context.flow_claims else {
            return Err(ManagerError::Poisoned {
                authority: "single-flow claim table",
            });
        };
        match claims.try_claim(flow, context.worker_pair_id) {
            Ok(claim) => Some(claim),
            Err(()) => {
                super::log_packet_disposition(
                    context.cfg,
                    trace,
                    PacketDisposition::DropFlowConflict,
                );
                return Ok(None);
            }
        }
    } else {
        None
    };

    let listener_flow = candidate.listener_flow;
    let client = listener_flow.inbound.map_or_else(
        || source.to_socket_addr(),
        |inbound| inbound.src.to_socket_addr(),
    );
    let managers: Vec<&SocketManager> =
        if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
            context
                .all_sock_mgrs
                .iter()
                .map(AsRef::<SocketManager>::as_ref)
                .collect()
        } else {
            vec![context.sock_mgr]
        };
    match SocketManager::prepare_client_flow_group(
        &managers,
        ClientFlowUpdate {
            flow,
            listener_flow,
            admitting_listener_slot: context.sock_mgr.socket_slot(),
            client,
        },
    ) {
        Ok(group) => Ok(Some(PreparedClientLock { group, claim })),
        Err(error) => Err(error),
    }
}

pub(super) fn release_prepared_client_lock(
    _context: &mut ClientWorkerContext<'_>,
    prepared: PreparedClientLock<'_>,
) {
    drop(prepared);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_client_lock_with_transaction(
    context: &mut ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    was_locked: &mut bool,
    prepared: PreparedClientLock<'_>,
    initial_icmp: Option<&IcmpPayloadMeta>,
    trace: PacketTraceId,
    flow_transaction: &mut ClientFlowReservation<'_>,
) -> Result<bool, ManagerError> {
    let PreparedClientLock { group, claim } = prepared;
    let claim_generation = claim.as_ref().map(crate::flow_claim::FlowClaim::generation);
    if flow_transaction.is_locked()? {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Ok(false);
    }
    let transition = SocketManager::begin_client_flow_group_transition(group, flow_transaction)?;
    if let Err(error) = reset_sequence_pair_for_client_lock(
        context.cfg.debug_logs.packets,
        context.client_side_state,
        client_side_cache,
        initial_icmp,
        context.upstream_side_state,
        upstream_side_cache,
    ) {
        let manager_error = match transition.abort(error.to_string()) {
            Err(manager_error) => manager_error,
            Ok(_) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "client-flow transition abort returned usable manager state"
                ));
                ManagerError::Poisoned {
                    authority: "client-flow transition abort",
                }
            }
        };
        return Err(manager_error);
    }
    let published = transition.publish(claim_generation)?;
    if let Some(claim) = claim {
        claim.commit();
    }

    let local_handles = published
        .into_iter()
        .find(|update| {
            update.handles.listener.evidence_key.socket_slot == context.sock_mgr.socket_slot()
        })
        .ok_or_else(|| ManagerError::TransactionFailed {
            operation: "publish client flow",
            cause: "shared transaction omitted the local socket manager".into(),
            journal: Vec::new(),
        })?
        .handles;
    *was_locked = true;
    *handles = local_handles;
    Ok(true)
}
