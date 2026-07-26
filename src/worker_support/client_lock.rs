use super::client::ClientWorkerContext;
use super::{CachedClientState, CachedSendRoute, PacketDisposition, PacketTraceId};
use crate::cli::WorkerFlowMode;
use crate::endpoint::LogicalEndpoint;
use crate::flow_state::PendingIcmpClientLock;
use crate::net::icmp_sequence::{IcmpSequenceCache, reset_sequence_state};
use crate::net::sock_mgr::{ClientFlowUpdate, ManagerError, SocketHandles, SocketManager};
use crate::stats::StatsSink;

const C2U: bool = true;

fn pending_session_control_reply_route(
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
    context: &ClientWorkerContext<'_>,
    candidate: Option<PendingIcmpClientLock>,
    trace: PacketTraceId,
) -> Result<Option<CachedSendRoute>, ()> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if context
        .flow_state
        .set_pending_icmp_client_lock(candidate)
        .is_err()
    {
        log_debug_dir!(
            context.cfg.debug_logs.drops,
            context.worker_id,
            C2U,
            "dropping mismatched pre-lock ICMP reply-ID negotiation"
        );
        context.stats.drop_err(C2U);
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Err(());
    }
    Ok(pending_session_control_reply_route(candidate))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_client_lock(
    context: &ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    was_locked: &mut bool,
    source: LogicalEndpoint,
    candidate: PendingIcmpClientLock,
    trace: PacketTraceId,
) -> Result<bool, ManagerError> {
    let flow_transaction = context.flow_state.client_lock_transaction();
    if flow_transaction.is_locked() {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Ok(false);
    }
    let flow = candidate.flow_key;
    let listener_flow = candidate.listener_flow;
    if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
        && context
            .flow_claims
            .is_some_and(|claims| !claims.try_claim(flow, context.worker_pair_id))
    {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Ok(false);
    }

    let client = listener_flow.inbound.map_or_else(
        || source.to_socket_addr(),
        |inbound| inbound.src.to_socket_addr(),
    );
    let connect_socket = context
        .sock_mgr
        .get_listener_worker_socket_policy()
        .connects_after_lock(handles.listener.policy);
    let managers: Vec<&SocketManager> =
        if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
            context
                .all_sock_mgrs
                .iter()
                .map(AsRef::<SocketManager>::as_ref)
                .collect::<Vec<_>>()
        } else {
            vec![context.sock_mgr]
        };
    let published = match SocketManager::establish_client_flow_group(
        &managers,
        &flow_transaction,
        ClientFlowUpdate {
            flow,
            listener_flow,
            connect_socket,
            client,
        },
    ) {
        Ok(published) => published,
        Err(error) => {
            if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
                && let Some(claims) = context.flow_claims
            {
                claims.release(flow, context.worker_pair_id);
            }
            return Err(error);
        }
    };

    reset_sequence_state(
        context.cfg.debug_logs.packets,
        context.client_side_state,
        client_side_cache,
    );
    reset_sequence_state(
        context.cfg.debug_logs.packets,
        context.upstream_side_state,
        upstream_side_cache,
    );
    context.flow_state.clear_pending_icmp_client_lock();
    *was_locked = true;
    *handles = published
        .into_iter()
        .find(|update| {
            update.handles.listener.evidence_key.socket_slot == context.sock_mgr.socket_slot()
        })
        .expect("shared transaction must return local manager handles")
        .handles;
    log_info!(
        "Locked to single client {} ({})",
        source,
        if handles.listener_connected() {
            "connected"
        } else {
            "not connected"
        }
    );
    log_debug_dir!(
        context.cfg.debug_logs.handles,
        context.worker_id,
        C2U,
        "publish lock: flow={:?} connected={} ver={}",
        flow,
        handles.listener_connected(),
        handles.version
    );
    if let Ok(new_handles) = context.sock_mgr.reresolve(
        context.cfg.reresolve_mode.allow_upstream(),
        false,
        "Re-resolved",
    ) {
        *handles = new_handles;
        cache.refresh_from_handles(handles);
    }
    Ok(true)
}
