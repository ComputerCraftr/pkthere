use super::client::ClientWorkerContext;
use super::{CachedClientState, CachedSendRoute, PacketDisposition, PacketTraceId};
use crate::cli::WorkerFlowMode;
use crate::flow_state::PendingIcmpClientLock;
use crate::net::icmp_sequence::{IcmpSequenceCache, reset_sequence_state};
use crate::net::params::CanonicalAddr;
use crate::net::sock_mgr::SocketHandles;
use crate::stats::StatsSink;
use std::sync::Arc;

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
            outbound.src.id,
            outbound.src.ip,
            inbound.dst.id,
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
    source: CanonicalAddr,
    candidate: PendingIcmpClientLock,
    trace: PacketTraceId,
) -> bool {
    let flow = candidate.flow_key;
    let listener_flow = candidate.listener_flow;
    if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
        && context
            .flow_claims
            .is_some_and(|claims| !claims.try_claim(flow, context.worker_pair_id))
    {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return false;
    }

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
    context.flow_state.set_locked(true);
    context.flow_state.clear_pending_icmp_client_lock();
    *was_locked = true;

    let source_socket_addr = listener_flow.inbound.map_or_else(
        || source.as_sock_addr(),
        |inbound| inbound.src.canonical().as_sock_addr(),
    );
    Arc::make_mut(&mut handles.listener).listener_connected = false;
    if context.cfg.debug_behavior.client_unconnected {
        log_info!("Locked to single client {} (not connected)", source);
    } else if let Err(error) = handles.client_sock.connect(&source_socket_addr) {
        log_warn!("connect client_sock to {} failed: {}", source, error);
        log_info!("Locked to single client {} (not connected)", source);
    } else {
        Arc::make_mut(&mut handles.listener).listener_connected = true;
        log_info!("Locked to single client {} (connected)", source);
    }

    handles.version = context.sock_mgr.set_listener_remote_connected(
        Some(flow),
        listener_flow,
        handles.listener.listener_connected,
        handles.version,
    );
    Arc::make_mut(&mut handles.listener).listener_flow = listener_flow;
    log_debug_dir!(
        context.cfg.debug_logs.handles,
        context.worker_id,
        C2U,
        "publish lock: flow={:?} connected={} ver={}",
        flow,
        handles.listener.listener_connected,
        handles.version
    );

    if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
        for manager in context.all_sock_mgrs {
            if !std::ptr::eq(manager.as_ref(), context.sock_mgr)
                && let Err(error) = manager.set_client_sock_connected(
                    Some(flow),
                    listener_flow,
                    handles.listener.listener_connected,
                    &source_socket_addr,
                    0,
                )
            {
                log_warn_dir!(
                    context.worker_id,
                    C2U,
                    "failed to publish shared client lock to worker pair: {}",
                    error
                );
            }
        }
    }
    if let Ok(new_handles) = context.sock_mgr.reresolve(
        context.cfg.reresolve_mode.allow_upstream(),
        false,
        "Re-resolved",
    ) {
        *handles = new_handles;
        cache.refresh_from_handles(handles);
    }
    true
}
