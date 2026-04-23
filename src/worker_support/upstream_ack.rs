use super::upstream::UpstreamWorkerContext;
use super::{
    CachedClientState, ObserveAckResult, PacketContext, PacketDisposition, PacketTraceId,
    SequenceContext, log_packet_disposition, observe_reply_id_ack, send_payload_event_now,
};
use crate::cli::{SupportedProtocol, WorkerFlowMode};
use crate::net::icmp_sequence::IcmpSequenceCache;
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::SocketHandles;
use std::time::Instant;

const C2U: bool = false;

fn update_upstream_peer_ids(
    context: &UpstreamWorkerContext<'_>,
    handles: &mut SocketHandles,
    peer_source_id: u16,
    peer_reply_id: u16,
) -> bool {
    let changed = handles.upstream.upstream_remote_filter.id != peer_reply_id
        || handles
            .upstream
            .upstream_flow
            .inbound
            .is_some_and(|flow| flow.src.id != peer_source_id)
        || handles
            .upstream
            .upstream_flow
            .outbound
            .is_some_and(|flow| flow.dst.id != peer_reply_id);
    if context.cfg.upstream_proto != SupportedProtocol::ICMP || !changed {
        return false;
    }

    log_info!(
        "Updating upstream ICMP peer IDs to source {}, reply {}",
        peer_source_id,
        peer_reply_id
    );
    if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
        for manager in context.all_sock_mgrs {
            let local_manager = std::ptr::eq(manager.as_ref(), context.sock_mgr);
            let previous_version = if local_manager {
                handles.version
            } else {
                manager.get_version()
            };
            let version =
                manager.set_upstream_peer_ids(peer_source_id, peer_reply_id, previous_version);
            if local_manager {
                handles.version = version;
            }
        }
    } else {
        handles.version =
            context
                .sock_mgr
                .set_upstream_peer_ids(peer_source_id, peer_reply_id, handles.version);
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(super) fn consume_reply_id_ack(
    context: &UpstreamWorkerContext<'_>,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
    handles: &mut SocketHandles,
    client_cache: &mut CachedClientState,
    c2u_cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
) -> bool {
    match observe_reply_id_ack(
        context.cfg,
        context.worker_id,
        C2U,
        event,
        handles,
        context.flow_state,
        trace,
    ) {
        ObserveAckResult::Matched {
            payload,
            peer_source_id,
            peer_reply_id,
            trigger_trace,
        } => {
            if update_upstream_peer_ids(context, handles, peer_source_id, peer_reply_id) {
                *handles = context.sock_mgr.refresh_handles();
                client_cache.refresh_from_handles(handles);
                c2u_cache.refresh_from_handles(handles);
            }

            let consumed_session_control = event.is_session_control();
            if consumed_session_control {
                log_packet_disposition(
                    context.cfg,
                    trigger_trace,
                    PacketDisposition::ConsumeSessionControl,
                );
            }
            let buffered_event = payload.as_event();
            if let Err(error) = send_payload_event_now(
                PacketContext::new(
                    context.worker_id,
                    context.t_start,
                    received_at,
                    context.cfg,
                    context.stats,
                    context.flow_state,
                ),
                &buffered_event,
                handles,
                c2u_cache,
                SequenceContext::new(
                    context.client_side_state,
                    client_side_cache,
                    context.upstream_side_state,
                    upstream_side_cache,
                ),
                payload.trace(),
            ) {
                log_debug_dir!(
                    context.cfg.debug_logs.drops,
                    context.worker_id,
                    C2U,
                    "buffered payload flush error: {}",
                    error
                );
                return true;
            }
            consumed_session_control
        }
        ObserveAckResult::Duplicate { trigger_trace } => {
            log_packet_disposition(context.cfg, trigger_trace, PacketDisposition::DropDuplicate);
            true
        }
        ObserveAckResult::WrongAckDestinationId { trigger_trace }
        | ObserveAckResult::NoPending { trigger_trace } => {
            log_packet_disposition(
                context.cfg,
                trigger_trace,
                PacketDisposition::ConsumeSessionControl,
            );
            true
        }
        ObserveAckResult::NotAck => false,
    }
}
