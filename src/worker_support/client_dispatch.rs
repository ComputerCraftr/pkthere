use super::client::ClientWorkerContext;
use super::client_lock::{accept_pending_negotiation, publish_client_lock};
use super::packet_admission::AdmittedWirePacket;
use super::{
    BufferedSyncUpdate, CachedClientState, PacketContext, PacketDisposition, PacketTraceId,
    SequenceContext, buffer_sync_event, handle_c2u_session_control, log_packet_disposition,
    send_payload_event_now, send_user_payload_event,
};
use crate::cli::SupportedProtocol;
use crate::net::icmp_sequence::IcmpSequenceCache;
use crate::net::payload::{BufferedPayload, PayloadEvent};
use crate::net::sock_mgr::SocketHandles;
use std::time::Instant;

const C2U: bool = true;

fn record_sync_buffer_update(cfg: &crate::cli::RuntimeConfig, update: BufferedSyncUpdate) {
    if let BufferedSyncUpdate::Buffered {
        buffered_trace,
        replaced_trace: Some(replaced_trace),
    } = update
    {
        debug_assert_ne!(buffered_trace, replaced_trace);
        log_packet_disposition(cfg, replaced_trace, PacketDisposition::DropSyncReplaced);
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_c2u_event(
    context: &ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    event: &PayloadEvent<'_>,
    trace: PacketTraceId,
    received_at: Instant,
) {
    let packet_context = PacketContext::new(
        context.worker_id,
        context.t_start,
        received_at,
        context.cfg,
        context.stats,
        context.flow_state,
    );
    let sequences = SequenceContext::new(
        context.client_side_state,
        client_side_cache,
        context.upstream_side_state,
        upstream_side_cache,
    );
    match event {
        PayloadEvent::UserPayload { .. } => {
            if let Err(error) = send_user_payload_event(
                packet_context,
                event,
                handles,
                cache,
                sequences,
                Some(trace),
            ) {
                log_debug_dir!(
                    context.cfg.debug_logs.drops,
                    context.worker_id,
                    C2U,
                    "outbound payload build error: {}",
                    error
                );
            }
        }
        PayloadEvent::SessionControl { dst_proto, .. } => {
            let should_forward = *dst_proto == context.cfg.upstream_proto
                && *dst_proto == SupportedProtocol::ICMP
                && context.cfg.is_icmp_sync_enabled();
            if should_forward {
                if let Err(error) = send_payload_event_now(
                    packet_context,
                    event,
                    handles,
                    cache,
                    sequences,
                    Some(trace),
                ) {
                    log_debug_dir!(
                        context.cfg.debug_logs.drops,
                        context.worker_id,
                        C2U,
                        "session-control forward error: {}",
                        error
                    );
                }
            } else {
                handle_c2u_session_control(
                    packet_context,
                    handles,
                    (context.client_side_state, client_side_cache),
                    cache.session_control_reply_route.as_ref(),
                    event,
                    Some(trace),
                );
            }
        }
        PayloadEvent::CadencePacket { .. } => {
            log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeCadence);
        }
    }
}

pub(super) fn process_sync_packet(
    context: &ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    latest_sync_payload: &mut Option<BufferedPayload>,
    admitted: AdmittedWirePacket<'_>,
) {
    let trace = admitted.trace.expect("received packet trace");
    let pending_reply_route =
        match accept_pending_negotiation(context, admitted.pending_negotiation, trace) {
            Ok(route) => route,
            Err(()) => return,
        };
    let update = buffer_sync_event(
        PacketContext::new(
            context.worker_id,
            context.t_start,
            Instant::now(),
            context.cfg,
            context.stats,
            context.flow_state,
        ),
        handles,
        (context.client_side_state, client_side_cache),
        pending_reply_route
            .as_ref()
            .or(cache.session_control_reply_route.as_ref()),
        latest_sync_payload,
        admitted.event,
        trace,
    );
    record_sync_buffer_update(context.cfg, update);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn process_client_packet(
    context: &ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    was_locked: &mut bool,
    admitted: AdmittedWirePacket<'_>,
) {
    let trace = admitted.trace.expect("received packet trace");
    let received_at = Instant::now();
    if context.flow_state.is_locked() {
        dispatch_c2u_event(
            context,
            handles,
            cache,
            client_side_cache,
            upstream_side_cache,
            &admitted.event,
            trace,
            received_at,
        );
        return;
    }
    if handles.listener.listener_connected {
        log_packet_disposition(context.cfg, trace, PacketDisposition::DropNoActiveFlow);
        return;
    }

    let Some(source) = admitted.normalized_source else {
        log_packet_disposition(context.cfg, trace, PacketDisposition::DropNoActiveFlow);
        return;
    };
    if admitted.event.is_cadence_packet() {
        log_packet_disposition(context.cfg, trace, PacketDisposition::ConsumeCadence);
        return;
    }
    if admitted.pending_negotiation.is_some() {
        let pending_reply_route =
            match accept_pending_negotiation(context, admitted.pending_negotiation, trace) {
                Ok(route) => route,
                Err(()) => return,
            };
        handle_c2u_session_control(
            PacketContext::new(
                context.worker_id,
                context.t_start,
                received_at,
                context.cfg,
                context.stats,
                context.flow_state,
            ),
            handles,
            (context.client_side_state, client_side_cache),
            pending_reply_route
                .as_ref()
                .or(cache.session_control_reply_route.as_ref()),
            &admitted.event,
            Some(trace),
        );
        return;
    }
    let Some(lock_candidate) = admitted.lock_candidate else {
        log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return;
    };
    if !publish_client_lock(
        context,
        handles,
        cache,
        client_side_cache,
        upstream_side_cache,
        was_locked,
        source,
        lock_candidate,
        trace,
    ) {
        return;
    }
    dispatch_c2u_event(
        context,
        handles,
        cache,
        client_side_cache,
        upstream_side_cache,
        &admitted.event,
        trace,
        received_at,
    );
}
