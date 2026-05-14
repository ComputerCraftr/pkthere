use super::{BufferedPayload, CachedClientState};
use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::payload::{
    PayloadEvent, outbound_payload_event, reply_id_negotiation_for_c2u, send_payload,
};
use crate::net::session::{counts_as_session_activity, handle_send_result};
use crate::net::sock_mgr::SocketHandles;
use crate::net::sync_icmp::{
    SharedSyncIcmpState, SyncIcmpCache, prepare_send, remember_request_seq, reset_session,
};
use crate::stats::StatsSink;
use std::io;
use std::time::Instant;

#[inline]
pub(crate) fn refresh_lock_and_sync_state(
    cfg: &RuntimeConfig,
    flow_state: &FlowRuntimeState,
    was_locked: &mut bool,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
) -> bool {
    let locked_now = flow_state.is_locked();
    if *was_locked && !locked_now {
        reset_session(cfg, sync_state, sync_cache);
    }
    *was_locked = locked_now;
    locked_now
}

#[inline]
pub(crate) fn send_user_payload_event(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    cache: &CachedClientState,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
) -> io::Result<()> {
    const C2U: bool = true;

    if let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = event
    {
        remember_request_seq(sync_state, sync_cache, icmp);
        observe_reply_id_ack(true, event, handles, flow_state);
    }
    let reply_id_negotiation = reply_id_negotiation_for_c2u(
        event,
        flow_state.upstream_reply_id_acked(),
        handles.upstream_local_filter.id,
    );
    let outbound = outbound_payload_event(
        event,
        cache.route.icmp_header_id,
        C2U,
        prepare_send(C2U, event, true, sync_state, sync_cache),
        reply_id_negotiation,
    )?;
    let send_res = send_payload(
        &handles.upstream_sock,
        handles.upstream_connected,
        cache.dest_sock_type,
        &cache.route.dest_sa,
        &outbound,
    );
    handle_send_result(
        C2U,
        worker_id,
        t_start,
        t_recv,
        cfg,
        stats,
        flow_state,
        event,
        counts_as_session_activity(event, true),
        &send_res,
        handles.upstream_connected,
        &cache.route.dest_sa,
        None,
    );
    Ok(())
}

#[inline]
pub(crate) fn send_sync_payload_or_cadence(
    worker_id: usize,
    t_start: Instant,
    t_send: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    handles: &SocketHandles,
    cache: &CachedClientState,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
    buffered_payload: Option<&BufferedPayload>,
) -> io::Result<()> {
    const C2U: bool = true;

    let synthetic_event;
    let event = if let Some(payload) = buffered_payload {
        payload.as_event()
    } else {
        let Some(ident) = handles
            .listener_flow
            .outbound_destination()
            .map(|peer_addr| peer_addr.id)
        else {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                C2U,
                "synthetic cadence packet error: missing listener outbound destination"
            );
            unreachable!("synthetic cadence packet validation must not fail")
        };
        synthetic_event = PayloadEvent::cadence_packet(ident, 0);
        synthetic_event
    };

    let reply_id_negotiation = reply_id_negotiation_for_c2u(
        &event,
        flow_state.upstream_reply_id_acked(),
        handles.upstream_local_filter.id,
    );
    let outbound = outbound_payload_event(
        &event,
        cache.route.icmp_header_id,
        C2U,
        prepare_send(C2U, &event, true, sync_state, sync_cache),
        reply_id_negotiation,
    )?;
    let send_res = send_payload(
        &handles.upstream_sock,
        handles.upstream_connected,
        cache.dest_sock_type,
        &cache.route.dest_sa,
        &outbound,
    );
    handle_send_result(
        C2U,
        worker_id,
        t_start,
        t_send,
        cfg,
        stats,
        flow_state,
        &event,
        counts_as_session_activity(&event, true),
        &send_res,
        handles.upstream_connected,
        &cache.route.dest_sa,
        None,
    );
    Ok(())
}

#[inline]
pub(crate) fn observe_reply_id_ack(
    c2u: bool,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    flow_state: &FlowRuntimeState,
) {
    let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = event
    else {
        return;
    };
    if !icmp.reply_id_ack {
        return;
    }
    if c2u {
        let expected = handles.listener_flow.outbound.map(|flow| flow.src.id);
        if icmp.advertised_reply_id == expected {
            flow_state.ack_listener_reply_id();
        }
    } else if icmp.advertised_reply_id == Some(handles.upstream_local_filter.id) {
        flow_state.ack_upstream_reply_id();
    }
}
