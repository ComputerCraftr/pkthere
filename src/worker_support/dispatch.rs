use super::{BufferedPayload, CachedClientState};
use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::payload::{
    PayloadEvent, PayloadOrigin, outbound_payload_event, send_payload, source_id_shim_for_c2u,
    validate_payload,
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
    }
    let source_id_for_shim =
        source_id_shim_for_c2u(event, sync_cache.latest_valid, handles.upstream_local.id);
    let outbound = outbound_payload_event(
        event,
        cache.route.icmp_header_id,
        C2U,
        prepare_send(C2U, event, true, sync_state, sync_cache),
        source_id_for_shim,
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
        synthetic_event = validate_payload(
            C2U,
            cfg,
            stats,
            &[],
            None,
            (0, 0),
            handles.client_peer.map(|peer_addr| peer_addr.id),
            PayloadOrigin::SyntheticCadencePacket,
            true,
        )
        .unwrap_or_else(|e| {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                C2U,
                "synthetic cadence packet error: {}",
                e
            );
            unreachable!("synthetic cadence packet validation must not fail")
        });
        synthetic_event
    };

    let source_id_for_shim =
        source_id_shim_for_c2u(&event, sync_cache.latest_valid, handles.upstream_local.id);
    let outbound = outbound_payload_event(
        &event,
        cache.route.icmp_header_id,
        C2U,
        prepare_send(C2U, &event, true, sync_state, sync_cache),
        source_id_for_shim,
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
