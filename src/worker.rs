use crate::cli::{RuntimeConfig, TimeoutAction, WorkerFlowMode};
use crate::flow_claim::FlowClaimTable;
use crate::flow_state::FlowRuntimeState;
use crate::net::params::MAX_WIRE_PAYLOAD;
use crate::net::payload::{
    PayloadEvent, PayloadOrigin, outbound_payload_event,
    reply_id_negotiation_for_u2c_listener_reply, send_payload,
};
use crate::net::session::{counts_as_session_activity, handle_send_result};
use crate::net::sock_mgr::SocketManager;
use crate::net::sync_icmp::{
    SharedSyncIcmpState, classify_u2c, prepare_send, reset_session, sync_icmp_enabled,
};
use crate::recv_buf::RecvBuf;
use crate::stats::{StatsShard, StatsSink};
use crate::worker_support::{
    BufferedPayload, BufferedSyncUpdate, CachedClientState, GlobalSyncPacer, SocketPeerRole,
    WirePacketAdmission, admit_wire_packet, buffer_sync_event, client_admission_spec,
    handle_c2u_session_control, log_rejected_packet, observe_reply_id_ack, record_rejection_stats,
    recv_packet, refresh_lock_and_sync_state, send_sync_payload_or_cadence,
    send_user_payload_event, upstream_admission_spec, wait_socket_until_readable,
};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomOrdering};
use std::{
    thread,
    time::{Duration, Instant},
};
pub(crate) fn run_reresolve_thread(
    sock_mgrs: &[Arc<SocketManager>],
    reresolve_secs: u64,
    allow_upstream: bool,
    allow_listen_rebind: bool,
) {
    let period = Duration::from_secs(reresolve_secs);
    loop {
        thread::sleep(period);
        for sock_mgr in sock_mgrs {
            let _ = sock_mgr.reresolve(allow_upstream, allow_listen_rebind, "Periodic re-resolve");
        }
    }
}
pub(crate) fn run_watchdog_thread(
    t_start: Instant,
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    exit_code_set: &AtomicU32,
    flow_claims: Option<&FlowClaimTable>,
) {
    let period = Duration::from_secs(1);
    loop {
        thread::sleep(period);
        let now_s = Instant::now().saturating_duration_since(t_start).as_secs();
        for (idx, flow_state) in flow_states.iter().enumerate() {
            if !flow_state.is_locked() {
                if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                    break;
                }
                continue;
            }
            let last_s = flow_state.last_seen_s();
            if last_s == 0 || now_s.saturating_sub(last_s) < cfg.timeout_secs {
                if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                    break;
                }
                continue;
            }
            match cfg.on_timeout {
                TimeoutAction::Drop => {
                    let locked_flow = sock_mgrs[idx].get_client_dest().0;
                    log_warn!(
                        "Idle timeout reached ({}s): dropping locked client on worker pair {}",
                        cfg.timeout_secs,
                        idx
                    );
                    // In SharedFlow mode, we must clear ALL managers because they share a single flow_state.
                    // In SingleFlow mode, we only clear the specific manager.
                    let managers_to_clear: Vec<_> =
                        if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                            sock_mgrs.iter().collect()
                        } else {
                            vec![&sock_mgrs[idx]]
                        };
                    for mgr in managers_to_clear {
                        let prev = mgr.get_version();
                        let ver = match mgr.clear_client_lock(prev) {
                            Ok(v) => v,
                            Err(e) => {
                                log_error!("watchdog disconnect_socket failed: {}", e);
                                exit_code_set.store((1 << 31) | 1, AtomOrdering::Relaxed);
                                return;
                            }
                        };
                        log_debug!(
                            cfg.debug_logs.handles,
                            "watchdog publish disconnect: ver {}->{}",
                            prev,
                            ver
                        );
                    }
                    flow_state.reset();
                    if let (Some(flow_claims), Some(flow)) = (flow_claims, locked_flow) {
                        flow_claims.release(flow, idx);
                    }
                }
                _ => {
                    log_warn!(
                        "Idle timeout reached ({}s): exiting cleanly",
                        cfg.timeout_secs
                    );
                    exit_code_set.store(1 << 31, AtomOrdering::Relaxed);
                    return;
                }
            }
            // If we were in SharedFlow mode, we've handled all workers by clearing all managers.
            if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                break;
            }
        }
    }
}
pub(crate) fn run_upstream_to_client_thread(
    t_start: Instant,
    cfg: &RuntimeConfig,
    sock_mgr: &SocketManager,
    worker_id: usize,
    flow_state: &FlowRuntimeState,
    stats: &StatsShard,
    sync_state: &SharedSyncIcmpState,
    _worker_pair_id: usize,
) {
    const C2U: bool = false;
    let mut buf = RecvBuf::<{ MAX_WIRE_PAYLOAD }>::new();
    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(C2U, worker_id, cfg, &handles, cfg.debug_logs.handles);
    loop {
        cache.refresh_handles_and_cache(cfg, sock_mgr, &mut handles);
        refresh_lock_and_sync_state(
            cfg,
            flow_state,
            &mut was_locked,
            sync_state,
            &mut sync_cache,
        );
        let upstream_admission = upstream_admission_spec(cfg, &handles);
        match recv_packet(
            &handles.upstream_sock,
            handles.upstream_connected,
            buf.recv_buf_mut(),
        ) {
            Ok((len, source)) => {
                let admitted = match admit_wire_packet(
                    C2U,
                    cfg,
                    upstream_admission,
                    buf.initialized(len),
                    source.as_ref(),
                ) {
                    WirePacketAdmission::Accepted(admitted) => admitted,
                    WirePacketAdmission::Filtered(rejected) => {
                        record_rejection_stats(stats, C2U, rejected);
                        log_rejected_packet(
                            worker_id,
                            C2U,
                            cfg,
                            SocketPeerRole::Upstream,
                            rejected,
                            upstream_admission,
                        );
                        continue;
                    }
                    WirePacketAdmission::UnsupportedSource => {
                        log_warn_dir!(
                            worker_id,
                            C2U,
                            "recv_from upstream non-IP address family (ignored)"
                        );
                        continue;
                    }
                };
                let t_recv = Instant::now();
                log_debug!(
                    cfg.debug_logs.packets,
                    "[worker {}] received {} bytes from upstream socket {:?}",
                    worker_id,
                    len,
                    handles.upstream_remote_filter
                );
                cache.refresh_handles_and_cache(cfg, sock_mgr, &mut handles);
                let locked_now = refresh_lock_and_sync_state(
                    cfg,
                    flow_state,
                    &mut was_locked,
                    sync_state,
                    &mut sync_cache,
                );
                if locked_now {
                    let event = admitted.event;
                    observe_reply_id_ack(C2U, &event, &handles, flow_state);
                    let decision = result_or_log_continue!(
                        classify_u2c(
                            cfg,
                            &event,
                            PayloadOrigin::Wire,
                            sync_state,
                            &mut sync_cache
                        ),
                        log_debug_dir,
                        cfg.debug_logs.drops,
                        worker_id,
                        C2U,
                        "classify_u2c error: {}"
                    );
                    let reply_id = reply_id_negotiation_for_u2c_listener_reply(
                        &event,
                        handles.listener_flow.outbound.and_then(|flow| {
                            cfg.listener_reply_id_request.resolved_reply_id(flow.src.id)
                        }),
                    )
                    .filter(|_| !flow_state.listener_reply_id_acked());
                    let send_res = if decision.should_send() {
                        let outbound = result_or_log_continue!(
                            outbound_payload_event(
                                &event,
                                cache.route.icmp_header_id,
                                C2U,
                                prepare_send(C2U, &event, true, sync_state, &mut sync_cache),
                                reply_id,
                            ),
                            log_debug_dir,
                            cfg.debug_logs.drops,
                            worker_id,
                            C2U,
                            "outbound payload build error: {}"
                        );
                        send_payload(
                            &handles.client_sock,
                            handles.listener_connected,
                            cache.dest_sock_type,
                            &cache.route.dest_sa,
                            &outbound,
                        )
                    } else {
                        Ok(true)
                    };
                    handle_send_result(
                        C2U,
                        worker_id,
                        t_start,
                        t_recv,
                        cfg,
                        stats,
                        flow_state,
                        &event,
                        counts_as_session_activity(&event, decision.counts_as_session_activity()),
                        &send_res,
                        handles.listener_connected,
                        &cache.route.dest_sa,
                        Some((&mut handles, sock_mgr)),
                    );
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                log_error_dir!(worker_id, C2U, "recv error: {}", e);
                stats.drop_err(C2U);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
pub(crate) fn run_client_to_upstream_thread(
    t_start: Instant,
    cfg: &RuntimeConfig,
    sock_mgr: &SocketManager,
    all_sock_mgrs: &[Arc<SocketManager>],
    worker_id: usize,
    flow_state: &FlowRuntimeState,
    stats: &StatsShard,
    sync_state: &SharedSyncIcmpState,
    sync_pacer: Option<&GlobalSyncPacer>,
    flow_claims: Option<&FlowClaimTable>,
    worker_pair_id: usize,
) {
    const C2U: bool = true;
    let mut buf = RecvBuf::<{ MAX_WIRE_PAYLOAD }>::new();
    let sync_icmp_mode = sync_icmp_enabled(cfg);
    let mut latest_sync_payload: Option<BufferedPayload> = None;
    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(C2U, worker_id, cfg, &handles, cfg.debug_logs.handles);
    loop {
        cache.refresh_handles_and_cache(cfg, sock_mgr, &mut handles);
        let locked_now = refresh_lock_and_sync_state(
            cfg,
            flow_state,
            &mut was_locked,
            sync_state,
            &mut sync_cache,
        );
        if handles.listener_connected {
            if sync_icmp_mode {
                if !locked_now {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }

                let Some(pacer) = sync_pacer else {
                    log_error_dir!(
                        worker_id,
                        C2U,
                        "sync pacing state missing while ICMP sync mode is enabled"
                    );
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let now = Instant::now();
                if pacer.try_acquire_send(now) {
                    result_or_log_continue!(
                        send_sync_payload_or_cadence(
                            worker_id,
                            t_start,
                            now,
                            cfg,
                            stats,
                            flow_state,
                            &handles,
                            &cache,
                            sync_state,
                            &mut sync_cache,
                            latest_sync_payload.take().as_ref(),
                        ),
                        log_debug_dir,
                        cfg.debug_logs.drops,
                        worker_id,
                        C2U,
                        "outbound payload build error: {}"
                    );
                    continue;
                }

                match wait_socket_until_readable(&handles.client_sock, pacer.poll_wait()) {
                    Ok(v) if !v => {
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log_error_dir!(worker_id, C2U, "poll/read wait error: {}", e);
                        stats.drop_err(C2U);
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                let client_admission = client_admission_spec(
                    cfg,
                    &handles,
                    if locked_now {
                        handles.listener_flow.inbound
                    } else {
                        None
                    },
                );

                match recv_packet(
                    &handles.client_sock,
                    handles.listener_connected,
                    buf.recv_buf_mut(),
                ) {
                    Ok((len, source)) => {
                        let admitted = match admit_wire_packet(
                            C2U,
                            cfg,
                            client_admission,
                            buf.initialized(len),
                            source.as_ref(),
                        ) {
                            WirePacketAdmission::Accepted(admitted) => admitted,
                            WirePacketAdmission::Filtered(rejected) => {
                                record_rejection_stats(stats, C2U, rejected);
                                log_rejected_packet(
                                    worker_id,
                                    C2U,
                                    cfg,
                                    SocketPeerRole::Client,
                                    rejected,
                                    client_admission,
                                );
                                continue;
                            }
                            WirePacketAdmission::UnsupportedSource => {
                                log_warn_dir!(
                                    worker_id,
                                    C2U,
                                    "recv_from client non-IP address family (ignored)"
                                );
                                continue;
                            }
                        };
                        match buffer_sync_event(
                            worker_id,
                            t_start,
                            Instant::now(),
                            cfg,
                            stats,
                            flow_state,
                            &mut handles,
                            sync_state,
                            &mut sync_cache,
                            cache.session_control_reply_route.as_ref(),
                            admitted.event,
                        ) {
                            BufferedSyncUpdate::Replace(payload) => {
                                latest_sync_payload = Some(payload);
                            }
                            BufferedSyncUpdate::Keep => {}
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(e) => {
                        log_error_dir!(worker_id, C2U, "recv error: {}", e);
                        stats.drop_err(C2U);
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                continue;
            }

            let client_admission = client_admission_spec(cfg, &handles, None);
            match recv_packet(
                &handles.client_sock,
                handles.listener_connected,
                buf.recv_buf_mut(),
            ) {
                Ok((len, source)) => {
                    let admitted = match admit_wire_packet(
                        C2U,
                        cfg,
                        client_admission,
                        buf.initialized(len),
                        source.as_ref(),
                    ) {
                        WirePacketAdmission::Accepted(admitted) => admitted,
                        WirePacketAdmission::Filtered(rejected) => {
                            record_rejection_stats(stats, C2U, rejected);
                            log_rejected_packet(
                                worker_id,
                                C2U,
                                cfg,
                                SocketPeerRole::Client,
                                rejected,
                                client_admission,
                            );
                            continue;
                        }
                        WirePacketAdmission::UnsupportedSource => {
                            log_warn_dir!(
                                worker_id,
                                C2U,
                                "recv_from client non-IP address family (ignored)"
                            );
                            continue;
                        }
                    };
                    let t_recv = Instant::now();

                    log_debug!(
                        cfg.debug_logs.packets,
                        "[worker {}] received {} bytes from client socket",
                        worker_id,
                        len
                    );

                    if flow_state.is_locked() {
                        let event = admitted.event;
                        match event {
                            PayloadEvent::UserPayload { .. } => result_or_log_continue!(
                                send_user_payload_event(
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    &event,
                                    &handles,
                                    &cache,
                                    sync_state,
                                    &mut sync_cache,
                                ),
                                log_debug_dir,
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "outbound payload build error: {}"
                            ),
                            PayloadEvent::SessionControl { .. } => handle_c2u_session_control(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.session_control_reply_route.as_ref(),
                                &event,
                            ),
                            PayloadEvent::CadencePacket { .. } => log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "dropping wire cadence packet from locked client session"
                            ),
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    log_error_dir!(worker_id, C2U, "recv error: {}", e);
                    stats.drop_err(C2U);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            if sync_icmp_mode && locked_now {
                let Some(pacer) = sync_pacer else {
                    log_error_dir!(
                        worker_id,
                        C2U,
                        "sync pacing state missing while ICMP sync mode is enabled"
                    );
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let now = Instant::now();
                if pacer.try_acquire_send(now) {
                    result_or_log_continue!(
                        send_sync_payload_or_cadence(
                            worker_id,
                            t_start,
                            now,
                            cfg,
                            stats,
                            flow_state,
                            &handles,
                            &cache,
                            sync_state,
                            &mut sync_cache,
                            latest_sync_payload.take().as_ref(),
                        ),
                        log_debug_dir,
                        cfg.debug_logs.drops,
                        worker_id,
                        C2U,
                        "outbound payload build error: {}"
                    );
                    continue;
                }

                let readable =
                    match wait_socket_until_readable(&handles.client_sock, pacer.poll_wait()) {
                        Ok(v) => v,
                        Err(e) => {
                            log_error_dir!(worker_id, C2U, "poll/read wait error: {}", e);
                            stats.drop_err(C2U);
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    };
                if !readable {
                    continue;
                }
                let client_admission =
                    client_admission_spec(cfg, &handles, handles.listener_flow.inbound);
                match recv_packet(
                    &handles.client_sock,
                    handles.listener_connected,
                    buf.recv_buf_mut(),
                ) {
                    Ok((len, source)) => {
                        let admitted = match admit_wire_packet(
                            C2U,
                            cfg,
                            client_admission,
                            buf.initialized(len),
                            source.as_ref(),
                        ) {
                            WirePacketAdmission::Accepted(admitted) => admitted,
                            WirePacketAdmission::Filtered(rejected) => {
                                record_rejection_stats(stats, C2U, rejected);
                                log_rejected_packet(
                                    worker_id,
                                    C2U,
                                    cfg,
                                    SocketPeerRole::Client,
                                    rejected,
                                    client_admission,
                                );
                                continue;
                            }
                            WirePacketAdmission::UnsupportedSource => {
                                log_warn_dir!(
                                    worker_id,
                                    C2U,
                                    "recv_from client non-IP address family (ignored)"
                                );
                                continue;
                            }
                        };
                        match buffer_sync_event(
                            worker_id,
                            t_start,
                            Instant::now(),
                            cfg,
                            stats,
                            flow_state,
                            &mut handles,
                            sync_state,
                            &mut sync_cache,
                            cache.session_control_reply_route.as_ref(),
                            admitted.event,
                        ) {
                            BufferedSyncUpdate::Replace(payload) => {
                                latest_sync_payload = Some(payload);
                            }
                            BufferedSyncUpdate::Keep => {}
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut => {}
                    Err(e) => {
                        log_error_dir!(worker_id, C2U, "recv_from error: {}", e);
                        stats.drop_err(C2U);
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                continue;
            }

            let client_admission = client_admission_spec(
                cfg,
                &handles,
                if flow_state.is_locked() {
                    handles.listener_flow.inbound
                } else {
                    None
                },
            );
            match recv_packet(
                &handles.client_sock,
                handles.listener_connected,
                buf.recv_buf_mut(),
            ) {
                Ok((len, source)) => {
                    let admitted = match admit_wire_packet(
                        C2U,
                        cfg,
                        client_admission,
                        buf.initialized(len),
                        source.as_ref(),
                    ) {
                        WirePacketAdmission::Accepted(admitted) => admitted,
                        WirePacketAdmission::Filtered(rejected) => {
                            record_rejection_stats(stats, C2U, rejected);
                            log_rejected_packet(
                                worker_id,
                                C2U,
                                cfg,
                                SocketPeerRole::Client,
                                rejected,
                                client_admission,
                            );
                            continue;
                        }
                        WirePacketAdmission::UnsupportedSource => {
                            log_warn_dir!(
                                worker_id,
                                C2U,
                                "recv_from client non-IP address family (ignored)"
                            );
                            continue;
                        }
                    };
                    let Some(src) = admitted.normalized_source else {
                        continue;
                    };
                    let t_recv = Instant::now();
                    if !flow_state.is_locked() {
                        let event = admitted.event;
                        let Some(lock_candidate) = admitted.lock_candidate else {
                            continue;
                        };
                        let flow = lock_candidate.flow_key;
                        let listener_flow = lock_candidate.listener_flow;

                        if cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
                            && flow_claims.is_some_and(|flow_claims| {
                                !flow_claims.try_claim(flow, worker_pair_id)
                            })
                        {
                            continue;
                        }
                        reset_session(cfg, sync_state, &mut sync_cache);
                        flow_state.set_locked(true);
                        was_locked = true;
                        let src_sa = listener_flow
                            .inbound
                            .map(|flow| flow.src.canonical().as_sock_addr())
                            .unwrap_or_else(|| src.as_sock_addr());
                        handles.listener_connected = false;
                        if cfg.debug_behavior.client_unconnected {
                            log_info!("Locked to single client {} (not connected)", src);
                        } else if let Err(e) = handles.client_sock.connect(&src_sa) {
                            log_warn!("connect client_sock to {} failed: {}", src, e);
                            log_info!("Locked to single client {} (not connected)", src);
                        } else {
                            handles.listener_connected = true;
                            log_info!("Locked to single client {} (connected)", src);
                        }
                        handles.version = sock_mgr.set_listener_remote_connected(
                            Some(flow),
                            listener_flow,
                            handles.listener_connected,
                            handles.version,
                        );
                        handles.listener_flow = listener_flow;
                        log_debug_dir!(
                            cfg.debug_logs.handles,
                            worker_id,
                            C2U,
                            "publish lock: flow={:?} connected={} ver={}",
                            flow,
                            handles.listener_connected,
                            handles.version
                        );
                        if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                            for mgr in all_sock_mgrs {
                                if !std::ptr::eq(mgr.as_ref(), sock_mgr) {
                                    let _ = mgr.set_client_sock_connected(
                                        Some(flow),
                                        listener_flow,
                                        handles.listener_connected,
                                        &src_sa,
                                        0,
                                    );
                                }
                            }
                        }
                        if let Ok(new_handles) = sock_mgr.reresolve(
                            cfg.reresolve_mode.allow_upstream(),
                            false,
                            "Re-resolved",
                        ) {
                            handles = new_handles;
                            cache.refresh_from_handles(cfg, &handles);
                        }
                        match event {
                            PayloadEvent::UserPayload { .. } => result_or_log_continue!(
                                send_user_payload_event(
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    &event,
                                    &handles,
                                    &cache,
                                    sync_state,
                                    &mut sync_cache,
                                ),
                                log_debug_dir,
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "outbound payload build error: {}"
                            ),
                            PayloadEvent::SessionControl { .. } => handle_c2u_session_control(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.session_control_reply_route.as_ref(),
                                &event,
                            ),
                            PayloadEvent::CadencePacket { .. } => log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "dropping wire cadence packet during initial lock"
                            ),
                        }
                    } else {
                        let event = admitted.event;
                        match event {
                            PayloadEvent::UserPayload { .. } => result_or_log_continue!(
                                send_user_payload_event(
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    &event,
                                    &handles,
                                    &cache,
                                    sync_state,
                                    &mut sync_cache,
                                ),
                                log_debug_dir,
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "outbound payload build error: {}"
                            ),
                            PayloadEvent::SessionControl { .. } => handle_c2u_session_control(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.session_control_reply_route.as_ref(),
                                &event,
                            ),
                            PayloadEvent::CadencePacket { .. } => log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "dropping wire cadence packet from active client flow"
                            ),
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => {
                    log_error_dir!(worker_id, C2U, "recv_from error: {}", e);
                    stats.drop_err(C2U);
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}
