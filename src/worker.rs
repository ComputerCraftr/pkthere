use crate::cli::{RuntimeConfig, TimeoutAction, WorkerFlowMode};
use crate::flow_claim::FlowClaimTable;
use crate::flow_key::ClientFlowKey;
use crate::flow_state::FlowRuntimeState;
use crate::net::params::CanonicalAddr;
use crate::net::payload::{
    IcmpIdPolicy, PayloadEvent, PayloadOrigin, send_payload, validate_payload,
};
use crate::net::session::{counts_as_session_activity, handle_send_result};
use crate::net::sock_mgr::SocketManager;
use crate::net::sync_icmp::{
    SharedSyncIcmpState, classify_u2c, prepare_send, remember_request_seq, reset_session,
    sync_icmp_enabled,
};
use crate::stats::{StatsShard, StatsSink};
use crate::worker_support::{
    AlignedBuf, BufferedSyncPayload, CachedClientState, GlobalSyncPacer, as_uninit_mut,
    buffer_sync_event, handle_c2u_keepalive, sync_session_on_lock_transition,
    wait_socket_until_readable,
};

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

pub fn run_reresolve_thread(
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

pub fn run_watchdog_thread(
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

pub fn run_upstream_to_client_thread(
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
    let mut buf = AlignedBuf::new();
    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(C2U, worker_id, cfg, &handles, cfg.debug_logs.handles);
    loop {
        match handles.upstream_sock.recv(as_uninit_mut(&mut buf.data)) {
            Ok(len) => {
                let t_recv = Instant::now();

                log_debug!(
                    cfg.debug_logs.packets,
                    "[worker {}] received {} bytes from upstream socket {:?}",
                    worker_id,
                    len,
                    handles.upstream
                );

                cache.refresh_handles_and_cache(cfg, sock_mgr, &mut handles);
                sync_session_on_lock_transition(
                    cfg,
                    &mut was_locked,
                    flow_state.is_locked(),
                    sync_state,
                    &mut sync_cache,
                );

                if flow_state.is_locked() {
                    let event = result_or_log_continue!(
                        validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &buf.data[..len],
                            IcmpIdPolicy::Exact(handles.upstream_local.id),
                            PayloadOrigin::Wire,
                        ),
                        log_debug_dir,
                        cfg.debug_logs.drops,
                        worker_id,
                        C2U,
                        "validate_payload error: {}"
                    );
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
                    let wire = event.wire();
                    let send_res = if decision.should_send() {
                        send_payload(
                            &handles.client_sock,
                            handles.client_connected,
                            cache.dest_sock_type,
                            &cache.route.dest_sa,
                            &event,
                            cache.route.icmp_header_id,
                            C2U,
                            prepare_send(C2U, wire, true, sync_state, &mut sync_cache),
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
                        wire.len(),
                        decision.counts_as_payload(),
                        counts_as_session_activity(&event, decision.counts_as_payload()),
                        &send_res,
                        handles.client_connected,
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

pub fn run_client_to_upstream_thread(
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
    let mut buf = AlignedBuf::new();
    let sync_icmp_mode = sync_icmp_enabled(cfg);
    let mut latest_sync_payload: Option<BufferedSyncPayload> = None;

    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(C2U, worker_id, cfg, &handles, cfg.debug_logs.handles);
    loop {
        let locked_now = flow_state.is_locked();
        sync_session_on_lock_transition(
            cfg,
            &mut was_locked,
            locked_now,
            sync_state,
            &mut sync_cache,
        );
        cache.refresh_handles_and_cache(cfg, sock_mgr, &mut handles);
        if handles.client_connected {
            if sync_icmp_mode {
                if !locked_now {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }

                let pacer = sync_pacer.expect("sync pacing state must exist in sync mode");
                let now = Instant::now();
                if pacer.try_acquire_send(now) {
                    let buffered_payload = latest_sync_payload.take();
                    let synthetic_event;
                    let event = if let Some(ref payload) = buffered_payload {
                        payload.as_event()
                    } else {
                        synthetic_event = validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &[],
                            handles.client_peer.map_or_else(
                                || IcmpIdPolicy::Any,
                                |peer_addr| IcmpIdPolicy::Exact(peer_addr.id),
                            ),
                            PayloadOrigin::SyntheticSyncKeepalive,
                        )
                        .unwrap_or_else(|e| {
                            log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "validate_payload error: {}",
                                e
                            );
                            unreachable!("synthetic sync keepalive validation must not fail")
                        });
                        synthetic_event
                    };
                    let wire = event.wire();
                    let send_res = send_payload(
                        &handles.upstream_sock,
                        handles.upstream_connected,
                        cache.dest_sock_type,
                        &cache.route.dest_sa,
                        &event,
                        cache.route.icmp_header_id,
                        C2U,
                        prepare_send(C2U, wire, true, sync_state, &mut sync_cache),
                    );
                    handle_send_result(
                        C2U,
                        worker_id,
                        t_start,
                        now,
                        cfg,
                        stats,
                        flow_state,
                        wire.len(),
                        event.is_user_data(),
                        counts_as_session_activity(&event, true),
                        &send_res,
                        handles.upstream_connected,
                        &cache.route.dest_sa,
                        None,
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
                match handles.client_sock.recv(as_uninit_mut(&mut buf.data)) {
                    Ok(len) => {
                        latest_sync_payload = match validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &buf.data[..len],
                            cache.recv_icmp_policy,
                            PayloadOrigin::Wire,
                        ) {
                            Ok(event) => buffer_sync_event(
                                worker_id,
                                t_start,
                                Instant::now(),
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.keepalive_reply_route.as_ref(),
                                event,
                            ),
                            Err(e) => {
                                log_debug_dir!(
                                    cfg.debug_logs.drops,
                                    worker_id,
                                    C2U,
                                    "validate_payload error: {}",
                                    e
                                );
                                None
                            }
                        };
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

            match handles.client_sock.recv(as_uninit_mut(&mut buf.data)) {
                Ok(len) => {
                    let t_recv = Instant::now();

                    log_debug!(
                        cfg.debug_logs.packets,
                        "[worker {}] received {} bytes from client socket",
                        worker_id,
                        len
                    );

                    if flow_state.is_locked() {
                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_icmp_policy,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_logs.drops,
                            worker_id,
                            C2U,
                            "validate_payload error: {}"
                        );
                        match event {
                            PayloadEvent::UserData(ref wire) => {
                                if wire.src_is_icmp {
                                    remember_request_seq(sync_state, &mut sync_cache, &wire);
                                }
                                let send_res = send_payload(
                                    &handles.upstream_sock,
                                    handles.upstream_connected,
                                    cache.dest_sock_type,
                                    &cache.route.dest_sa,
                                    &event,
                                    cache.route.icmp_header_id,
                                    C2U,
                                    prepare_send(C2U, &wire, true, sync_state, &mut sync_cache),
                                );
                                handle_send_result(
                                    C2U,
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    wire.len(),
                                    event.is_user_data(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.route.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.keepalive_reply_route.as_ref(),
                                &wire,
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
                let pacer = sync_pacer.expect("sync pacing state must exist in sync mode");
                let now = Instant::now();
                if pacer.try_acquire_send(now) {
                    let buffered_payload = latest_sync_payload.take();
                    let synthetic_event;
                    let event = if let Some(ref payload) = buffered_payload {
                        payload.as_event()
                    } else {
                        synthetic_event = validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &[],
                            handles.client_peer.map_or_else(
                                || IcmpIdPolicy::Any,
                                |peer_addr| IcmpIdPolicy::Exact(peer_addr.id),
                            ),
                            PayloadOrigin::SyntheticSyncKeepalive,
                        )
                        .unwrap_or_else(|e| {
                            log_debug_dir!(
                                cfg.debug_logs.drops,
                                worker_id,
                                C2U,
                                "validate_payload error: {}",
                                e
                            );
                            unreachable!("synthetic sync keepalive validation must not fail")
                        });
                        synthetic_event
                    };
                    let wire = event.wire();
                    let send_res = send_payload(
                        &handles.upstream_sock,
                        handles.upstream_connected,
                        cache.dest_sock_type,
                        &cache.route.dest_sa,
                        &event,
                        cache.route.icmp_header_id,
                        C2U,
                        prepare_send(C2U, wire, true, sync_state, &mut sync_cache),
                    );
                    handle_send_result(
                        C2U,
                        worker_id,
                        t_start,
                        now,
                        cfg,
                        stats,
                        flow_state,
                        wire.len(),
                        event.is_user_data(),
                        counts_as_session_activity(&event, true),
                        &send_res,
                        handles.upstream_connected,
                        &cache.route.dest_sa,
                        None,
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
                match handles.client_sock.recv_from(as_uninit_mut(&mut buf.data)) {
                    Ok((len, src_sa)) => {
                        let Some(src) = src_sa.as_socket() else {
                            log_warn_dir!(
                                worker_id,
                                C2U,
                                "recv_from client non-IP address family (ignored): {:?}",
                                src_sa
                            );
                            continue;
                        };

                        let event = match validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &buf.data[..len],
                            cache.recv_icmp_policy,
                            PayloadOrigin::Wire,
                        ) {
                            Ok(event) => event,
                            Err(e) => {
                                log_debug_dir!(
                                    cfg.debug_logs.drops,
                                    worker_id,
                                    C2U,
                                    "validate_payload error: {}",
                                    e
                                );
                                continue;
                            }
                        };
                        let flow_key = ClientFlowKey::from_wire(src, cfg.listen_proto, &event);
                        if Some(flow_key) == handles.locked_flow {
                            latest_sync_payload = buffer_sync_event(
                                worker_id,
                                t_start,
                                Instant::now(),
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.keepalive_reply_route.as_ref(),
                                event,
                            );
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

            match handles.client_sock.recv_from(as_uninit_mut(&mut buf.data)) {
                Ok((len, src_sa)) => {
                    let t_recv = Instant::now();
                    let Some(src) = src_sa.as_socket() else {
                        log_warn_dir!(
                            worker_id,
                            C2U,
                            "recv_from client non-IP address family (ignored): {:?}",
                            src_sa
                        );
                        continue;
                    };

                    if !flow_state.is_locked() {
                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_icmp_policy,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_logs.drops,
                            worker_id,
                            C2U,
                            "validate_payload error: {}"
                        );
                        let flow = ClientFlowKey::from_wire(src, cfg.listen_proto, &event);

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
                        let peer_canonical = if let Some(ident) = flow.icmp_ident() {
                            CanonicalAddr::new(flow.display_addr(), ident)
                        } else {
                            CanonicalAddr::from_socket_addr(src)
                        };
                        let peer_addr = Some(peer_canonical);

                        handles.client_connected = false;
                        if cfg.debug_behavior.no_connect {
                            log_info!("Locked to single client {} (not connected)", src);
                        } else if let Err(e) = handles.client_sock.connect(&src_sa) {
                            log_warn!("connect client_sock to {} failed: {}", src, e);
                            log_info!("Locked to single client {} (not connected)", src);
                        } else {
                            handles.client_connected = true;
                            log_info!("Locked to single client {} (connected)", src);
                        }

                        handles.version = sock_mgr.set_client_addr_connected(
                            Some(flow),
                            peer_addr,
                            handles.client_connected,
                            handles.version,
                        );
                        log_debug_dir!(
                            cfg.debug_logs.handles,
                            worker_id,
                            C2U,
                            "publish lock: flow={:?} connected={} ver={}",
                            flow,
                            handles.client_connected,
                            handles.version
                        );

                        if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                            for mgr in all_sock_mgrs {
                                if !std::ptr::eq(mgr.as_ref(), sock_mgr) {
                                    let _ = mgr.set_client_sock_connected(
                                        Some(flow),
                                        peer_addr,
                                        handles.client_connected,
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
                            PayloadEvent::UserData(ref wire) => {
                                if wire.src_is_icmp {
                                    remember_request_seq(sync_state, &mut sync_cache, &wire);
                                }
                                let send_res = send_payload(
                                    &handles.upstream_sock,
                                    handles.upstream_connected,
                                    cache.dest_sock_type,
                                    &cache.route.dest_sa,
                                    &event,
                                    cache.route.icmp_header_id,
                                    C2U,
                                    prepare_send(C2U, &wire, true, sync_state, &mut sync_cache),
                                );
                                handle_send_result(
                                    C2U,
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    wire.len(),
                                    event.is_user_data(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.route.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.keepalive_reply_route.as_ref(),
                                &wire,
                            ),
                        }
                    } else {
                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_icmp_policy,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_logs.drops,
                            worker_id,
                            C2U,
                            "validate_payload error: {}"
                        );
                        if Some(ClientFlowKey::from_wire(src, cfg.listen_proto, &event))
                            != handles.locked_flow
                        {
                            continue;
                        }
                        match event {
                            PayloadEvent::UserData(ref wire) => {
                                if wire.src_is_icmp {
                                    remember_request_seq(sync_state, &mut sync_cache, &wire);
                                }
                                let send_res = send_payload(
                                    &handles.upstream_sock,
                                    handles.upstream_connected,
                                    cache.dest_sock_type,
                                    &cache.route.dest_sa,
                                    &event,
                                    cache.route.icmp_header_id,
                                    C2U,
                                    prepare_send(C2U, &wire, true, sync_state, &mut sync_cache),
                                );
                                handle_send_result(
                                    C2U,
                                    worker_id,
                                    t_start,
                                    t_recv,
                                    cfg,
                                    stats,
                                    flow_state,
                                    wire.len(),
                                    event.is_user_data(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.route.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                flow_state,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                cache.keepalive_reply_route.as_ref(),
                                &wire,
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
