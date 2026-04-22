use crate::cli::{Config, TimeoutAction};
use crate::net::payload::{PayloadEvent, PayloadOrigin, send_payload, validate_payload};
use crate::net::session::{counts_as_session_activity, handle_send_result};
use crate::net::sock_mgr::SocketManager;
use crate::net::sync_icmp::{
    SharedSyncIcmpState, classify_u2c, prepare_send, remember_request_seq, reset_session,
    sync_icmp_enabled,
};
use crate::stats::{StatsShard, StatsSink};
use crate::worker_support::{
    AlignedBuf, BestEffortPacer, BufferedSyncPayload, CachedClientState, as_uninit_mut,
    buffer_sync_event, handle_c2u_keepalive, locked_client_matches, normalize_client_sockaddr,
    sync_session_on_lock_transition, wait_socket_until_readable,
};
use socket2::SockAddr;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
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
    cfg: &Config,
    sock_mgrs: &[Arc<SocketManager>],
    locked: &AtomicBool,
    last_seen_s: &AtomicU64,
    exit_code_set: &AtomicU32,
) {
    let period = Duration::from_secs(1);
    loop {
        thread::sleep(period);
        if locked.load(AtomOrdering::Relaxed) {
            let now = Instant::now();
            let now_s = now.saturating_duration_since(t_start).as_secs();
            let last_s = last_seen_s.load(AtomOrdering::Relaxed);

            if last_s != 0 && now_s.saturating_sub(last_s) >= cfg.timeout_secs {
                match cfg.on_timeout {
                    TimeoutAction::Drop => {
                        log_warn!(
                            "Idle timeout reached ({}s): dropping locked client; waiting for a new client",
                            cfg.timeout_secs
                        );
                        for sock_mgr in sock_mgrs {
                            if sock_mgr.get_client_connected() {
                                let prev = sock_mgr.get_version();
                                let ver = match sock_mgr
                                    .set_client_sock_disconnected(None, false, prev)
                                {
                                    Ok(v) => v,
                                    Err(e) => {
                                        log_error!("watchdog disconnect_socket failed: {}", e);
                                        exit_code_set.store((1 << 31) | 1, AtomOrdering::Relaxed);
                                        return;
                                    }
                                };
                                log_debug!(
                                    cfg.debug_log_handles,
                                    "watchdog publish disconnect: ver {}->{}",
                                    prev,
                                    ver
                                );
                            }
                        }
                        locked.store(false, AtomOrdering::Relaxed);
                        last_seen_s.store(0, AtomOrdering::Relaxed);
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
            }
        }
    }
}

pub fn run_upstream_to_client_thread(
    t_start: Instant,
    cfg: &Config,
    sock_mgr: &SocketManager,
    worker_id: usize,
    locked: &AtomicBool,
    last_seen_s: &AtomicU64,
    stats: &StatsShard,
    sync_state: &SharedSyncIcmpState,
) {
    const C2U: bool = false;
    let mut buf = AlignedBuf::new();
    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(
        C2U,
        worker_id,
        &handles,
        handles.upstream_addr.port(),
        cfg.debug_log_handles,
    );
    loop {
        match handles.upstream_sock.recv(as_uninit_mut(&mut buf.data)) {
            Ok(len) => {
                let t_recv = Instant::now();
                cache.refresh_handles_and_cache(sock_mgr, &mut handles);
                sync_session_on_lock_transition(
                    &mut was_locked,
                    locked.load(AtomOrdering::Relaxed),
                    sync_state,
                    &mut sync_cache,
                );

                if locked.load(AtomOrdering::Relaxed) {
                    let event = result_or_log_continue!(
                        validate_payload(
                            C2U,
                            cfg,
                            stats,
                            &buf.data[..len],
                            cache.recv_port_id,
                            PayloadOrigin::Wire,
                        ),
                        log_debug_dir,
                        cfg.debug_log_drops,
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
                        cfg.debug_log_drops,
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
                            &cache.dest_sa,
                            cache.dest_port_id,
                            &event,
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
                        last_seen_s,
                        wire.len(),
                        counts_as_session_activity(&event, decision.counts_as_payload()),
                        &send_res,
                        handles.client_connected,
                        &cache.dest_sa,
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
    cfg: &Config,
    sock_mgr: &SocketManager,
    all_sock_mgrs: &[Arc<SocketManager>],
    worker_id: usize,
    locked: &AtomicBool,
    last_seen_s: &AtomicU64,
    stats: &StatsShard,
    sync_state: &SharedSyncIcmpState,
) {
    const C2U: bool = true;
    let mut buf = AlignedBuf::new();
    let sync_icmp_mode = sync_icmp_enabled(cfg);
    let mut sync_pacer = sync_icmp_mode.then(|| {
        BestEffortPacer::new(Duration::from_nanos(
            (1_000_000_000u64 / u64::from(cfg.icmp_sync_pps)).max(1),
        ))
    });
    let mut latest_sync_payload: Option<BufferedSyncPayload> = None;

    let mut handles = sock_mgr.refresh_handles();
    let mut was_locked = false;
    let mut sync_cache = sync_state.cache();
    let mut cache = CachedClientState::new(
        C2U,
        worker_id,
        &handles,
        cfg.listen_port_id,
        cfg.debug_log_handles,
    );
    loop {
        let locked_now = locked.load(AtomOrdering::Relaxed);
        if !was_locked && locked_now {
            if let Some(pacer) = sync_pacer.as_mut() {
                pacer.reset();
            }
        }
        sync_session_on_lock_transition(&mut was_locked, locked_now, sync_state, &mut sync_cache);
        cache.refresh_handles_and_cache(sock_mgr, &mut handles);
        if handles.client_connected {
            if sync_icmp_mode {
                if !locked_now {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }

                let pacer = sync_pacer
                    .as_mut()
                    .expect("sync pacing state must exist in sync mode");
                let now = Instant::now();
                if pacer.send_due(now) {
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
                            cache.recv_port_id,
                            PayloadOrigin::SyntheticSyncKeepalive,
                        )
                        .unwrap_or_else(|e| {
                            log_debug_dir!(
                                cfg.debug_log_drops,
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
                        &cache.dest_sa,
                        cache.dest_port_id,
                        &event,
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
                        last_seen_s,
                        wire.len(),
                        counts_as_session_activity(&event, true),
                        &send_res,
                        handles.upstream_connected,
                        &cache.dest_sa,
                        None,
                    );
                    pacer.mark_sent(now);
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
                            cache.recv_port_id,
                            PayloadOrigin::Wire,
                        ) {
                            Ok(event) => buffer_sync_event(
                                worker_id,
                                t_start,
                                Instant::now(),
                                cfg,
                                stats,
                                last_seen_s,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                None,
                                event,
                            ),
                            Err(e) => {
                                log_debug_dir!(
                                    cfg.debug_log_drops,
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

                    if locked.load(AtomOrdering::Relaxed) {
                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_port_id,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_log_drops,
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
                                    &cache.dest_sa,
                                    cache.dest_port_id,
                                    &event,
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
                                    last_seen_s,
                                    wire.len(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                last_seen_s,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                None,
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
                let pacer = sync_pacer
                    .as_mut()
                    .expect("sync pacing state must exist in sync mode");
                let now = Instant::now();
                if pacer.send_due(now) {
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
                            cache.recv_port_id,
                            PayloadOrigin::SyntheticSyncKeepalive,
                        )
                        .unwrap_or_else(|e| {
                            log_debug_dir!(
                                cfg.debug_log_drops,
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
                        &cache.dest_sa,
                        cache.dest_port_id,
                        &event,
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
                        last_seen_s,
                        wire.len(),
                        counts_as_session_activity(&event, true),
                        &send_res,
                        handles.upstream_connected,
                        &cache.dest_sa,
                        None,
                    );
                    pacer.mark_sent(now);
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
                        let normalized_src = normalize_client_sockaddr(
                            &src_sa,
                            cfg.listen_proto,
                            cfg.listen_port_id,
                        );
                        if locked_client_matches(normalized_src, handles.client_addr) {
                            latest_sync_payload = match validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_port_id,
                                PayloadOrigin::Wire,
                            ) {
                                Ok(event) => buffer_sync_event(
                                    worker_id,
                                    t_start,
                                    Instant::now(),
                                    cfg,
                                    stats,
                                    last_seen_s,
                                    &mut handles,
                                    sync_state,
                                    &mut sync_cache,
                                    None,
                                    event,
                                ),
                                Err(e) => {
                                    log_debug_dir!(
                                        cfg.debug_log_drops,
                                        worker_id,
                                        C2U,
                                        "validate_payload error: {}",
                                        e
                                    );
                                    None
                                }
                            };
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
                    let normalized_src =
                        normalize_client_sockaddr(&src_sa, cfg.listen_proto, cfg.listen_port_id);

                    if !locked.load(AtomOrdering::Relaxed) {
                        let Some(src) = normalized_src else {
                            log_warn_dir!(
                                worker_id,
                                C2U,
                                "recv_from client non-IP address family (ignored): {:?}",
                                src_sa
                            );
                            continue;
                        };

                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_port_id,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_log_drops,
                            worker_id,
                            C2U,
                            "validate_payload error: {}"
                        );

                        reset_session(sync_state, &mut sync_cache);
                        locked.store(true, AtomOrdering::Relaxed);
                        was_locked = true;
                        let src_sa_clean = SockAddr::from(src);
                        let addr_opt = Some(src);

                        handles.client_connected = false;
                        if cfg.debug_no_connect {
                            log_info!("Locked to single client {} (not connected)", src);
                        } else if let Err(e) = handles.client_sock.connect(&src_sa_clean) {
                            log_warn!("connect client_sock to {} failed: {}", src, e);
                            log_info!("Locked to single client {} (not connected)", src);
                        } else {
                            handles.client_connected = true;
                            log_info!("Locked to single client {} (connected)", src);
                        }

                        handles.version = sock_mgr.set_client_addr_connected(
                            addr_opt,
                            handles.client_connected,
                            handles.version,
                        );
                        log_debug_dir!(
                            cfg.debug_log_handles,
                            worker_id,
                            C2U,
                            "publish lock: addr={:?} connected={} ver={}",
                            addr_opt,
                            handles.client_connected,
                            handles.version
                        );

                        for mgr in all_sock_mgrs {
                            if !std::ptr::eq(mgr.as_ref(), sock_mgr) {
                                let _ = mgr.set_client_sock_connected(
                                    addr_opt,
                                    handles.client_connected,
                                    &src_sa_clean,
                                    0,
                                );
                            }
                        }

                        if let Ok(new_handles) = sock_mgr.reresolve(
                            cfg.reresolve_mode.allow_upstream(),
                            false,
                            "Re-resolved",
                        ) {
                            handles = new_handles;
                            cache.refresh_from_handles(&handles);
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
                                    &cache.dest_sa,
                                    cache.dest_port_id,
                                    &event,
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
                                    last_seen_s,
                                    wire.len(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                last_seen_s,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                Some((src_sa_clean.clone(), src.port())),
                                &wire,
                            ),
                        }
                    } else if locked_client_matches(normalized_src, handles.client_addr) {
                        let event = result_or_log_continue!(
                            validate_payload(
                                C2U,
                                cfg,
                                stats,
                                &buf.data[..len],
                                cache.recv_port_id,
                                PayloadOrigin::Wire,
                            ),
                            log_debug_dir,
                            cfg.debug_log_drops,
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
                                    &cache.dest_sa,
                                    cache.dest_port_id,
                                    &event,
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
                                    last_seen_s,
                                    wire.len(),
                                    counts_as_session_activity(&event, true),
                                    &send_res,
                                    handles.upstream_connected,
                                    &cache.dest_sa,
                                    None,
                                );
                            }
                            PayloadEvent::SyncKeepalive(wire) => handle_c2u_keepalive(
                                worker_id,
                                t_start,
                                t_recv,
                                cfg,
                                stats,
                                last_seen_s,
                                &mut handles,
                                sync_state,
                                &mut sync_cache,
                                None,
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
