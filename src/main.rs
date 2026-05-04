#[macro_use]
mod logging;
mod cli;
mod flow_claim;
mod flow_key;
mod flow_state;
mod net;
mod recv_buf;
mod runtime_support;
mod stats;
mod stats_support;
mod worker;
mod worker_support;

use cli::{RuntimeConfig, SupportedProtocol, WorkerFlowMode, parse_args, realize_config};
use flow_claim::FlowClaimTable;
use flow_state::FlowRuntimeState;
use net::sock_mgr::SocketManager;
use net::socket::make_socket;
use net::socket_policy::{SocketRole, socket_reuse_capability};
use net::sync_icmp::SharedSyncIcmpState;
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use runtime_support::SIGINT_EXIT;
use stats::Stats;
use worker::{
    run_client_to_upstream_thread, run_reresolve_thread, run_upstream_to_client_thread,
    run_watchdog_thread,
};
use worker_support::GlobalSyncPacer;

use std::io;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

fn print_startup(cfg: &RuntimeConfig, sock_mgr: &SocketManager) {
    let (_, _, client_proto) = sock_mgr.get_client_dest();
    let (upstream_addr, _, upstream_proto) = sock_mgr.get_upstream_dest();
    let snapshot = sock_mgr.snapshot_state();
    log_info!(
        "Listening on {}:{}, forwarding to upstream {}:{}; waiting for first client",
        client_proto,
        sock_mgr.get_listen_addr(),
        upstream_proto,
        upstream_addr
    );
    log_info!(
        "Timeout: {}s, on-timeout: {:?}",
        cfg.timeout_secs,
        cfg.on_timeout
    );
    log_info!("Workers: {}", cfg.workers);
    match cfg.worker_flow_mode {
        WorkerFlowMode::SharedFlow => {
            log_info!(
                "Worker flow mode: shared-flow (one global locked flow shared across worker pairs)"
            );
        }
        WorkerFlowMode::SingleFlow => {
            log_info!(
                "Worker flow mode: single-flow (worker-pair-local locked flows and worker-pair-local ICMP sync state)"
            );
            if cfg.workers == 1 {
                log_info!(
                    "single-flow with --workers 1 is valid but has no distribution benefit; flow ownership behaves like shared-flow"
                );
            }
        }
    }
    if cfg.listen_mode == cli::ListenMode::Dynamic {
        if cfg.listen_proto == SupportedProtocol::UDP {
            log_info!("UDP listener bind: dynamic local port requested with --here UDP:host:0");
        } else {
            log_info!(
                "ICMP listener mode: wildcard-learn (--here ICMP:host:0 learns the peer ICMP id on first lock)"
            );
        }
    } else {
        if cfg.listen_proto == SupportedProtocol::ICMP {
            log_info!(
                "ICMP listener mode: fixed-id (effective local id {})",
                cfg.listen.id
            );
        }
    }
    if cfg.upstream_proto == SupportedProtocol::UDP {
        log_info!(
            "UDP upstream destination: fixed remote port {}",
            cfg.upstream.id
        );
    }
    if cfg.upstream_proto == SupportedProtocol::ICMP {
        if cfg.upstream.id == 0 {
            log_info!(
                "ICMP upstream mode: dynamic local source id (--there ICMP:host:0 uses a kernel-assigned ping-socket id)"
            );
        } else {
            log_info!(
                "ICMP upstream mode: fixed remote peer/listener id {}",
                cfg.upstream.id
            );
        }
    }
    let client_mode_reason = if cfg.debug_behavior.client_unconnected {
        if !socket_reuse_capability(
            SocketRole::Listener,
            cfg.listen_proto,
            snapshot.listen_sock_type,
            cfg.on_timeout,
            cfg.debug_behavior.client_unconnected,
        )
        .can_reconnect_in_place
        {
            "policy/debug"
        } else {
            "debug"
        }
    } else if !socket_reuse_capability(
        SocketRole::Listener,
        cfg.listen_proto,
        snapshot.listen_sock_type,
        cfg.on_timeout,
        cfg.debug_behavior.client_unconnected,
    )
    .can_reconnect_in_place
    {
        "policy"
    } else {
        "default"
    };
    log_info!(
        "Client socket mode after lock: {} ({})",
        if cfg.debug_behavior.client_unconnected {
            "unconnected"
        } else {
            "connected"
        },
        client_mode_reason
    );
    let upstream_mode_reason = if cfg.debug_behavior.upstream_unconnected {
        if !socket_reuse_capability(
            SocketRole::Upstream,
            cfg.listen_proto,
            snapshot.listen_sock_type,
            cfg.on_timeout,
            cfg.debug_behavior.upstream_unconnected,
        )
        .should_start_connected
        {
            "policy/debug"
        } else {
            "debug"
        }
    } else if !socket_reuse_capability(
        SocketRole::Upstream,
        cfg.listen_proto,
        snapshot.listen_sock_type,
        cfg.on_timeout,
        cfg.debug_behavior.upstream_unconnected,
    )
    .should_start_connected
    {
        "policy"
    } else {
        "default"
    };
    log_info!(
        "Upstream socket mode: {} ({})",
        if snapshot.upstream_connected {
            "connected"
        } else {
            "unconnected"
        },
        upstream_mode_reason
    );
    if cfg.icmp_sync_pps > 0 {
        log_info!(
            "ICMP sync pace: global total best-effort target {} packet(s)/s shared across all workers and flows",
            cfg.icmp_sync_pps
        );
    }
    log_info!("Re-resolve every: {}s (0=disabled)", cfg.reresolve_secs);
}

fn main() -> io::Result<()> {
    let t_start = Instant::now();
    let mut requested_cfg = parse_args();
    let worker_count = requested_cfg.workers.max(1);

    // Listener for the local client (this may require root for low ports)
    let (client_sock, actual_listen, listen_sock_type, listen_capability) = make_socket(
        requested_cfg.listen_request.addr,
        requested_cfg.listen_proto,
        1000,
        worker_count != 1,
        requested_cfg.on_timeout,
        requested_cfg.debug_behavior.client_unconnected,
    )?;

    if !listen_capability.can_reconnect_in_place {
        requested_cfg.debug_behavior.client_unconnected = true;
    }

    let cfg = Arc::new(realize_config(requested_cfg, actual_listen)?);

    // Initial upstream resolution + socket managers (one per worker)
    let mut sock_mgrs = Vec::with_capacity(worker_count);

    sock_mgrs.push(Arc::new(SocketManager::new(
        client_sock,
        cfg.listen,
        listen_sock_type,
        cfg.listen_str.clone(),
        cfg.listen_proto,
        listen_capability,
        cfg.debug_behavior.client_unconnected,
        cfg.upstream,
        cfg.upstream_str.clone(),
        cfg.upstream_local_id,
        cfg.upstream_proto,
        cfg.debug_behavior.upstream_unconnected,
        cfg.on_timeout,
        cfg.debug_logs.handles,
    )?));

    for _ in 1..worker_count {
        let (extra_sock, _, extra_sock_type, _) = make_socket(
            cfg.listen.addr,
            cfg.listen_proto,
            1000,
            true,
            cfg.on_timeout,
            cfg.debug_behavior.client_unconnected,
        )?;
        sock_mgrs.push(Arc::new(SocketManager::new(
            extra_sock,
            cfg.listen,
            extra_sock_type,
            cfg.listen_str.clone(),
            cfg.listen_proto,
            listen_capability,
            cfg.debug_behavior.client_unconnected,
            cfg.upstream,
            cfg.upstream_str.clone(),
            cfg.upstream_local_id,
            cfg.upstream_proto,
            cfg.debug_behavior.upstream_unconnected,
            cfg.on_timeout,
            cfg.debug_logs.handles,
        )?));
    }

    // Drop privileges (Unix) now that the privileged socket is bound.
    #[cfg(unix)]
    drop_privileges(&cfg)?;

    // Global application state
    let stats = Arc::new(Stats::with_worker_shards(worker_count));
    let exit_code_set = Arc::new(AtomicU32::new(0));
    let flow_states: Vec<_> = match cfg.worker_flow_mode {
        WorkerFlowMode::SharedFlow => {
            let shared = Arc::new(FlowRuntimeState::new());
            (0..worker_count).map(|_| Arc::clone(&shared)).collect()
        }
        WorkerFlowMode::SingleFlow => (0..worker_count)
            .map(|_| Arc::new(FlowRuntimeState::new()))
            .collect(),
    };
    let flow_claims = matches!(cfg.worker_flow_mode, WorkerFlowMode::SingleFlow)
        .then(|| Arc::new(FlowClaimTable::new()));
    let global_sync_pacer =
        (cfg.icmp_sync_pps > 0 && cfg.upstream_proto == SupportedProtocol::ICMP).then(|| {
            Arc::new(GlobalSyncPacer::new(Duration::from_nanos(
                (1_000_000_000u64 / u64::from(cfg.icmp_sync_pps)).max(1),
            )))
        });

    // Graceful shutdown on Ctrl-C / SIGINT (and SIGTERM on Unix via ctrlc)
    {
        let exit_code_set_c = Arc::clone(&exit_code_set);
        ctrlc::set_handler(move || {
            // Signal the main loop to exit with code 130
            exit_code_set_c.store(SIGINT_EXIT, AtomOrdering::Relaxed);
        })
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("ctrlc::set_handler failed: {e}"),
            )
        })?;
    }

    print_startup(&cfg, &sock_mgrs[0]);

    let shared_sync_state = matches!(cfg.worker_flow_mode, WorkerFlowMode::SharedFlow)
        .then(|| Arc::new(SharedSyncIcmpState::new(cfg.icmp_sync_pps)));

    for (idx, sock_mgr) in sock_mgrs.iter().enumerate() {
        let worker_base = idx * 2;
        let sync_state = shared_sync_state
            .clone()
            .unwrap_or_else(|| Arc::new(SharedSyncIcmpState::new(cfg.icmp_sync_pps)));
        // Client -> Upstream
        {
            let cfg_a = Arc::clone(&cfg);
            let sock_mgr_a = Arc::clone(&sock_mgr);
            let sock_mgrs_a = sock_mgrs.clone();
            let worker_id = worker_base;
            let flow_state_a = Arc::clone(&flow_states[idx]);
            let stats_a = stats.shard(idx);
            let sync_state_a = Arc::clone(&sync_state);
            let sync_pacer_a = global_sync_pacer.clone();
            let flow_claims_a = flow_claims.clone();

            thread::spawn(move || {
                run_client_to_upstream_thread(
                    t_start,
                    &cfg_a,
                    &sock_mgr_a,
                    &sock_mgrs_a,
                    worker_id,
                    &flow_state_a,
                    &stats_a,
                    &sync_state_a,
                    sync_pacer_a.as_deref(),
                    flow_claims_a.as_deref(),
                    idx,
                )
            });
        }

        // Upstream -> Client
        {
            let cfg_b = Arc::clone(&cfg);
            let sock_mgr_b = Arc::clone(&sock_mgr);
            let worker_id = worker_base + 1;
            let flow_state_b = Arc::clone(&flow_states[idx]);
            let stats_b = stats.shard(idx);
            let sync_state_b = Arc::clone(&sync_state);

            thread::spawn(move || {
                run_upstream_to_client_thread(
                    t_start,
                    &cfg_b,
                    &sock_mgr_b,
                    worker_id,
                    &flow_state_b,
                    &stats_b,
                    &sync_state_b,
                    idx,
                )
            });
        }
    }

    // Idle timeout watchdog for all workers
    {
        let cfg_w = Arc::clone(&cfg);
        let sock_mgrs_w = sock_mgrs.clone();
        let flow_states_w = flow_states.clone();
        let exit_code_set_w = Arc::clone(&exit_code_set);
        let flow_claims_w = flow_claims.clone();

        thread::spawn(move || {
            run_watchdog_thread(
                t_start,
                &cfg_w,
                &sock_mgrs_w,
                &flow_states_w,
                &exit_code_set_w,
                flow_claims_w.as_deref(),
            )
        });
    }

    // Optional periodic re-resolve across all workers
    let reresolve_secs = cfg.reresolve_secs;
    let allow_upstream = cfg.reresolve_mode.allow_upstream();
    let allow_listen_rebind = cfg.reresolve_mode.allow_listen();
    if reresolve_secs != 0 && (allow_upstream || allow_listen_rebind) {
        let sock_mgrs_r = sock_mgrs.clone();

        thread::spawn(move || {
            run_reresolve_thread(
                &sock_mgrs_r,
                reresolve_secs,
                allow_upstream,
                allow_listen_rebind,
            );
        });
    }

    // Stats thread (report peer info from the first worker), unless disabled.
    let stats_interval_secs = if !cfg.debug_behavior.fast_stats {
        u64::from(cfg.stats_interval_mins).saturating_mul(60)
    } else {
        1
    };
    if stats_interval_secs != 0 {
        stats.spawn_stats_printer(
            sock_mgrs.clone(),
            flow_states.clone(),
            t_start,
            stats_interval_secs,
            Arc::clone(&exit_code_set),
        );

        // Keep main alive
        loop {
            thread::park();
        }
    } else {
        // Handle exit without final stats print
        loop {
            thread::park_timeout(Duration::from_secs(1));
            let exit_code_local = exit_code_set.load(AtomOrdering::Relaxed);
            if (exit_code_local & (1 << 31)) != 0 {
                log_info!("Exiting, uptime {} seconds", t_start.elapsed().as_secs());
                let exit_code = (exit_code_local & !(1 << 31)) as i32;
                process::exit(exit_code);
            }
        }
    }
}

#[cfg(unix)]
fn drop_privileges(cfg: &RuntimeConfig) -> io::Result<()> {
    if !unistd::geteuid().is_root() {
        // Not root: ignore any requested run-as flags.
        if cfg.run_as_user.is_some() || cfg.run_as_group.is_some() {
            log_warn!("--user/--group specified but process is not running as root; ignoring");
        }
        return Ok(());
    }

    let user_name = cfg.run_as_user.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "must specify --user when running as root",
        )
    })?;

    let user = User::from_name(user_name)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("user lookup failed for {user_name}: {e}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, format!("user {user_name} not found"))
        })?;

    // Determine primary group: explicit --group overrides user's primary group.
    let primary_gid = if let Some(group_name) = cfg.run_as_group.as_ref() {
        let grp = Group::from_name(group_name)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("group lookup failed for {group_name}: {e}"),
                )
            })?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("group {group_name} not found"),
                )
            })?;
        grp.gid
    } else {
        user.gid
    };

    let uid = user.uid;
    let gid = primary_gid;

    // Drop supplementary groups entirely to avoid retaining root-level groups.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        // This function is not available on Apple platforms.
        let empty: &[nix::unistd::Gid] = &[];
        unistd::setgroups(empty)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setgroups failed: {e}")))?;
    }

    // Order: primary gid -> uid
    unistd::setgid(gid)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setgid failed: {e}")))?;
    unistd::setuid(uid)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("setuid failed: {e}")))?;

    log_info!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user.name,
        uid.as_raw(),
        gid.as_raw()
    );
    Ok(())
}
