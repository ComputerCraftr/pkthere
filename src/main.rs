#[macro_use]
mod logging;
mod cli;
mod diagnostics;
mod endpoint;
mod flow_claim;
mod flow_key;
mod flow_state;
mod net;
mod packet_trace;
mod recv_buf;
mod runtime_support;
mod stats;
mod stats_support;
mod worker_support;

use cli::{RuntimeConfig, SupportedProtocol, WorkerFlowMode, parse_args, realize_config};
use flow_claim::FlowClaimTable;
use flow_state::FlowRuntimeState;
use net::icmp_sequence::SharedIcmpSequenceState;
use net::sock_mgr::{SocketManager, SocketManagerInit};
use net::socket::make_socket;
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use runtime_support::SIGINT_EXIT;
use stats::Stats;
use worker_support::{ClientWorkerContext, run_client_to_upstream_thread};
use worker_support::{
    GlobalSyncPacer, UpstreamWorkerContext, run_reresolve_thread, run_upstream_to_client_thread,
    run_watchdog_thread,
};

use std::io;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

use pkthere_socket_policy::{ListenerWorkerDistribution, listener_worker_socket_policy};

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
    log_info!(
        "ICMP reply-ID handshake timeout: {}s",
        cfg.icmp_handshake_timeout_secs
    );
    log_info!("Workers: {}", cfg.workers);
    let worker_socket_policy = sock_mgr.get_listener_worker_socket_policy();
    let worker_distribution = match worker_socket_policy.distribution {
        ListenerWorkerDistribution::SingleSocket => "single-socket",
        ListenerWorkerDistribution::SharedState => "shared-state",
        ListenerWorkerDistribution::KernelFlowAffinity => "kernel-flow-affinity",
        ListenerWorkerDistribution::UnsupportedSeparateState => "unsupported-separate-state",
    };
    log_info!(
        "Listener worker socket policy: distribution={}, reuse_address={}, reuse_port={}",
        worker_distribution,
        worker_socket_policy.reuse_address,
        worker_socket_policy.reuse_port
    );
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
                "ICMP listener mode: wildcard-learn (listen id {}, requested client reply id {:?})",
                cfg.listen.id(),
                cfg.listener_reply_id_request
            );
        }
    } else if cfg.listen_proto == SupportedProtocol::ICMP {
        log_info!(
            "ICMP listener mode: fixed-id (listen id {}, requested client reply id {:?})",
            cfg.listen.id(),
            cfg.listener_reply_id_request
        );
    }
    if cfg.upstream_proto == SupportedProtocol::UDP {
        log_info!(
            "UDP upstream destination: fixed remote port {}",
            cfg.upstream.id()
        );
    }
    if cfg.upstream_proto == SupportedProtocol::ICMP {
        let dynamic_icmp_upstream = matches!(
            cfg.upstream_source_id_request,
            cli::IcmpReplyIdRequest::Default
        ) && matches!(
            cfg.upstream_reply_id_request,
            cli::IcmpReplyIdRequest::Default
        ) && snapshot.upstream_local_filter.id()
            == snapshot.upstream_remote_filter.id();
        log_info!(
            "ICMP upstream mode: {} (local id {}, remote id {})",
            if dynamic_icmp_upstream {
                "dynamic/wildcard local reply id (--there ICMP:host:0 advertises the realized ping-socket id)"
            } else {
                "fixed remote peer/listener id"
            },
            snapshot.upstream_local_filter.id(),
            snapshot.upstream_remote_filter.id()
        );
    }
    let client_after_lock_connected = !cfg.debug_behavior.client_unconnected
        && snapshot.listen_policy.reuse.connects_after_lock();
    let client_mode_reason = socket_mode_reason(
        cfg.debug_behavior.client_unconnected,
        client_after_lock_connected,
        snapshot.listen_policy.reuse.connects_after_lock(),
    );
    log_info!(
        "Client socket mode after lock: {} ({})",
        if client_after_lock_connected {
            "connected"
        } else {
            "unconnected"
        },
        client_mode_reason
    );
    let upstream_mode_reason = socket_mode_reason(
        cfg.debug_behavior.upstream_unconnected,
        snapshot.upstream_connected,
        snapshot.upstream_policy.reuse.starts_connected(),
    );
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

fn socket_mode_reason(
    debug_unconnected_requested: bool,
    connected: bool,
    policy_allows_connected: bool,
) -> &'static str {
    if debug_unconnected_requested && !connected {
        "debug"
    } else if !connected || (debug_unconnected_requested && policy_allows_connected) {
        "policy"
    } else {
        "default"
    }
}

fn main() -> io::Result<()> {
    let t_start = Instant::now();
    let mut requested_cfg = parse_args();
    let worker_count = requested_cfg.workers.max(1);
    let listener_worker_socket_policy = listener_worker_socket_policy(
        worker_count,
        requested_cfg.worker_flow_mode == WorkerFlowMode::SingleFlow,
    );
    if !listener_worker_socket_policy.supports_requested_distribution() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "single-flow with {worker_count} workers requires kernel reuse-port flow affinity on this platform"
            ),
        ));
    }

    // Listener for the local client (this may require root for low ports)
    let (client_sock, actual_listen, listen_local_kernel_addr, listen_sock_type, listen_capability) =
        make_socket(
            requested_cfg.listen_request.to_socket_addr(),
            requested_cfg.listen_proto,
            1000,
            listener_worker_socket_policy,
            requested_cfg.on_timeout,
            requested_cfg.debug_behavior.client_unconnected,
            requested_cfg.debug_behavior.icmp_kernel_echo_self_handshake,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("listener socket setup failed: {e}")))?;

    if !listen_capability.reuse.connects_after_lock() {
        requested_cfg.debug_behavior.client_unconnected = true;
    }
    if requested_cfg.listen_proto == SupportedProtocol::ICMP
        && let crate::cli::IcmpReplyIdRequest::Fixed(source_id) =
            requested_cfg.listener_source_id_request
        && source_id != actual_listen.id()
        && !listen_capability
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    {
        return Err(io::Error::other(format!(
            "ICMP listener requested independent listen/source ids {} -> {} but socket type {:?} cannot preserve disjoint ICMP ids; use a raw-capable deployment",
            actual_listen.id(),
            source_id,
            listen_sock_type
        )));
    }

    let cfg = Arc::new(realize_config(requested_cfg, actual_listen)?);

    // Initial upstream resolution + socket managers (one per worker)
    let mut sock_mgrs = Vec::with_capacity(worker_count);

    sock_mgrs.push(Arc::new(
        SocketManager::new(SocketManagerInit {
            socket_slot: 0,
            client_sock,
            listen_local_filter: cfg.listen,
            listen_local_kernel_addr,
            listen_sock_type,
            listen_target: cfg.listen_str.clone(),
            listen_proto: cfg.listen_proto,
            listen_policy: listen_capability,
            listen_worker_socket_policy: listener_worker_socket_policy,
            listen_debug_unconnected: cfg.debug_behavior.client_unconnected,
            upstream_remote_filter: cfg.upstream,
            upstream_target: cfg.upstream_str.clone(),
            upstream_source_id_request: cfg.upstream_source_id_request,
            upstream_reply_id_request: cfg.upstream_reply_id_request,
            upstream_proto: cfg.upstream_proto,
            upstream_debug_unconnected: cfg.debug_behavior.upstream_unconnected,
            upstream_icmp_kernel_echo_self_handshake: cfg
                .debug_behavior
                .icmp_kernel_echo_self_handshake,
            force_raw_icmp_wildcard_upstream: cfg.debug_behavior.force_raw_icmp_wildcard_upstream,
            timeout_act: cfg.on_timeout,
            debug_handles: cfg.debug_logs.handles,
        })
        .map_err(|e| io::Error::new(e.kind(), format!("upstream socket setup failed: {e}")))?,
    ));

    for worker_slot in 1..worker_count {
        let (extra_sock, _, extra_listen_kernel, extra_sock_type, extra_listen_capability) =
            make_socket(
                cfg.listen.to_socket_addr(),
                cfg.listen_proto,
                1000,
                listener_worker_socket_policy,
                cfg.on_timeout,
                cfg.debug_behavior.client_unconnected,
                cfg.debug_behavior.icmp_kernel_echo_self_handshake,
            )?;
        sock_mgrs.push(Arc::new(SocketManager::new(SocketManagerInit {
            socket_slot: u32::try_from(worker_slot)
                .map_err(|_| io::Error::other("worker socket slot exceeds u32"))?,
            client_sock: extra_sock,
            listen_local_filter: cfg.listen,
            listen_local_kernel_addr: extra_listen_kernel,
            listen_sock_type: extra_sock_type,
            listen_target: cfg.listen_str.clone(),
            listen_proto: cfg.listen_proto,
            listen_policy: extra_listen_capability,
            listen_worker_socket_policy: listener_worker_socket_policy,
            listen_debug_unconnected: cfg.debug_behavior.client_unconnected,
            upstream_remote_filter: cfg.upstream,
            upstream_target: cfg.upstream_str.clone(),
            upstream_source_id_request: cfg.upstream_source_id_request,
            upstream_reply_id_request: cfg.upstream_reply_id_request,
            upstream_proto: cfg.upstream_proto,
            upstream_debug_unconnected: cfg.debug_behavior.upstream_unconnected,
            upstream_icmp_kernel_echo_self_handshake: cfg
                .debug_behavior
                .icmp_kernel_echo_self_handshake,
            force_raw_icmp_wildcard_upstream: cfg.debug_behavior.force_raw_icmp_wildcard_upstream,
            timeout_act: cfg.on_timeout,
            debug_handles: cfg.debug_logs.handles,
        })?));
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
        .map_err(|e| io::Error::other(format!("ctrlc::set_handler failed: {e}")))?;
    }

    print_startup(&cfg, &sock_mgrs[0]);

    let shared_client_side_state = (cfg.worker_flow_mode == WorkerFlowMode::SharedFlow)
        .then(|| Arc::new(SharedIcmpSequenceState::new()));
    let shared_upstream_side_state = (cfg.worker_flow_mode == WorkerFlowMode::SharedFlow)
        .then(|| Arc::new(SharedIcmpSequenceState::new()));

    for (idx, sock_mgr) in sock_mgrs.iter().enumerate() {
        let worker_base = idx * 2;
        let client_side_state = shared_client_side_state
            .clone()
            .unwrap_or_else(|| Arc::new(SharedIcmpSequenceState::new()));
        let upstream_side_state = shared_upstream_side_state
            .clone()
            .unwrap_or_else(|| Arc::new(SharedIcmpSequenceState::new()));

        // Client -> Upstream
        {
            let cfg_a = Arc::clone(&cfg);
            let sock_mgr_a = Arc::clone(sock_mgr);
            let sock_mgrs_a = sock_mgrs.clone();
            let worker_id = worker_base;
            let flow_state_a = Arc::clone(&flow_states[idx]);
            let stats_a = stats.shard(idx);
            let client_side_state_a = Arc::clone(&client_side_state);
            let upstream_side_state_a = Arc::clone(&upstream_side_state);
            let sync_pacer_a = global_sync_pacer.clone();
            let flow_claims_a = flow_claims.clone();

            thread::spawn(move || {
                run_client_to_upstream_thread(ClientWorkerContext {
                    t_start,
                    cfg: &cfg_a,
                    sock_mgr: &sock_mgr_a,
                    all_sock_mgrs: &sock_mgrs_a,
                    worker_id,
                    flow_state: &flow_state_a,
                    stats: &stats_a,
                    client_side_state: &client_side_state_a,
                    upstream_side_state: &upstream_side_state_a,
                    sync_pacer: sync_pacer_a.as_deref(),
                    flow_claims: flow_claims_a.as_deref(),
                    worker_pair_id: idx,
                })
            });
        }

        // Upstream -> Client
        {
            let cfg_b = Arc::clone(&cfg);
            let sock_mgr_b = Arc::clone(sock_mgr);
            let sock_mgrs_b = sock_mgrs.clone();
            let worker_id = worker_base + 1;
            let flow_state_b = Arc::clone(&flow_states[idx]);
            let stats_b = stats.shard(idx);
            let client_side_state_b = Arc::clone(&client_side_state);
            let upstream_side_state_b = Arc::clone(&upstream_side_state);

            thread::spawn(move || {
                run_upstream_to_client_thread(UpstreamWorkerContext {
                    t_start,
                    cfg: &cfg_b,
                    sock_mgr: &sock_mgr_b,
                    all_sock_mgrs: &sock_mgrs_b,
                    worker_id,
                    flow_state: &flow_state_b,
                    stats: &stats_b,
                    client_side_state: &client_side_state_b,
                    upstream_side_state: &upstream_side_state_b,
                })
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
    let allow_upstream = cfg.reresolve_mode.allow_upstream();
    let allow_listen_rebind = cfg.reresolve_mode.allow_listen();
    if cfg.reresolve_secs != 0 && (allow_upstream || allow_listen_rebind) {
        let cfg_r = Arc::clone(&cfg);
        let sock_mgrs_r = sock_mgrs.clone();
        let flow_states_r = flow_states.clone();
        let flow_claims_r = flow_claims.clone();

        thread::spawn(move || {
            run_reresolve_thread(
                &cfg_r,
                &sock_mgrs_r,
                &flow_states_r,
                flow_claims_r.as_deref(),
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

    let user_name = cfg
        .run_as_user
        .as_ref()
        .ok_or_else(|| io::Error::other("must specify --user when running as root"))?;

    let user = User::from_name(user_name)
        .map_err(|e| io::Error::other(format!("user lookup failed for {user_name}: {e}")))?
        .ok_or_else(|| io::Error::other(format!("user {user_name} not found")))?;

    // Determine primary group: explicit --group overrides user's primary group.
    let primary_gid = if let Some(group_name) = cfg.run_as_group.as_ref() {
        let grp = Group::from_name(group_name)
            .map_err(|e| io::Error::other(format!("group lookup failed for {group_name}: {e}")))?
            .ok_or_else(|| io::Error::other(format!("group {group_name} not found")))?;
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
        unistd::setgroups(empty).map_err(|e| io::Error::other(format!("setgroups failed: {e}")))?;
    }

    // Order: primary gid -> uid
    unistd::setgid(gid).map_err(|e| io::Error::other(format!("setgid failed: {e}")))?;
    unistd::setuid(uid).map_err(|e| io::Error::other(format!("setuid failed: {e}")))?;

    log_info!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user.name,
        uid.as_raw(),
        gid.as_raw()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::socket_mode_reason;

    #[test]
    fn socket_mode_reason_reports_debug_only_when_debug_causes_unconnected_mode() {
        assert_eq!(socket_mode_reason(true, false, false), "debug");
        assert_eq!(socket_mode_reason(true, true, true), "policy");
        assert_eq!(socket_mode_reason(false, false, false), "policy");
        assert_eq!(socket_mode_reason(false, true, true), "default");
    }
}
