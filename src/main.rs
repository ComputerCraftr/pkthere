#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::undocumented_unsafe_blocks,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used
    )
)]

#[cfg(not(panic = "unwind"))]
compile_error!("pkthere production supervision requires panic=unwind");

macro_rules! format {
    ($($arguments:tt)*) => {{
        let _formatting_scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::Formatting,
        )
        .unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(::std::format_args!(
                "formatting crossed an incompatible synchronization authority at {}:{}: {error}",
                file!(),
                line!(),
            ))
        });
        ::std::format!($($arguments)*)
    }};
}

macro_rules! audited_json {
    ($($arguments:tt)*) => {{
        let _json_scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::JsonSerialization,
        )
        .unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(::std::format_args!(
                "JSON serialization crossed an incompatible synchronization authority at {}:{}: {error}",
                file!(),
                line!(),
            ))
        });
        ::serde_json::json!($($arguments)*)
    }};
}

#[macro_use]
mod logging;
mod app_runtime;
mod atomic_core;
mod authority;
mod cli;
mod diagnostics;
mod endpoint;
mod flow_claim;
mod flow_key;
mod flow_state;
mod net;
mod runtime_support;
mod shutdown_publication;
mod stats;
mod worker_support;

#[cfg(any(test, feature = "authority-audit"))]
mod allocation_test_support;
#[cfg(test)]
mod allocation_test_support_tests;

use cli::{RuntimeConfig, SupportedProtocol, WorkerFlowMode, parse_args, realize_config};
use flow_claim::FlowClaimTable;
use flow_state::FlowRuntimeState;
use net::icmp_sequence::SharedIcmpSequenceState;
use net::sock_mgr::{SharedUpstreamIdentity, SocketManager, SocketManagerInit};
use net::socket::make_socket;
#[cfg(unix)]
use nix::unistd::{self, Group, User};
use stats::Stats;
use worker_support::{ClientWorkerContext, run_client_to_upstream_thread};
use worker_support::{
    GlobalSyncPacer, UpstreamWorkerContext, run_reresolve_thread, run_upstream_to_client_thread,
    run_watchdog_thread,
};

use std::io;
use std::process;
use std::time::Instant;

use pkthere_socket_policy::{
    ListenerWorkerDistribution, listener_worker_socket_policy, upstream_socket_creation_policy,
    upstream_worker_socket_policy,
};

fn print_startup(cfg: &RuntimeConfig, sock_mgr: &SocketManager) -> io::Result<()> {
    let snapshot = sock_mgr.try_snapshot_state().map_err(io::Error::other)?;
    log_info!(
        "Listening on {}:{}, forwarding to upstream {}:{}; waiting for first client",
        snapshot.client_proto,
        snapshot.listen_local_filter,
        snapshot.upstream_proto,
        snapshot.upstream_remote_filter
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
    if cfg.listen_proto == SupportedProtocol::ICMP || cfg.upstream_proto == SupportedProtocol::ICMP
    {
        log_info!(
            "ICMP ready session pool target: {} per transmit leg",
            cfg.icmp_session_pool_size
        );
    }
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
    let listener_policy_allows_connected = snapshot
        .listen_policy
        .listener_lifecycle
        .is_some_and(pkthere_socket_policy::ListenerLockLifecycle::connects_after_lock);
    let client_after_lock_connected = listener_policy_allows_connected;
    let client_mode_reason = socket_mode_reason(
        cfg.debug_behavior.client_unconnected,
        client_after_lock_connected,
        listener_policy_allows_connected,
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
    Ok(())
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
    crate::authority::validate_catalog()
        .map_err(|error| io::Error::other(format!("authority catalog is invalid: {error}")))?;
    let started_at = Instant::now();
    let mut runtime = app_runtime::initialize()?;
    let threads = app_runtime::spawn_threads(&mut runtime, started_at)?;
    app_runtime::wait(runtime, threads, started_at)
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
mod tests;
