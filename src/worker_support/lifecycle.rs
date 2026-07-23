use crate::cli::{RuntimeConfig, TimeoutAction, WorkerFlowMode};
use crate::flow_claim::FlowClaimTable;
use crate::flow_state::FlowRuntimeState;
use crate::net::sock_mgr::{
    DebugAddressResolver, DebugAddressRevision, DebugResolverDecision, ReresolveSummary,
    SocketManager, socket_evidence_key_json,
};
use crate::worker_support::handshake_trace::{log_handshake_reset, log_handshake_timeout};
use crate::worker_support::packet_dump::{PacketDisposition, log_packet_disposition};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering as AtomOrdering};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) fn run_reresolve_thread(
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
) {
    let period = Duration::from_secs(cfg.reresolve_secs);
    let allow_upstream = cfg.reresolve_mode.allow_upstream();
    let allow_listen_rebind = cfg.reresolve_mode.allow_listen();
    let mut debug_resolver = cfg
        .debug_reresolve_address_file
        .clone()
        .map(DebugAddressResolver::new);
    loop {
        thread::sleep(period);
        if let Some(resolver) = &mut debug_resolver {
            run_debug_reresolve(
                cfg,
                sock_mgrs,
                flow_states,
                flow_claims,
                resolver,
                allow_upstream,
                allow_listen_rebind,
            );
            continue;
        }
        for (worker_pair, sock_mgr) in sock_mgrs.iter().enumerate() {
            match sock_mgr.reresolve_with_addresses(
                allow_upstream,
                allow_listen_rebind,
                "Periodic re-resolve",
                None,
                None,
            ) {
                Ok(summary) => apply_listener_rebind_reset(
                    cfg,
                    flow_states,
                    flow_claims,
                    worker_pair,
                    &summary,
                ),
                Err(err) => {
                    crate::log_warn!("Periodic re-resolve failed: {}", err);
                }
            }
        }
    }
}

fn run_debug_reresolve(
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
    resolver: &mut DebugAddressResolver,
    allow_upstream: bool,
    allow_listen_rebind: bool,
) {
    let decision = resolver.read(allow_listen_rebind, allow_upstream);
    match decision {
        DebugResolverDecision::AlreadyApplied { revision } => {
            log_resolver_evidence(serde_json::json!({
                "revision": revision,
                "parse_result": "valid",
                "application_result": "already-applied",
            }));
        }
        DebugResolverDecision::Rejected { revision, reason } => {
            log_resolver_evidence(serde_json::json!({
                "revision": revision,
                "parse_result": "rejected",
                "application_result": "not-applied",
                "reason": reason,
            }));
        }
        DebugResolverDecision::Apply(update) => {
            let mut summaries = Vec::with_capacity(sock_mgrs.len());
            for (worker_pair, sock_mgr) in sock_mgrs.iter().enumerate() {
                match sock_mgr.reresolve_with_addresses(
                    allow_upstream,
                    allow_listen_rebind,
                    "Debug revisioned re-resolve",
                    update.listen_addr,
                    update.upstream_addr,
                ) {
                    Ok(summary) => {
                        apply_listener_rebind_reset(
                            cfg,
                            flow_states,
                            flow_claims,
                            worker_pair,
                            &summary,
                        );
                        summaries.push(summary);
                    }
                    Err(error) => {
                        log_resolver_evidence(serde_json::json!({
                            "revision": update.revision,
                            "listen_addr": update.listen_addr.map(|addr| addr.to_string()),
                            "upstream_addr": update.upstream_addr.map(|addr| addr.to_string()),
                            "parse_result": "valid",
                            "application_result": "failed",
                            "reason": error.to_string(),
                        }));
                        return;
                    }
                }
            }
            for summary in &summaries {
                log_applied_summary(update, summary);
            }
            resolver.mark_applied(update.revision);
        }
    }
}

fn apply_listener_rebind_reset(
    cfg: &RuntimeConfig,
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
    worker_pair: usize,
    summary: &ReresolveSummary,
) {
    if !summary.listener_replaced() {
        return;
    }
    let reset = flow_states[worker_pair].reset();
    if let Some(trace) = reset.and_then(|payload| payload.buffered_trace) {
        log_packet_disposition(cfg, trace, PacketDisposition::HandshakeResetDrop);
    }
    if let (Some(claims), Some(flow)) = (flow_claims, summary.old_locked_flow) {
        claims.release(flow, worker_pair);
    }
}

fn log_applied_summary(update: DebugAddressRevision, summary: &ReresolveSummary) {
    log_resolver_evidence(serde_json::json!({
        "revision": update.revision,
        "listen_addr": update.listen_addr.map(|addr| addr.to_string()),
        "upstream_addr": update.upstream_addr.map(|addr| addr.to_string()),
        "parse_result": "valid",
        "application_result": "applied",
        "listener_update": summary.listener_update.wire_name(),
        "upstream_update": summary.upstream_update.wire_name(),
        "old_listener_key": socket_evidence_key_json(summary.old_listener_key),
        "new_listener_key": socket_evidence_key_json(summary.new_listener_key),
        "old_upstream_key": socket_evidence_key_json(summary.old_upstream_key),
        "new_upstream_key": socket_evidence_key_json(summary.new_upstream_key),
    }));
}

fn log_resolver_evidence(value: serde_json::Value) {
    crate::log_debug!(
        true,
        "resolver-evidence {}",
        crate::diagnostics::stamp(serde_json::json!({
            "event": "resolver_evidence",
            "resolver": value,
        }))
    );
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
            let expired_handshake =
                flow_state.expire_reply_id_handshake(now_s, cfg.icmp_handshake_timeout_secs);
            if let Some(expired) = expired_handshake {
                log_handshake_timeout(cfg, idx, expired);
                if let Some(trace) = expired.buffered_trace {
                    log_packet_disposition(cfg, trace, PacketDisposition::HandshakeTimeoutDrop);
                }
            }
            let handshake_timed_out = expired_handshake.is_some();
            let last_s = flow_state.last_seen_s();
            if !handshake_timed_out
                && (last_s == 0 || now_s.saturating_sub(last_s) < cfg.timeout_secs)
            {
                if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                    break;
                }
                continue;
            }
            match cfg.on_timeout {
                TimeoutAction::Drop => {
                    let locked_flow = sock_mgrs[idx].get_client_dest().0;
                    if handshake_timed_out {
                        log_warn!(
                            "ICMP reply-ID handshake timeout reached ({}s): dropping locked client on worker pair {}",
                            cfg.icmp_handshake_timeout_secs,
                            idx
                        );
                    } else {
                        log_warn!(
                            "Idle timeout reached ({}s): dropping locked client on worker pair {}",
                            cfg.timeout_secs,
                            idx
                        );
                    }
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
                                log_error!("watchdog client-lock cleanup failed: {}", e);
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
                    let reset_payload = flow_state.reset();
                    if let Some(dropped) = reset_payload
                        && let Some(trace) = dropped.buffered_trace
                    {
                        log_packet_disposition(cfg, trace, PacketDisposition::HandshakeResetDrop);
                    }
                    if handshake_timed_out {
                        log_handshake_reset(cfg, idx, "handshake-timeout", None);
                    } else if reset_payload.is_some() {
                        log_handshake_reset(cfg, idx, "idle-timeout", reset_payload);
                    }
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
            if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                break;
            }
        }
    }
}
