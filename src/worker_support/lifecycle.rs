use crate::cli::{RuntimeConfig, TimeoutAction, WorkerFlowMode};
use crate::flow_claim::FlowClaimTable;
use crate::flow_state::{ClientFlowReservation, FlowRuntimeState};
use crate::net::sock_mgr::{
    DebugAddressResolver, DebugAddressRevision, DebugResolverDecision, ManagerError,
    ReresolveSummary, SocketManager, socket_evidence_key_json,
};
use crate::runtime_support::{CLEAN_EXIT, FATAL_EXIT, ShutdownController};
use crate::worker_support::handshake_trace::{log_handshake_reset, log_handshake_timeout};
use crate::worker_support::packet_dump::{PacketDisposition, log_packet_disposition};
use crate::worker_support::reresolve_publication::{
    FlowVisibilityPublication, ManagerTopologyPublication, ReresolvePublicationCore,
    ReresolvePublicationError,
};
use std::sync::Arc;
use std::sync::atomic::Ordering as AtomOrdering;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct ReresolvePermissions {
    upstream: bool,
    listener: bool,
}

impl ManagerTopologyPublication for crate::net::sock_mgr::PreparedReresolveGroup<'_> {
    type Error = ManagerError;
    type Output = Vec<ReresolveSummary>;

    fn publish_manager_topology(self) -> Result<Self::Output, Self::Error> {
        self.publish()
    }
}

struct ReresolveFlowVisibility<'reservation, 'flow> {
    visibility: Vec<ReresolveVisibility<'reservation, 'flow>>,
}

enum ReresolveVisibility<'reservation, 'flow> {
    Manager(crate::flow_state::PreparedClientFlowTopology<'reservation, 'flow>),
    Committed(crate::flow_state::CommittedClientFlowTopology<'reservation, 'flow>),
}

impl FlowVisibilityPublication for ReresolveFlowVisibility<'_, '_> {
    type Error = crate::flow_state::FlowTopologyError;

    fn publish_flow_visibility(self) -> Result<(), Self::Error> {
        for reservation in self.visibility {
            match reservation {
                ReresolveVisibility::Manager(reservation) => reservation.publish_manager_only(),
                ReresolveVisibility::Committed(reservation) => reservation.publish(),
            }?;
        }
        Ok(())
    }
}

pub(crate) fn run_reresolve_thread(
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
    exit_code_set: &ShutdownController,
) {
    let period = Duration::from_secs(cfg.reresolve_secs);
    let allow_upstream = cfg.reresolve_mode.allow_upstream();
    let allow_listen_rebind = cfg.reresolve_mode.allow_listen();
    let permissions = ReresolvePermissions {
        upstream: allow_upstream,
        listener: allow_listen_rebind,
    };
    let mut debug_resolver = cfg
        .debug_reresolve_address_file
        .clone()
        .map(DebugAddressResolver::new);
    loop {
        exit_code_set.wait_for_change(Instant::now() + period);
        if exit_code_set.is_requested() {
            return;
        }
        if let Some(resolver) = &mut debug_resolver {
            run_debug_reresolve(
                cfg,
                sock_mgrs,
                flow_states,
                flow_claims,
                resolver,
                permissions,
                exit_code_set,
            );
            continue;
        }
        if let Err(error) = reresolve_all(
            cfg,
            sock_mgrs,
            flow_states,
            flow_claims,
            allow_upstream,
            allow_listen_rebind,
            "Periodic re-resolve",
            None,
            None,
        ) {
            if error.is_fatal_topology_invariant() {
                crate::log_error!("Periodic re-resolve fatal topology invariant: {}", error);
                exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                return;
            }
            crate::log_warn!("Periodic re-resolve failed: {}", error);
        }
    }
}

fn run_debug_reresolve(
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
    resolver: &mut DebugAddressResolver,
    permissions: ReresolvePermissions,
    exit_code_set: &ShutdownController,
) {
    let decision = resolver.read(permissions.listener, permissions.upstream);
    match decision {
        DebugResolverDecision::AlreadyApplied { revision } => {
            log_resolver_evidence(audited_json!({
                "revision": revision,
                "parse_result": "valid",
                "application_result": "already-applied",
            }));
        }
        DebugResolverDecision::Rejected { revision, reason } => {
            log_resolver_evidence(audited_json!({
                "revision": revision,
                "parse_result": "rejected",
                "application_result": "not-applied",
                "reason": reason,
            }));
        }
        DebugResolverDecision::Apply(update) => {
            let summaries = match reresolve_all(
                cfg,
                sock_mgrs,
                flow_states,
                flow_claims,
                permissions.upstream,
                permissions.listener,
                "Debug revisioned re-resolve",
                update.listen_addr,
                update.upstream_addr,
            ) {
                Ok(summaries) => summaries,
                Err(error) => {
                    let fatal = error.is_fatal_topology_invariant();
                    log_resolver_evidence(audited_json!({
                        "revision": update.revision,
                        "listen_addr": update.listen_addr.map(|addr| addr.to_string()),
                        "upstream_addr": update.upstream_addr.map(|addr| addr.to_string()),
                        "parse_result": "valid",
                        "application_result": "failed",
                        "reason": error.to_string(),
                    }));
                    if fatal {
                        exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                    }
                    return;
                }
            };
            for summary in &summaries {
                log_applied_summary(update, summary);
            }
            resolver.mark_applied(update.revision);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reresolve_all(
    cfg: &RuntimeConfig,
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    flow_claims: Option<&FlowClaimTable>,
    allow_upstream: bool,
    allow_listen_rebind: bool,
    context: &str,
    listen_addr: Option<std::net::SocketAddr>,
    upstream_addr: Option<std::net::SocketAddr>,
) -> Result<Vec<ReresolveSummary>, ManagerError> {
    let transaction_deadline =
        Instant::now() + crate::net::sock_mgr::transaction_lock::MANAGER_RESERVATION_TIMEOUT;
    let mut unique_flow_states = Vec::<&FlowRuntimeState>::new();
    for state in flow_states {
        if !unique_flow_states
            .iter()
            .any(|existing| std::ptr::eq(*existing, state.as_ref()))
        {
            unique_flow_states.push(state.as_ref());
        }
    }
    let mut flow_transactions = unique_flow_states
        .iter()
        .map(|state| {
            state
                .try_reserve_client_flow_until(transaction_deadline)
                .map_err(|cause| ManagerError::Reservation {
                    operation: "reserve flow for grouped re-resolution",
                    cause,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let visibility = flow_transactions
        .iter_mut()
        .map(|transaction| {
            transaction
                .reserve_topology_until(transaction_deadline)
                .map_err(|error| ManagerError::FlowTopology {
                    operation: "reserve re-resolution flow visibility",
                    cause: error,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let managers = sock_mgrs.iter().map(Arc::as_ref).collect::<Vec<_>>();
    let transition = SocketManager::begin_reresolve_group_with_addresses(
        &managers,
        allow_upstream,
        allow_listen_rebind,
        listen_addr,
        upstream_addr,
    )?;
    let prepared_visibility = visibility
        .into_iter()
        .map(|reservation| {
            reservation
                .socket_transitions_applied()
                .and_then(
                    crate::flow_state::ClientFlowSocketTransitionsApplied::manager_state_prepared,
                )
                .map_err(|error| ManagerError::FlowTopology {
                    operation: "stage re-resolution flow visibility",
                    cause: error,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut final_visibility = Vec::with_capacity(prepared_visibility.len());
    for (worker_pair, reservation) in prepared_visibility.into_iter().enumerate() {
        let summary = if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
            transition
                .summaries()
                .iter()
                .find(|summary| summary.listener_replaced())
        } else {
            transition.summaries().iter().find(|summary| {
                summary.listener_replaced()
                    && usize::try_from(summary.socket_slot) == Ok(worker_pair)
            })
        };
        let Some(_summary) = summary else {
            final_visibility.push(ReresolveVisibility::Manager(reservation));
            continue;
        };
        let (committed, (reset, claim_binding)) = reservation
            .commit_session_with(|flow| {
                let claim_binding = flow.flow_claim_binding()?;
                Ok((flow.reset()?, claim_binding))
            })
            .map_err(|error| ManagerError::FlowTopology {
                operation: "commit re-resolution session visibility",
                cause: match error {
                    crate::flow_state::FlowAuthorityError::Topology(cause) => cause,
                    crate::flow_state::FlowAuthorityError::Reservation(_) => {
                        crate::flow_state::FlowTopologyError::OwnershipLost
                    }
                },
            })?;
        if let Some(trace) = reset.and_then(|payload| payload.buffered_trace) {
            log_packet_disposition(cfg, trace, PacketDisposition::HandshakeResetDrop);
        }
        if let (Some(claims), (Some(flow), Some(generation))) = (flow_claims, claim_binding) {
            claims
                .take_committed(flow, worker_pair, generation)
                .map_err(|()| ManagerError::Poisoned {
                    authority: "re-resolution flow claim generation",
                })?
                .release();
        }
        final_visibility.push(ReresolveVisibility::Committed(committed));
    }
    let summaries = ReresolvePublicationCore::new(
        transition,
        ReresolveFlowVisibility {
            visibility: final_visibility,
        },
    )
    .publish()
    .map_err(|error| match error {
        ReresolvePublicationError::Manager(error) => error,
        ReresolvePublicationError::FlowAfterManager(cause) => {
            crate::runtime_support::publish_process_fatal(format_args!(
                "re-resolution flow visibility failed after manager publication: {cause}"
            ));
            ManagerError::FlowTopology {
                operation: "publish re-resolution flow visibility",
                cause,
            }
        }
    })?;
    drop(flow_transactions);
    for summary in &summaries {
        if let Some(manager) = sock_mgrs
            .iter()
            .find(|manager| manager.socket_slot() == summary.socket_slot)
        {
            manager.log_reresolve_summary(context, summary);
        }
    }
    Ok(summaries)
}

fn log_applied_summary(update: DebugAddressRevision, summary: &ReresolveSummary) {
    log_resolver_evidence(audited_json!({
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
        crate::diagnostics::stamp(audited_json!({
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
    exit_code_set: &ShutdownController,
    flow_claims: Option<&FlowClaimTable>,
) {
    let period = Duration::from_secs(1);
    let mut flow_snapshot_caches = flow_states
        .iter()
        .map(|_| crate::flow_state::FlowSnapshotCache::new())
        .collect::<Vec<_>>();
    loop {
        exit_code_set.wait_for_change(Instant::now() + period);
        if exit_code_set.is_requested() {
            return;
        }
        let now = Instant::now();
        let idle_timeout = Duration::from_secs(cfg.timeout_secs);
        for (idx, flow_state) in flow_states.iter().enumerate() {
            let Some(snapshot_cache) = flow_snapshot_caches.get_mut(idx) else {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "watchdog flow snapshot cache index {idx} is missing"
                ));
                return;
            };
            let mut flow_snapshot = match watchdog_flow_snapshot(flow_state, snapshot_cache) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    if error.class().is_fatal() {
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "watchdog flow snapshot failed: {error}"
                        ));
                        return;
                    }
                    continue;
                }
            };
            if flow_snapshot
                .pending_icmp_client_deadline
                .is_some_and(|deadline| now >= deadline)
            {
                let transition = match flow_state.try_reserve_client_flow() {
                    Ok(transition) => transition,
                    Err(error) => {
                        if error.class().is_fatal() {
                            crate::runtime_support::publish_process_fatal(format_args!(
                                "watchdog pending-flow expiry reservation failed: {error}"
                            ));
                            return;
                        }
                        continue;
                    }
                };
                let expired =
                    match flow_state.expire_pending_icmp_client_lock_under(&transition, now) {
                        Ok(expired) => expired,
                        Err(error) => {
                            if error.class().is_fatal() {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "watchdog pending-flow expiry failed: {error}"
                                ));
                                return;
                            }
                            continue;
                        }
                    };
                if let Err(error) = transition.commit() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "watchdog pending-flow expiry completion failed: {error}"
                    ));
                    return;
                }
                if let Some(expired) = expired {
                    log_warn!(
                        "ICMP client negotiation timeout reached ({}s): clearing pending flow {:?} on worker pair {}",
                        cfg.icmp_handshake_timeout_secs,
                        expired.candidate.flow_key,
                        idx
                    );
                    log_packet_disposition(
                        cfg,
                        expired.trace,
                        PacketDisposition::HandshakeTimeoutDrop,
                    );
                }
                flow_snapshot = match watchdog_flow_snapshot(flow_state, snapshot_cache) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        if error.class().is_fatal() {
                            crate::runtime_support::publish_process_fatal(format_args!(
                                "watchdog post-expiry flow snapshot failed: {error}"
                            ));
                            return;
                        }
                        continue;
                    }
                };
            }
            if !flow_snapshot.locked {
                if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                    break;
                }
                continue;
            }
            let handshake_may_time_out = handshake_timeout_reached(&flow_snapshot, now);
            match cfg.on_timeout {
                TimeoutAction::Drop => {
                    let locked_flow = flow_snapshot.client_flow;
                    let claim_generation = flow_snapshot.flow_claim_generation;
                    let managers_to_clear: Vec<_> =
                        if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                            sock_mgrs.iter().map(Arc::as_ref).collect()
                        } else {
                            vec![sock_mgrs[idx].as_ref()]
                        };
                    let mut flow_reservation = match reserve_due_timeout(
                        flow_state,
                        t_start,
                        now,
                        idle_timeout,
                        handshake_may_time_out,
                    ) {
                        Ok(Some(reservation)) => reservation,
                        Ok(None) => continue,
                        Err(error) => {
                            log_error!("watchdog timeout transition failed: {error}");
                            exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                            return;
                        }
                    };
                    let expired_handshake =
                        match flow_state.expire_reply_id_handshake_under(&flow_reservation, now) {
                            Ok(expired) => expired,
                            Err(error) => {
                                drop(flow_reservation);
                                log_error!("watchdog handshake expiry failed: {error}");
                                exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                                return;
                            }
                        };
                    let handshake_timed_out = expired_handshake.is_some();
                    let cleared = match SocketManager::clear_client_flow_group(
                        &managers_to_clear,
                        &mut flow_reservation,
                    ) {
                        Ok(cleared) => cleared,
                        Err(e) => {
                            drop(flow_reservation);
                            log_error!("watchdog client-lock cleanup failed: {}", e);
                            exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                            return;
                        }
                    };
                    if let Err(error) = flow_reservation.commit() {
                        log_error!("watchdog client-lock completion failed: {error}");
                        exit_code_set.store(FATAL_EXIT, AtomOrdering::Release);
                        return;
                    }
                    for update in &cleared.updates {
                        if update
                            .handles
                            .listener
                            .policy
                            .listener_lifecycle
                            .is_some_and(
                                pkthere_socket_policy::ListenerLockLifecycle::replaces_on_clear,
                            )
                            && let Some(manager) = managers_to_clear.iter().find(|manager| {
                                manager.socket_slot()
                                    == update.handles.listener.evidence_key.socket_slot
                            })
                        {
                            manager.log_listener_replacement_evidence(
                                &update.handles.listener,
                                "replace-listener-on-clear",
                            );
                        }
                    }
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
                    if let Some(expired) = expired_handshake {
                        log_handshake_timeout(cfg, idx, expired);
                        if let Some(trace) = expired.buffered_trace {
                            log_packet_disposition(
                                cfg,
                                trace,
                                PacketDisposition::HandshakeTimeoutDrop,
                            );
                        }
                    }
                    for update in &cleared.updates {
                        let event = audited_json!({
                            "event": "flow-clear-committed",
                            "worker_pair": idx,
                            "socket_slot": update.handles.listener.evidence_key.socket_slot,
                        });
                        log_debug!(
                            cfg.debug_logs.handles,
                            "runtime-trace {}",
                            crate::diagnostics::stamp(event)
                        );
                    }
                    let reset_payload = cleared.dropped_handshake;
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
                    if let (Some(flow_claims), Some(flow), Some(generation)) =
                        (flow_claims, locked_flow, claim_generation)
                    {
                        match flow_claims.take_committed(flow, idx, generation) {
                            Ok(claim) => claim.release(),
                            Err(()) => {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "watchdog lost generation-bound flow claim ownership"
                                ));
                                return;
                            }
                        }
                    }
                }
                _ => {
                    let flow_reservation = match reserve_due_timeout(
                        flow_state,
                        t_start,
                        now,
                        idle_timeout,
                        handshake_may_time_out,
                    ) {
                        Ok(Some(reservation)) => reservation,
                        Ok(None) => continue,
                        Err(error) => {
                            if error.class().is_fatal() {
                                crate::runtime_support::publish_process_fatal(format_args!(
                                    "watchdog exit-policy timeout transition failed: {error}"
                                ));
                                return;
                            }
                            continue;
                        }
                    };
                    if let Err(error) = flow_reservation.commit() {
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "watchdog exit-policy reservation completion failed: {error}"
                        ));
                        return;
                    }
                    log_warn!(
                        "Idle timeout reached ({}s): exiting cleanly",
                        cfg.timeout_secs
                    );
                    exit_code_set.store(CLEAN_EXIT, AtomOrdering::Release);
                    return;
                }
            }
            if cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
                break;
            }
        }
    }
}

struct RuntimeIdleTransition<'state> {
    flow_state: &'state FlowRuntimeState,
    t_start: Instant,
    now: Instant,
    idle_timeout: Duration,
    handshake_may_time_out: bool,
}

impl<'state> crate::atomic_core::IdleTransitionBackend for RuntimeIdleTransition<'state> {
    type Reservation = ClientFlowReservation<'state>;
    type Error = crate::flow_state::FlowAuthorityError;

    fn tentative_timeout(&mut self) -> bool {
        self.handshake_may_time_out
            || self
                .flow_state
                .idle_timeout_reached(self.t_start, self.now, self.idle_timeout)
    }

    fn reserve_and_drain(&mut self) -> Result<Self::Reservation, Self::Error> {
        self.flow_state
            .try_reserve_client_flow()
            .map_err(crate::flow_state::FlowAuthorityError::from)
    }

    fn revalidate_after_drain(
        &mut self,
        reservation: &Self::Reservation,
    ) -> Result<bool, Self::Error> {
        self.flow_state
            .timeout_due_under(reservation, self.t_start, self.now, self.idle_timeout)
    }
}

fn reserve_due_timeout(
    flow_state: &FlowRuntimeState,
    t_start: Instant,
    now: Instant,
    idle_timeout: Duration,
    handshake_may_time_out: bool,
) -> Result<Option<ClientFlowReservation<'_>>, crate::flow_state::FlowAuthorityError> {
    let transition = RuntimeIdleTransition {
        flow_state,
        t_start,
        now,
        idle_timeout,
        handshake_may_time_out,
    };
    crate::atomic_core::attempt_idle_transition(transition).map(|attempt| match attempt {
        crate::atomic_core::IdleTransitionAttempt::Authorized(reservation) => Some(reservation),
        crate::atomic_core::IdleTransitionAttempt::NotDue
        | crate::atomic_core::IdleTransitionAttempt::Cancelled => None,
    })
}

fn watchdog_flow_snapshot(
    flow_state: &FlowRuntimeState,
    cache: &mut crate::flow_state::FlowSnapshotCache,
) -> Result<crate::flow_state::FlowAdmissionSnapshot, crate::flow_state::FlowTopologyError> {
    let read = flow_state.try_watchdog_topology_read()?;
    flow_state
        .admission_snapshot_with_read(&read, cache, Instant::now())
        .copied()
}

fn handshake_timeout_reached(
    snapshot: &crate::flow_state::FlowAdmissionSnapshot,
    now: Instant,
) -> bool {
    snapshot
        .upstream_handshake_deadline
        .is_some_and(|deadline| now >= deadline)
}

#[cfg(all(test, not(miri)))]
mod tests;
