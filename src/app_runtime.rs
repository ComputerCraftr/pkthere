#[cfg(unix)]
use super::drop_privileges;
use super::{
    ClientWorkerContext, FlowClaimTable, FlowRuntimeState, GlobalSyncPacer, RuntimeConfig,
    SharedIcmpSequenceState, SharedUpstreamIdentity, SocketManager, SocketManagerInit, Stats,
    SupportedProtocol, UpstreamWorkerContext, WorkerFlowMode, cli, endpoint,
    listener_worker_socket_policy, make_socket, net, parse_args, print_startup, process,
    realize_config, run_client_to_upstream_thread, run_reresolve_thread,
    run_upstream_to_client_thread, run_watchdog_thread, upstream_socket_creation_policy,
    upstream_worker_socket_policy,
};
use crate::runtime_support::{
    RUNTIME_SHUTDOWN_DEADLINE, RuntimeFailure, ShutdownController, ThreadRole, ThreadSupervisor,
    immediate_exit, register_shutdown_controller,
};
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, UpstreamWorkerSocketPolicy};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_AUTHORITY_LANE_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct AppRuntime {
    cfg: Arc<RuntimeConfig>,
    sock_mgrs: Vec<Arc<SocketManager>>,
    stats: Arc<Stats>,
    stats_aggregator: Option<crate::stats::StatsAggregatorBootstrap>,
    shutdown: Arc<ShutdownController>,
    supervisor_events: Option<crate::runtime_support::SupervisorEventReceiver>,
    flow_states: Vec<Arc<FlowRuntimeState>>,
    flow_claims: Option<Arc<FlowClaimTable>>,
    global_sync_pacer: Option<Arc<GlobalSyncPacer>>,
}

struct WorkerSocketPolicies {
    listener: ListenerWorkerSocketPolicy,
    upstream: UpstreamWorkerSocketPolicy,
    shared_upstream_identity: Option<
        Arc<
            crate::authority::AuthorityOnceLock<
                crate::authority::tags::IdentityAllocation,
                SharedUpstreamIdentity,
            >,
        >,
    >,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerPairThreadIds {
    client: usize,
    upstream: usize,
}

impl WorkerPairThreadIds {
    fn checked(pair: usize) -> io::Result<Self> {
        let client = pair
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("client worker id exceeds usize"))?;
        let upstream = client
            .checked_add(1)
            .ok_or_else(|| io::Error::other("upstream worker id exceeds usize"))?;
        Ok(Self { client, upstream })
    }
}

pub(super) fn initialize() -> io::Result<AppRuntime> {
    let requested = parse_args();
    let worker_count = requested.workers.max(1);
    validate_authority_lane_capacity(worker_count, requested.worker_flow_mode)?;
    let worker_thread_count = worker_count
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("worker thread count exceeds usize"))?;
    if worker_thread_count > cli::MAX_FORWARDING_THREADS {
        return Err(io::Error::other(format!(
            "worker thread count {worker_thread_count} exceeds {}",
            cli::MAX_FORWARDING_THREADS
        )));
    }
    let policies = resolve_worker_socket_policies(&requested, worker_count)?;
    let (cfg, sock_mgrs) = create_socket_managers(requested, worker_count, &policies)?;
    #[cfg(unix)]
    drop_privileges(&cfg)?;

    if cfg.debug_logs.packet_dump {
        crate::worker_support::configure_packet_diagnostics(worker_thread_count)?;
    }
    let stats_enabled = cfg.debug_behavior.fast_stats || cfg.stats_interval_mins != 0;
    let (stats, stats_aggregator) = Stats::bootstrap(worker_thread_count, stats_enabled)?;
    let stats = Arc::new(stats);
    let supervised_slots = worker_thread_count
        .checked_add(4)
        .ok_or_else(|| io::Error::other("supervised thread count exceeds usize"))?;
    let (shutdown, supervisor_events) = ShutdownController::bootstrap(supervised_slots)?;
    register_shutdown_controller(&shutdown)?;
    let flow_states = create_flow_states(&cfg, worker_count);
    let flow_claims = matches!(cfg.worker_flow_mode, WorkerFlowMode::SingleFlow)
        .then(|| Arc::new(FlowClaimTable::new()));
    let global_sync_pacer =
        (cfg.icmp_sync_pps > 0 && cfg.upstream_proto == SupportedProtocol::ICMP).then(|| {
            Arc::new(GlobalSyncPacer::new(Duration::from_nanos(
                (1_000_000_000u64 / u64::from(cfg.icmp_sync_pps)).max(1),
            )))
        });
    install_shutdown_handler(&shutdown)?;
    Ok(AppRuntime {
        cfg,
        sock_mgrs,
        stats,
        stats_aggregator,
        shutdown,
        supervisor_events: Some(supervisor_events),
        flow_states,
        flow_claims,
        global_sync_pacer,
    })
}

fn validate_authority_lane_capacity(
    worker_count: usize,
    flow_mode: WorkerFlowMode,
) -> io::Result<()> {
    if !(1..=cli::MAX_WORKER_PAIRS).contains(&worker_count) {
        return Err(io::Error::other(format!(
            "worker pair count must be between 1 and {}",
            cli::MAX_WORKER_PAIRS
        )));
    }
    let worker_lanes = worker_count
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("worker lane count exceeds usize"))?;
    let descriptor_cache_lanes =
        crate::worker_support::descriptor_cache_lane_count(worker_count)
            .ok_or_else(|| io::Error::other("descriptor-cache lane count exceeds usize"))?;
    let socket_gates = worker_count
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("socket gate count exceeds usize"))?;
    let socket_lane_count = socket_gates
        .checked_mul(
            descriptor_cache_lanes
                .checked_add(1)
                .ok_or_else(|| io::Error::other("socket control lane count exceeds usize"))?,
        )
        .ok_or_else(|| io::Error::other("socket authority lane count exceeds usize"))?;
    let flow_lane_count = match flow_mode {
        WorkerFlowMode::SharedFlow => worker_lanes
            .checked_add(2)
            .ok_or_else(|| io::Error::other("shared-flow lane count exceeds usize"))?,
        WorkerFlowMode::SingleFlow => worker_count
            .checked_mul(4)
            .ok_or_else(|| io::Error::other("single-flow lane count exceeds usize"))?,
    };
    let socket_bytes = socket_lane_count
        .checked_mul(crate::net::managed_socket::SOCKET_IO_LANE_BYTES)
        .ok_or_else(|| io::Error::other("socket authority lane memory exceeds usize"))?;
    // Each logical flow lane owns one topology slot, one activity slot, and
    // one control-observation slot. Use the concrete aligned type sizes so
    // additions to any lane cannot silently bypass the 64 MiB startup gate.
    let flow_lane_bytes = crate::flow_state::FLOW_READER_LANE_BYTES
        .checked_add(crate::flow_state::ACTIVITY_LANE_BYTES)
        .and_then(|bytes| bytes.checked_add(crate::flow_state::CONTROL_OBSERVATION_LANE_BYTES))
        .ok_or_else(|| io::Error::other("flow authority lane width exceeds usize"))?;
    let flow_bytes = flow_lane_count
        .checked_mul(flow_lane_bytes)
        .ok_or_else(|| io::Error::other("flow authority lane memory exceeds usize"))?;
    let bytes = socket_bytes
        .checked_add(flow_bytes)
        .ok_or_else(|| io::Error::other("authority lane memory exceeds usize"))?;
    if bytes > MAX_AUTHORITY_LANE_BYTES {
        return Err(io::Error::other(format!(
            "authority lane memory {bytes} exceeds {MAX_AUTHORITY_LANE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn resolve_worker_socket_policies(
    requested: &cli::RequestedConfig,
    worker_count: usize,
) -> io::Result<WorkerSocketPolicies> {
    let single_flow = requested.worker_flow_mode == WorkerFlowMode::SingleFlow;
    let listener = listener_worker_socket_policy(worker_count, single_flow);
    let force_raw_wildcard_upstream = requested.upstream_proto == SupportedProtocol::ICMP
        && requested.debug_behavior.force_raw_icmp_wildcard_upstream
        && requested.upstream_request.id() == 0
        && requested.upstream_source_id_request.requested_socket_id() == 0;
    let upstream_socket_type = upstream_socket_creation_policy(
        requested.upstream_proto,
        requested.upstream_request.domain(),
        requested.upstream_request.id(),
        requested.upstream_source_id_request.requested_socket_id(),
        force_raw_wildcard_upstream,
    )
    .primary
    .socket_type;
    let upstream = upstream_worker_socket_policy(
        worker_count,
        single_flow,
        requested.upstream_proto,
        upstream_socket_type,
        requested.upstream_request.domain(),
    );
    if !listener.supports_requested_distribution() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "single-flow with {worker_count} workers requires kernel reuse-port flow affinity on this platform"
            ),
        ));
    }
    if !upstream.supports_requested_distribution() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "shared-flow ICMP with {worker_count} workers requires a platform policy with shared upstream transport identity"
            ),
        ));
    }
    let shared_upstream_identity = upstream
        .shares_icmp_identity()
        .then(|| Arc::new(crate::authority::AuthorityOnceLock::new()));
    Ok(WorkerSocketPolicies {
        listener,
        upstream,
        shared_upstream_identity,
    })
}

fn create_socket_managers(
    requested: cli::RequestedConfig,
    worker_count: usize,
    policies: &WorkerSocketPolicies,
) -> io::Result<(Arc<RuntimeConfig>, Vec<Arc<SocketManager>>)> {
    let worker_io_lanes = crate::worker_support::descriptor_cache_lane_count(worker_count)
        .ok_or_else(|| io::Error::other("worker I/O lane count exceeds usize"))?;
    let (client_sock, actual_listen, kernel_addr, socket_type, capability) = make_socket(
        requested.listen_request.to_socket_addr(),
        requested.listen_proto,
        policies.listener,
        requested.on_timeout,
        requested.debug_behavior.client_unconnected,
        requested.debug_behavior.icmp_kernel_echo_self_handshake,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("listener socket setup failed: {error}"),
        )
    })?;
    validate_listener_ids(&requested, actual_listen, socket_type, capability)?;
    let cfg = Arc::new(realize_config(requested, actual_listen)?);
    let mut managers = Vec::with_capacity(worker_count);
    managers.push(create_manager(
        ManagerSocketSetup {
            socket_slot: 0,
            worker_io_lanes,
            client_sock,
            listen_local_kernel_addr: kernel_addr,
            listen_sock_type: socket_type,
            listen_policy: capability,
        },
        &cfg,
        policies,
    )?);
    for worker_slot in 1..worker_count {
        let (socket, _, kernel_addr, socket_type, capability) = make_socket(
            cfg.listen.to_socket_addr(),
            cfg.listen_proto,
            policies.listener,
            cfg.on_timeout,
            cfg.debug_behavior.client_unconnected,
            cfg.debug_behavior.icmp_kernel_echo_self_handshake,
        )?;
        managers.push(create_manager(
            ManagerSocketSetup {
                socket_slot: u32::try_from(worker_slot)
                    .map_err(|_| io::Error::other("worker socket slot exceeds u32"))?,
                worker_io_lanes,
                client_sock: socket,
                listen_local_kernel_addr: kernel_addr,
                listen_sock_type: socket_type,
                listen_policy: capability,
            },
            &cfg,
            policies,
        )?);
    }
    Ok((cfg, managers))
}

fn validate_listener_ids(
    requested: &cli::RequestedConfig,
    actual_listen: endpoint::LogicalEndpoint,
    socket_type: socket2::Type,
    capability: pkthere_socket_policy::ResolvedSocketPolicy,
) -> io::Result<()> {
    if requested.listen_proto == SupportedProtocol::ICMP
        && let cli::IcmpReplyIdRequest::Fixed(source_id) = requested.listener_source_id_request
        && source_id != actual_listen.id()
        && !capability
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    {
        return Err(io::Error::other(format!(
            "ICMP listener requested independent listen/source ids {} -> {} but socket type {:?} cannot preserve disjoint ICMP ids; use a raw-capable deployment",
            actual_listen.id(),
            source_id,
            socket_type
        )));
    }
    Ok(())
}

struct ManagerSocketSetup {
    socket_slot: u32,
    worker_io_lanes: usize,
    client_sock: net::managed_socket::ManagedSocket,
    listen_local_kernel_addr: std::net::SocketAddr,
    listen_sock_type: socket2::Type,
    listen_policy: pkthere_socket_policy::ResolvedSocketPolicy,
}

fn create_manager(
    setup: ManagerSocketSetup,
    cfg: &RuntimeConfig,
    policies: &WorkerSocketPolicies,
) -> io::Result<Arc<SocketManager>> {
    let ManagerSocketSetup {
        socket_slot,
        worker_io_lanes,
        client_sock,
        listen_local_kernel_addr,
        listen_sock_type,
        listen_policy,
    } = setup;
    SocketManager::new(SocketManagerInit {
        socket_slot,
        worker_io_lanes,
        client_sock,
        listen_local_filter: cfg.listen,
        listen_local_kernel_addr,
        listen_sock_type,
        listen_target: cfg.listen_str.clone(),
        listen_proto: cfg.listen_proto,
        listen_policy,
        listen_worker_socket_policy: policies.listener,
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
        upstream_worker_socket_policy: policies.upstream,
        shared_upstream_identity: policies.shared_upstream_identity.clone(),
        force_raw_icmp_wildcard_upstream: cfg.debug_behavior.force_raw_icmp_wildcard_upstream,
        timeout_act: cfg.on_timeout,
        debug_handles: cfg.debug_logs.handles,
    })
    .map(Arc::new)
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("upstream socket setup failed: {error}"),
        )
    })
}

fn create_flow_states(cfg: &RuntimeConfig, worker_count: usize) -> Vec<Arc<FlowRuntimeState>> {
    match cfg.worker_flow_mode {
        WorkerFlowMode::SharedFlow => {
            let reader_lanes = worker_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(2))
                .unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "shared-flow reader lane capacity exceeds usize"
                    ))
                });
            let shared = Arc::new(FlowRuntimeState::with_session_pool_size_and_reader_lanes(
                cfg.icmp_session_pool_size,
                reader_lanes,
            ));
            (0..worker_count).map(|_| Arc::clone(&shared)).collect()
        }
        WorkerFlowMode::SingleFlow => (0..worker_count)
            .map(|_| {
                Arc::new(FlowRuntimeState::with_session_pool_size_and_reader_lanes(
                    cfg.icmp_session_pool_size,
                    4,
                ))
            })
            .collect(),
    }
}

fn install_shutdown_handler(shutdown: &Arc<ShutdownController>) -> io::Result<()> {
    let shutdown = Arc::clone(shutdown);
    ctrlc::set_handler(move || shutdown.request_graceful(130))
        .map_err(|error| io::Error::other(format!("ctrlc::set_handler failed: {error}")))
}

pub(super) struct RuntimeThreads {
    sequence_states: Vec<Arc<SharedIcmpSequenceState>>,
    supervisor: ThreadSupervisor,
}

pub(super) fn spawn_threads(
    runtime: &mut AppRuntime,
    t_start: Instant,
) -> io::Result<RuntimeThreads> {
    let events = runtime
        .supervisor_events
        .take()
        .ok_or_else(|| io::Error::other("supervisor event receiver was already consumed"))?;
    let mut supervisor = ThreadSupervisor::new(Arc::clone(&runtime.shutdown), events);
    let shared_client = (runtime.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow)
        .then(|| Arc::new(SharedIcmpSequenceState::new()));
    let shared_upstream = (runtime.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow)
        .then(|| Arc::new(SharedIcmpSequenceState::new()));
    let mut sequence_states = Vec::with_capacity(runtime.sock_mgrs.len() * 2);
    let startup = (|| -> io::Result<()> {
        for (idx, manager) in runtime.sock_mgrs.iter().enumerate() {
            let client_state = shared_client
                .clone()
                .unwrap_or_else(|| Arc::new(SharedIcmpSequenceState::new()));
            let upstream_state = shared_upstream
                .clone()
                .unwrap_or_else(|| Arc::new(SharedIcmpSequenceState::new()));
            sequence_states.push(Arc::clone(&client_state));
            sequence_states.push(Arc::clone(&upstream_state));
            spawn_client_worker(
                &mut supervisor,
                runtime,
                t_start,
                idx,
                manager,
                &client_state,
                &upstream_state,
            )?;
            spawn_upstream_worker(
                &mut supervisor,
                runtime,
                t_start,
                idx,
                manager,
                &client_state,
                &upstream_state,
            )?;
        }
        spawn_background_threads(&mut supervisor, runtime, t_start)
    })();
    if let Err(error) = startup {
        runtime
            .shutdown
            .request_current_fatal(RuntimeFailure::fatal(format_args!(
                "thread startup failed after partial initialization: {error}"
            )));
        if !supervisor.finish(Instant::now() + RUNTIME_SHUTDOWN_DEADLINE) {
            eprintln!("partial startup shutdown exceeded the runtime deadline");
        }
        return Err(error);
    }
    print_startup(&runtime.cfg, &runtime.sock_mgrs[0])?;
    Ok(RuntimeThreads {
        sequence_states,
        supervisor,
    })
}

fn spawn_client_worker(
    supervisor: &mut ThreadSupervisor,
    runtime: &AppRuntime,
    t_start: Instant,
    idx: usize,
    manager: &Arc<SocketManager>,
    client_state: &Arc<SharedIcmpSequenceState>,
    upstream_state: &Arc<SharedIcmpSequenceState>,
) -> io::Result<()> {
    let worker_id = WorkerPairThreadIds::checked(idx)?.client;
    let recorder = runtime
        .stats
        .try_recorder(worker_id)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let cfg = Arc::clone(&runtime.cfg);
    let manager = Arc::clone(manager);
    let managers = runtime.sock_mgrs.clone();
    let flow_state = runtime
        .flow_states
        .get(idx)
        .map(Arc::clone)
        .ok_or_else(|| io::Error::other("client worker has no matching flow state"))?;
    let client_state = Arc::clone(client_state);
    let upstream_state = Arc::clone(upstream_state);
    let sync_pacer = runtime.global_sync_pacer.clone();
    let flow_claims = runtime.flow_claims.clone();
    let shutdown = Arc::clone(&runtime.shutdown);
    let flow_lane =
        crate::flow_state::FlowReaderLane::for_worker(worker_id, runtime.cfg.worker_flow_mode);
    supervisor.spawn_forwarder_with_stats(
        ThreadRole::ClientWorker,
        format!("client-worker-{idx}"),
        crate::authority::WorkerAuditIdentity {
            worker: idx,
            direction: crate::authority::AuditDirection::ClientToUpstream,
        },
        recorder,
        move |recorder| {
            run_client_to_upstream_thread(ClientWorkerContext {
                t_start,
                cfg: &cfg,
                sock_mgr: &manager,
                all_sock_mgrs: &managers,
                worker_id,
                flow_lane,
                flow_state: &flow_state,
                stats: recorder,
                client_side_state: &client_state,
                upstream_side_state: &upstream_state,
                sync_pacer: sync_pacer.as_deref(),
                flow_claims: flow_claims.as_deref(),
                worker_pair_id: idx,
                exit_code_set: &shutdown,
            });
            Ok(())
        },
    )
}

fn spawn_upstream_worker(
    supervisor: &mut ThreadSupervisor,
    runtime: &AppRuntime,
    t_start: Instant,
    idx: usize,
    manager: &Arc<SocketManager>,
    client_state: &Arc<SharedIcmpSequenceState>,
    upstream_state: &Arc<SharedIcmpSequenceState>,
) -> io::Result<()> {
    let worker_id = WorkerPairThreadIds::checked(idx)?.upstream;
    let recorder = runtime
        .stats
        .try_recorder(worker_id)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let cfg = Arc::clone(&runtime.cfg);
    let manager = Arc::clone(manager);
    let managers = runtime.sock_mgrs.clone();
    let flow_state = runtime
        .flow_states
        .get(idx)
        .map(Arc::clone)
        .ok_or_else(|| io::Error::other("upstream worker has no matching flow state"))?;
    let client_state = Arc::clone(client_state);
    let upstream_state = Arc::clone(upstream_state);
    let shutdown = Arc::clone(&runtime.shutdown);
    let flow_lane =
        crate::flow_state::FlowReaderLane::for_worker(worker_id, runtime.cfg.worker_flow_mode);
    supervisor.spawn_forwarder_with_stats(
        ThreadRole::UpstreamWorker,
        format!("upstream-worker-{idx}"),
        crate::authority::WorkerAuditIdentity {
            worker: idx,
            direction: crate::authority::AuditDirection::UpstreamToClient,
        },
        recorder,
        move |recorder| {
            run_upstream_to_client_thread(UpstreamWorkerContext {
                t_start,
                cfg: &cfg,
                sock_mgr: &manager,
                all_sock_mgrs: &managers,
                worker_id,
                flow_lane,
                flow_state: &flow_state,
                stats: recorder,
                client_side_state: &client_state,
                upstream_side_state: &upstream_state,
                exit_code_set: &shutdown,
            });
            Ok(())
        },
    )
}

fn spawn_background_threads(
    supervisor: &mut ThreadSupervisor,
    runtime: &AppRuntime,
    t_start: Instant,
) -> io::Result<()> {
    let cfg = Arc::clone(&runtime.cfg);
    let managers = runtime.sock_mgrs.clone();
    let states = runtime.flow_states.clone();
    let shutdown = Arc::clone(&runtime.shutdown);
    let claims = runtime.flow_claims.clone();
    supervisor.spawn(ThreadRole::Watchdog, "watchdog".to_string(), move || {
        run_watchdog_thread(
            t_start,
            &cfg,
            &managers,
            &states,
            &shutdown,
            claims.as_deref(),
        );
        Ok(())
    })?;
    if runtime.cfg.reresolve_secs != 0
        && (runtime.cfg.reresolve_mode.allow_upstream()
            || runtime.cfg.reresolve_mode.allow_listen())
    {
        let cfg = Arc::clone(&runtime.cfg);
        let managers = runtime.sock_mgrs.clone();
        let states = runtime.flow_states.clone();
        let claims = runtime.flow_claims.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        supervisor.spawn(
            ThreadRole::Reresolver,
            "reresolver".to_string(),
            move || {
                run_reresolve_thread(&cfg, &managers, &states, claims.as_deref(), &shutdown);
                Ok(())
            },
        )?;
    }
    Ok(())
}

pub(super) fn wait(mut runtime: AppRuntime, mut threads: RuntimeThreads, t_start: Instant) -> ! {
    let stats_interval_secs = if runtime.cfg.debug_behavior.fast_stats {
        1
    } else {
        u64::from(runtime.cfg.stats_interval_mins).saturating_mul(60)
    };
    if stats_interval_secs != 0 {
        if let Some(stats_aggregator) = runtime.stats_aggregator.take() {
            let stats = Arc::clone(&runtime.stats);
            let sock_mgrs = runtime.sock_mgrs.clone();
            let flow_states = runtime.flow_states.clone();
            let sequence_states = std::mem::take(&mut threads.sequence_states);
            let shutdown = Arc::clone(&runtime.shutdown);
            if let Err(error) = threads.supervisor.spawn(
                ThreadRole::StatsPrinter,
                "stats-printer".to_string(),
                move || {
                    stats.run_stats_printer(
                        stats_aggregator,
                        crate::stats::StatsPrinterInputs {
                            sock_mgrs,
                            flow_states,
                            sequence_states,
                            start: t_start,
                            every_secs: stats_interval_secs,
                            shutdown,
                        },
                    )
                },
            ) {
                runtime
                    .shutdown
                    .request_fatal(RuntimeFailure::fatal(format_args!(
                        "could not start stats printer: {error}"
                    )));
            }
        } else {
            runtime
                .shutdown
                .request_current_fatal(RuntimeFailure::fatal(format_args!(
                    "enabled stats runtime has no aggregator bootstrap token"
                )));
        }
    }
    loop {
        if let Some(shutdown_transaction) = runtime.shutdown.begin_supervision() {
            if let Some(outcome) = runtime.shutdown.primary_fatal_outcome() {
                log_error!("Fatal shutdown cause: {outcome:?}");
            }
            log_info!("Exiting, uptime {} seconds", t_start.elapsed().as_secs());
            for flow_state in &runtime.flow_states {
                flow_state.invalidate_maintenance_schedule();
            }
            runtime
                .stats
                .request_final_flush(Instant::now() + Duration::from_millis(500));
            let (completed, final_exit_code) = shutdown_transaction.complete(|| {
                threads
                    .supervisor
                    .finish(Instant::now() + RUNTIME_SHUTDOWN_DEADLINE)
            });
            if !completed {
                if let Some(outcome) = runtime.shutdown.primary_fatal_outcome() {
                    log_error!("Fatal shutdown during supervisor completion: {outcome:?}");
                }
                immediate_exit(final_exit_code);
            }
            process::exit(final_exit_code);
        }
        runtime
            .shutdown
            .wait_for_change(Instant::now() + Duration::from_millis(50));
    }
}

#[cfg(test)]
mod authority_lane_capacity_tests;
