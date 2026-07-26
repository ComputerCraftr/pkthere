use super::diagnostic_capture::{DiagnosticCaptureTransaction, DiagnosticCaptureTransactionError};
use super::{
    Arc, DirectionSnapshot, FlowRuntimeState, SequenceRejectionCounters, SharedIcmpSequenceState,
    Snapshot, SocketManager, Stats,
};
use socket2::Type;

struct SnapshotProjection {
    c2u_bytes: u64,
    u2c_bytes: u64,
    c2u_lat_sum_ns: u64,
    u2c_lat_sum_ns: u64,
    c2u_queue_sum_ns: u64,
    u2c_queue_sum_ns: u64,
    c2u_service_sum_ns: u64,
    u2c_service_sum_ns: u64,
    accounting_overflowed: bool,
}

pub(super) struct SnapshotRenderInput<'a> {
    pub(super) snapshot: Snapshot,
    pub(super) sock_mgrs: &'a [Arc<SocketManager>],
    pub(super) flow_states: &'a [Arc<FlowRuntimeState>],
    pub(super) sequence_states: &'a [Arc<SharedIcmpSequenceState>],
    pub(super) c2u_ewma_ns: u64,
    pub(super) u2c_ewma_ns: u64,
    pub(super) uptime: u64,
    pub(super) final_flush_incomplete: bool,
}

struct SummaryInput {
    snapshot: Snapshot,
    projection: SnapshotProjection,
    sequence: SequenceRejectionCounters,
    worker_flows: Vec<serde_json::Value>,
    locked_worker_pairs: usize,
    uptime: u64,
    c2u_ewma_ns: u64,
    u2c_ewma_ns: u64,
    final_flush_incomplete: bool,
}

pub(super) struct DiagnosticFlowSnapshot {
    socket: crate::net::sock_mgr::SocketStateSnapshot,
    pub(super) locked: bool,
    sessions: crate::flow_state::SessionPoolSnapshot,
}

#[derive(Debug)]
pub(super) enum DiagnosticCaptureError {
    Manager(crate::net::sock_mgr::ManagerError),
    Flow(crate::flow_state::FlowTopologyError),
    Changed,
}

impl std::fmt::Display for DiagnosticCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manager(error) => write!(formatter, "manager snapshot unavailable: {error}"),
            Self::Flow(error) => write!(formatter, "flow topology unavailable: {error}"),
            Self::Changed => {
                formatter.write_str("flow topology changed while capturing diagnostics")
            }
        }
    }
}

pub(super) fn capture_diagnostic_flow(
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
) -> Result<DiagnosticFlowSnapshot, DiagnosticCaptureError> {
    let capture = DiagnosticCaptureTransaction::run(
        || {
            manager
                .try_snapshot_state()
                .map_err(DiagnosticCaptureError::Manager)
        },
        || {
            flow_state
                .try_diagnostic_topology_read()
                .map_err(DiagnosticCaptureError::Flow)
        },
        |_| (flow_state.is_locked(), flow_state.session_pool_snapshot()),
        crate::flow_state::FlowTopologyReadLease::is_current,
        |before, after| before.version == after.version,
    );
    match capture {
        Ok((socket, (locked, sessions))) => Ok(DiagnosticFlowSnapshot {
            socket,
            locked,
            sessions,
        }),
        Err(DiagnosticCaptureTransactionError::Operation(error)) => Err(error),
        Err(DiagnosticCaptureTransactionError::Changed) => Err(DiagnosticCaptureError::Changed),
    }
}

fn diagnostic_snapshot_error(
    worker_pair: usize,
    error: DiagnosticCaptureError,
) -> (serde_json::Value, bool) {
    (
        audited_json!({
            "worker_pair": worker_pair,
            "locked": false,
            "snapshot_error": error.to_string(),
        }),
        false,
    )
}

pub(super) fn render_snapshot(input: SnapshotRenderInput<'_>) -> serde_json::Value {
    let (sequence_rejections, sequence_overflowed) =
        Stats::sequence_rejection_snapshot(input.sequence_states);
    let projection = project_snapshot(input.snapshot, sequence_overflowed);
    let (worker_flows, locked_worker_pairs) =
        match build_worker_flows(input.sock_mgrs, input.flow_states, input.sequence_states) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                crate::runtime_support::publish_process_fatal(format_args!("{error}"));
                (vec![audited_json!({ "snapshot_error": error })], 0)
            }
        };
    build_summary(SummaryInput {
        snapshot: input.snapshot,
        projection,
        sequence: sequence_rejections,
        worker_flows,
        locked_worker_pairs,
        uptime: input.uptime,
        c2u_ewma_ns: input.c2u_ewma_ns,
        u2c_ewma_ns: input.u2c_ewma_ns,
        final_flush_incomplete: input.final_flush_incomplete,
    })
}

fn project_snapshot(snapshot: Snapshot, sequence_overflowed: bool) -> SnapshotProjection {
    let (c2u_bytes, c2u_bytes_projected) = Stats::project_u128(snapshot.c2u.bytes);
    let (u2c_bytes, u2c_bytes_projected) = Stats::project_u128(snapshot.u2c.bytes);
    let (c2u_lat_sum_ns, c2u_lat_projected) = Stats::project_u128(snapshot.c2u.lat_sum_ns);
    let (u2c_lat_sum_ns, u2c_lat_projected) = Stats::project_u128(snapshot.u2c.lat_sum_ns);
    let (c2u_queue_sum_ns, c2u_queue_projected) = Stats::project_u128(snapshot.c2u.queue_sum_ns);
    let (u2c_queue_sum_ns, u2c_queue_projected) = Stats::project_u128(snapshot.u2c.queue_sum_ns);
    let (c2u_service_sum_ns, c2u_service_projected) =
        Stats::project_u128(snapshot.c2u.service_sum_ns);
    let (u2c_service_sum_ns, u2c_service_projected) =
        Stats::project_u128(snapshot.u2c.service_sum_ns);
    SnapshotProjection {
        c2u_bytes,
        u2c_bytes,
        c2u_lat_sum_ns,
        u2c_lat_sum_ns,
        c2u_queue_sum_ns,
        u2c_queue_sum_ns,
        c2u_service_sum_ns,
        u2c_service_sum_ns,
        accounting_overflowed: snapshot.accounting_overflowed
            || sequence_overflowed
            || c2u_bytes_projected
            || u2c_bytes_projected
            || c2u_lat_projected
            || u2c_lat_projected
            || c2u_queue_projected
            || u2c_queue_projected
            || c2u_service_projected
            || u2c_service_projected,
    }
}

fn build_worker_flows(
    sock_mgrs: &[Arc<SocketManager>],
    flow_states: &[Arc<FlowRuntimeState>],
    sequence_states: &[Arc<SharedIcmpSequenceState>],
) -> Result<(Vec<serde_json::Value>, usize), &'static str> {
    if sock_mgrs.len() != flow_states.len() {
        return Err("socket-manager and flow-state cardinalities differ");
    }
    let Some(expected_sequence_states) = flow_states.len().checked_mul(2) else {
        return Err("flow-state sequence cardinality overflowed");
    };
    if sequence_states.len() != expected_sequence_states {
        return Err("flow-state and sequence-state cardinalities differ");
    }
    let mut worker_flows = Vec::with_capacity(flow_states.len());
    let mut locked_worker_pairs = 0;
    for (worker_pair, ((manager, flow_state), sequences)) in sock_mgrs
        .iter()
        .zip(flow_states)
        .zip(sequence_states.chunks_exact(2))
        .enumerate()
    {
        let Some(sequence_state) = sequences.get(1) else {
            return Err("a worker flow was missing its upstream sequence authority");
        };
        let (flow, locked) = build_worker_flow(worker_pair, manager, flow_state, sequence_state);
        worker_flows.push(flow);
        locked_worker_pairs += usize::from(locked);
    }
    Ok((worker_flows, locked_worker_pairs))
}

fn build_worker_flow(
    worker_pair: usize,
    manager: &SocketManager,
    flow_state: &FlowRuntimeState,
    sequence_state: &SharedIcmpSequenceState,
) -> (serde_json::Value, bool) {
    let DiagnosticFlowSnapshot {
        socket,
        locked,
        mut sessions,
    } = match capture_diagnostic_flow(manager, flow_state) {
        Ok(snapshot) => snapshot,
        Err(error) => return diagnostic_snapshot_error(worker_pair, error),
    };
    let mut estimated_reserve_packets = None;
    let mut reserve_snapshot_stable = false;
    for _ in 0..2 {
        let estimate =
            sequence_state.remaining_outbound_sequences(sessions.pool.ready_session_ids.iter());
        if flow_state.reserve_accounting_snapshot_is_current(
            sessions.pool.pool_epoch,
            &sessions.pool.ready_session_ids,
        ) {
            estimated_reserve_packets = estimate;
            reserve_snapshot_stable = true;
            break;
        }
        sessions = flow_state.session_pool_snapshot();
    }
    let reserve_accounting_invariant = reserve_snapshot_stable
        && estimated_reserve_packets.is_none()
        || sessions.pool.pool_epoch_exhausted;
    let mut flow = socket_flow_json(worker_pair, socket, locked);
    append_session_fields(
        &mut flow,
        sessions,
        estimated_reserve_packets,
        reserve_snapshot_stable,
        reserve_accounting_invariant,
    );
    (flow, locked)
}

fn socket_flow_json(
    worker_pair: usize,
    snapshot: crate::net::sock_mgr::SocketStateSnapshot,
    locked: bool,
) -> serde_json::Value {
    let socket_type = |kind| match kind {
        Type::RAW => "RAW",
        Type::DGRAM => "DGRAM",
        _ => "OTHER",
    };
    audited_json!({
        "worker_pair": worker_pair,
        "locked": locked,
        "client_proto": snapshot.client_proto.to_str(),
        "client_sock_type": socket_type(snapshot.listen_sock_type),
        "listener_connected": locked && snapshot.listener_connected,
        "listener_lifecycle": snapshot.listen_policy.listener_lifecycle.map(pkthere_socket_policy::ListenerLockLifecycle::wire_name),
        "flow_key": if locked { snapshot.locked_flow.map(|key| key.to_string()) } else { None::<String> },
        "listener_flow_inbound": if locked { snapshot.listener_flow.inbound.map(|flow| format!("{} -> {}", flow.src, flow.dst)) } else { None::<String> },
        "listener_flow_outbound": if locked { snapshot.listener_flow.outbound.map(|flow| format!("{} -> {}", flow.src, flow.dst)) } else { None::<String> },
        "listener_local_filter": snapshot.listen_local_filter.to_string(),
        "listen_socket_evidence": socket_evidence_json(snapshot.listen_evidence_key, "listener"),
        "upstream_remote_filter": snapshot.upstream_remote_filter.to_string(),
        "upstream_flow_inbound": snapshot.upstream_flow.inbound.map(|flow| format!("{} -> {}", flow.src, flow.dst)),
        "upstream_flow_outbound": snapshot.upstream_flow.outbound.map(|flow| format!("{} -> {}", flow.src, flow.dst)),
        "upstream_connected": snapshot.upstream_connected,
        "upstream_peer_mode": snapshot.upstream_policy.reuse.startup_peer_mode.wire_name(),
        "upstream_local_filter": snapshot.upstream_local_filter.to_string(),
        "upstream_socket_evidence": socket_evidence_json(snapshot.upstream_evidence_key, "upstream"),
        "upstream_proto": snapshot.upstream_proto.to_str(),
        "upstream_sock_type": socket_type(snapshot.upstream_sock_type),
    })
}

fn socket_evidence_json(
    evidence: pkthere_socket_policy::SocketEvidenceKey,
    role: &'static str,
) -> serde_json::Value {
    audited_json!({
        "process_id": evidence.process_id,
        "role": role,
        "domain": if evidence.domain == socket2::Domain::IPV4 { "ipv4" } else { "ipv6" },
        "socket_slot": evidence.socket_slot,
        "generation": evidence.generation,
    })
}

fn append_session_fields(
    flow: &mut serde_json::Value,
    sessions: crate::flow_state::SessionPoolSnapshot,
    estimated_reserve_packets: Option<u64>,
    reserve_snapshot_stable: bool,
    reserve_accounting_invariant: bool,
) {
    let Some(fields) = flow.as_object_mut() else {
        crate::runtime_support::publish_process_fatal(format_args!(
            "worker flow diagnostics lost their object shape"
        ));
        return;
    };
    fields.insert(
        "icmp_active_session_count".into(),
        audited_json!(sessions.pool.active),
    );
    fields.insert(
        "icmp_client_transmit_session_id".into(),
        audited_json!(sessions.pool.client_transmit_session_id.map(|id| id.get())),
    );
    fields.insert(
        "icmp_client_receive_session_id".into(),
        audited_json!(sessions.pool.client_receive_session_id.map(|id| id.get())),
    );
    fields.insert(
        "icmp_upstream_transmit_session_id".into(),
        audited_json!(
            sessions
                .pool
                .upstream_transmit_session_id
                .map(|id| id.get())
        ),
    );
    fields.insert(
        "icmp_upstream_receive_session_id".into(),
        audited_json!(sessions.pool.upstream_receive_session_id.map(|id| id.get())),
    );
    let values = [
        (
            "icmp_negotiated_ready_session_count",
            audited_json!(sessions.pool.ready),
        ),
        (
            "icmp_negotiating_session_count",
            audited_json!(sessions.pool.negotiating),
        ),
        (
            "icmp_draining_session_count",
            audited_json!(sessions.pool.draining),
        ),
        (
            "icmp_session_pool_target",
            audited_json!(sessions.pool.target),
        ),
        (
            "icmp_candidate_retry_attempts",
            audited_json!(sessions.metrics.candidate_retry_attempts),
        ),
        (
            "icmp_candidate_expirations",
            audited_json!(sessions.metrics.candidate_expirations),
        ),
        (
            "icmp_candidate_negotiations_completed",
            audited_json!(sessions.metrics.candidate_negotiations_completed),
        ),
        (
            "icmp_estimated_reserve_packets",
            audited_json!(estimated_reserve_packets),
        ),
        (
            "icmp_reserve_accounting_incomplete",
            audited_json!(!reserve_snapshot_stable || estimated_reserve_packets.is_none()),
        ),
        (
            "icmp_reserve_accounting_invariant_failure",
            audited_json!(reserve_accounting_invariant),
        ),
        (
            "icmp_normal_session_handoffs",
            audited_json!(sessions.metrics.normal_handoffs),
        ),
        (
            "icmp_pool_empty_stalls",
            audited_json!(sessions.metrics.pool_empty_stalls),
        ),
        (
            "icmp_stale_session_evictions",
            audited_json!(sessions.metrics.stale_session_evictions),
        ),
        (
            "icmp_sparse_retirement_exhaustions",
            audited_json!(sessions.metrics.sparse_retirement_exhaustions),
        ),
        (
            "icmp_generation_rollovers",
            audited_json!(sessions.metrics.generation_rollovers),
        ),
        (
            "icmp_maintenance_wake_failures",
            audited_json!(sessions.maintenance_wake_failures),
        ),
        (
            "icmp_reset_challenges_created",
            audited_json!(sessions.reset_recovery.reset_challenges_created),
        ),
        (
            "icmp_reset_challenges_reused",
            audited_json!(sessions.reset_recovery.reset_challenges_reused),
        ),
        (
            "icmp_reset_challenges_consumed",
            audited_json!(sessions.reset_recovery.reset_challenges_consumed),
        ),
        (
            "icmp_reset_challenges_expired",
            audited_json!(sessions.reset_recovery.reset_challenges_expired),
        ),
        (
            "icmp_reset_responses_rate_limited",
            audited_json!(sessions.reset_recovery.reset_responses_rate_limited),
        ),
        (
            "icmp_reset_responses_accepted",
            audited_json!(sessions.reset_recovery.reset_responses_accepted),
        ),
        (
            "icmp_reset_responses_ignored",
            audited_json!(sessions.reset_recovery.reset_responses_ignored),
        ),
    ];
    fields.extend(values.map(|(key, value)| (key.to_owned(), value)));
    fields.insert(
        "icmp_candidate_negotiation_latency_ns_total".into(),
        audited_json!(
            sessions
                .metrics
                .candidate_negotiation_latency_ns_total
                .to_string()
        ),
    );
    fields.insert(
        "icmp_candidate_negotiation_latency_ns_average".into(),
        audited_json!(
            (sessions.metrics.candidate_negotiations_completed != 0).then(|| {
                (sessions.metrics.candidate_negotiation_latency_ns_total
                    / u128::from(sessions.metrics.candidate_negotiations_completed))
                .to_string()
            })
        ),
    );
}

fn build_summary(input: SummaryInput) -> serde_json::Value {
    let mut value = audited_json!({
        "stats_schema": 3,
        "stats_final_flush_incomplete": input.final_flush_incomplete,
        "uptime_s": input.uptime,
        "locked": input.locked_worker_pairs > 0,
        "locked_worker_pairs": input.locked_worker_pairs,
        "worker_flows": input.worker_flows,
    });
    append_direction_fields(
        &mut value,
        "c2u",
        input.snapshot.c2u,
        input.c2u_ewma_ns,
        &input.projection,
    );
    append_direction_fields(
        &mut value,
        "u2c",
        input.snapshot.u2c,
        input.u2c_ewma_ns,
        &input.projection,
    );
    append_error_fields(
        &mut value,
        input.snapshot,
        input.sequence,
        input.projection.accounting_overflowed,
    );
    crate::diagnostics::stamp(value)
}

fn append_direction_fields(
    value: &mut serde_json::Value,
    prefix: &str,
    direction: DirectionSnapshot,
    ewma_ns: u64,
    projection: &SnapshotProjection,
) {
    let Some(object) = value.as_object_mut() else {
        crate::runtime_support::publish_process_fatal(format_args!(
            "direction stats diagnostics lost their object shape"
        ));
        return;
    };
    let (bytes, latency, queue, service) = if prefix == "c2u" {
        (
            projection.c2u_bytes,
            projection.c2u_lat_sum_ns,
            projection.c2u_queue_sum_ns,
            projection.c2u_service_sum_ns,
        )
    } else {
        (
            projection.u2c_bytes,
            projection.u2c_lat_sum_ns,
            projection.u2c_queue_sum_ns,
            projection.u2c_service_sum_ns,
        )
    };
    let average = |sum| (direction.pkts != 0).then(|| Stats::average_ns(sum, direction.pkts));
    let fields = [
        ("pkts", audited_json!(direction.pkts)),
        ("bytes", audited_json!(bytes)),
        ("bytes_max", audited_json!(direction.bytes_max)),
        ("drops_oversize", audited_json!(direction.drops_oversize)),
        ("latency_ns_sum", audited_json!(latency)),
        (
            "latency_ns_avg",
            audited_json!(average(direction.lat_sum_ns)),
        ),
        (
            "interval_mean_latency_ns_ewma",
            audited_json!((direction.pkts != 0).then_some(ewma_ns)),
        ),
        ("latency_ns_max", audited_json!(direction.lat_max_ns)),
        ("queue_delay_ns_sum", audited_json!(queue)),
        (
            "queue_delay_ns_avg",
            audited_json!(average(direction.queue_sum_ns)),
        ),
        ("queue_delay_ns_max", audited_json!(direction.queue_max_ns)),
        ("send_service_ns_sum", audited_json!(service)),
        (
            "send_service_ns_avg",
            audited_json!(average(direction.service_sum_ns)),
        ),
        (
            "send_service_ns_max",
            audited_json!(direction.service_max_ns),
        ),
        ("errs", audited_json!(direction.errs)),
        (
            "zero_resolution_samples",
            audited_json!(direction.zero_resolution_samples),
        ),
        ("receive_errors", audited_json!(direction.receive_errors)),
        (
            "user_send_errors",
            audited_json!(direction.user_send_errors),
        ),
        (
            "control_send_errors",
            audited_json!(direction.control_send_errors),
        ),
        ("admission_drops", audited_json!(direction.admission_drops)),
        ("topology_errors", audited_json!(direction.topology_errors)),
        ("bytes_exact", audited_json!(direction.bytes.to_string())),
        (
            "latency_ns_sum_exact",
            audited_json!(direction.lat_sum_ns.to_string()),
        ),
        (
            "queue_delay_ns_sum_exact",
            audited_json!(direction.queue_sum_ns.to_string()),
        ),
        (
            "send_service_ns_sum_exact",
            audited_json!(direction.service_sum_ns.to_string()),
        ),
    ];
    object.extend(fields.map(|(suffix, field)| (format!("{prefix}_{suffix}"), field)));
}

fn append_error_fields(
    value: &mut serde_json::Value,
    snapshot: Snapshot,
    sequence: SequenceRejectionCounters,
    accounting_overflowed: bool,
) {
    let Some(object) = value.as_object_mut() else {
        crate::runtime_support::publish_process_fatal(format_args!(
            "error stats diagnostics lost their object shape"
        ));
        return;
    };
    let fields = [
        ("icmp_sequence_future", audited_json!(sequence.future)),
        ("icmp_sequence_stale", audited_json!(sequence.stale)),
        ("icmp_sequence_duplicate", audited_json!(sequence.duplicate)),
        (
            "handshake_invalid_control",
            audited_json!(snapshot.control.handshake_invalid_control),
        ),
        (
            "handshake_stale_ack",
            audited_json!(snapshot.control.handshake_stale_ack),
        ),
        (
            "spurious_readiness_events",
            audited_json!(snapshot.control.spurious_readiness_events),
        ),
        (
            "malformed_packets",
            audited_json!(snapshot.admission.malformed_packets),
        ),
        (
            "wrong_peer_drops",
            audited_json!(snapshot.admission.wrong_peer_drops),
        ),
        (
            "wrong_source_drops",
            audited_json!(snapshot.admission.wrong_source_drops),
        ),
        (
            "handshake_invalid_drops",
            audited_json!(snapshot.admission.handshake_invalid_drops),
        ),
        (
            "replay_drops",
            audited_json!(snapshot.admission.replay_drops),
        ),
        (
            "icmp_abuse_budget_drops",
            audited_json!(snapshot.admission.icmp_abuse_budget_drops),
        ),
        (
            "stale_session_drops",
            audited_json!(snapshot.admission.stale_session_drops),
        ),
        (
            "stale_authority_drops",
            audited_json!(snapshot.admission.stale_authority_drops),
        ),
        (
            "invariant_failures",
            audited_json!(snapshot.admission.invariant_failures),
        ),
        (
            "ip_missing_header",
            audited_json!(snapshot.network.ip_missing_header),
        ),
        (
            "ip_invalid_version",
            audited_json!(snapshot.network.ip_invalid_version),
        ),
        (
            "ip_truncated_header",
            audited_json!(snapshot.network.ip_truncated_header),
        ),
        (
            "ip_declared_length_invalid",
            audited_json!(snapshot.network.ip_declared_length_invalid),
        ),
        (
            "ip_capture_truncated",
            audited_json!(snapshot.network.ip_capture_truncated),
        ),
        (
            "ip_fragmented",
            audited_json!(snapshot.network.ip_fragmented),
        ),
        (
            "ip_reserved_flag",
            audited_json!(snapshot.network.ip_reserved_flag),
        ),
        (
            "ip_extension_chain",
            audited_json!(snapshot.network.ip_extension_chain),
        ),
        (
            "ip_routing_unsupported",
            audited_json!(snapshot.network.ip_routing_unsupported),
        ),
        (
            "ip_jumbogram_unsupported",
            audited_json!(snapshot.network.ip_jumbogram_unsupported),
        ),
        (
            "ip_source_mismatch",
            audited_json!(snapshot.network.ip_source_mismatch),
        ),
        (
            "ip_destination_mismatch",
            audited_json!(snapshot.network.ip_destination_mismatch),
        ),
        (
            "unrelated_ip_protocol",
            audited_json!(snapshot.network.unrelated_ip_protocol),
        ),
        (
            "icmp_malformed",
            audited_json!(snapshot.network.icmp_malformed),
        ),
        (
            "stats_accounting_overflowed",
            audited_json!(accounting_overflowed),
        ),
    ];
    object.extend(fields.map(|(key, field)| (key.to_owned(), field)));
}
