mod diagnostic_store;
mod formatting;

use super::packet_admission::{
    PeerSourceRequirement, ReceiveContext, RejectionReason, TransportAdmission,
    WirePacketAdmission, admit_network_layer, admit_packet_with_parsed, admit_transport_packet,
    transport_requires_authenticated_work,
};
use crate::cli::RuntimeConfig;
use crate::diagnostics::PacketTraceId;
use crate::net::packet_headers::{
    IpMalformedReason, IpUnsupportedReason, NetworkParseOutcome, ParsedIcmpEcho,
    ParsedNetworkLayer, ParsedPacketHeaders, ParsedTransport,
};
use crate::net::sock_mgr::SocketEvidenceKey;
use diagnostic_store::{
    DiagnosticClass, begin_trace_output, finish_trace_output, take_any_completed_trace,
    take_completed_trace,
};
use formatting::{
    client_flow_key_string, flow_endpoint_string, flow_tuple_string, ip_version,
    network_layer_name, payload_event_kind, protocol_name, role_name, socket_type_name,
    transport_name,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Instant;

const PACKET_DUMP_HEX_LIMIT: usize = 2048;

#[derive(Clone, Copy)]
struct PacketDumpContext {
    role: super::packet_admission::SocketLeg,
    proto: crate::cli::SupportedProtocol,
    sock_type: socket2::Type,
    parser: crate::net::packet_headers::ReceiveParserKernel,
    receive_syscall: pkthere_socket_policy::ReceiveSyscall,
    connected: bool,
    peer_source: PeerSourceRequirement,
    socket_is_ipv4: bool,
    can_honor_disjoint_icmp_ids: bool,
    allow_debug_kernel_echo_self_handshake: bool,
    local_filter: crate::endpoint::LogicalEndpoint,
    evidence_key: SocketEvidenceKey,
    expected_inbound: Option<crate::flow_key::FlowTuple>,
    expected_local: Option<crate::endpoint::LogicalEndpoint>,
    expected_remote: Option<crate::endpoint::LogicalEndpoint>,
    locked_flow: Option<crate::flow_key::ClientFlowKey>,
}

impl PacketDumpContext {
    fn capture(spec: ReceiveContext<'_>) -> Self {
        Self {
            role: spec.socket.role,
            proto: spec.socket.proto,
            sock_type: spec.socket.sock_type,
            parser: spec.socket.parser,
            receive_syscall: spec.socket.policy.receive_syscall(spec.socket.connected),
            connected: spec.socket.connected,
            peer_source: spec.socket.evidence_policy().peer_source,
            socket_is_ipv4: spec.socket.socket_is_ipv4(),
            can_honor_disjoint_icmp_ids: spec.socket.can_honor_disjoint_icmp_ids(),
            allow_debug_kernel_echo_self_handshake: spec
                .socket
                .allow_debug_kernel_echo_self_handshake(),
            local_filter: spec.socket.local_filter,
            evidence_key: spec.socket.evidence_key,
            expected_inbound: spec.admission.expected_inbound,
            expected_local: spec.admission.expected_local,
            expected_remote: spec.expected_remote(),
            locked_flow: spec.admission.locked_flow,
        }
    }
}

#[derive(Clone, Copy)]
struct PacketDumpCandidate {
    flow_key: crate::flow_key::ClientFlowKey,
    listener_flow_inbound: Option<crate::flow_key::FlowTuple>,
    listener_flow_outbound: Option<crate::flow_key::FlowTuple>,
}

impl PacketDumpCandidate {
    fn capture(candidate: crate::flow_state::PendingIcmpClientLock) -> Self {
        Self {
            flow_key: candidate.flow_key,
            listener_flow_inbound: candidate.listener_flow.inbound,
            listener_flow_outbound: candidate.listener_flow.outbound,
        }
    }
}

enum PacketParseRecord<'a> {
    Parsed(&'a ParsedPacketHeaders),
    MalformedNetwork(IpMalformedReason),
    UnsupportedNetwork(IpUnsupportedReason),
    UnexpectedNetworkVersion,
    MalformedTransport(Option<crate::net::packet_headers::IcmpMalformedReason>),
    ReceiveNoise { transport: ParsedTransport },
}

impl<'a> From<&'a ParsedPacketHeaders> for PacketParseRecord<'a> {
    fn from(parsed: &'a ParsedPacketHeaders) -> Self {
        match parsed.network {
            ParsedNetworkLayer::Malformed(reason) => return Self::MalformedNetwork(reason),
            ParsedNetworkLayer::Unsupported { reason, .. } => {
                return Self::UnsupportedNetwork(reason);
            }
            ParsedNetworkLayer::UnexpectedVersion { .. } => {
                return Self::UnexpectedNetworkVersion;
            }
            ParsedNetworkLayer::NotPresent | ParsedNetworkLayer::Valid(_) => {}
        }
        match parsed.transport {
            ParsedTransport::NotParsed => Self::ReceiveNoise {
                transport: parsed.transport,
            },
            ParsedTransport::MalformedIcmp => {
                Self::MalformedTransport(parsed.icmp_malformed_reason)
            }
            ParsedTransport::UnrelatedProtocol | ParsedTransport::UnrelatedIcmp => {
                Self::ReceiveNoise {
                    transport: parsed.transport,
                }
            }
            _ => Self::Parsed(parsed),
        }
    }
}

#[derive(Clone, Copy)]
struct PacketDumpRecord<'a> {
    worker_id: usize,
    c2u: bool,
    packet_id: u64,
    context: PacketDumpContext,
    bytes: &'a [u8],
    socket_source: Option<SocketAddr>,
    parsed: ParsedPacketHeaders,
    include_detail: bool,
}

#[derive(Clone, Copy)]
struct AcceptedPacketDump {
    normalized_source: Option<crate::endpoint::LogicalEndpoint>,
    event_kind: &'static str,
    payload_len: usize,
    icmp: Option<PacketDumpIcmp>,
    lock_candidate: Option<PacketDumpCandidate>,
    pending_negotiation: Option<PacketDumpCandidate>,
}

#[derive(Clone, Copy)]
struct PacketDumpIcmp {
    remote_source_id: u16,
    inbound_header_ident: u16,
    sequence: u16,
    session_id: u64,
    advertised_reply_id: Option<u16>,
    negotiates_reply_id: bool,
    acknowledges_reply_id: bool,
}

impl PacketDumpIcmp {
    fn capture(meta: crate::net::payload::IcmpPayloadMeta) -> Self {
        Self {
            remote_source_id: meta.flow_identity().remote_source_id(),
            inbound_header_ident: meta.inbound_header_ident(),
            sequence: meta.seq(),
            session_id: meta.session_id().get(),
            advertised_reply_id: meta.advertised_reply_id(),
            negotiates_reply_id: meta.negotiates_reply_id(),
            acknowledges_reply_id: meta.acknowledges_reply_id(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketAdmissionKind {
    Accepted,
    ReceiveNoise,
    Filtered,
}

#[derive(Clone, Copy)]
struct PacketAdmissionSummary {
    kind: PacketAdmissionKind,
    accepted: Option<AcceptedPacketDump>,
    receive_noise: Option<super::packet_admission::ReceiveNoiseReason>,
    filtered: Option<super::packet_admission::RejectedPacket>,
}

impl PacketAdmissionSummary {
    fn capture(admission: &WirePacketAdmission<'_>) -> Self {
        match admission {
            Ok(admitted) => Self {
                kind: PacketAdmissionKind::Accepted,
                accepted: Some(AcceptedPacketDump {
                    normalized_source: admitted.normalized_source,
                    event_kind: payload_event_kind(&admitted.event),
                    payload_len: admitted.event.payload_len(),
                    icmp: admitted
                        .event
                        .icmp_meta()
                        .copied()
                        .map(PacketDumpIcmp::capture),
                    lock_candidate: admitted.lock_candidate().map(PacketDumpCandidate::capture),
                    pending_negotiation: admitted
                        .pending_negotiation()
                        .map(PacketDumpCandidate::capture),
                }),
                receive_noise: None,
                filtered: None,
            },
            Err(crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(
                reason,
            )) => Self {
                kind: PacketAdmissionKind::ReceiveNoise,
                accepted: None,
                receive_noise: Some(*reason),
                filtered: None,
            },
            Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                rejected,
            )) => Self {
                kind: PacketAdmissionKind::Filtered,
                accepted: None,
                receive_noise: None,
                filtered: Some(*rejected),
            },
        }
    }
}

pub(crate) struct DeferredPacketDump<'a> {
    record: PacketDumpRecord<'a>,
    admission: PacketAdmissionSummary,
}

impl DeferredPacketDump<'_> {
    pub(crate) const fn trace(&self) -> PacketTraceId {
        PacketTraceId {
            worker_id: self.record.worker_id,
            c2u: self.record.c2u,
            packet_id: self.record.packet_id,
        }
    }

    pub(crate) fn emit(self, cfg: &RuntimeConfig) {
        {
            let _json_scope = crate::authority::AuditedOperationScope::enter(
                crate::authority::OperationId::JsonSerialization,
            )
            .unwrap_or_else(|error| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "packet diagnostic JSON scope conflicted with packet authority: {error}"
                ))
            });
            log_packet_dump_received(cfg, self.record);
            log_packet_dump_admission(cfg, self.record, self.admission);
        }
        emit_completed_trace(
            self.record.worker_id,
            self.record.c2u,
            self.record.packet_id,
        );
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PacketDumpAdmissionContext<'a, 'snapshot> {
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) trace: PacketTraceId,
    pub(crate) spec: ReceiveContext<'snapshot>,
    pub(crate) received_at: Instant,
}

pub(crate) fn admit_received_packet_with_dump<'a>(
    context: PacketDumpAdmissionContext<'_, '_>,
    bytes: &'a [u8],
    socket_source: Option<SocketAddr>,
    authenticated_frame_budget: &mut super::work_budget::AuthenticatedFrameBudget,
    packet_dump_detail_budget: &mut super::work_budget::PacketDumpDetailBudget,
) -> ReceivedPacketAdmission<'a> {
    let PacketDumpAdmissionContext {
        cfg,
        trace,
        spec,
        received_at,
    } = context;
    let c2u = trace.c2u;
    let network = spec.socket.parser.parse_network(bytes);
    let network_layer = match network {
        NetworkParseOutcome::NotPresent => ParsedNetworkLayer::NotPresent,
        NetworkParseOutcome::Valid(validated) => ParsedNetworkLayer::Valid(validated.header),
        NetworkParseOutcome::Rejected(layer) => layer,
    };
    let network_admission = admit_network_layer(spec, network_layer);
    let parsed = match network_admission {
        Some(_) => ParsedPacketHeaders::network_only(network_layer),
        None => spec.socket.parser.parse_transport(bytes, network),
    };
    let (mut admission, authenticated_work_charged): (WirePacketAdmission<'_>, bool) =
        match network_admission {
            Some(TransportAdmission::Filtered(rejected)) => (
                Err(
                    crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                        rejected,
                    ),
                ),
                false,
            ),
            Some(TransportAdmission::ReceiveNoise(reason)) => (
                Err(
                    crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(
                        reason,
                    ),
                ),
                false,
            ),
            Some(TransportAdmission::Accepted(_)) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "network-layer admission returned an accepted transport outcome"
                ));
                return ReceivedPacketAdmission {
                    admission: None,
                    authenticated_work_charged: false,
                    deferred_dump: None,
                };
            }
            None => match admit_packet_with_parsed(spec, bytes, socket_source, &parsed) {
                TransportAdmission::Accepted(transport) => {
                    let charge = transport_requires_authenticated_work(spec, &transport);
                    if charge && !authenticated_frame_budget.take(received_at) {
                        return ReceivedPacketAdmission {
                            admission: None,
                            authenticated_work_charged: false,
                            deferred_dump: None,
                        };
                    }
                    let mut admission = admit_transport_packet(c2u, cfg, spec, transport);
                    if let Ok(admitted) = &mut admission {
                        admitted.trace = Some(trace);
                    }
                    let diagnostic_class = match &admission {
                    Ok(_) => DiagnosticClass::Accepted,
                    Err(crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(_)) => DiagnosticClass::ReceiveNoise,
                    Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(_)) => DiagnosticClass::Filtered,
                };
                    let deferred_dump = deferred_packet_dump(
                        context,
                        bytes,
                        socket_source,
                        parsed,
                        &admission,
                        diagnostic_class,
                        packet_dump_detail_budget,
                    );
                    return ReceivedPacketAdmission {
                        admission: Some(admission),
                        authenticated_work_charged: charge,
                        deferred_dump,
                    };
                }
                TransportAdmission::Filtered(rejected) => (
                    Err(
                        crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                            rejected,
                        ),
                    ),
                    false,
                ),
                TransportAdmission::ReceiveNoise(reason) => (
                    Err(
                        crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(
                            reason,
                        ),
                    ),
                    false,
                ),
            },
        };
    if let Ok(admitted) = &mut admission {
        admitted.trace = Some(trace);
    }
    let diagnostic_class = match &admission {
        Ok(_) => DiagnosticClass::Accepted,
        Err(crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(_)) => {
            DiagnosticClass::ReceiveNoise
        }
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(_)) => {
            DiagnosticClass::Filtered
        }
    };
    let deferred_dump = deferred_packet_dump(
        context,
        bytes,
        socket_source,
        parsed,
        &admission,
        diagnostic_class,
        packet_dump_detail_budget,
    );
    ReceivedPacketAdmission {
        admission: Some(admission),
        authenticated_work_charged,
        deferred_dump,
    }
}

#[inline]
fn deferred_packet_dump<'a>(
    context: PacketDumpAdmissionContext<'_, '_>,
    bytes: &'a [u8],
    socket_source: Option<SocketAddr>,
    parsed: ParsedPacketHeaders,
    admission: &WirePacketAdmission<'_>,
    diagnostic_class: DiagnosticClass,
    packet_dump_detail_budget: &mut super::work_budget::PacketDumpDetailBudget,
) -> Option<DeferredPacketDump<'a>> {
    if !context.cfg.debug_logs.packet_dump
        || !begin_trace_output(context.trace, diagnostic_class, context.received_at)
    {
        return None;
    }
    let PacketTraceId {
        worker_id,
        c2u,
        packet_id,
    } = context.trace;
    let detail_class = match diagnostic_class {
        DiagnosticClass::Accepted => super::work_budget::PacketDumpDetailClass::Accepted,
        DiagnosticClass::Filtered => super::work_budget::PacketDumpDetailClass::Filtered,
        DiagnosticClass::ReceiveNoise => super::work_budget::PacketDumpDetailClass::ReceiveNoise,
    };
    Some(DeferredPacketDump {
        record: PacketDumpRecord {
            worker_id,
            c2u,
            packet_id,
            context: PacketDumpContext::capture(context.spec),
            bytes,
            socket_source,
            parsed,
            include_detail: packet_dump_detail_budget.take(detail_class, context.received_at),
        },
        admission: PacketAdmissionSummary::capture(admission),
    })
}

pub(crate) struct ReceivedPacketAdmission<'a> {
    pub(crate) admission: Option<WirePacketAdmission<'a>>,
    pub(crate) authenticated_work_charged: bool,
    pub(crate) deferred_dump: Option<DeferredPacketDump<'a>>,
}

pub(crate) fn configure_packet_diagnostics(worker_threads: usize) -> std::io::Result<()> {
    diagnostic_store::configure(worker_threads)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketDisposition {
    Forwarded,
    SendFailed,
    DropDuplicate,
    DropRateLimited,
    DropHandshakePending,
    DropSyncReplaced,
    DropFlowConflict,
    DropStaleAuthority,
    DropSyncInvalid,
    DropNoActiveFlow,
    ConsumeCadence,
    ConsumeSessionControl,
    ReplySessionControl,
    ReplyFailed,
    ReceiveNoise,
    Filtered,
    HandshakeTimeoutDrop,
    HandshakeResetDrop,
}

impl PacketDisposition {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 18] = [
        Self::Forwarded,
        Self::SendFailed,
        Self::DropDuplicate,
        Self::DropRateLimited,
        Self::DropHandshakePending,
        Self::DropSyncReplaced,
        Self::DropFlowConflict,
        Self::DropStaleAuthority,
        Self::DropSyncInvalid,
        Self::DropNoActiveFlow,
        Self::ConsumeCadence,
        Self::ConsumeSessionControl,
        Self::ReplySessionControl,
        Self::ReplyFailed,
        Self::ReceiveNoise,
        Self::Filtered,
        Self::HandshakeTimeoutDrop,
        Self::HandshakeResetDrop,
    ];

    #[inline]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::SendFailed => "send-failed",
            Self::DropDuplicate => "drop-duplicate",
            Self::DropRateLimited => "drop-rate-limited",
            Self::DropHandshakePending => "drop-handshake-pending",
            Self::DropSyncReplaced => "drop-sync-replaced",
            Self::DropFlowConflict => "drop-flow-conflict",
            Self::DropStaleAuthority => "drop-stale-authority",
            Self::DropSyncInvalid => "drop-sync-invalid",
            Self::DropNoActiveFlow => "drop-no-active-flow",
            Self::ConsumeCadence => "consume-cadence",
            Self::ConsumeSessionControl => "consume-session-control",
            Self::ReplySessionControl => "reply-session-control",
            Self::ReplyFailed => "reply-failed",
            Self::ReceiveNoise => "receive-noise",
            Self::Filtered => "filtered",
            Self::HandshakeTimeoutDrop => "handshake-timeout-drop",
            Self::HandshakeResetDrop => "handshake-reset-drop",
        }
    }
}

pub(crate) fn log_packet_disposition(
    cfg: &RuntimeConfig,
    trace: PacketTraceId,
    disposition: PacketDisposition,
) {
    log_packet_disposition_with_retry(cfg, trace, disposition, None);
}

pub(crate) fn log_packet_send_disposition(
    cfg: &RuntimeConfig,
    trace: PacketTraceId,
    disposition: PacketDisposition,
    retried_unconnected: bool,
) {
    log_packet_disposition_with_retry(cfg, trace, disposition, Some(retried_unconnected));
}

fn log_packet_disposition_with_retry(
    cfg: &RuntimeConfig,
    trace: PacketTraceId,
    disposition: PacketDisposition,
    retried_unconnected: Option<bool>,
) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    finish_trace_output(trace, disposition, retried_unconnected);
}

fn emit_completed_trace(worker_id: usize, c2u: bool, packet_id: u64) {
    let trace = PacketTraceId {
        worker_id,
        c2u,
        packet_id,
    };
    let Some(completed) = take_completed_trace(trace) else {
        return;
    };
    emit_completed_disposition(completed);
}

fn emit_completed_disposition(completed: diagnostic_store::CompletedPacketDisposition) {
    let disposition = completed.disposition.as_str();
    let PacketTraceId {
        worker_id,
        c2u,
        packet_id,
    } = completed.trace;
    let mut value = audited_json!({
        "event": "packet_dump",
        "stage": "disposition",
        "worker": worker_id,
        "direction": if c2u { "c2u" } else { "u2c" },
        "packet_id": packet_id,
        "disposition": disposition,
    });
    if let Some(retried_unconnected) = completed.retried_unconnected {
        value["send_retry_unconnected"] = retried_unconnected.into();
    }
    log_packet_dump_line(worker_id, c2u, value);
}

pub(crate) fn flush_completed_packet_diagnostics(cfg: &RuntimeConfig, worker_id: usize) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    while let Some(completed) = take_any_completed_trace(worker_id) {
        let _json_scope = crate::authority::AuditedOperationScope::enter(
            crate::authority::OperationId::JsonSerialization,
        )
        .unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "completed packet diagnostic JSON scope conflicted with packet authority: {error}"
            ))
        });
        emit_completed_disposition(completed);
    }
}

#[cfg(test)]
mod disposition_tests;

fn log_packet_dump_received(cfg: &RuntimeConfig, record: PacketDumpRecord<'_>) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    if !record.include_detail {
        log_packet_dump_line(
            record.worker_id,
            record.c2u,
            audited_json!({
                "event": "packet_dump",
                "stage": "received",
                "worker": record.worker_id,
                "direction": if record.c2u { "c2u" } else { "u2c" },
                "packet_id": record.packet_id,
                "captured_length": record.bytes.len(),
                "detail_suppressed": true,
            }),
        );
        return;
    }
    let mut obj = base_packet_dump_json("received", record);
    let (hex, truncated) = bounded_hex(record.bytes);
    obj["receive"] = audited_json!({
        "len": record.bytes.len(),
        "socket_source": record.socket_source.map(|source| source.to_string()),
    });
    obj["packet"] = audited_json!({
        "original_len": record.bytes.len(),
        "hex": hex,
        "truncated": truncated,
        "hex_cap": PACKET_DUMP_HEX_LIMIT,
    });
    log_packet_dump_line(record.worker_id, record.c2u, obj);
}

fn log_packet_dump_admission(
    cfg: &RuntimeConfig,
    record: PacketDumpRecord<'_>,
    admission: PacketAdmissionSummary,
) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    if !record.include_detail {
        log_packet_dump_line(
            record.worker_id,
            record.c2u,
            compact_packet_admission_json(record, admission),
        );
        return;
    }
    let mut obj = base_packet_dump_json("admission", record);
    obj["parser_kernel"] = record.context.parser.name().into();
    obj["parse"] = packet_parse_record_json(&record.parsed);
    obj["admission"] = admission_json(admission);
    log_packet_dump_line(record.worker_id, record.c2u, obj);
}

fn compact_packet_admission_json(
    record: PacketDumpRecord<'_>,
    admission: PacketAdmissionSummary,
) -> Value {
    let (result, reason) = match admission.kind {
        PacketAdmissionKind::Accepted => ("accepted", None),
        PacketAdmissionKind::ReceiveNoise => ("receive-noise", None),
        PacketAdmissionKind::Filtered => (
            "filtered",
            admission
                .filtered
                .map(|rejected| rejection_reason_name(rejected.reason)),
        ),
    };
    audited_json!({
        "event": "packet_dump",
        "stage": "admission",
        "worker": record.worker_id,
        "direction": if record.c2u { "c2u" } else { "u2c" },
        "packet_id": record.packet_id,
        "admission": {
            "result": result,
            "reason": reason,
        },
        // Identity fields are correlation evidence, not an expensive packet
        // snapshot. Preserve them when hex/detail output is suppressed so
        // interface-global capture noise cannot hide an accepted RAW packet.
        "parse": packet_parse_record_json(&record.parsed),
        "socket": {
            "evidence_key": socket_evidence_key_json(record.context.evidence_key),
        },
        "detail_suppressed": true,
    })
}

fn log_packet_dump_line(worker_id: usize, c2u: bool, obj: Value) {
    crate::log_debug_dir!(
        true,
        worker_id,
        c2u,
        "packet-dump {}",
        crate::diagnostics::stamp(obj)
    );
}

fn base_packet_dump_json(stage: &'static str, record: PacketDumpRecord<'_>) -> Value {
    let PacketDumpRecord {
        worker_id,
        c2u,
        packet_id,
        context,
        bytes: _,
        socket_source: _,
        parsed: _,
        include_detail: _,
    } = record;
    audited_json!({
        "event": "packet_dump",
        "stage": stage,
        "worker": worker_id,
        "direction": if c2u { "c2u" } else { "u2c" },
        "packet_id": packet_id,
        "role": role_name(context.role),
        "socket": {
            "protocol": protocol_name(context.proto),
            "socket_type": socket_type_name(context.sock_type),
            "ip_version": format!("{:?}", context.parser.version()),
            "receive_header": format!("{:?}", context.parser.mode()),
            "receive_syscall": match context.receive_syscall {
                pkthere_socket_policy::ReceiveSyscall::Recv => "recv",
                pkthere_socket_policy::ReceiveSyscall::RecvFrom => "recv_from",
            },
            "connected": context.connected,
            "source_evidence": match context.peer_source {
                PeerSourceRequirement::ConnectedKernel => "ConnectedKernelFiltering",
                PeerSourceRequirement::SourceMetadata => "SourceMetadata",
                PeerSourceRequirement::RawPacketHeader => "RawPacketSource",
            },
            "socket_is_ipv4": context.socket_is_ipv4,
            "can_honor_disjoint_icmp_ids": context.can_honor_disjoint_icmp_ids,
            "allow_debug_kernel_echo_self_handshake": context.allow_debug_kernel_echo_self_handshake,
            "local_filter": context.local_filter.to_string(),
            "evidence_key": socket_evidence_key_json(context.evidence_key),
            "expected_inbound": context.expected_inbound.map(flow_tuple_string),
            "expected_local": context.expected_local.map(flow_endpoint_string),
            "expected_remote": context.expected_remote.map(|remote| remote.to_string()),
            "locked_flow": context.locked_flow.map(client_flow_key_string),
        },
    })
}

fn packet_parse_record_json(parsed: &ParsedPacketHeaders) -> Value {
    match PacketParseRecord::from(parsed) {
        PacketParseRecord::MalformedNetwork(reason) => audited_json!({
            "kind": "malformed-network",
            "network_reason": format!("{reason:?}"),
        }),
        PacketParseRecord::UnsupportedNetwork(reason) => audited_json!({
            "kind": "unsupported-network",
            "network_reason": format!("{reason:?}"),
        }),
        PacketParseRecord::UnexpectedNetworkVersion => audited_json!({
            "kind": "receive-noise",
            "network_reason": "UnexpectedVersion",
        }),
        PacketParseRecord::MalformedTransport(icmp_reason) => audited_json!({
            "kind": "malformed-transport",
            "transport": transport_name(parsed.transport),
            "icmp_reason": icmp_reason.map(|reason| format!("{reason:?}")),
        }),
        PacketParseRecord::ReceiveNoise { transport } => audited_json!({
            "kind": "receive-noise",
            "transport": transport_name(transport),
        }),
        PacketParseRecord::Parsed(parsed) => audited_json!({
            "kind": "parsed",
            "headers": parsed_headers_json(parsed),
        }),
    }
}

fn socket_evidence_key_json(key: SocketEvidenceKey) -> Value {
    audited_json!({
        "process_id": key.process_id,
        "role": match key.role {
            pkthere_socket_policy::SocketRole::Listener => "listener",
            pkthere_socket_policy::SocketRole::Upstream => "upstream",
        },
        "domain": if key.domain == socket2::Domain::IPV4 {
            "ipv4"
        } else if key.domain == socket2::Domain::IPV6 {
            "ipv6"
        } else {
            "other"
        },
        "socket_slot": key.socket_slot,
        "generation": key.generation,
    })
}

fn admission_json(admission: PacketAdmissionSummary) -> Value {
    match admission.kind {
        PacketAdmissionKind::Accepted => admission.accepted.map_or_else(
            || audited_json!({"result": "invalid-diagnostic-state"}),
            accepted_json,
        ),
        PacketAdmissionKind::ReceiveNoise => audited_json!({
            "result": "receive-noise",
            "reason": admission.receive_noise.map(receive_noise_reason_name),
        }),
        PacketAdmissionKind::Filtered => admission.filtered.map_or_else(
            || audited_json!({"result": "invalid-diagnostic-state"}),
            |rejected| audited_json!({
            "result": "filtered",
            "reason": rejection_reason_name(rejected.reason),
            "malformed_reason": malformed_reason_name(rejected.reason),
            "normalized_source": rejected.normalized_source.map(|source| source.to_string()),
            "actual_dst_id": rejected.actual_dst_id,
        })),
    }
}

fn receive_noise_reason_name(reason: super::packet_admission::ReceiveNoiseReason) -> &'static str {
    match reason {
        super::packet_admission::ReceiveNoiseReason::UnexpectedEchoDirection => {
            "UnexpectedEchoDirection"
        }
        super::packet_admission::ReceiveNoiseReason::UnrelatedIpProtocol => "UnrelatedIpProtocol",
        super::packet_admission::ReceiveNoiseReason::UnrelatedIcmpType => "UnrelatedIcmpType",
        super::packet_admission::ReceiveNoiseReason::UnexpectedIpVersion => "UnexpectedIpVersion",
    }
}

fn accepted_json(admitted: AcceptedPacketDump) -> Value {
    audited_json!({
        "result": "accepted",
        "normalized_source": admitted.normalized_source.map(|source| source.to_string()),
        "event_kind": admitted.event_kind,
        "payload_len": admitted.payload_len,
        "icmp": admitted.icmp.map(|meta| audited_json!({
            "remote_source_id": meta.remote_source_id,
            "inbound_header_ident": meta.inbound_header_ident,
            "seq": meta.sequence,
            "session_id": meta.session_id,
            "advertised_reply_id": meta.advertised_reply_id,
            "reply_id_negotiate": meta.negotiates_reply_id,
            "reply_id_ack": meta.acknowledges_reply_id,
        })),
        "lock_candidate": admitted.lock_candidate.map(|candidate| audited_json!({
            "flow_key": candidate.flow_key.to_string(),
            "listener_flow_inbound": candidate.listener_flow_inbound.map(flow_tuple_string),
            "listener_flow_outbound": candidate.listener_flow_outbound.map(flow_tuple_string),
        })),
        "pending_negotiation": admitted.pending_negotiation.map(|candidate| audited_json!({
            "flow_key": candidate.flow_key.to_string(),
            "listener_flow_inbound": candidate.listener_flow_inbound.map(flow_tuple_string),
            "listener_flow_outbound": candidate.listener_flow_outbound.map(flow_tuple_string),
        })),
    })
}

fn parsed_headers_json(parsed: &ParsedPacketHeaders) -> Value {
    audited_json!({
        "network": network_layer_name(parsed.network),
        "transport": transport_name(parsed.transport),
        "ip_version": ip_version(parsed.network),
        "src_ip": parsed.source_ip().map(|ip| ip.to_string()),
        "dst_ip": parsed.destination_ip().map(|ip| ip.to_string()),
        "ipv6_flow_label": match parsed.network {
            ParsedNetworkLayer::Valid(header)
            | ParsedNetworkLayer::Unsupported { header, .. } => header.ipv6_flow_label,
            _ => None,
        },
        "udp": parsed.udp.map(|udp| audited_json!({
            "src_port": udp.src_port,
            "dst_port": udp.dst_port,
        })),
        "icmp": parsed.icmp.map(parsed_icmp_json),
        "payload_bounds": {
            "start": parsed.payload_bounds.0,
            "end": parsed.payload_bounds.1,
        },
        "malformed_reason": parsed.icmp_malformed_reason.map(|reason| format!("{reason:?}")),
    })
}

fn rejection_reason_name(reason: RejectionReason) -> &'static str {
    match reason {
        RejectionReason::MalformedIpHeader(_) => "MalformedIpHeader",
        RejectionReason::UnsupportedIpLayout(_) => "UnsupportedIpLayout",
        RejectionReason::MalformedIcmpHeader(_) => "MalformedIcmpHeader",
        RejectionReason::UnexpectedRemotePeer => "UnexpectedRemotePeer",
        RejectionReason::UnexpectedLocalReceiveId => "UnexpectedLocalReceiveId",
        RejectionReason::UnexpectedLocalReceiveAddress => "UnexpectedLocalReceiveAddress",
        RejectionReason::MissingSourceEvidence => "MissingSourceEvidence",
        RejectionReason::IcmpReplyIdNegotiationRequired => "IcmpReplyIdNegotiationRequired",
        RejectionReason::IcmpSourceEndpointMismatch => "IcmpSourceEndpointMismatch",
        RejectionReason::IcmpReplyIdRenegotiationMismatch => "IcmpReplyIdRenegotiationMismatch",
        RejectionReason::IcmpSessionMismatch => "IcmpSessionMismatch",
        RejectionReason::UnsupportedDisjointReplyId => "UnsupportedDisjointReplyId",
        RejectionReason::PayloadOversize => "PayloadOversize",
        RejectionReason::InvalidPayloadBounds => "InvalidPayloadBounds",
    }
}

fn malformed_reason_name(reason: RejectionReason) -> Option<&'static str> {
    match reason {
        RejectionReason::MalformedIpHeader(reason) => Some(match reason {
            IpMalformedReason::MissingHeader => "MissingHeader",
            IpMalformedReason::InvalidVersion { .. } => "InvalidVersion",
            IpMalformedReason::TruncatedHeader => "TruncatedHeader",
            IpMalformedReason::InvalidHeaderLength => "InvalidHeaderLength",
            IpMalformedReason::InvalidPacketLength => "InvalidPacketLength",
            IpMalformedReason::CaptureTruncated => "CaptureTruncated",
            IpMalformedReason::ReservedIpv4Flag => "ReservedIpv4Flag",
            IpMalformedReason::TruncatedExtension => "TruncatedExtension",
        }),
        RejectionReason::UnsupportedIpLayout(reason) => Some(match reason {
            IpUnsupportedReason::Fragmented => "Fragmented",
            IpUnsupportedReason::ExtensionChain => "ExtensionChain",
            IpUnsupportedReason::RoutingHeaderWithSegments => "RoutingHeaderWithSegments",
            IpUnsupportedReason::AuthenticationHeader => "AuthenticationHeader",
            IpUnsupportedReason::EncryptedPayload => "EncryptedPayload",
            IpUnsupportedReason::Jumbogram => "Jumbogram",
        }),
        RejectionReason::MalformedIcmpHeader(Some(reason)) => Some(match reason {
            crate::net::packet_headers::IcmpMalformedReason::TruncatedEchoHeader => {
                "TruncatedEchoHeader"
            }
            crate::net::packet_headers::IcmpMalformedReason::InvalidEchoTypeOrCode => {
                "InvalidEchoTypeOrCode"
            }
            crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags => "InvalidShimFlags",
            crate::net::packet_headers::IcmpMalformedReason::TruncatedSourceId => {
                "TruncatedSourceId"
            }
            crate::net::packet_headers::IcmpMalformedReason::IllegalFrameFlags => {
                "IllegalFrameFlags"
            }
            crate::net::packet_headers::IcmpMalformedReason::SessionControlReplyIdLength => {
                "SessionControlReplyIdLength"
            }
            crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlFlags => {
                "InvalidSessionControlFlags"
            }
            crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection => {
                "InvalidSessionControlDirection"
            }
            crate::net::packet_headers::IcmpMalformedReason::MissingSessionId => "MissingSessionId",
            crate::net::packet_headers::IcmpMalformedReason::ZeroSessionId => "ZeroSessionId",
            crate::net::packet_headers::IcmpMalformedReason::ZeroSourceId => "ZeroSourceId",
            crate::net::packet_headers::IcmpMalformedReason::ZeroReplyId => "ZeroReplyId",
        }),
        _ => None,
    }
}

fn parsed_icmp_json(icmp: ParsedIcmpEcho) -> Value {
    audited_json!({
        "type": if icmp.is_req { "echo-request" } else { "echo-reply" },
        "code": 0,
        "echo_identifier": icmp.identity.destination_id,
        "sequence": icmp.seq,
        "session_id": icmp.session_id,
        "shim_flags": icmp.shim_flags.map(|shim| format!("0x{shim:02x}")),
        "logical_source_id": icmp.identity.source_id,
        "logical_destination_id": icmp.identity.destination_id,
    })
}

fn bounded_hex(bytes: &[u8]) -> (String, bool) {
    let shown = bytes
        .get(..bytes.len().min(PACKET_DUMP_HEX_LIMIT))
        .unwrap_or_default();
    let mut hex = String::with_capacity(shown.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in shown {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    (hex, shown.len() != bytes.len())
}

#[cfg(test)]
mod diagnostic_store_unit_tests;
#[cfg(test)]
mod tests;
