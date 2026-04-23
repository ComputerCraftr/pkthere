use super::packet_admission::{
    AdmittedWirePacket, PeerSourceRequirement, ReceiveContext, RejectionReason, SocketLeg,
    WirePacketAdmission, admit_wire_packet_with_parsed,
};
use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::flow_key::{ClientFlowKey, FlowEndpoint, FlowTuple};
use crate::net::packet_headers::{ParsedIcmpEcho, ParsedPacketHeaders, ParsedTransport};
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::SocketEvidenceKey;
use crate::packet_trace::PacketTraceId;
use serde_json::{Value, json};
use socket2::{SockAddr, Type};
use std::fmt::Write;

const PACKET_DUMP_HEX_LIMIT: usize = 2048;

enum PacketParseRecord<'a> {
    Parsed(&'a ParsedPacketHeaders),
    Malformed {
        transport: ParsedTransport,
        icmp_reason: Option<crate::net::packet_headers::IcmpMalformedReason>,
    },
    ReceiveNoise {
        transport: ParsedTransport,
    },
}

impl<'a> From<&'a ParsedPacketHeaders> for PacketParseRecord<'a> {
    fn from(parsed: &'a ParsedPacketHeaders) -> Self {
        match parsed.transport {
            ParsedTransport::Malformed => Self::Malformed {
                transport: parsed.transport,
                icmp_reason: parsed.icmp_malformed_reason,
            },
            ParsedTransport::Unsupported => Self::ReceiveNoise {
                transport: parsed.transport,
            },
            _ => Self::Parsed(parsed),
        }
    }
}

#[derive(Clone, Copy)]
struct PacketDumpRecord<'a> {
    worker_id: usize,
    c2u: bool,
    packet_id: u64,
    spec: ReceiveContext,
    bytes: &'a [u8],
    socket_source: Option<&'a SockAddr>,
    parsed: &'a ParsedPacketHeaders,
}

pub(crate) fn admit_received_packet_with_dump<'a>(
    cfg: &RuntimeConfig,
    trace: PacketTraceId,
    spec: ReceiveContext,
    bytes: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> WirePacketAdmission<'a> {
    let PacketTraceId {
        worker_id,
        c2u,
        packet_id,
    } = trace;
    let parsed = spec.socket.parser.parse(bytes);
    let record = PacketDumpRecord {
        worker_id,
        c2u,
        packet_id,
        spec,
        bytes,
        socket_source,
        parsed: &parsed,
    };
    log_packet_dump_received(cfg, record);
    let mut admission =
        admit_wire_packet_with_parsed(c2u, cfg, spec, bytes, socket_source, &parsed);
    if let WirePacketAdmission::Accepted(admitted) = &mut admission {
        admitted.trace = Some(trace);
    }
    log_packet_dump_admission(cfg, record, &admission);
    match &admission {
        WirePacketAdmission::Accepted(_) => {}
        WirePacketAdmission::ReceiveNoise(_) => {
            log_packet_disposition(cfg, trace, PacketDisposition::ReceiveNoise);
        }
        WirePacketAdmission::Filtered(_) => {
            log_packet_disposition(cfg, trace, PacketDisposition::Filtered);
        }
    }
    admission
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketDisposition {
    Forwarded,
    SendFailed,
    DropDuplicate,
    DropHandshakePending,
    DropSyncReplaced,
    DropFlowConflict,
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
    pub(crate) const ALL: [Self; 16] = [
        Self::Forwarded,
        Self::SendFailed,
        Self::DropDuplicate,
        Self::DropHandshakePending,
        Self::DropSyncReplaced,
        Self::DropFlowConflict,
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
        debug_assert!(Self::ALL.contains(&self));
        match self {
            Self::Forwarded => "forwarded",
            Self::SendFailed => "send-failed",
            Self::DropDuplicate => "drop-duplicate",
            Self::DropHandshakePending => "drop-handshake-pending",
            Self::DropSyncReplaced => "drop-sync-replaced",
            Self::DropFlowConflict => "drop-flow-conflict",
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
    let disposition = disposition.as_str();
    let PacketTraceId {
        worker_id,
        c2u,
        packet_id,
    } = trace;
    let mut value = json!({
        "event": "packet_dump",
        "stage": "disposition",
        "worker": worker_id,
        "direction": if c2u { "c2u" } else { "u2c" },
        "packet_id": packet_id,
        "disposition": disposition,
    });
    if let Some(retried_unconnected) = retried_unconnected {
        value["send_retry_unconnected"] = retried_unconnected.into();
    }
    log_packet_dump_line(worker_id, c2u, value);
}

#[cfg(test)]
#[path = "packet_dump/disposition_tests.rs"]
mod disposition_tests;

fn log_packet_dump_received(cfg: &RuntimeConfig, record: PacketDumpRecord<'_>) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    let mut obj = base_packet_dump_json("received", record);
    let (hex, truncated) = bounded_hex(record.bytes);
    obj["receive"] = json!({
        "len": record.bytes.len(),
        "socket_source": record.socket_source.and_then(socket_source_string),
    });
    obj["packet"] = json!({
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
    admission: &WirePacketAdmission<'_>,
) {
    if !cfg.debug_logs.packet_dump {
        return;
    }
    let mut obj = base_packet_dump_json("admission", record);
    obj["parser_kernel"] = record.spec.socket.parser.name().into();
    obj["parse"] = packet_parse_record_json(record.parsed);
    obj["admission"] = admission_json(admission);
    log_packet_dump_line(record.worker_id, record.c2u, obj);
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
        spec,
        bytes: _,
        socket_source: _,
        parsed: _,
    } = record;
    json!({
        "event": "packet_dump",
        "stage": stage,
        "worker": worker_id,
        "direction": if c2u { "c2u" } else { "u2c" },
        "packet_id": packet_id,
        "role": role_name(spec.socket.role),
        "socket": {
            "protocol": protocol_name(spec.socket.proto),
            "socket_type": socket_type_name(spec.socket.sock_type),
            "ip_version": format!("{:?}", spec.socket.parser.version()),
            "receive_header": format!("{:?}", spec.socket.parser.mode()),
            "receive_syscall": match spec.socket.policy.receive_syscall(spec.socket.connected) {
                pkthere_socket_policy::ReceiveSyscall::Recv => "recv",
                pkthere_socket_policy::ReceiveSyscall::RecvFrom => "recv_from",
            },
            "connected": spec.socket.connected,
            "source_evidence": match spec.socket.evidence_policy().peer_source {
                PeerSourceRequirement::ConnectedKernel => "ConnectedKernelFiltering",
                PeerSourceRequirement::SourceMetadata => "SourceMetadata",
                PeerSourceRequirement::RawPacketHeader => "RawPacketSource",
            },
            "socket_is_ipv4": spec.socket.socket_is_ipv4(),
            "can_honor_disjoint_icmp_ids": spec.socket.can_honor_disjoint_icmp_ids(),
            "allow_debug_kernel_echo_self_handshake": spec.socket.allow_debug_kernel_echo_self_handshake(),
            "local_filter": spec.socket.local_filter.to_string(),
            "local_kernel_addr": spec.socket.local_kernel_addr.to_string(),
            "evidence_key": socket_evidence_key_json(spec.socket.evidence_key),
            "remote_filter": spec.expected_remote().map(|remote| remote.to_string()),
            "expected_inbound": spec.admission.expected_inbound.map(flow_tuple_string),
            "expected_local": spec.admission.expected_local.map(flow_endpoint_string),
            "expected_remote": spec.expected_remote().map(|remote| remote.to_string()),
            "locked_flow": spec.admission.locked_flow.map(client_flow_key_string),
        },
    })
}

fn packet_parse_record_json(parsed: &ParsedPacketHeaders) -> Value {
    match PacketParseRecord::from(parsed) {
        PacketParseRecord::Malformed {
            transport,
            icmp_reason,
        } => json!({
            "kind": "malformed",
            "transport": transport_name(transport),
            "icmp_reason": icmp_reason.map(|reason| format!("{reason:?}")),
        }),
        PacketParseRecord::ReceiveNoise { transport } => json!({
            "kind": "receive-noise",
            "transport": transport_name(transport),
        }),
        PacketParseRecord::Parsed(parsed) => json!({
            "kind": "parsed",
            "headers": parsed_headers_json(parsed),
        }),
    }
}

fn socket_evidence_key_json(key: SocketEvidenceKey) -> Value {
    json!({
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

fn admission_json(admission: &WirePacketAdmission<'_>) -> Value {
    match admission {
        WirePacketAdmission::Accepted(admitted) => accepted_json(admitted),
        WirePacketAdmission::ReceiveNoise(reason) => json!({
            "result": "receive-noise",
            "reason": match reason {
                super::packet_admission::ReceiveNoiseReason::UnexpectedEchoDirection => "UnexpectedEchoDirection",
            },
        }),
        WirePacketAdmission::Filtered(rejected) => json!({
            "result": "filtered",
            "reason": rejection_reason_name(rejected.reason),
            "malformed_reason": malformed_reason_name(rejected.reason),
            "normalized_source": rejected.normalized_source.map(|source| source.to_string()),
            "actual_dst_id": rejected.actual_dst_id,
        }),
    }
}

fn accepted_json(admitted: &AdmittedWirePacket<'_>) -> Value {
    let event = &admitted.event;
    json!({
        "result": "accepted",
        "normalized_source": admitted.normalized_source.map(|source| source.to_string()),
        "event_kind": payload_event_kind(event),
        "payload_len": event.payload_len(),
        "icmp": event.icmp_meta().map(|meta| json!({
            "remote_source_id": meta.flow_identity().remote_source_id,
            "inbound_header_ident": meta.inbound_header_ident(),
            "seq": meta.seq(),
            "advertised_reply_id": meta.advertised_reply_id(),
            "reply_id_negotiate": meta.negotiates_reply_id(),
            "reply_id_ack": meta.acknowledges_reply_id(),
        })),
        "lock_candidate": admitted.lock_candidate.map(|candidate| json!({
            "flow_key": candidate.flow_key.to_string(),
            "listener_flow_inbound": candidate.listener_flow.inbound.map(flow_tuple_string),
            "listener_flow_outbound": candidate.listener_flow.outbound.map(flow_tuple_string),
        })),
        "pending_negotiation": admitted.pending_negotiation.map(|candidate| json!({
            "flow_key": candidate.flow_key.to_string(),
            "listener_flow_inbound": candidate.listener_flow.inbound.map(flow_tuple_string),
            "listener_flow_outbound": candidate.listener_flow.outbound.map(flow_tuple_string),
        })),
    })
}

fn parsed_headers_json(parsed: &ParsedPacketHeaders) -> Value {
    json!({
        "transport": transport_name(parsed.transport),
        "ip_version": ip_version(parsed.transport),
        "src_ip": parsed.src_ip.map(|ip| ip.to_string()),
        "dst_ip": parsed.dst_ip.map(|ip| ip.to_string()),
        "udp": parsed.udp.map(|udp| json!({
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
        RejectionReason::MalformedIcmpHeader(_) => "MalformedIcmpHeader",
        RejectionReason::UnexpectedRemotePeer => "UnexpectedRemotePeer",
        RejectionReason::UnexpectedLocalReceiveId => "UnexpectedLocalReceiveId",
        RejectionReason::UnexpectedLocalReceiveAddress => "UnexpectedLocalReceiveAddress",
        RejectionReason::MissingSourceEvidence => "MissingSourceEvidence",
        RejectionReason::IcmpReplyIdNegotiationRequired => "IcmpReplyIdNegotiationRequired",
        RejectionReason::IcmpSourceEndpointMismatch => "IcmpSourceEndpointMismatch",
        RejectionReason::IcmpReplyIdRenegotiationMismatch => "IcmpReplyIdRenegotiationMismatch",
        RejectionReason::UnsupportedDisjointReplyId => "UnsupportedDisjointReplyId",
        RejectionReason::PayloadOversize => "PayloadOversize",
        RejectionReason::InvalidPayloadBounds => "InvalidPayloadBounds",
    }
}

fn malformed_reason_name(reason: RejectionReason) -> Option<&'static str> {
    match reason {
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
            crate::net::packet_headers::IcmpMalformedReason::SessionControlMissingReplyId => {
                "SessionControlMissingReplyId"
            }
            crate::net::packet_headers::IcmpMalformedReason::SessionControlReplyIdLength => {
                "SessionControlReplyIdLength"
            }
        }),
        _ => None,
    }
}

fn parsed_icmp_json(icmp: ParsedIcmpEcho) -> Value {
    json!({
        "type": if icmp.is_req { "echo-request" } else { "echo-reply" },
        "code": 0,
        "echo_identifier": icmp.identity.destination_id,
        "sequence": icmp.seq,
        "shim_flags": icmp.shim_flags.map(|shim| format!("0x{shim:02x}")),
        "logical_source_id": icmp.identity.source_id,
        "logical_destination_id": icmp.identity.destination_id,
    })
}

fn bounded_hex(bytes: &[u8]) -> (String, bool) {
    let shown = &bytes[..bytes.len().min(PACKET_DUMP_HEX_LIMIT)];
    let mut hex = String::with_capacity(shown.len() * 2);
    for byte in shown {
        write!(&mut hex, "{byte:02x}").expect("write to String cannot fail");
    }
    (hex, shown.len() != bytes.len())
}

fn socket_source_string(source: &SockAddr) -> Option<String> {
    source.as_socket().map(|addr| addr.to_string())
}

fn protocol_name(proto: SupportedProtocol) -> &'static str {
    match proto {
        SupportedProtocol::UDP => "UDP",
        SupportedProtocol::ICMP => "ICMP",
    }
}

fn socket_type_name(sock_type: Type) -> &'static str {
    if sock_type == Type::DGRAM {
        "DGRAM"
    } else if sock_type == Type::RAW {
        "RAW"
    } else if sock_type == Type::STREAM {
        "STREAM"
    } else {
        "OTHER"
    }
}

fn role_name(role: SocketLeg) -> &'static str {
    match role {
        SocketLeg::ClientFacing => "client",
        SocketLeg::UpstreamFacing => "upstream",
    }
}

fn transport_name(transport: ParsedTransport) -> &'static str {
    match transport {
        ParsedTransport::UdpDatagram => "UdpDatagram",
        ParsedTransport::HeaderlessIcmp => "HeaderlessIcmp",
        ParsedTransport::Ipv4Icmp => "Ipv4Icmp",
        ParsedTransport::Ipv6Icmp => "Ipv6Icmp",
        ParsedTransport::Ipv4Udp => "Ipv4Udp",
        ParsedTransport::Ipv6Udp => "Ipv6Udp",
        ParsedTransport::Unsupported => "Unsupported",
        ParsedTransport::Malformed => "Malformed",
    }
}

fn ip_version(transport: ParsedTransport) -> Option<u8> {
    match transport {
        ParsedTransport::UdpDatagram => None,
        ParsedTransport::Ipv4Icmp | ParsedTransport::Ipv4Udp => Some(4),
        ParsedTransport::Ipv6Icmp | ParsedTransport::Ipv6Udp => Some(6),
        _ => None,
    }
}

fn payload_event_kind(event: &PayloadEvent<'_>) -> &'static str {
    match event {
        PayloadEvent::UserPayload { .. } => "user-payload",
        PayloadEvent::SessionControl { .. } => "session-control",
        PayloadEvent::CadencePacket { .. } => "cadence",
    }
}

fn flow_endpoint_string(endpoint: FlowEndpoint) -> String {
    endpoint.canonical().to_string()
}

fn flow_tuple_string(flow: FlowTuple) -> String {
    format!(
        "{} -> {}",
        flow_endpoint_string(flow.src),
        flow_endpoint_string(flow.dst)
    )
}

fn client_flow_key_string(flow_key: ClientFlowKey) -> String {
    flow_key.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        PACKET_DUMP_HEX_LIMIT, PacketDumpRecord, admission_json, base_packet_dump_json,
        bounded_hex, parsed_headers_json,
    };
    use crate::cli::SupportedProtocol;
    use crate::net::packet_headers::{ParsedPacketHeaders, ParsedTransport};
    use crate::worker_support::packet_admission::{
        RejectedPacket, WirePacketAdmission, test_support,
    };
    use pkthere_socket_policy::{
        PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy,
    };
    use socket2::Type;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn packet_dump_caps_hex_payload() {
        let bytes = vec![0xab; PACKET_DUMP_HEX_LIMIT + 1];
        let (hex, truncated) = bounded_hex(&bytes);
        assert!(truncated);
        assert_eq!(hex.len(), PACKET_DUMP_HEX_LIMIT * 2);
    }

    #[test]
    fn admission_json_reports_filtered_reason() {
        let admission = WirePacketAdmission::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: None,
            reason: crate::worker_support::RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
            )),
        });
        let json = admission_json(&admission);
        assert_eq!(json["result"], "filtered");
        assert_eq!(json["reason"], "MalformedIcmpHeader");
        assert_eq!(json["malformed_reason"], "InvalidShimFlags");
    }

    #[test]
    fn parsed_json_reports_udp_fields() {
        let parsed = ParsedPacketHeaders {
            transport: ParsedTransport::Ipv4Udp,
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            udp: Some(crate::net::packet_headers::ParsedUdpHeader {
                src_port: 40000,
                dst_port: 9999,
            }),
            icmp: None,
            payload_bounds: (28, 32),
            icmp_malformed_reason: None,
        };
        let json = parsed_headers_json(&parsed);
        assert_eq!(json["transport"], "Ipv4Udp");
        assert_eq!(json["udp"]["src_port"], 40000);
        assert_eq!(json["udp"]["dst_port"], 9999);
    }

    #[test]
    fn packet_dump_base_json_includes_socket_metadata() {
        let parsed = ParsedPacketHeaders {
            transport: ParsedTransport::Unsupported,
            src_ip: None,
            dst_ip: None,
            udp: None,
            icmp: None,
            payload_bounds: (0, 0),
            icmp_malformed_reason: None,
        };
        let spec = test_support::admission_spec(
            crate::worker_support::SocketLeg::ClientFacing,
            SupportedProtocol::UDP,
            Type::DGRAM,
            ReceiveEvidencePolicy {
                peer_source: PeerSourceRequirement::SourceMetadata,
                protocol_id: ProtocolIdRequirement::None,
            },
            None,
            Some(8080),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        let json = base_packet_dump_json(
            "received",
            PacketDumpRecord {
                worker_id: 7,
                c2u: true,
                packet_id: 11,
                spec,
                bytes: b"abc",
                socket_source: None,
                parsed: &parsed,
            },
        );
        assert_eq!(json["event"], "packet_dump");
        assert_eq!(json["worker"], 7);
        assert_eq!(json["packet_id"], 11);
        assert_eq!(json["socket"]["protocol"], "UDP");
        assert!(json["socket"].get("parser_kernel").is_none());
        assert_eq!(json["socket"]["receive_header"], "PayloadOnly");
        assert_eq!(json["socket"]["receive_syscall"], "recv_from");
        assert_eq!(json["socket"]["source_evidence"], "SourceMetadata");
        assert_eq!(json["socket"]["local_kernel_addr"], "127.0.0.1:8080");
        assert_eq!(json["socket"]["evidence_key"]["socket_slot"], 0);
        assert!(json["socket"].get("local_kernel").is_none());
    }
}
