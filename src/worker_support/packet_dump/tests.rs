use super::{
    PACKET_DUMP_HEX_LIMIT, PacketAdmissionSummary, PacketDumpAdmissionContext, PacketDumpContext,
    PacketDumpRecord, ReceivedPacketAdmission, admission_json, admit_received_packet_with_dump,
    base_packet_dump_json, bounded_hex, compact_packet_admission_json, packet_parse_record_json,
    parsed_headers_json,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::diagnostics::PacketTraceId;
use crate::flow_key::ClientFlowKey;
use crate::net::framing_shim::SessionId;
use crate::net::packet_headers::{ParsedNetworkLayer, ParsedPacketHeaders, ParsedTransport};
use crate::worker_support::packet_admission::{RejectedPacket, test_support};
use pkthere_socket_policy::{PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

#[test]
fn unknown_session_spends_work_budget_before_session_classification() {
    let mut spec = test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(1001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    spec.admission.expected_session_id = SessionId::new(2);
    let packet = test_support::icmp_data_packet(1001, true, 2002, b"unknown");
    let source = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let cfg = test_support::test_config(IcmpReplyIdRequest::Fixed(1001));
    let now = Instant::now();
    let mut budget = super::super::work_budget::AuthenticatedFrameBudget::new();
    let mut detail_budget = super::super::work_budget::PacketDumpDetailBudget::new();
    while budget.take(now) {}

    let result = admit_received_packet_with_dump(
        PacketDumpAdmissionContext {
            cfg: &cfg,
            trace: PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            spec: spec.as_receive_context(),
            received_at: now,
        },
        &packet,
        Some(source),
        &mut budget,
        &mut detail_budget,
    );

    assert!(matches!(
        result,
        ReceivedPacketAdmission {
            admission: None,
            authenticated_work_charged: false,
            ..
        }
    ));
}

#[test]
fn valid_active_data_bypasses_authenticated_work_budget() {
    let mut spec = test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(1001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    spec.admission.expected_session_id = Some(SessionId::for_tests());
    spec.admission.locked_flow = Some(ClientFlowKey::Icmp(
        crate::endpoint::LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002),
    ));
    let packet = test_support::icmp_data_packet(1001, true, 2002, b"active");
    let source = std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let cfg = test_support::test_config(IcmpReplyIdRequest::Fixed(1001));
    let now = Instant::now();
    let mut budget = super::super::work_budget::AuthenticatedFrameBudget::new();
    let mut detail_budget = super::super::work_budget::PacketDumpDetailBudget::new();
    while budget.take(now) {}
    let result = admit_received_packet_with_dump(
        PacketDumpAdmissionContext {
            cfg: &cfg,
            trace: PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            spec: spec.as_receive_context(),
            received_at: now,
        },
        &packet,
        Some(source),
        &mut budget,
        &mut detail_budget,
    );
    assert!(matches!(
        result,
        ReceivedPacketAdmission {
            admission: Some(Ok(_)),
            authenticated_work_charged: false,
            ..
        }
    ));
}

#[test]
fn disabled_diagnostics_leave_locked_udp_admission_allocation_free() {
    const PACKET_COUNT: u64 = 10_000;
    let remote_address = SocketAddr::from((Ipv4Addr::LOCALHOST, 2002));
    let remote = crate::endpoint::LogicalEndpoint::from_socket_addr(remote_address);
    let mut spec = test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        Some(remote),
        Some(1001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    spec.admission.locked_flow = Some(ClientFlowKey::Udp(remote));
    let source = remote_address;
    let mut cfg = test_support::test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    assert!(!cfg.debug_logs.packet_dump);
    let now = Instant::now();
    let mut budget = super::super::work_budget::AuthenticatedFrameBudget::new();
    let mut detail_budget = super::super::work_budget::PacketDumpDetailBudget::new();

    let (((all_stable, payload_copies), endpoint_normalizations), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_endpoint_normalizations(|| {
                crate::allocation_test_support::count_payload_copies(|| {
                    (0..PACKET_COUNT).all(|packet_id| {
                        let result = admit_received_packet_with_dump(
                            PacketDumpAdmissionContext {
                                cfg: &cfg,
                                trace: PacketTraceId {
                                    worker_id: 0,
                                    c2u: true,
                                    packet_id,
                                },
                                spec: spec.as_receive_context(),
                                received_at: now,
                            },
                            b"payload",
                            Some(source),
                            &mut budget,
                            &mut detail_budget,
                        );
                        matches!(
                            result,
                            ReceivedPacketAdmission {
                                admission: Some(Ok(ref admitted)),
                                deferred_dump: None,
                                ..
                            } if admitted.lock_candidate().is_none()
                        )
                    })
                })
            })
        });

    assert!(all_stable);
    assert_eq!(allocations, 0);
    assert_eq!(payload_copies, 0);
    assert_eq!(endpoint_normalizations, 0);
}

#[test]
fn packet_dump_caps_hex_payload() {
    let bytes = vec![0xab; PACKET_DUMP_HEX_LIMIT + 1];
    let (hex, truncated) = bounded_hex(&bytes);
    assert!(truncated);
    assert_eq!(hex.len(), PACKET_DUMP_HEX_LIMIT * 2);
}

#[test]
fn admission_json_reports_filtered_reason() {
    let admission = Err(
        crate::worker_support::packet_admission::WirePacketRejection::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: None,
            reason: crate::worker_support::RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
            )),
        }),
    );
    let json = admission_json(PacketAdmissionSummary::capture(&admission));
    assert_eq!(json["result"], "filtered");
    assert_eq!(json["reason"], "MalformedIcmpHeader");
    assert_eq!(json["malformed_reason"], "InvalidShimFlags");
}

#[test]
fn parsed_json_reports_udp_fields() {
    let parsed = ParsedPacketHeaders {
        network: ParsedNetworkLayer::Valid(crate::net::packet_headers::ParsedNetworkHeader {
            version: crate::net::packet_headers::IpVersion::V4,
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ipv6_flow_label: None,
            protocol: 17,
            packet_end: 32,
            transport_offset: 20,
        }),
        transport: ParsedTransport::Udp,
        udp: Some(crate::net::packet_headers::ParsedUdpHeader {
            src_port: 40000,
            dst_port: 9999,
        }),
        icmp: None,
        packet_bounds: (0, 32),
        transport_bounds: (20, 32),
        payload_bounds: (28, 32),
        icmp_malformed_reason: None,
    };
    let json = parsed_headers_json(&parsed);
    assert_eq!(json["transport"], "Udp");
    assert_eq!(json["udp"]["src_port"], 40000);
    assert_eq!(json["udp"]["dst_port"], 9999);
}

#[test]
fn packet_parse_json_separates_network_and_transport_failures() {
    let malformed_network = ParsedPacketHeaders {
        network: ParsedNetworkLayer::Malformed(
            crate::net::packet_headers::IpMalformedReason::MissingHeader,
        ),
        transport: ParsedTransport::UnrelatedProtocol,
        udp: None,
        icmp: None,
        packet_bounds: (0, 0),
        transport_bounds: (0, 0),
        payload_bounds: (0, 0),
        icmp_malformed_reason: None,
    };
    let network_json = packet_parse_record_json(&malformed_network);
    assert_eq!(network_json["kind"], "malformed-network");
    assert_eq!(network_json["network_reason"], "MissingHeader");
    assert!(network_json.get("icmp_reason").is_none());

    let malformed_transport = ParsedPacketHeaders {
        network: ParsedNetworkLayer::NotPresent,
        transport: ParsedTransport::MalformedIcmp,
        udp: None,
        icmp: None,
        packet_bounds: (0, 8),
        transport_bounds: (0, 8),
        payload_bounds: (8, 8),
        icmp_malformed_reason: Some(
            crate::net::packet_headers::IcmpMalformedReason::InvalidEchoTypeOrCode,
        ),
    };
    let transport_json = packet_parse_record_json(&malformed_transport);
    assert_eq!(transport_json["kind"], "malformed-transport");
    assert_eq!(transport_json["icmp_reason"], "InvalidEchoTypeOrCode");
    assert!(transport_json.get("network_reason").is_none());
}

#[test]
fn packet_dump_base_json_includes_socket_metadata() {
    let parsed = ParsedPacketHeaders {
        network: ParsedNetworkLayer::NotPresent,
        transport: ParsedTransport::UnrelatedProtocol,
        udp: None,
        icmp: None,
        packet_bounds: (0, 0),
        transport_bounds: (0, 0),
        payload_bounds: (0, 0),
        icmp_malformed_reason: None,
    };
    let spec = test_support::synthetic_receive_context(
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
            context: PacketDumpContext::capture(spec.as_receive_context()),
            bytes: b"abc",
            socket_source: None,
            parsed,
            include_detail: true,
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
    assert_eq!(json["socket"]["evidence_key"]["socket_slot"], 0);
    assert!(json["socket"].get("local_kernel_addr").is_none());
    assert!(json["socket"].get("remote_filter").is_none());
    assert!(json["socket"].get("local_kernel").is_none());
}

#[test]
fn suppressed_admission_retains_socket_generation_and_parsed_ids() {
    let parsed = ParsedPacketHeaders {
        network: ParsedNetworkLayer::NotPresent,
        transport: ParsedTransport::Icmp,
        udp: None,
        icmp: Some(crate::net::packet_headers::ParsedIcmpEcho {
            identity: crate::net::packet_headers::WireIcmpIdentity {
                source_id: Some(7777),
                destination_id: 40001,
            },
            session_id: SessionId::for_tests().get(),
            seq: 7,
            is_req: false,
            shim_flags: Some(0),
        }),
        packet_bounds: (0, 31),
        transport_bounds: (0, 31),
        payload_bounds: (31, 31),
        icmp_malformed_reason: None,
    };
    let spec = test_support::synthetic_receive_context(
        crate::worker_support::SocketLeg::UpstreamFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(40001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let record = PacketDumpRecord {
        worker_id: 1,
        c2u: false,
        packet_id: 9,
        context: PacketDumpContext::capture(spec.as_receive_context()),
        bytes: &[],
        socket_source: None,
        parsed,
        include_detail: false,
    };
    let admission = PacketAdmissionSummary {
        kind: super::PacketAdmissionKind::Accepted,
        accepted: None,
        receive_noise: None,
        filtered: None,
    };

    let json = compact_packet_admission_json(record, admission);
    assert_eq!(json["socket"]["evidence_key"]["generation"], 1);
    assert_eq!(json["parse"]["headers"]["icmp"]["logical_source_id"], 7777);
    assert_eq!(
        json["parse"]["headers"]["icmp"]["logical_destination_id"],
        40001
    );
}
