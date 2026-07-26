use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, admit_packet, admit_wire_packet,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::packet_headers::{SHIM_IS_CADENCE, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER};
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    icmp_cadence_packet, icmp_negotiate_packet, icmp_raw_shim_packet, icmp_v6_cadence_packet,
    icmp_wire_spec, set_test_ipv4_receive_length, synthetic_receive_context, test_config,
    test_icmp_echo_packet,
};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn connected_icmp_cadence_uses_kernel_filtered_expected_peer() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let mut spec = icmp_wire_spec(Some(FlowTuple::new(remote, local)), None);
    spec.socket.role = SocketLeg::UpstreamFacing;
    spec.socket.sock_type = Type::DGRAM;
    spec.socket.policy.receive_evidence.unconnected = ReceiveEvidencePolicy {
        peer_source: PeerSourceRequirement::ConnectedKernel,
        protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
    };
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    spec.admission.expected_session_id = Some(crate::net::framing_shim::SessionId::for_tests());

    let packet = icmp_cadence_packet(1001, false, 2002);
    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, None) {
        Ok(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(
        admitted.normalized_source,
        Some(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002))
    );
    assert!(matches!(admitted.event, PayloadEvent::CadencePacket { .. }));
    assert!(admitted.lock_candidate().is_none());
    assert!(admitted.pending_negotiation().is_none());
}

#[test]
fn icmp_raw_ipv6_headerless_requires_socket_metadata_source() {
    let spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    );
    let packet = icmp_v6_cadence_packet(1001, true, 1001);
    assert!(matches!(
        admit_packet(spec, &packet, None),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn icmp_transport_admission_uses_header_parser_source_and_body() {
    let spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let mut packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1001,
        true,
    );
    packet.truncate(packet.len() - 9);
    let mut packet = packet
        .into_iter()
        .chain(
            [SHIM_IS_DATA, 0x20, 0x02]
                .into_iter()
                .chain(1_u64.to_be_bytes())
                .chain(*b"x"),
        )
        .collect::<Vec<_>>();
    set_test_ipv4_receive_length(&mut packet);
    let admitted = match admit_packet(spec, &packet, None) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(
        admitted
            .icmp_identity()
            .expect("ICMP admission carries validated identity")
            .remote_source_id(),
        0x2002
    );
    assert_eq!(admitted.payload, b"x");
    assert_eq!(admitted.reply_id_negotiation, None);
}

#[test]
fn compact_icmp_identity_rejects_zero_header_id() {
    let spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let mut body = vec![SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER];
    body.extend_from_slice(&1_u64.to_be_bytes());
    let packet = icmp_raw_shim_packet(0, true, &body);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();

    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason
                == RejectionReason::MalformedIcmpHeader(Some(
                    crate::net::packet_headers::IcmpMalformedReason::ZeroSourceId
                ))
    ));
}

#[test]
fn wire_admission_accepts_compact_session_control_before_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 1001, 0x3003, false);
    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(None, None),
        &packet,
        Some(&source),
    ) {
        Ok(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert!(admitted.pending_negotiation().is_some());
}

#[test]
fn wire_admission_rejects_reserved_control_flags_before_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_raw_shim_packet(1001, true, &[0x40, 0x20, 0x02, 3, 1, 0x30, 0x03]);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if matches!(
                rej.reason,
                RejectionReason::MalformedIcmpHeader(Some(
                    crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags
                ))
            )
    ));
}

#[test]
fn wire_admission_rejects_session_control_with_truncated_reply_id() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_raw_shim_packet(1001, true, &[SHIM_SOURCE_ID_EQUALS_HEADER, 3, 1, 0x03]);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if matches!(
                rej.reason,
                RejectionReason::MalformedIcmpHeader(Some(
                    crate::net::packet_headers::IcmpMalformedReason::SessionControlReplyIdLength
                ))
            )
    ));
}

#[test]
fn wire_admission_dgram_accepts_independent_source_id_when_reply_id_matches_receive_id() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 1001, false);
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let admitted = match admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) {
        Ok(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let lock = admitted
        .pending_negotiation()
        .expect("pending negotiation candidate");
    assert_eq!(
        lock.flow_key,
        ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            0x2002
        ))
    );
    let inbound = lock.listener_flow.inbound.expect("inbound tuple");
    assert_eq!(inbound.src.id(), 0x2002);
    assert_eq!(inbound.dst.id(), 1001);
    let outbound = lock.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(outbound.dst.id(), 1001);
}
