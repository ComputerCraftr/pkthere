use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, WirePacketAdmission, admit_packet, admit_wire_packet,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    admission_spec, icmp_tunnel_packet, icmp_wire_spec, test_config, test_icmp_echo_packet,
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

    let packet = icmp_tunnel_packet(1001, false, &[]);
    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, None) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(
        admitted.normalized_source,
        Some(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002))
    );
    assert!(matches!(admitted.event, PayloadEvent::CadencePacket { .. }));
    assert!(admitted.lock_candidate.is_none());
    assert!(admitted.pending_negotiation.is_none());
}

#[test]
fn icmp_raw_ipv6_headerless_requires_socket_metadata_source() {
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    );
    let packet = icmp_tunnel_packet(1001, true, &[]);
    assert!(matches!(
        admit_packet(spec, &packet, None),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn icmp_transport_admission_uses_header_parser_source_and_body() {
    let spec = admission_spec(
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
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1001,
        true,
    )
    .into_iter()
    .chain([0x80, 0x20, 0x02, b'x'])
    .collect::<Vec<_>>();
    let admitted = match admit_packet(spec, &packet, None) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(admitted.flow_identity.remote_source_id, 0x2002);
    assert_eq!(admitted.payload, b"x");
    assert_eq!(admitted.reply_id_negotiation, None);
}

#[test]
fn wire_admission_accepts_compact_session_control_before_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x58, 0x30, 0x03]); // Compact SessionControl, reply ID 0x3003
    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(None, None),
        &packet,
        Some(&source),
    ) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert!(admitted.pending_negotiation.is_some());
}

#[test]
fn wire_admission_rejects_session_control_without_reply_id_bit_before_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x40, 0x20, 0x02, 0x30, 0x03]); // Missing SHIM_HAS_REPLY_ID (0x08)
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej)
            if matches!(
                rej.reason,
                RejectionReason::MalformedIcmpHeader(Some(
                    crate::net::packet_headers::IcmpMalformedReason::SessionControlMissingReplyId
                ))
            )
    ));
}

#[test]
fn wire_admission_rejects_session_control_with_truncated_reply_id() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x58, 0x03]);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej)
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
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x03, 0xE9]);
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let admitted = match admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let lock = admitted
        .pending_negotiation
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
