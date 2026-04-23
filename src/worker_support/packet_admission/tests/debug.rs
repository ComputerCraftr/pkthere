use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, WirePacketAdmission, admit_packet, admit_wire_packet,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::flow_key::{ClientFlowKey, FlowEndpoint, FlowTuple};
use crate::net::params::CanonicalAddr;
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    admission_spec, icmp_tunnel_packet, icmp_wire_spec, test_config,
};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn connected_kernel_filter_evidence_scopes_reflected_negotiation_policy() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let packet = icmp_tunnel_packet(1001, false, &[0x48, 0x03, 0xE9, 0x03, 0xE9]);
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut v4_spec = icmp_wire_spec(
        Some(FlowTuple::new(
            FlowEndpoint::new(v4, 1001),
            FlowEndpoint::new(v4, 1001),
        )),
        None,
    );
    v4_spec.socket.role = SocketLeg::UpstreamFacing;
    v4_spec.socket.policy.receive_evidence.unconnected = ReceiveEvidencePolicy {
        peer_source: PeerSourceRequirement::ConnectedKernel,
        protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
    };

    v4_spec
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .allow_debug_kernel_echo_self_handshake = true;
    v4_spec
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &packet, None),
        WirePacketAdmission::Accepted(_)
    ));

    let mut no_policy = v4_spec;
    no_policy
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .allow_debug_kernel_echo_self_handshake = false;
    assert!(matches!(
        admit_wire_packet(false, &cfg, no_policy, &packet, None),
        WirePacketAdmission::Filtered(_)
    ));

    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let local_v6 = FlowEndpoint::new(v6, 1001);
    let mut v6_spec = icmp_wire_spec(Some(FlowTuple::new(local_v6, local_v6)), None);
    v6_spec.socket.role = SocketLeg::UpstreamFacing;
    v6_spec.socket.policy.receive_evidence.unconnected = ReceiveEvidencePolicy {
        peer_source: PeerSourceRequirement::ConnectedKernel,
        protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
    };
    v6_spec
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .allow_debug_kernel_echo_self_handshake = true;
    v6_spec
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    v6_spec.socket.local_filter = CanonicalAddr::from_v6(Ipv6Addr::LOCALHOST, 1001, 0, 0);
    v6_spec.admission.expected_local = Some(local_v6);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v6_spec, &packet, None),
        WirePacketAdmission::Accepted(_)
    ));

    let user_payload = icmp_tunnel_packet(1001, false, &[0x90, b'x']);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &user_payload, None),
        WirePacketAdmission::Accepted(_)
    ));

    let mut locked_self_payload = v4_spec;
    locked_self_payload.admission.locked_flow = Some(ClientFlowKey::IcmpV4 {
        ip: Ipv4Addr::LOCALHOST,
        ident: 1001,
    });
    assert!(matches!(
        admit_wire_packet(false, &cfg, locked_self_payload, &user_payload, None),
        WirePacketAdmission::Accepted(_)
    ));

    let missing_reply_id = icmp_tunnel_packet(1001, false, &[0x40, 0x03, 0xE9]);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &missing_reply_id, None),
        WirePacketAdmission::Filtered(rej)
            if matches!(rej.reason, RejectionReason::MalformedIcmpHeader(_))
    ));

    let wrong_reply_id = icmp_tunnel_packet(1001, false, &[0x48, 0x03, 0xE9, 0x03, 0xEA]);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &wrong_reply_id, None),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::IcmpReplyIdRenegotiationMismatch
    ));

    let mut disjoint_capable = v4_spec;
    disjoint_capable
        .socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::DisjointIds;
    assert!(matches!(
        admit_wire_packet(false, &cfg, disjoint_capable, &packet, None),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::IcmpReplyIdRenegotiationMismatch
    ));

    let mut wrong_role = v4_spec;
    wrong_role.socket.role = SocketLeg::ClientFacing;
    let request_packet = icmp_tunnel_packet(1001, true, &[0x48, 0x03, 0xE9, 0x03, 0xE9]);
    assert!(matches!(
        admit_wire_packet(true, &cfg, wrong_role, &request_packet, None),
        WirePacketAdmission::Accepted(_)
    ));
}

#[test]
fn wire_admission_accepts_disjoint_session_control_ack_source_and_reply_ids() {
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut spec = icmp_wire_spec(
        Some(FlowTuple::new(
            FlowEndpoint::new(v4, 9999),
            FlowEndpoint::new(v4, 40001),
        )),
        None,
    );
    spec.socket.role = SocketLeg::UpstreamFacing;
    let packet = icmp_tunnel_packet(40001, false, &[0x28, 0x1E, 0x61, 0x27, 0x0F]);
    let source = SocketAddr::new(v4, 0).into();
    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let PayloadEvent::SessionControl { icmp, .. } = admitted.event else {
        panic!("unexpected event: {:?}", admitted.event);
    };
    assert_eq!(icmp.flow_identity().remote_source_id, 7777);
    assert_eq!(icmp.inbound_header_ident(), 40001);
    assert_eq!(icmp.advertised_reply_id(), Some(9999));
    assert!(icmp.acknowledges_reply_id());
    assert!(!icmp.negotiates_reply_id());
}

#[test]
fn icmp_direction_is_derived_from_client_role() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let spec = admission_spec(
        SocketLeg::ClientFacing,
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
    let packet = icmp_tunnel_packet(1001, false, &[]);
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::ReceiveNoise(_)
    ));
}

#[test]
fn icmp_direction_is_derived_from_upstream_role() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let spec = admission_spec(
        SocketLeg::UpstreamFacing,
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
    let packet = icmp_tunnel_packet(1001, true, &[]);
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::ReceiveNoise(_)
    ));
}

#[test]
fn icmp_ipv6_raw_admission_preserves_metadata_scope_when_available() {
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
        None,
    );
    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[6] = 58;
    packet[8..24].copy_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
    packet[40] = 128;
    packet[44..46].copy_from_slice(&1001u16.to_be_bytes());

    let source = SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        0,
    )
    .into();
    let mut source = CanonicalAddr::from_sock_addr(&source).unwrap();
    if let SocketAddr::V6(v6) = &mut source.addr {
        v6.set_scope_id(7);
    }

    let admitted = match admit_packet(spec, &packet, Some(&source.addr.into())) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let actual_source = admitted.normalized_source.unwrap();
    assert_eq!(
        actual_source.addr.ip(),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
    );
    if let SocketAddr::V6(v6) = actual_source.addr {
        assert_eq!(v6.scope_id(), 7);
    } else {
        panic!("expected IPv6 source");
    }
    assert_eq!(actual_source.id, 1001);
}
