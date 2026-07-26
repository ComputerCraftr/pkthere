use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, admit_packet, admit_wire_packet,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    icmp_cadence_packet, icmp_data_packet, icmp_negotiate_packet, icmp_raw_shim_packet,
    icmp_v6_cadence_packet, icmp_wire_spec, synthetic_receive_context, test_config,
    test_icmp_echo_packet,
};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn connected_kernel_filter_evidence_scopes_reflected_negotiation_policy() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let packet = icmp_negotiate_packet(1001, false, 1001, 1001, false);
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut v4_spec = icmp_wire_spec(
        Some(FlowTuple::new(
            LogicalEndpoint::new(v4, 1001),
            LogicalEndpoint::new(v4, 1001),
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
    assert!(admit_wire_packet(false, &cfg, v4_spec, &packet, None).is_ok());

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
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(_))
    ));

    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let local_v6 = LogicalEndpoint::new(v6, 1001);
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
    v6_spec.socket.local_filter = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 1001, 0);
    v6_spec.admission.expected_local = Some(local_v6);
    assert!(admit_wire_packet(false, &cfg, v6_spec, &packet, None).is_ok());

    let user_payload = icmp_data_packet(1001, false, 1001, b"x");
    v4_spec.admission.expected_session_id = Some(crate::net::framing_shim::SessionId::for_tests());
    assert!(admit_wire_packet(false, &cfg, v4_spec, &user_payload, None).is_ok());

    let mut locked_self_payload = v4_spec;
    locked_self_payload.admission.locked_flow = Some(ClientFlowKey::Icmp(
        LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 1001),
    ));
    assert!(admit_wire_packet(false, &cfg, locked_self_payload, &user_payload, None).is_ok());

    let missing_reply_id = icmp_raw_shim_packet(1001, false, &[0x10, 3, 1, 0x03]);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &missing_reply_id, None),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if matches!(rej.reason, RejectionReason::MalformedIcmpHeader(_))
    ));

    let wrong_reply_id = icmp_negotiate_packet(1001, false, 1001, 1002, false);
    assert!(matches!(
        admit_wire_packet(false, &cfg, v4_spec, &wrong_reply_id, None),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if rej.reason == RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection
            ))
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
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if rej.reason == RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection
            ))
    ));

    let mut wrong_role = v4_spec;
    wrong_role.socket.role = SocketLeg::ClientFacing;
    let request_packet = icmp_negotiate_packet(1001, true, 1001, 1001, false);
    assert!(admit_wire_packet(true, &cfg, wrong_role, &request_packet, None).is_ok());
}

#[test]
fn wire_admission_accepts_disjoint_session_control_ack_source_and_reply_ids() {
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut spec = icmp_wire_spec(
        Some(FlowTuple::new(
            LogicalEndpoint::new(v4, 9999),
            LogicalEndpoint::new(v4, 40001),
        )),
        None,
    );
    spec.socket.role = SocketLeg::UpstreamFacing;
    let packet = icmp_negotiate_packet(40001, false, 7777, 9999, true);
    let source = SocketAddr::new(v4, 0).into();
    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, Some(&source)) {
        Ok(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let PayloadEvent::SessionControl { icmp, .. } = admitted.event else {
        panic!("unexpected event: {:?}", admitted.event);
    };
    assert_eq!(icmp.flow_identity().remote_source_id(), 7777);
    assert_eq!(icmp.inbound_header_ident(), 40001);
    assert_eq!(icmp.advertised_reply_id(), Some(9999));
    assert!(icmp.acknowledges_reply_id());
    assert!(!icmp.negotiates_reply_id());
}

#[test]
fn wire_admission_ack_identity_learning_keeps_destination_id_strict() {
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut spec = icmp_wire_spec(
        Some(FlowTuple::new(
            LogicalEndpoint::new(v4, 9999),
            LogicalEndpoint::new(v4, 40001),
        )),
        None,
    );
    spec.socket.role = SocketLeg::UpstreamFacing;
    let packet = icmp_negotiate_packet(40002, false, 7777, 9999, true);
    let source = SocketAddr::new(v4, 0).into();
    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source)),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected))
            if rejected.reason == RejectionReason::UnexpectedLocalReceiveId
    ));
}

#[test]
fn wire_admission_ack_identity_learning_keeps_peer_ip_strict() {
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let expected_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut spec = icmp_wire_spec(
        Some(FlowTuple::new(
            LogicalEndpoint::new(expected_ip, 9999),
            LogicalEndpoint::new(expected_ip, 40001),
        )),
        None,
    );
    spec.socket.role = SocketLeg::UpstreamFacing;
    let packet = icmp_negotiate_packet(40001, false, 7777, 9999, true);
    let wrong_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&wrong_source)),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected))
            if rejected.reason == RejectionReason::UnexpectedRemotePeer
    ));
}

#[test]
fn icmp_direction_is_derived_from_client_role() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let spec = synthetic_receive_context(
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
    let packet = icmp_cadence_packet(1001, false, 1001);
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::ReceiveNoise(_)
    ));
}

#[test]
fn icmp_direction_is_derived_from_upstream_role() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let spec = synthetic_receive_context(
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
    let packet = icmp_cadence_packet(1001, true, 1001);
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::ReceiveNoise(_)
    ));
}

#[test]
fn icmp_ipv6_raw_admission_preserves_metadata_scope_when_available() {
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
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let packet = icmp_v6_cadence_packet(1001, true, 1001);

    let source = LogicalEndpoint::from_socket_addr(SocketAddr::V6(std::net::SocketAddrV6::new(
        link_local, 0, 0x1_2345, 7,
    )));

    let admitted = match admit_packet(spec, &packet, Some(&source.to_sock_addr())) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let actual_source = admitted.normalized_source.unwrap();
    assert_eq!(
        actual_source.ip(),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(actual_source.scope_id(), 7);
    assert_eq!(actual_source.id(), 1001);
}

#[test]
fn icmp_ipv6_raw_link_local_destination_requires_concrete_interface_evidence() {
    let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
    let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V6(source_ip)),
        Some(IpAddr::V6(destination_ip)),
        1001,
        true,
    );
    let source = socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(
        source_ip, 0, 0, 0,
    )));
    let mut unscoped = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V6(destination_ip)),
    );
    unscoped.socket.local_filter = LogicalEndpoint::from_v6(destination_ip, 1001, 0);
    let rejected = match admit_packet(unscoped, &packet, Some(&source)) {
        TransportAdmission::Filtered(rejected) => rejected,
        other => panic!("missing destination scope unexpectedly admitted: {other:?}"),
    };
    assert_eq!(
        rejected.reason,
        RejectionReason::UnexpectedLocalReceiveAddress
    );

    let mut scoped = unscoped;
    scoped.socket.local_filter = LogicalEndpoint::from_v6(destination_ip, 1001, 9);
    scoped.socket.local_kernel_addr =
        SocketAddr::V6(std::net::SocketAddrV6::new(destination_ip, 1001, 0, 9));
    assert!(matches!(
        admit_packet(scoped, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));

    let mut conflicting = scoped;
    conflicting.socket.local_kernel_addr =
        SocketAddr::V6(std::net::SocketAddrV6::new(destination_ip, 1001, 0, 10));
    assert!(matches!(
        admit_packet(conflicting, &packet, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason == RejectionReason::UnexpectedLocalReceiveAddress
    ));

    let mut unsupported = scoped;
    unsupported.socket.policy.ipv6_destination_scope =
        pkthere_socket_policy::Ipv6DestinationScopeEvidence::NotApplicable;
    assert!(matches!(
        admit_packet(unsupported, &packet, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason == RejectionReason::UnexpectedLocalReceiveAddress
    ));
}

#[test]
fn icmp_ipv6_raw_global_destination_does_not_require_interface_scope_evidence() {
    let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
    let destination_ip = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2);
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V6(source_ip)),
        Some(IpAddr::V6(destination_ip)),
        1001,
        true,
    );
    let source = socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(
        source_ip, 0, 0, 0,
    )));
    let mut spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        Some(IpAddr::V6(destination_ip)),
    );
    spec.socket.local_filter = LogicalEndpoint::from_v6(destination_ip, 1001, 0);
    spec.socket.local_kernel_addr =
        SocketAddr::V6(std::net::SocketAddrV6::new(destination_ip, 1001, 0, 0));
    spec.socket.policy.ipv6_destination_scope =
        pkthere_socket_policy::Ipv6DestinationScopeEvidence::NotApplicable;

    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));
}

#[test]
fn icmp_ipv6_raw_link_local_source_requires_matching_scoped_metadata() {
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
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    );
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V6(link_local)),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        1001,
        true,
    );
    let missing_scope = socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(
        link_local, 0, 0, 0,
    )));
    let wrong_ip = socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
        0,
        0,
        7,
    )));

    for source in [&missing_scope, &wrong_ip] {
        let rejected = match admit_packet(spec, &packet, Some(source)) {
            TransportAdmission::Filtered(rejected) => rejected,
            other => panic!("unexpected admission: {other:?}"),
        };
        assert_eq!(rejected.reason, RejectionReason::MissingSourceEvidence);
    }
}
