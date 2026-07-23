use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, WirePacketAdmission, admit_packet, admit_wire_packet,
    record_rejection_stats,
};

#[test]
fn wire_packet_admission_stays_stack_sized_without_hot_path_boxing() {
    let size = std::mem::size_of::<WirePacketAdmission<'static>>();
    assert!(
        size <= 416,
        "WirePacketAdmission grew enough to reconsider its unboxed hot-path representation: {size} bytes"
    );
}
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    admission_spec, icmp_tunnel_packet, icmp_wire_spec, pending_icmp_lock_candidate, test_config,
    test_icmp_echo_packet, test_udp_packet,
};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[test]
fn wire_admission_accepts_user_payload_reply_id_negotiation() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x20, 0x02]);
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
    assert!(admitted.lock_candidate.is_none());
    assert!(admitted.pending_negotiation.is_some());
}

#[test]
fn wire_admission_builds_pending_state_from_session_control_negotiation_without_user_bytes() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x20, 0x02]);
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
    assert!(admitted.lock_candidate.is_none());
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
    assert_eq!(outbound.src.id(), 3003);
    assert_eq!(outbound.dst.id(), 0x2002);
}

#[test]
fn wire_admission_consumes_pending_negotiation_for_first_shimmed_user_payload() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let pending = pending_icmp_lock_candidate();
    let mut spec = icmp_wire_spec(None, None);
    spec.admission.pending_icmp_client_lock = Some(pending);

    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02, b'x']);
    let admitted = match admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let lock = admitted.lock_candidate.expect("lock candidate");
    assert_eq!(lock, pending);
    assert!(admitted.pending_negotiation.is_none());
    let inbound = lock.listener_flow.inbound.expect("inbound tuple");
    assert_eq!(inbound.src.id(), 0x2002);
    assert_eq!(inbound.dst.id(), 1001);
    let outbound = lock.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(outbound.src.id(), 3003);
    assert_eq!(outbound.dst.id(), 0x2002);
    match &admitted.event {
        PayloadEvent::UserPayload {
            bytes,
            icmp: Some(icmp),
            ..
        } => {
            assert_eq!(*bytes, b"x");
            assert_eq!(icmp.flow_identity().remote_source_id, 0x2002);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn wire_admission_rejects_initial_user_payload_without_negotiation_or_pending_state() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02, b'x']);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::IcmpReplyIdNegotiationRequired
    ));
}

#[test]
fn wire_admission_wildcard_local_reply_id_yields_to_peer_reply_id_and_uses_realized_local() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x20, 0x02]);
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
    assert!(admitted.lock_candidate.is_none());
    let pending = admitted
        .pending_negotiation
        .expect("pending negotiation candidate");
    assert_eq!(
        pending.flow_key,
        ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            0x2002
        ))
    );
    let inbound = pending.listener_flow.inbound.expect("inbound tuple");
    assert_eq!(inbound.src.id(), 0x2002);
    assert_eq!(inbound.dst.id(), 1001);
    let outbound = pending.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(outbound.src.id(), 1001);
    assert_eq!(outbound.dst.id(), 0x2002);
}

#[test]
fn wire_admission_locked_icmp_user_payload_without_renegotiation_uses_locked_reply_id() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02, b'x']);
    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    ) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = admitted.event
    else {
        panic!("expected admitted ICMP user payload");
    };
    assert_eq!(icmp.flow_identity().remote_source_id, 0x2002);
    assert_eq!(icmp.reply_id_negotiation(), None);
}

#[test]
fn wire_admission_rejects_locked_reply_id_renegotiation_after_source_match() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x20, 0x02]);
    match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    ) {
        WirePacketAdmission::Filtered(rej) => {
            assert_eq!(
                rej.reason,
                RejectionReason::IcmpReplyIdRenegotiationMismatch
            );
        }
        other => panic!("unexpected admission result: {other:?}"),
    }
}

#[test]
fn wire_admission_rejects_locked_icmp_source_endpoint_mismatch() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x30, 0x03, b'x']);
    let res = admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    );
    match res {
        WirePacketAdmission::Filtered(rej) => {
            assert_eq!(rej.reason, RejectionReason::IcmpSourceEndpointMismatch);
            assert_eq!(
                rej.normalized_source.unwrap().id(),
                0x3003,
                "rejection source ID must match logical shim ID, not physical header ID"
            );
        }
        other => panic!("unexpected admission result: {other:?}"),
    }
}

#[test]
fn wire_admission_rejects_locked_flow_wrong_source_ip() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02, b'x']);
    let res = admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    );
    match res {
        WirePacketAdmission::Filtered(rej) => {
            assert_eq!(rej.reason, RejectionReason::UnexpectedRemotePeer);
            assert_eq!(
                rej.normalized_source.unwrap().id(),
                0x2002,
                "rejection source ID must match logical shim ID, not physical header ID"
            );
        }
        other => panic!("unexpected admission result: {other:?}"),
    }
}

#[test]
fn wire_admission_rejects_mismatched_os_id_after_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let packet = icmp_tunnel_packet(1002, true, &[0x80, 0x20, 0x02, b'x']);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedLocalReceiveId
    ));
}

#[test]
fn wire_admission_u2c_reflected_reply_id_does_not_create_client_lock() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, false, &[0x48, 0x20, 0x02, 0x20, 0x02]);
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.role = SocketLeg::UpstreamFacing;

    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert!(admitted.lock_candidate.is_none());
    assert!(admitted.pending_negotiation.is_none());
}

#[test]
fn udp_admission_requires_exact_remote_ip_and_port() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        Some(remote),
        Some(local.id()),
        None,
    );
    let packet = test_udp_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1111,
        1001,
        &[],
    );
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));

    let wrong_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1111).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&wrong_source)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));
}

#[test]
fn udp_unconnected_admission_rejects_missing_socket_source() {
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        None,
        Some(1001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let packet = test_udp_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1111,
        1001,
        &[],
    );
    assert!(matches!(
            admit_packet(spec, &packet, None)
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn udp_connected_admission_accepts_kernel_filtered_missing_socket_source() {
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::ConnectedKernel,
            protocol_id: ProtocolIdRequirement::None,
        },
        None,
        Some(1001),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let packet = test_udp_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1111,
        1001,
        &[],
    );
    assert!(matches!(
        admit_packet(spec, &packet, None),
        TransportAdmission::Accepted(admitted) if
        admitted.normalized_source.is_none() &&
        admitted.payload == packet.as_slice()
    ));
}

#[test]
fn icmp_dgram_admission_requires_remote_ip_and_local_receive_id() {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        Some(remote),
        Some(local.id()),
        None,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001).into();
    let packet = icmp_tunnel_packet(1001, true, &[]);
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));

    let source_wrong = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source_wrong)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));

    let wrong_id = test_icmp_echo_packet(None, None, 0x9999, true);
    assert!(matches!(
        admit_packet(spec, &wrong_id, Some(&source)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedLocalReceiveId
    ));
}

#[test]
fn icmp_dgram_admission_rejects_missing_socket_source_as_malformed() {
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        None,
        None,
    );
    let packet = icmp_tunnel_packet(1001, true, &[]);
    assert!(matches!(
            admit_packet(spec, &packet, None)
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn icmp_raw_admission_requires_packet_destination_to_match_local_filter() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(local.id()),
        Some(local.ip()),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1001,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));

    let wrong_dest = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        1001,
        true,
    );
    assert!(matches!(
        admit_packet(spec, &wrong_dest, Some(&source)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedLocalReceiveAddress
    ));
}

#[test]
fn icmp_raw_destination_check_allows_unspecified_listener_filter() {
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
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1001,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Accepted(_)
    ));
}

#[test]
fn icmp_raw_destination_check_rejects_missing_destination_for_concrete_filter() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(local.id()),
        Some(local.ip()),
    );
    let packet = test_icmp_echo_packet(None, None, 1001, true);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
            admit_packet(spec, &packet, Some(&source))
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn icmp_raw_admission_rejects_missing_raw_packet_source_as_malformed() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(local.id()),
        Some(local.ip()),
    );
    let packet_without_ip_header = test_icmp_echo_packet(None, None, 1001, true);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet_without_ip_header, Some(&source)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn icmp_raw_reflected_self_loop_is_rejected_by_remote_ip_check() {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        Some(remote),
        Some(local.id()),
        Some(local.ip()),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        1001,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
            admit_packet(spec, &packet, Some(&source))
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
        ));
}

#[test]
fn icmp_raw_admission_uses_packet_source_ip_not_socket_metadata() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 65410);
    let spec = admission_spec(
        SocketLeg::ClientFacing,
        SupportedProtocol::ICMP,
        Type::RAW,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::RawPacketHeader,
            protocol_id: ProtocolIdRequirement::ParsedTransportIdentifier,
        },
        None,
        Some(local.id()),
        Some(local.ip()),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        65410,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    let admitted = match admit_packet(spec, &packet, Some(&source)) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(
        admitted.normalized_source,
        Some(LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
            65410
        ))
    );
}

#[test]
fn icmp_raw_reflected_reply_to_other_destination_is_receive_noise() {
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
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        65410,
        false,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::ReceiveNoise(_)
    ));
}

#[test]
fn wire_admission_dgram_c2u_rejects_explicit_reply_id_matching_local() {
    // c2u client DGRAM: peer advertises a reply ID equal to the local socket ID.
    // This is valid because no disjoint receive ID is required.
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x03, 0xE9, 0x03, 0xE9]); // reply ID 1001 == local 1001
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Accepted(_)
    ));
}

#[test]
fn wire_admission_dgram_rejects_disjoint_reply_id_even_when_locked() {
    // User payload source IDs are independent from reply IDs and do not imply
    // disjoint receive capability.
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
        Ipv4Addr::new(127, 0, 0, 2),
        0x2002,
    ));
    let mut spec = icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked));
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02]); // reply ID 0x2002 != local 1001
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Accepted(_)
    ));
}

#[test]
fn wire_admission_dgram_rejects_disjoint_reply_id_on_session_control() {
    // Session-control frames also carry an advertised reply ID and are subject to the same check.
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x20, 0x02, 0x20, 0x02]); // NEGOTIATE session-control, reply ID 0x2002 != local 1001
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::UnsupportedDisjointReplyId
    ));
}

#[test]
fn reflected_icmp_rejections_do_not_count_as_forwarding_errors() {
    struct TestStats {
        err: AtomicUsize,
        oversize: AtomicUsize,
    }
    impl crate::stats::StatsSink for TestStats {
        fn send_add(&self, _c2u: bool, _bytes: u64, _start: Instant, _end: Instant) {}
        fn drop_err(&self, _c2u: bool) {
            self.err.fetch_add(1, Ordering::Relaxed);
        }
        fn drop_oversize(&self, _c2u: bool) {
            self.oversize.fetch_add(1, Ordering::Relaxed);
        }
    }
    let stats = TestStats {
        err: AtomicUsize::new(0),
        oversize: AtomicUsize::new(0),
    };
    for reason in [
        RejectionReason::UnexpectedLocalReceiveAddress,
        RejectionReason::UnexpectedLocalReceiveId,
    ] {
        record_rejection_stats(
            &stats,
            true,
            super::RejectedPacket {
                normalized_source: None,
                actual_dst_id: None,
                reason,
            },
        );
    }
    assert_eq!(stats.err.load(Ordering::Relaxed), 0);
    assert_eq!(stats.oversize.load(Ordering::Relaxed), 0);
}

#[test]
fn icmp_raw_ipv6_admission_accepts_headerless_packet() {
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
    let source = socket2::SockAddr::from(SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        0,
        0,
        7,
    )));

    let admitted = match admit_packet(spec, &packet, Some(&source)) {
        TransportAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert_eq!(
        admitted.normalized_source,
        Some(LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)),
            1001
        ))
    );
}

#[test]
fn icmp_raw_ipv4_admission_rejects_headerless_packet_as_malformed() {
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
    let packet = icmp_tunnel_packet(1001, true, &[]);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
            admit_packet(spec, &packet, Some(&source))
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn wire_admission_debug_kernel_echo_allows_reflected_explicit_self_negotiation() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let mut spec = icmp_wire_spec(Some(FlowTuple::new(remote, local)), None);
    spec.socket.role = SocketLeg::UpstreamFacing;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .allow_debug_kernel_echo_self_handshake = true;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;

    let packet = icmp_tunnel_packet(1001, false, &[0x48, 0x03, 0xE9, 0x03, 0xE9]); // ID 1001
    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Accepted(_)
    ));

    // macOS ping sockets can retain an unspecified logical local address while
    // exposing the loopback peer address as receive metadata. In that shape,
    // the configured kernel-echo peer is the authoritative reflection address.
    spec.socket.local_filter = LogicalEndpoint::from_v4(Ipv4Addr::UNSPECIFIED, 1001);
    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Accepted(_)
    ));
}

#[test]
fn wire_admission_rejects_non_empty_unparseable_icmp_tunnel_payload() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x0F, b'x']); // Invalid flags
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej)
            if matches!(rej.reason, RejectionReason::MalformedIcmpHeader(_))
    ));
}

#[test]
fn wire_admission_rejects_first_user_payload_that_does_not_match_pending_negotiation() {
    // Non-negotiating user payload from a different source IP than the pending candidate.
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0).into(); // wrong IP
    let packet = icmp_tunnel_packet(1001, true, &[0x80, 0x20, 0x02, b'x']);
    let mut spec = icmp_wire_spec(None, None);
    spec.admission.pending_icmp_client_lock = Some(pending_icmp_lock_candidate());
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::IcmpReplyIdRenegotiationMismatch
    ));
}

#[test]
fn wire_admission_prelock_cadence_cannot_lock_or_create_pending_state() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[]);
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
    assert!(admitted.lock_candidate.is_none());
    assert!(admitted.pending_negotiation.is_none());
}

#[test]
fn wire_admission_dgram_accepts_source_id_equals_header_when_ids_match() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x03, 0xE9, 0x03, 0xE9]);
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
    assert!(admitted.lock_candidate.is_none());
    let lock = admitted
        .pending_negotiation
        .expect("pending negotiation candidate");
    assert_eq!(
        lock.flow_key,
        ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::new(127, 0, 0, 2), 1001))
    );
    let inbound = lock.listener_flow.inbound.expect("inbound tuple");
    assert_eq!(inbound.src.id(), 1001);
    assert_eq!(inbound.dst.id(), 1001);
}

#[test]
fn wire_admission_dgram_rejects_unsupported_disjoint_reply_id() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.sock_type = Type::DGRAM;
    spec.socket
        .policy
        .icmp
        .as_mut()
        .expect("ICMP policy")
        .id_capability = pkthere_socket_policy::IcmpSocketIdCapability::FixedCollapsedId;
    let packet = icmp_tunnel_packet(1001, true, &[0x48, 0x30, 0x03, 0x20, 0x02]);
    let rejected = match admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Filtered(rej) => rej,
        other => panic!("expected unsupported disjoint reply ID rejection, got {other:?}"),
    };
    assert_eq!(rejected.reason, RejectionReason::UnsupportedDisjointReplyId);
}
