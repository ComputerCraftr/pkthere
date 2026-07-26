use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, WirePacketAdmission, admit_packet, admit_wire_packet,
};

#[test]
fn wire_packet_admission_stays_stack_sized_without_boxing_every_admitted_packet() {
    const MAX_STACK_ADMISSION_BYTES: usize = 464;
    let size = std::mem::size_of::<WirePacketAdmission<'static>>();
    assert!(
        size <= MAX_STACK_ADMISSION_BYTES,
        "WirePacketAdmission grew enough to reconsider its unboxed hot-path representation: {size} bytes"
    );
}

#[test]
fn active_u2c_udp_admission_remains_allocation_free() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111);
    let spec = synthetic_receive_context(
        SocketLeg::UpstreamFacing,
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
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let packet = [];

    let (admission, allocations) = crate::allocation_test_support::count_allocations(|| {
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source))
    });

    assert!(admission.is_ok());
    assert_eq!(allocations, 0);
}

#[test]
fn locked_c2u_udp_admission_is_allocation_free_without_a_transition_candidate() {
    const PACKET_COUNT: usize = 10_000;
    let source_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111);
    let source = source_address.into();
    let remote = LogicalEndpoint::from_socket_addr(source_address);
    let local =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001));
    let mut spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        Some(remote),
        Some(local.id()),
        Some(local.ip()),
    );
    spec.admission.locked_flow = Some(ClientFlowKey::Udp(remote));
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let packet = [];

    let ((all_stable, candidates), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_lock_candidate_constructions(|| {
                (0..PACKET_COUNT).all(|_| {
                    matches!(
                        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
                        Ok(ref admitted)
                            if admitted.lock_candidate().is_none()
                    )
                })
            })
        });

    assert!(all_stable);
    assert_eq!(allocations, 0);
    assert_eq!(candidates, 0);
}

#[test]
fn first_unlocked_c2u_udp_packet_constructs_its_transition_candidate_without_allocating() {
    let source_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111);
    let source = source_address.into();
    let remote = LogicalEndpoint::from_socket_addr(source_address);
    let local =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001));
    let spec = synthetic_receive_context(
        SocketLeg::ClientFacing,
        SupportedProtocol::UDP,
        Type::DGRAM,
        ReceiveEvidencePolicy {
            peer_source: PeerSourceRequirement::SourceMetadata,
            protocol_id: ProtocolIdRequirement::None,
        },
        Some(remote),
        Some(local.id()),
        Some(local.ip()),
    );
    let mut cfg = test_config(IcmpReplyIdRequest::Default);
    cfg.listen_proto = SupportedProtocol::UDP;
    let packet = [];

    let ((has_candidate, candidates), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_lock_candidate_constructions(|| {
                matches!(
                    admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
                    Ok(ref admitted)
                        if admitted.lock_candidate().is_some()
                )
            })
        });

    assert!(has_candidate);
    assert_eq!(allocations, 0);
    assert_eq!(candidates, 1);
}

#[test]
fn active_icmp_admission_is_allocation_and_payload_copy_free_in_both_directions() {
    const PACKET_COUNT: usize = 10_000;
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let flow = ClientFlowKey::Icmp(remote);
    let inbound = FlowTuple::new(remote, local);
    let source = SocketAddr::new(remote.ip(), 0).into();
    let c2u_packet = icmp_data_packet(1001, true, remote.id(), b"active");
    let u2c_packet = icmp_data_packet(1001, false, remote.id(), b"active");
    let c2u = icmp_wire_spec(Some(inbound), Some(flow));
    let mut u2c = icmp_wire_spec(Some(inbound), Some(flow));
    u2c.socket.role = SocketLeg::UpstreamFacing;

    let ((all_stable, payload_copies), allocations) =
        crate::allocation_test_support::count_allocations(|| {
            crate::allocation_test_support::count_payload_copies(|| {
                (0..PACKET_COUNT).all(|_| {
                    [&c2u_packet, &u2c_packet]
                        .into_iter()
                        .zip([c2u, u2c])
                        .zip([true, false])
                        .all(|((packet, spec), c2u)| {
                            matches!(
                                admit_wire_packet(c2u, &cfg, spec, packet, Some(&source)),
                                Ok(ref admitted)
                                    if admitted.lock_candidate().is_none()
                                        && admitted.pending_negotiation().is_none()
                                        && !admitted.unknown_session_for_reset()
                            )
                        })
                })
            })
        });

    assert!(all_stable);
    assert_eq!(allocations, 0);
    assert_eq!(payload_copies, 0);
}

use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::payload::PayloadEvent;
use crate::worker_support::admission_test_support::{
    icmp_cadence_packet, icmp_data_packet, icmp_negotiate_packet, icmp_wire_spec,
    pending_icmp_lock_candidate, synthetic_receive_context, test_config, test_icmp_echo_packet,
};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn wire_admission_accepts_control_only_reply_id_negotiation() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, false);
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
    assert!(admitted.lock_candidate().is_none());
    assert!(admitted.pending_negotiation().is_some());
}

#[test]
fn wire_admission_builds_pending_state_from_session_control_negotiation_without_user_bytes() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, false);
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
    assert!(admitted.lock_candidate().is_none());
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
    assert_eq!(outbound.src.id(), 3003);
    assert_eq!(outbound.dst.id(), 0x2002);
}

#[test]
fn wire_admission_promotes_only_the_matching_pending_session() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let pending = pending_icmp_lock_candidate();
    let mut spec = icmp_wire_spec(None, None);
    spec.admission.pending_icmp_client_lock = Some(pending);

    let packet = icmp_data_packet(1001, true, 0x2002, b"x");
    let Ok(admitted) = admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) else {
        panic!("matching first data did not promote the pending session");
    };
    assert_eq!(admitted.lock_candidate(), Some(pending));
}

#[test]
fn wire_admission_routes_initial_unknown_session_data_only_to_reset_recovery() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_data_packet(1001, true, 0x2002, b"x");
    let Ok(admitted) = admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(None, None),
        &packet,
        Some(&source),
    ) else {
        panic!("authenticated unknown-session data did not reach reset recovery");
    };
    assert!(admitted.unknown_session_for_reset());
    let reset_candidate = admitted
        .reset_candidate()
        .expect("reset admission retains its authenticated flow");
    assert_eq!(
        admitted.candidate_flow_key(),
        Some(reset_candidate.flow_key)
    );
    assert!(admitted.lock_candidate().is_none());
    assert!(admitted.pending_negotiation().is_none());
}

#[test]
fn wire_admission_wildcard_local_reply_id_yields_to_peer_reply_id_and_uses_realized_local() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, false);
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
    assert!(admitted.lock_candidate().is_none());
    let pending = admitted
        .pending_negotiation()
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
    let packet = icmp_data_packet(1001, true, 0x2002, b"x");
    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    ) {
        Ok(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = admitted.event
    else {
        panic!("expected admitted ICMP user payload");
    };
    assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002);
    assert_eq!(icmp.reply_id_negotiation(), None);
}

#[test]
fn authenticated_unknown_session_data_is_admitted_only_for_bounded_reset_recovery() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::Icmp(remote);
    let mut packet = icmp_data_packet(1001, true, 0x2002, b"x");
    packet[11..19].copy_from_slice(&2_u64.to_be_bytes());

    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    ) {
        Ok(admitted) => admitted,
        other => panic!("authenticated unknown session should reach reset recovery: {other:?}"),
    };
    assert!(admitted.unknown_session_for_reset());
    assert!(admitted.reset_candidate().is_some());
    assert!(admitted.lock_candidate().is_none());
    assert!(admitted.pending_negotiation().is_none());
}

#[test]
fn authenticated_unknown_session_data_reaches_stateless_reset_recovery_while_unlocked() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let mut packet = icmp_data_packet(1001, true, 0x2002, b"x");
    packet[11..19].copy_from_slice(&2_u64.to_be_bytes());

    let admitted = match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(None, None),
        &packet,
        Some(&source),
    ) {
        Ok(admitted) => admitted,
        other => panic!("authenticated unknown session should reach stateless recovery: {other:?}"),
    };
    assert!(admitted.unknown_session_for_reset());
    let reset_candidate = admitted
        .reset_candidate()
        .expect("stateless recovery retains the admitted flow identity");
    assert_eq!(
        reset_candidate.flow_key,
        ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            0x2002
        ))
    );
    assert!(admitted.lock_candidate().is_none());
    assert!(admitted.pending_negotiation().is_none());
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
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, false);
    match admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    ) {
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej)) => {
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
    let packet = icmp_data_packet(1001, true, 0x3003, b"x");
    let res = admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    );
    match res {
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej)) => {
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
    let packet = icmp_data_packet(1001, true, 0x2002, b"x");
    let res = admit_wire_packet(
        true,
        &cfg,
        icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
        &packet,
        Some(&source),
    );
    match res {
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej)) => {
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
    let packet = icmp_data_packet(1002, true, 0x2002, b"x");
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej)) if rej.reason == RejectionReason::UnexpectedLocalReceiveId
    ));
}

#[test]
fn wire_admission_rejects_negotiate_control_from_upstream_role() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, false, 0x2002, 0x2002, false);
    let mut spec = icmp_wire_spec(None, None);
    spec.socket.role = SocketLeg::UpstreamFacing;

    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source)),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected))
            if rejected.reason == RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection
            ))
    ));
}

#[test]
fn wire_admission_rejects_ack_control_from_client_role() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, true);

    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected))
            if rejected.reason == RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection
            ))
    ));
}

#[test]
fn udp_admission_requires_exact_remote_ip_and_port() {
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111).into();
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1111);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
    let packet = [];
    let TransportAdmission::Accepted(admitted) = admit_packet(spec, &packet, Some(&source)) else {
        panic!("expected UDP packet admission");
    };
    assert!(
        admitted.icmp_identity().is_none(),
        "UDP admission must not fabricate an ICMP endpoint identity"
    );

    let wrong_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1111).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&wrong_source)),
        TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));
}

#[test]
fn udp_unconnected_admission_rejects_missing_socket_source() {
    let spec = synthetic_receive_context(
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
    let packet = [];
    assert!(matches!(
            admit_packet(spec, &packet, None)
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn udp_connected_admission_accepts_kernel_filtered_missing_socket_source() {
    let spec = synthetic_receive_context(
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
    let packet = [];
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
    let spec = synthetic_receive_context(
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
    let packet = icmp_cadence_packet(1001, true, 1001);
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
