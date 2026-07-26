use super::{
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy, RejectionReason,
    SocketLeg, TransportAdmission, admit_packet, admit_wire_packet, record_rejection_stats,
};
use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::worker_support::admission_test_support::{
    icmp_cadence_packet, icmp_data_packet, icmp_negotiate_packet, icmp_raw_shim_packet,
    icmp_v6_cadence_packet, icmp_wire_spec, pending_icmp_lock_candidate,
    set_test_ipv4_receive_length, synthetic_receive_context, test_config, test_icmp_echo_packet,
};
use crate::worker_support::packet_admission::ReceiveNoiseReason;
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[test]
fn protocol_zero_capture_treats_unrelated_ipv4_protocols_as_receive_noise() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let mut spec = synthetic_receive_context(
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
    spec.socket.parser = pkthere_wire::packet_headers::select_receive_parser(
        pkthere_wire::SupportedProtocol::ICMP,
        pkthere_wire::packet_headers::IpVersion::V4,
        pkthere_wire::packet_headers::ReceiveHeaderMode::IpHeaderIncluded,
        pkthere_wire::packet_headers::Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("protocol-zero IPv4 parser");

    let mut unrelated_udp = [0u8; 20];
    unrelated_udp[0] = 0x45;
    unrelated_udp[2..4].copy_from_slice(&20_u16.to_be_bytes());
    unrelated_udp[9] = 17;
    unrelated_udp[12..16].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
    unrelated_udp[16..20].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());

    assert!(matches!(
        admit_packet(spec, &unrelated_udp, None),
        TransportAdmission::ReceiveNoise(ReceiveNoiseReason::UnrelatedIpProtocol)
    ));
}

#[test]
fn icmp_dgram_admission_rejects_missing_socket_source_as_malformed() {
    let spec = synthetic_receive_context(
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
    let packet = icmp_cadence_packet(1001, true, 1001);
    assert!(matches!(
            admit_packet(spec, &packet, None)
    ,
            TransportAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
        ));
}

#[test]
fn icmp_raw_admission_requires_packet_destination_to_match_local_filter() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
    let admission = admit_packet(spec, &packet, Some(&source));
    assert!(
        matches!(admission, TransportAdmission::Accepted(_)),
        "unexpected admission: {admission:?}"
    );

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
fn raw_admission_checks_ip_addresses_before_malformed_icmp() {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
    let source = SocketAddr::new(remote.ip(), 0).into();

    let mut wrong_destination = test_icmp_echo_packet(
        Some(remote.ip()),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        1001,
        true,
    );
    wrong_destination.push(0x01);
    set_test_ipv4_receive_length(&mut wrong_destination);
    assert!(matches!(
        admit_packet(spec, &wrong_destination, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason == RejectionReason::UnexpectedLocalReceiveAddress
    ));

    let mut wrong_source = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        Some(local.ip()),
        1001,
        true,
    );
    wrong_source.push(0x01);
    set_test_ipv4_receive_length(&mut wrong_source);
    assert!(matches!(
        admit_packet(spec, &wrong_source, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason == RejectionReason::UnexpectedRemotePeer
    ));

    let mut malformed_icmp = test_icmp_echo_packet(Some(remote.ip()), Some(local.ip()), 1001, true);
    malformed_icmp.push(0x01);
    set_test_ipv4_receive_length(&mut malformed_icmp);
    let rejected = match admit_packet(spec, &malformed_icmp, Some(&source)) {
        TransportAdmission::Filtered(rejected) => rejected,
        other => panic!("expected malformed ICMP rejection, got {other:?}"),
    };
    assert_eq!(
        rejected.reason,
        RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::IllegalFrameFlags
        ))
    );
}

#[test]
fn raw_admission_filters_fragments_at_layer_three() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
    let mut packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(local.ip()),
        1001,
        true,
    );
    packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        TransportAdmission::Filtered(rejected)
            if rejected.reason == RejectionReason::UnsupportedIpLayout(
                crate::net::packet_headers::IpUnsupportedReason::Fragmented
            )
    ));
}

#[test]
fn icmp_raw_destination_check_allows_unspecified_listener_filter() {
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
    let spec = synthetic_receive_context(
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
            TransportAdmission::Filtered(rej)
                if rej.reason == RejectionReason::MalformedIpHeader(
                    crate::net::packet_headers::IpMalformedReason::InvalidVersion {
                        observed_nibble: 0
                    }
                )
        ));
}

#[test]
fn icmp_raw_admission_rejects_missing_raw_packet_source_as_malformed() {
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
        TransportAdmission::Filtered(rej)
            if rej.reason == RejectionReason::MalformedIpHeader(
                crate::net::packet_headers::IpMalformedReason::InvalidVersion {
                    observed_nibble: 0
                }
            )
    ));
}

#[test]
fn icmp_raw_reflected_self_loop_is_rejected_by_remote_ip_check() {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1001);
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let spec = synthetic_receive_context(
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
    let spec = synthetic_receive_context(
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
    let packet = icmp_negotiate_packet(1001, true, 1001, 1001, false);
    assert!(admit_wire_packet(true, &cfg, spec, &packet, Some(&source)).is_ok());
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
    let packet = icmp_data_packet(1001, true, 0x2002, b"");
    assert!(admit_wire_packet(true, &cfg, spec, &packet, Some(&source)).is_ok());
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
    let packet = icmp_negotiate_packet(1001, true, 0x2002, 0x2002, false);
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
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
        fn send_add(
            &mut self,
            _c2u: bool,
            _bytes: u64,
            _received_at: Instant,
            _attempted_at: Instant,
            _completed_at: Instant,
        ) {
        }
        fn drop_err(&mut self, _c2u: bool) {
            self.err.fetch_add(1, Ordering::Relaxed);
        }
        fn drop_oversize(&mut self, _c2u: bool) {
            self.oversize.fetch_add(1, Ordering::Relaxed);
        }
        fn handshake_invalid_control(&mut self, _c2u: bool) {}
        fn handshake_stale_ack(&mut self) {}
    }
    let mut stats = TestStats {
        err: AtomicUsize::new(0),
        oversize: AtomicUsize::new(0),
    };
    for reason in [
        RejectionReason::UnexpectedLocalReceiveAddress,
        RejectionReason::UnexpectedLocalReceiveId,
    ] {
        record_rejection_stats(
            &mut stats,
            true,
            crate::worker_support::packet_admission::RejectedPacket {
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
fn protocol_zero_capture_rejects_headerless_packet_as_malformed() {
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
        None,
    );
    spec.socket.policy.receive_capture_scope =
        pkthere_socket_policy::ReceiveCaptureScope::InterfaceIpv4;
    spec.socket.parser = pkthere_wire::packet_headers::select_receive_parser(
        pkthere_wire::SupportedProtocol::ICMP,
        pkthere_wire::packet_headers::IpVersion::V4,
        pkthere_wire::packet_headers::ReceiveHeaderMode::IpHeaderIncluded,
        pkthere_wire::packet_headers::Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("protocol-zero IPv4 parser");
    let packet = icmp_cadence_packet(1001, true, 1001);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();
    assert!(matches!(
            admit_packet(spec, &packet, Some(&source))
    ,
            TransportAdmission::Filtered(rej)
                if rej.reason == RejectionReason::MalformedIpHeader(
                    crate::net::packet_headers::IpMalformedReason::InvalidVersion {
                        observed_nibble: 0
                    }
                )
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

    let packet = icmp_negotiate_packet(1001, false, 1001, 1001, false);
    assert!(admit_wire_packet(false, &cfg, spec, &packet, Some(&source)).is_ok());

    // macOS ping sockets can retain an unspecified logical local address while
    // exposing the loopback peer address as receive metadata. In that shape,
    // the configured kernel-echo peer is the authoritative reflection address.
    spec.socket.local_filter = LogicalEndpoint::from_v4(Ipv4Addr::UNSPECIFIED, 1001);
    assert!(admit_wire_packet(false, &cfg, spec, &packet, Some(&source)).is_ok());
}

#[test]
fn wire_admission_rejects_non_empty_unparseable_icmp_tunnel_payload() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_raw_shim_packet(1001, true, &[0x0f, b'x']);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if matches!(rej.reason, RejectionReason::MalformedIcmpHeader(_))
    ));
}

#[test]
fn wire_admission_rejects_first_user_payload_even_when_pending_negotiation_exists() {
    // Non-negotiating user payload from a different source IP than the pending candidate.
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0).into(); // wrong IP
    let packet = icmp_data_packet(1001, true, 0x2002, b"x");
    let mut spec = icmp_wire_spec(None, None);
    spec.admission.pending_icmp_client_lock = Some(pending_icmp_lock_candidate());
    assert!(matches!(
        admit_wire_packet(true, &cfg, spec, &packet, Some(&source)),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej))
            if rej.reason == RejectionReason::IcmpReplyIdNegotiationRequired
    ));
}

#[test]
fn wire_admission_prelock_cadence_cannot_lock_or_create_pending_state() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_cadence_packet(1001, true, 1001);
    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(None, None),
            &packet,
            Some(&source),
        ),
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected))
            if rejected.reason == RejectionReason::IcmpSessionMismatch
    ));
}

#[test]
fn wire_admission_dgram_accepts_source_id_equals_header_when_ids_match() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_negotiate_packet(1001, true, 1001, 1001, false);
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
    assert!(admitted.lock_candidate().is_none());
    let lock = admitted
        .pending_negotiation()
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
    let packet = icmp_negotiate_packet(1001, true, 0x3003, 0x2002, false);
    let rejected = match admit_wire_packet(true, &cfg, spec, &packet, Some(&source)) {
        Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(rej)) => rej,
        other => panic!("expected unsupported disjoint reply ID rejection, got {other:?}"),
    };
    assert_eq!(rejected.reason, RejectionReason::UnsupportedDisjointReplyId);
}
