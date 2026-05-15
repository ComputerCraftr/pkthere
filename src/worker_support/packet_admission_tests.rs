use super::{
    PacketAdmission, PacketAdmissionSpec, RejectionReason, SocketPeerRole, SourceEvidenceMode,
    WirePacketAdmission, admit_packet, admit_wire_packet, record_rejection_stats,
};
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::flow_key::{ClientFlowKey, FlowEndpoint, FlowTuple};
use crate::net::packet_headers::parse_packet_headers;
use crate::net::params::CanonicalAddr;
use crate::net::payload::PayloadEvent;
use crate::stats::StatsSink;
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn test_icmp_echo_packet(
    source_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    ident: u16,
    is_request: bool,
) -> Vec<u8> {
    let icmp_type = match (source_ip, is_request) {
        (Some(IpAddr::V6(_)), true) => 128,
        (Some(IpAddr::V6(_)), false) => 129,
        (_, true) => 8,
        (_, false) => 0,
    };
    let mut icmp = vec![icmp_type, 0, 0, 0, 0, 0, 0, 1];
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());

    match (source_ip, dest_ip) {
        (Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))) => {
            let mut packet = vec![0u8; 20 + icmp.len()];
            packet[0] = 0x45; // IPv4, 20-byte header
            packet[9] = 1; // ICMP protocol
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            packet[20..].copy_from_slice(&icmp);
            packet
        }
        (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
            let mut packet = vec![0u8; 40 + icmp.len()];
            packet[0] = 0x60; // IPv6
            packet[6] = 58; // ICMPv6 next header
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..].copy_from_slice(&icmp);
            packet
        }
        _ => icmp,
    }
}

fn admission_spec(
    role: SocketPeerRole,
    proto: SupportedProtocol,
    sock_type: Type,
    source_evidence: SourceEvidenceMode,
    expected_remote: Option<CanonicalAddr>,
    expected_local_icmp_id: Option<u16>,
) -> PacketAdmissionSpec {
    let expected_remote_endpoint = expected_remote.map(FlowEndpoint::from_canonical);
    let expected_local =
        expected_local_icmp_id.map(|id| FlowEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), id));
    let expected_inbound = expected_remote_endpoint.map(|remote| {
        let local = expected_local
            .unwrap_or_else(|| FlowEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        FlowTuple::new(remote, local)
    });
    PacketAdmissionSpec {
        role,
        proto,
        sock_type,
        source_evidence,
        expected_inbound,
        expected_local,
        local_filter: expected_local.map(|endpoint| endpoint.canonical()),
        locked_flow: None,
    }
}

fn test_config(listener_reply_id_request: IcmpReplyIdRequest) -> RuntimeConfig {
    RuntimeConfig {
        listen: CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)),
            1001,
        ),
        listener_reply_id_request,
        listen_proto: SupportedProtocol::ICMP,
        listen_mode: ListenMode::Fixed,
        listen_str: String::from("test-listen"),
        workers: 1,
        worker_flow_mode: WorkerFlowMode::SharedFlow,
        upstream: CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000)),
            9000,
        ),
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_str: String::from("test-upstream"),
        timeout_secs: 10,
        on_timeout: TimeoutAction::Drop,
        stats_interval_mins: 0,
        max_payload: 1500,
        icmp_sync_pps: 0,
        reresolve_secs: 0,
        reresolve_mode: ReresolveMode::Upstream,
        #[cfg(unix)]
        run_as_user: None,
        #[cfg(unix)]
        run_as_group: None,
        debug_behavior: DebugBehavior::default(),
        debug_logs: DebugLogs::default(),
    }
}

fn icmp_tunnel_packet(ident: u16, is_request: bool, shim_payload: &[u8]) -> Vec<u8> {
    let mut packet = test_icmp_echo_packet(None, None, ident, is_request);
    packet.extend_from_slice(shim_payload);
    packet
}

fn icmp_wire_spec(
    expected_inbound: Option<FlowTuple>,
    locked_flow: Option<ClientFlowKey>,
) -> PacketAdmissionSpec {
    PacketAdmissionSpec {
        role: SocketPeerRole::Client,
        proto: SupportedProtocol::ICMP,
        sock_type: Type::RAW,
        source_evidence: SourceEvidenceMode::SocketSourceRequired,
        expected_inbound,
        expected_local: Some(FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001)),
        local_filter: Some(CanonicalAddr::from_v4(Ipv4Addr::LOCALHOST, 1001)),
        locked_flow,
    }
}

#[test]
fn wire_admission_builds_initial_icmp_lock_from_reply_id_negotiation() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0xB0, 0x20, 0x02]);

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
    let lock = admitted.lock_candidate.expect("lock candidate");
    assert_eq!(
        lock.flow_key,
        ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::new(127, 0, 0, 2),
            ident: 0x2002
        }
    );
    let inbound = lock.listener_flow.inbound.expect("inbound tuple");
    let outbound = lock.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(inbound.src.id, 0x2002);
    assert_eq!(inbound.dst.id, 1001);
    assert_eq!(outbound.src.id, 3003);
    assert_eq!(outbound.dst.id, 0x2002);
}

#[test]
fn wire_admission_builds_initial_icmp_lock_from_session_control_negotiation_without_user_bytes() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0x30, 0x20, 0x02]);

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
    assert!(matches!(
        admitted.event,
        PayloadEvent::SessionControl {
            icmp: crate::net::payload::IcmpPayloadMeta {
                negotiated_remote_reply_id: 0x2002,
                advertised_reply_id: Some(0x2002),
                reply_id_negotiate: true,
                reply_id_ack: false,
                ..
            },
            ..
        }
    ));
    let lock = admitted.lock_candidate.expect("lock candidate");
    assert_eq!(
        lock.flow_key,
        ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::new(127, 0, 0, 2),
            ident: 0x2002
        }
    );
    let inbound = lock.listener_flow.inbound.expect("inbound tuple");
    let outbound = lock.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(inbound.src.id, 0x2002);
    assert_eq!(inbound.dst.id, 1001);
    assert_eq!(outbound.src.id, 3003);
    assert_eq!(outbound.dst.id, 0x2002);
}

#[test]
fn wire_admission_wildcard_local_reply_id_yields_to_peer_reply_id_and_uses_realized_local() {
    let cfg = test_config(IcmpReplyIdRequest::Wildcard);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let packet = icmp_tunnel_packet(1001, true, &[0xB0, 0x20, 0x02]);

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
    let lock = admitted.lock_candidate.expect("lock candidate");
    let outbound = lock.listener_flow.outbound.expect("outbound tuple");
    assert_eq!(outbound.src.id, 1001);
    assert_eq!(outbound.dst.id, 0x2002);
}

#[test]
fn wire_admission_locked_icmp_inherits_reply_id_without_shim() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::IcmpV4 {
        ip: Ipv4Addr::new(127, 0, 0, 2),
        ident: 0x2002,
    };
    let packet = icmp_tunnel_packet(1001, true, &[0x80]);

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
    assert!(admitted.lock_candidate.is_none());
    assert!(matches!(
        admitted.event,
        PayloadEvent::UserPayload {
            icmp: Some(crate::net::payload::IcmpPayloadMeta {
                negotiated_remote_reply_id: 0x2002,
                advertised_reply_id: None,
                ..
            }),
            ..
        }
    ));
}

#[test]
fn wire_admission_rejects_locked_icmp_reply_id_renegotiation() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::IcmpV4 {
        ip: Ipv4Addr::new(127, 0, 0, 2),
        ident: 0x2002,
    };
    let packet = icmp_tunnel_packet(1001, true, &[0xB0, 0x30, 0x03]);

    assert!(matches!(
        admit_wire_packet(
            true,
            &cfg,
            icmp_wire_spec(Some(FlowTuple::new(remote, local)), Some(locked)),
            &packet,
            Some(&source),
        ),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::PostLockIcmpReplyIdNegotiation
    ));
}

#[test]
fn wire_admission_rejects_mismatched_os_id_after_handshake() {
    let cfg = test_config(IcmpReplyIdRequest::Fixed(3003));
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let remote = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let local = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let locked = ClientFlowKey::IcmpV4 {
        ip: Ipv4Addr::new(127, 0, 0, 2),
        ident: 0x2002,
    };
    // Packet has OS ID 9999, but expected local receive ID is 1001.
    let packet = icmp_tunnel_packet(9999, true, &[0x80]);

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
    let spec = PacketAdmissionSpec {
        role: SocketPeerRole::Upstream,
        proto: SupportedProtocol::ICMP,
        sock_type: Type::RAW,
        source_evidence: SourceEvidenceMode::SocketSourceRequired,
        expected_inbound: None,
        expected_local: None,
        local_filter: Some(CanonicalAddr::from_v4(Ipv4Addr::LOCALHOST, 1001)),
        locked_flow: None,
    };
    let packet = icmp_tunnel_packet(1001, false, &[0xB0, 0x20, 0x02]);

    let admitted = match admit_wire_packet(false, &cfg, spec, &packet, Some(&source)) {
        WirePacketAdmission::Accepted(admitted) => admitted,
        other => panic!("unexpected admission: {other:?}"),
    };
    assert!(admitted.lock_candidate.is_none());
}

#[test]
fn wire_admission_dgram_rejects_unsupported_disjoint_reply_id() {
    let cfg = test_config(IcmpReplyIdRequest::Default);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    let spec = PacketAdmissionSpec {
        role: SocketPeerRole::Upstream,
        proto: SupportedProtocol::ICMP,
        sock_type: Type::DGRAM,
        source_evidence: SourceEvidenceMode::SocketSourceRequired,
        expected_inbound: None,
        expected_local: None,
        local_filter: Some(CanonicalAddr::from_v4(Ipv4Addr::LOCALHOST, 1001)),
        locked_flow: None,
    };
    let packet = icmp_tunnel_packet(1001, false, &[0xB0, 0x20, 0x02]);

    assert!(matches!(
        admit_wire_packet(false, &cfg, spec, &packet, Some(&source)),
        WirePacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::UnsupportedDisjointReplyId
    ));
}

#[test]
fn udp_admission_requires_exact_remote_ip_and_port() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        SourceEvidenceMode::SocketSourceRequired,
        Some(CanonicalAddr::from_socket_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4444,
        ))),
        None,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444).into();
    assert!(matches!(
        admit_packet(spec, &[], Some(&source)),
        PacketAdmission::Accepted(_)
    ));
    let source_wrong = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4445).into();
    assert!(matches!(
        admit_packet(spec, &[], Some(&source_wrong)),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));
}

#[test]
fn udp_unconnected_admission_rejects_missing_socket_source() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        SourceEvidenceMode::SocketSourceRequired,
        Some(CanonicalAddr::from_socket_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4444,
        ))),
        None,
    );
    assert!(matches!(
        admit_packet(spec, b"payload", None),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn udp_connected_admission_accepts_kernel_filtered_missing_socket_source() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        SourceEvidenceMode::ConnectedKernelFiltered,
        Some(CanonicalAddr::from_socket_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            4444,
        ))),
        None,
    );
    assert!(matches!(
        admit_packet(spec, b"payload", None),
        PacketAdmission::Accepted(admitted)
            if admitted.payload_bounds == (0, b"payload".len())
                && admitted.normalized_source.is_none()
    ));
}

#[test]
fn icmp_dgram_admission_requires_remote_ip_and_local_receive_id() {
    let spec = admission_spec(
        SocketPeerRole::Client,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        SourceEvidenceMode::SocketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            0x1234,
        )),
        Some(0x1234),
    );
    let packet = test_icmp_echo_packet(None, None, 0x1234, true);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Accepted(_)
    ));
    let source_wrong = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source_wrong)),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));
    let wrong_id = test_icmp_echo_packet(None, None, 0x9999, true);
    assert!(matches!(
        admit_packet(spec, &wrong_id, Some(&source)),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedLocalReceiveId
    ));
}

#[test]
fn icmp_dgram_admission_rejects_missing_socket_source() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        SourceEvidenceMode::SocketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 0),
            0x1234,
        )),
        Some(0x1234),
    );
    let packet = test_icmp_echo_packet(None, None, 0x1234, false);
    assert!(matches!(
        admit_packet(spec, &packet, None),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn icmp_raw_admission_uses_packet_source_ip_not_socket_metadata() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        SourceEvidenceMode::RawPacketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
            65410,
        )),
        Some(65410),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        65410,
        false,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Accepted(admitted)
            if admitted.normalized_source
                == Some(CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0), 65410))
    ));
}

#[test]
fn icmp_raw_admission_requires_packet_destination_to_match_local_filter() {
    let spec = PacketAdmissionSpec {
        role: SocketPeerRole::Client,
        proto: SupportedProtocol::ICMP,
        sock_type: Type::RAW,
        source_evidence: SourceEvidenceMode::RawPacketSourceRequired,
        expected_inbound: None,
        expected_local: Some(FlowEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            65410,
        )),
        local_filter: Some(CanonicalAddr::from_v4(Ipv4Addr::new(127, 0, 0, 2), 65410)),
        locked_flow: None,
    };
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        65410,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into();

    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Accepted(admitted)
            if admitted.normalized_source
                == Some(CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), 65410))
    ));
}

#[test]
fn icmp_raw_destination_check_rejects_missing_destination_for_concrete_filter() {
    let packet = test_icmp_echo_packet(None, None, 65410, true);
    let parsed = parse_packet_headers(&packet);
    let concrete_local = CanonicalAddr::from_v4(Ipv4Addr::new(127, 0, 0, 2), 65410);

    assert!(
        !super::raw_packet_destination_matches(&parsed, concrete_local),
        "headerless RAW ICMP has no destination-IP evidence for a concrete listener filter"
    );
}

#[test]
fn icmp_raw_destination_check_allows_unspecified_listener_filter() {
    let packet = test_icmp_echo_packet(None, None, 65410, true);
    let parsed = parse_packet_headers(&packet);
    let unspecified_local = CanonicalAddr::from_v4(Ipv4Addr::UNSPECIFIED, 65410);

    assert!(super::raw_packet_destination_matches(
        &parsed,
        unspecified_local
    ));
}

#[test]
fn icmp_raw_reflected_reply_to_other_destination_is_receive_noise() {
    let spec = PacketAdmissionSpec {
        role: SocketPeerRole::Client,
        proto: SupportedProtocol::ICMP,
        sock_type: Type::RAW,
        source_evidence: SourceEvidenceMode::RawPacketSourceRequired,
        expected_inbound: None,
        expected_local: Some(FlowEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            65410,
        )),
        local_filter: Some(CanonicalAddr::from_v4(Ipv4Addr::new(127, 0, 0, 2), 65410)),
        locked_flow: None,
    };
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        65410,
        false,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();

    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Filtered(rej)
            if rej.reason == RejectionReason::UnexpectedLocalReceiveAddress
                && rej.normalized_source
                    == Some(CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0), 65410))
    ));
}

#[test]
fn reflected_icmp_rejections_do_not_count_as_forwarding_errors() {
    struct TestStats {
        err: AtomicUsize,
        oversize: AtomicUsize,
    }

    impl StatsSink for TestStats {
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
        RejectionReason::IcmpDirectionMismatch,
    ] {
        record_rejection_stats(
            &stats,
            true,
            super::RejectedPacket {
                normalized_source: None,
                reason,
            },
        );
    }

    assert_eq!(stats.err.load(Ordering::Relaxed), 0);
    assert_eq!(stats.oversize.load(Ordering::Relaxed), 0);
}

#[test]
fn icmp_raw_admission_rejects_missing_raw_packet_source() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        SourceEvidenceMode::RawPacketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
            65410,
        )),
        Some(65410),
    );
    let packet_without_ip_header = test_icmp_echo_packet(None, None, 65410, false);
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet_without_ip_header, Some(&source)),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::MissingSourceEvidence
    ));
}

#[test]
fn icmp_raw_reflected_self_loop_is_rejected_by_remote_ip_check() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        SourceEvidenceMode::RawPacketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
            65410,
        )),
        Some(65410),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        65410,
        true,
    );
    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
    ));
}

#[test]
fn icmp_ipv6_raw_admission_preserves_metadata_scope_when_available() {
    let spec = admission_spec(
        SocketPeerRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        SourceEvidenceMode::RawPacketSourceRequired,
        Some(CanonicalAddr::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)),
            9999,
        )),
        Some(9999),
    );
    let packet = test_icmp_echo_packet(
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        9999,
        false,
    );
    let source = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)).into();
    assert!(matches!(
        admit_packet(spec, &packet, Some(&source)),
        PacketAdmission::Accepted(admitted)
            if admitted.normalized_source
                == Some(CanonicalAddr::new(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)), 9999))
    ));
}
