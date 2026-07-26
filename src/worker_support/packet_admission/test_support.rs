use super::{
    AdmissionStateContext, ReceiveContext, ReceiveEvidencePolicy, ReceiveSocketContext, SocketLeg,
};
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::PendingIcmpClientLock;
use crate::net::framing_shim::{
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelControl, IcmpTunnelFrameKind, ReplyIdNegotiation,
    SessionId, SessionKey, encode_icmp_control_prefix_with_source,
    encode_icmp_tunnel_prefix_with_source,
};
use crate::net::packet_headers::select_packet_parser;
use crate::net::packet_headers::{SHIM_IS_CADENCE, SHIM_SOURCE_ID_EQUALS_HEADER};
use pkthere_socket_policy::{
    IcmpPolicyIntent, ProtocolPolicyIntent, SocketRole, current_icmp_platform_capabilities,
    resolve_socket_policy_with_protocol_intent,
};
use pkthere_wire::packet_headers::{Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use socket2::{Domain, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

/// An intentionally synthetic receive context for parser/admission unit tests.
///
/// Unlike `ReceiveContext` values built by the socket manager, this fixture may
/// combine evidence and parser policies that no supported kernel exposes. It
/// must never be used as socket-reality evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyntheticReceiveContext {
    pub(crate) socket: ReceiveSocketContext,
    pub(crate) admission: SyntheticAdmissionStateContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyntheticAdmissionStateContext {
    pub(crate) expected_inbound: Option<FlowTuple>,
    pub(crate) expected_local: Option<LogicalEndpoint>,
    pub(crate) locked_flow: Option<ClientFlowKey>,
    pub(crate) pending_icmp_client_lock: Option<PendingIcmpClientLock>,
    pub(crate) expected_session_id: Option<SessionId>,
    pub(crate) additional_sessions: crate::flow_state::SessionAdmissionSnapshot,
}

impl SyntheticReceiveContext {
    pub(crate) fn as_receive_context(&self) -> ReceiveContext<'_> {
        ReceiveContext {
            socket: self.socket,
            admission: AdmissionStateContext {
                expected_inbound: self.admission.expected_inbound,
                expected_local: self.admission.expected_local,
                locked_flow: self.admission.locked_flow,
                pending_icmp_client_lock: self.admission.pending_icmp_client_lock,
                expected_session_id: self.admission.expected_session_id,
                additional_sessions: &self.admission.additional_sessions,
            },
        }
    }
}

pub(crate) fn test_icmp_echo_packet(
    source_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    ident: u16,
    is_request: bool,
) -> Vec<u8> {
    let mut packet = test_icmp_echo_packet_base(source_ip, dest_ip, ident, is_request);
    packet.push(SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER);
    packet.extend_from_slice(&1_u64.to_be_bytes());
    if matches!(
        (source_ip, dest_ip),
        (Some(IpAddr::V4(_)), Some(IpAddr::V4(_)))
    ) {
        set_test_ipv4_receive_length(&mut packet);
    } else if matches!(
        (source_ip, dest_ip),
        (Some(IpAddr::V6(_)), Some(IpAddr::V6(_)))
    ) {
        let payload_len = u16::try_from(packet.len() - 40).expect("test IPv6 payload length");
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }
    packet
}

fn test_icmp_echo_packet_base(
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
            set_test_ipv4_receive_length(&mut packet);
            packet
        }
        (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
            let mut packet = vec![0u8; 40 + icmp.len()];
            packet[0] = 0x60; // IPv6
            packet[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            packet[6] = 58; // ICMPv6 next header
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..].copy_from_slice(&icmp);
            packet
        }
        _ => icmp,
    }
}

pub(crate) fn set_test_ipv4_receive_length(packet: &mut [u8]) {
    const IPV4_HEADER_LEN: usize = 20;
    assert!(packet.len() >= IPV4_HEADER_LEN);
    let declared = match current_icmp_platform_capabilities().ipv4_receive_length {
        Ipv4PacketLengthEncoding::NetworkTotal => u16::try_from(packet.len())
            .expect("test IPv4 packet length")
            .to_be_bytes(),
        Ipv4PacketLengthEncoding::DarwinHostPayload => {
            u16::try_from(packet.len() - IPV4_HEADER_LEN)
                .expect("test IPv4 payload length")
                .to_ne_bytes()
        }
    };
    packet[2..4].copy_from_slice(&declared);
}

pub(crate) fn synthetic_receive_context(
    role: SocketLeg,
    proto: SupportedProtocol,
    sock_type: Type,
    evidence_policy: ReceiveEvidencePolicy,
    expected_remote: Option<LogicalEndpoint>,
    expected_local_id: Option<u16>,
    local_filter_ip: Option<IpAddr>,
) -> SyntheticReceiveContext {
    let expected_remote_endpoint = expected_remote;
    let socket_is_ipv4 = match (expected_remote, local_filter_ip) {
        (Some(remote), _) => remote.ip().is_ipv4(),
        (None, Some(ip)) => ip.is_ipv4(),
        (None, None) => true,
    };

    let local_ip = match local_filter_ip {
        Some(ip) => ip,
        None if socket_is_ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let expected_local = expected_local_id.map(|id| LogicalEndpoint::new(local_ip, id));
    let expected_inbound = expected_remote_endpoint.map(|remote| {
        let local = match expected_local {
            Some(local) => local,
            None => LogicalEndpoint::new(local_ip, 0),
        };
        FlowTuple::new(remote, local)
    });
    let mut policy = resolve_socket_policy_with_protocol_intent(
        match role {
            SocketLeg::ClientFacing => SocketRole::Listener,
            SocketLeg::UpstreamFacing => SocketRole::Upstream,
        },
        match proto {
            SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
            SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        },
        sock_type,
        TimeoutAction::Drop,
        false,
        if socket_is_ipv4 {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
    );
    policy.receive_header = match proto {
        SupportedProtocol::UDP => ReceiveHeaderMode::PayloadOnly,
        SupportedProtocol::ICMP
            if evidence_policy.peer_source
                == pkthere_socket_policy::PeerSourceRequirement::RawPacketHeader =>
        {
            ReceiveHeaderMode::IpHeaderIncluded
        }
        SupportedProtocol::ICMP => ReceiveHeaderMode::TransportHeaderOnly,
    };
    policy.receive_evidence.connected = evidence_policy;
    policy.receive_evidence.unconnected = evidence_policy;
    let local_filter = expected_local.unwrap_or_else(|| {
        LogicalEndpoint::from_socket_addr_with_id(SocketAddr::new(local_ip, 0), 0)
    });
    SyntheticReceiveContext {
        socket: ReceiveSocketContext {
            role,
            proto,
            sock_type,
            parser: select_packet_parser(
                proto,
                if socket_is_ipv4 {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                },
                policy,
            )
            .expect("test packet parser"),
            policy,
            connected: false,
            local_filter,
            local_kernel_addr: local_filter.to_socket_addr(),
            evidence_key: pkthere_socket_policy::SocketEvidenceKey::initial(
                match role {
                    SocketLeg::ClientFacing => SocketRole::Listener,
                    SocketLeg::UpstreamFacing => SocketRole::Upstream,
                },
                0,
                local_filter.to_socket_addr(),
            ),
        },
        admission: SyntheticAdmissionStateContext {
            expected_inbound,
            expected_local,
            locked_flow: None,
            pending_icmp_client_lock: None,
            expected_session_id: None,
            additional_sessions: crate::flow_state::SessionAdmissionSnapshot::empty(),
        },
    }
}

pub(crate) fn test_config(listener_reply_id_request: IcmpReplyIdRequest) -> RuntimeConfig {
    RuntimeConfig {
        listen: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)),
            1001,
        ),
        listener_source_id_request: listener_reply_id_request,
        listener_reply_id_request,
        listen_proto: SupportedProtocol::ICMP,
        listen_mode: ListenMode::Fixed,
        listen_str: String::from("test-listen"),
        upstream: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000)),
            9000,
        ),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_str: String::from("test-upstream"),
        options: RuntimeOptions {
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            timeout_secs: 10,
            icmp_handshake_timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 0,
            icmp_session_pool_size: crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            debug_reresolve_address_file: None,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        },
    }
}

fn icmp_packet_with_prefix(ident: u16, is_request: bool, prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut packet = test_icmp_echo_packet_base(None, None, ident, is_request);
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(payload);
    packet
}

fn icmp_v6_packet_with_prefix(
    ident: u16,
    is_request: bool,
    prefix: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = test_icmp_echo_packet_base(
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        None,
        ident,
        is_request,
    );
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(payload);
    packet
}

pub(crate) fn icmp_raw_shim_packet(ident: u16, is_request: bool, shim_and_body: &[u8]) -> Vec<u8> {
    icmp_packet_with_prefix(ident, is_request, shim_and_body, &[])
}

pub(crate) fn icmp_cadence_packet(ident: u16, is_request: bool, source_id: u16) -> Vec<u8> {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let prefix = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::Cadence,
        ident,
        source_id,
        SessionId::for_tests(),
        None,
        0,
        &mut scratch,
    )
    .expect("encode test cadence");
    icmp_packet_with_prefix(ident, is_request, prefix, &[])
}

pub(crate) fn icmp_v6_cadence_packet(ident: u16, is_request: bool, source_id: u16) -> Vec<u8> {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let prefix = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::Cadence,
        ident,
        source_id,
        SessionId::for_tests(),
        None,
        0,
        &mut scratch,
    )
    .expect("encode test IPv6 cadence");
    icmp_v6_packet_with_prefix(ident, is_request, prefix, &[])
}

pub(crate) fn icmp_data_packet(
    ident: u16,
    is_request: bool,
    source_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let prefix = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::UserPayload,
        ident,
        source_id,
        SessionId::for_tests(),
        None,
        payload.len(),
        &mut scratch,
    )
    .expect("encode test user payload");
    icmp_packet_with_prefix(ident, is_request, prefix, payload)
}

pub(crate) fn icmp_negotiate_packet(
    ident: u16,
    is_request: bool,
    source_id: u16,
    reply_id: u16,
    acknowledge: bool,
) -> Vec<u8> {
    let negotiation = if acknowledge {
        ReplyIdNegotiation::acknowledge_key(reply_id, SessionKey::for_tests())
    } else {
        ReplyIdNegotiation::negotiate_with_key(reply_id, SessionKey::for_tests())
    }
    .expect("test negotiation IDs are nonzero");
    let control = if acknowledge {
        IcmpTunnelControl::NegotiateAck(negotiation)
    } else {
        IcmpTunnelControl::Negotiate(negotiation)
    };
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let prefix = encode_icmp_control_prefix_with_source(control, ident, source_id, &mut scratch)
        .expect("encode test control");
    icmp_packet_with_prefix(ident, is_request, prefix, &[])
}
pub(crate) fn icmp_wire_spec(
    expected_inbound: Option<FlowTuple>,
    locked_flow: Option<ClientFlowKey>,
) -> SyntheticReceiveContext {
    let mut policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Listener,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::RAW,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let source_metadata = ReceiveEvidencePolicy {
        peer_source: pkthere_socket_policy::PeerSourceRequirement::SourceMetadata,
        protocol_id: pkthere_socket_policy::ProtocolIdRequirement::ParsedTransportIdentifier,
    };
    policy.receive_evidence.connected = source_metadata;
    policy.receive_evidence.unconnected = source_metadata;
    policy.receive_header = ReceiveHeaderMode::TransportHeaderOnly;
    SyntheticReceiveContext {
        socket: ReceiveSocketContext {
            role: SocketLeg::ClientFacing,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::RAW,
            parser: select_packet_parser(SupportedProtocol::ICMP, Domain::IPV4, policy)
                .expect("test ICMP packet parser"),
            policy,
            connected: false,
            local_filter: LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 1001),
            local_kernel_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            evidence_key: pkthere_socket_policy::SocketEvidenceKey::initial(
                SocketRole::Listener,
                0,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            ),
        },
        admission: SyntheticAdmissionStateContext {
            expected_inbound,
            expected_local: Some(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001)),
            locked_flow,
            pending_icmp_client_lock: None,
            expected_session_id: locked_flow
                .map(|_| crate::net::framing_shim::SessionId::for_tests()),
            additional_sessions: crate::flow_state::SessionAdmissionSnapshot::empty(),
        },
    }
}

pub(crate) fn pending_icmp_lock_candidate() -> crate::flow_state::PendingIcmpClientLock {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let inbound_local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let outbound_local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3003);
    let session_key = crate::net::framing_shim::SessionKey::for_tests();
    crate::flow_state::PendingIcmpClientLock {
        flow_key: ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            0x2002,
        )),
        session_key: Some(session_key),
        observed_control: Some(crate::flow_state::PendingClientControl::Negotiate {
            reply_id: remote.id(),
        }),
        reset_challenge: 0,
        reset_evidence: None,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(outbound_local, remote)),
        ),
    }
}
