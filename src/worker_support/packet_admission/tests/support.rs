use super::{
    AdmissionStateContext, ReceiveContext, ReceiveEvidencePolicy, ReceiveSocketContext, SocketLeg,
};
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::net::packet_headers::select_packet_parser;
use pkthere_socket_policy::{IcmpPolicyIntent, SocketRole, resolve_socket_policy_with_icmp_intent};
use socket2::{Domain, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

pub(crate) fn test_icmp_echo_packet(
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

pub(crate) fn admission_spec(
    role: SocketLeg,
    proto: SupportedProtocol,
    sock_type: Type,
    evidence_policy: ReceiveEvidencePolicy,
    expected_remote: Option<LogicalEndpoint>,
    expected_local_id: Option<u16>,
    local_filter_ip: Option<IpAddr>,
) -> ReceiveContext {
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
    let mut policy = resolve_socket_policy_with_icmp_intent(
        match role {
            SocketLeg::ClientFacing => SocketRole::Listener,
            SocketLeg::UpstreamFacing => SocketRole::Upstream,
        },
        proto,
        sock_type,
        TimeoutAction::Drop,
        false,
        if socket_is_ipv4 {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        IcmpPolicyIntent::default(),
    );
    policy.receive_evidence.connected = evidence_policy;
    policy.receive_evidence.unconnected = evidence_policy;
    let local_filter = expected_local.unwrap_or_else(|| {
        LogicalEndpoint::from_socket_addr_with_id(SocketAddr::new(local_ip, 0), 0)
    });
    ReceiveContext {
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
        admission: AdmissionStateContext {
            expected_inbound,
            expected_local,
            locked_flow: None,
            pending_icmp_client_lock: None,
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

pub(crate) fn test_udp_packet(
    source_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    match (source_ip, dest_ip) {
        (Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))) => {
            let mut packet = vec![0u8; 20 + 8 + payload.len()];
            packet[0] = 0x45;
            packet[9] = 17; // UDP
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            packet[20..28].copy_from_slice(&udp);
            packet[28..].copy_from_slice(payload);
            packet
        }
        (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
            let mut packet = vec![0u8; 40 + 8 + payload.len()];
            packet[0] = 0x60;
            packet[6] = 17; // UDP
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..48].copy_from_slice(&udp);
            packet[48..].copy_from_slice(payload);
            packet
        }
        _ => {
            let mut packet = udp;
            packet.extend_from_slice(payload);
            packet
        }
    }
}

pub(crate) fn icmp_tunnel_packet(ident: u16, is_request: bool, shim_payload: &[u8]) -> Vec<u8> {
    let mut packet = test_icmp_echo_packet(None, None, ident, is_request);
    packet.extend_from_slice(shim_payload);
    packet
}

pub(crate) fn icmp_wire_spec(
    expected_inbound: Option<FlowTuple>,
    locked_flow: Option<ClientFlowKey>,
) -> ReceiveContext {
    let mut policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Listener,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    let source_metadata = ReceiveEvidencePolicy {
        peer_source: pkthere_socket_policy::PeerSourceRequirement::SourceMetadata,
        protocol_id: pkthere_socket_policy::ProtocolIdRequirement::ParsedTransportIdentifier,
    };
    policy.receive_evidence.connected = source_metadata;
    policy.receive_evidence.unconnected = source_metadata;
    ReceiveContext {
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
        admission: AdmissionStateContext {
            expected_inbound,
            expected_local: Some(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001)),
            locked_flow,
            pending_icmp_client_lock: None,
        },
    }
}

pub(crate) fn pending_icmp_lock_candidate() -> crate::flow_state::PendingIcmpClientLock {
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0x2002);
    let inbound_local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
    let outbound_local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3003);
    crate::flow_state::PendingIcmpClientLock {
        flow_key: ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            0x2002,
        )),
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(outbound_local, remote)),
        ),
    }
}
