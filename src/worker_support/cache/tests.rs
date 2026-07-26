use super::{CachedClientState, SocketHandles};
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::net::sock_mgr::{ListenerMetadata, StateVersion, UpstreamMetadata};
use crate::worker_support::test_support::udp_socket;
use pkthere_socket_policy::{
    ProtocolPolicyIntent, SocketRole, resolve_socket_policy_with_protocol_intent,
};
use socket2::{Domain, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

pub(crate) fn test_config(lp: SupportedProtocol, up: SupportedProtocol) -> RuntimeConfig {
    RuntimeConfig {
        listen: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            8888,
        ),
        listener_source_id_request: IcmpReplyIdRequest::Default,
        listener_reply_id_request: IcmpReplyIdRequest::Default,
        listen_proto: lp,
        listen_mode: ListenMode::Fixed,
        listen_str: String::from("127.0.0.1:8888"),
        upstream: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
            9999,
        ),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: up,
        upstream_str: String::from("127.0.0.1:9999"),
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

fn test_handles() -> SocketHandles {
    let upstream_local = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777),
        7777,
    );
    let upstream_remote = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
        9999,
    );
    let upstream_flow = SocketLegFlow::new(
        Some(FlowTuple::new(upstream_remote, upstream_local)),
        Some(FlowTuple::new(upstream_local, upstream_remote)),
    );
    let listen_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Listener,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let upstream_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    SocketHandles::new(
        ListenerMetadata {
            flow: None,
            listener_flow: SocketLegFlow::empty(),
            listen_local_filter: LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                8888,
            ),
            listen_local_kernel_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                SocketRole::Listener,
                0,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            ),
            sock_type: Type::DGRAM,
            policy: listen_policy,
            parser: crate::net::packet_headers::select_packet_parser(
                SupportedProtocol::UDP,
                Domain::IPV4,
                listen_policy,
            )
            .expect("listener parser"),
        },
        udp_socket(),
        UpstreamMetadata {
            upstream_remote_filter: upstream_remote,
            upstream_local_filter: upstream_local,
            upstream_local_kernel_addr: upstream_local.to_socket_addr(),
            evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                SocketRole::Upstream,
                0,
                upstream_local.to_socket_addr(),
            ),
            upstream_flow,
            sock_type: Type::DGRAM,
            policy: upstream_policy,
            parser: crate::net::packet_headers::select_packet_parser(
                SupportedProtocol::UDP,
                Domain::IPV4,
                upstream_policy,
            )
            .expect("upstream parser"),
        },
        udp_socket(),
        StateVersion::INITIAL,
    )
}

#[test]
fn client_flow_key_compares_udp_and_icmp_explicitly() {
    let udp_a = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8888),
    )));
    let udp_b = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999),
    )));
    let icmp_a = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 11));
    let icmp_b = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 22));
    let icmp_c = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 11, 0));
    assert_ne!(udp_a, udp_b);
    assert_ne!(icmp_a, icmp_b);
    assert_ne!(icmp_a, icmp_c);
}

#[test]
fn cached_session_control_reply_route_is_built_from_listener_outbound_tuple() {
    let mut handles = test_handles();
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555);
    let listener = Arc::make_mut(&mut handles.listener);
    listener.listener_flow = SocketLegFlow::new(
        Some(FlowTuple::new(remote, local)),
        Some(FlowTuple::new(local, remote)),
    );
    listener.flow = Some(ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
    )));

    let reply_route = CachedClientState::maybe_build_session_control_reply_route(&handles)
        .expect("reply route exists");
    assert_eq!(reply_route.dest.id(), 5555);
    assert_eq!(reply_route.icmp_source_id(), 8888);
    assert_eq!(reply_route.icmp_advertised_reply_id(), 8888);
}

#[test]
fn pending_session_control_reply_route_keeps_source_and_reply_ids_distinct() {
    let route = CachedClientState::build_pending_session_control_reply_route(
        LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001),
            40001,
        ),
        7777,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        9999,
    );

    assert_eq!(route.icmp_header_id, 40001);
    assert_eq!(route.icmp_source_id(), 7777);
    assert_eq!(route.icmp_advertised_reply_id(), 9999);
}

#[test]
fn client_udp_route_uses_no_icmp_header_id() {
    let handles = test_handles();
    let route = CachedClientState::build_direction_send_route(false, &handles, None);
    assert_eq!(route.icmp_header_id, 0);
}

#[test]
fn client_raw_icmp_uses_locked_peer_id() {
    let mut handles = test_handles();
    let listener = Arc::make_mut(&mut handles.listener);
    listener.sock_type = Type::RAW;
    let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
    let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    listener.listener_flow = SocketLegFlow::new(
        Some(FlowTuple::new(remote, local)),
        Some(FlowTuple::new(local, remote)),
    );
    let route = CachedClientState::build_direction_send_route(false, &handles, None);
    assert_eq!(route.icmp_header_id, 12345);
}

#[test]
fn upstream_udp_route_uses_no_icmp_header_id() {
    let handles = test_handles();
    let route = CachedClientState::build_direction_send_route(true, &handles, None);
    assert_eq!(route.icmp_header_id, 9999);
}

#[test]
fn upstream_raw_icmp_supports_independent_local_and_remote_ids() {
    let mut handles = test_handles();
    let upstream = Arc::make_mut(&mut handles.upstream);
    upstream.sock_type = Type::RAW;
    // Our "Source Port" (local ID) is 7777
    upstream.upstream_local_filter = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        7777,
    );
    // Our "Destination Port" (remote ID) is 9999
    upstream.upstream_remote_filter = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        9999,
    );

    let route = CachedClientState::build_direction_send_route(true, &handles, None);

    // Outgoing packets must use the remote/destination ID (9999)
    assert_eq!(route.icmp_header_id, 9999);
}

#[test]
fn upstream_raw_icmp_uses_logical_remote_id() {
    let mut handles = test_handles();
    Arc::make_mut(&mut handles.upstream).sock_type = Type::RAW;
    let route = CachedClientState::build_direction_send_route(true, &handles, None);
    assert_eq!(route.icmp_header_id, 9999);
}
