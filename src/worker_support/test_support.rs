#![cfg(all(test, not(miri)))]

use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::net::sock_mgr::{
    ListenerMetadata, SocketHandles, SocketManager, SocketManagerInit, StateVersion,
    UpstreamMetadata,
};
use pkthere_socket_policy::{
    ProtocolPolicyIntent, SocketRole, listener_worker_socket_policy,
    resolve_socket_policy_with_protocol_intent,
};
use socket2::{Domain, Type};
use std::net::SocketAddr;

pub(crate) fn udp_socket() -> crate::net::managed_socket::ManagedSocket {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind UDP test socket");
    let local_bind = socket.local_addr().expect("UDP test socket address");
    crate::net::managed_socket::ManagedSocket::from_unconnected(
        socket2::Socket::from(socket),
        pkthere_socket_policy::PeerVerification::RequirePeerAddr,
        local_bind,
    )
    .expect("wrap unconnected UDP test socket")
}

pub(crate) fn bind_test_socket_authority(
    socket: &crate::net::managed_socket::ManagedSocket,
    role: SocketRole,
    socket_slot: u32,
) {
    socket
        .bind_authority_identity(role, socket_slot, 1, false)
        .expect("bind production socket authority identity for test");
}

pub(crate) fn activate_upstream_session_for_forwarding(
    flow_state: &crate::flow_state::FlowRuntimeState,
    session_id: u64,
) {
    use crate::cli::SupportedProtocol;
    use crate::net::payload::{BufferedPayload, PayloadEvent};
    use std::time::Instant;

    let initial = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"initial");
    flow_state.begin_upstream_reply_id_handshake(
        2002,
        session_id,
        1,
        BufferedPayload::from_event(&initial, None),
    );
    if let Some(lease) = flow_state.lease_due_upstream_reply_id_negotiation(Instant::now()) {
        flow_state
            .record_upstream_negotiation_sequence(&lease, 0)
            .expect("record active-session negotiation sequence");
        flow_state.complete_upstream_reply_id_negotiation_send(lease, 0, true, Instant::now());
    }
    let crate::flow_state::ReplyIdHandshakeAck::Matched { token, .. } =
        flow_state.ack_upstream_reply_id_handshake(2002, session_id, 0, None)
    else {
        panic!("active-session negotiation ACK did not match");
    };
    let initial_payload = flow_state
        .commit_upstream_reply_id_handshake(token)
        .expect("commit active transmit session");
    assert!(
        !flow_state
            .complete_upstream_reply_id_payload_send(initial_payload)
            .expect("complete initial active-session payload")
    );
}

fn udp_policy(role: SocketRole) -> pkthere_socket_policy::ResolvedSocketPolicy {
    resolve_socket_policy_with_protocol_intent(
        role,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    )
}

pub(crate) fn forwarding_handles(
    protocol: SupportedProtocol,
    client: SocketAddr,
    upstream_peer: SocketAddr,
) -> SocketHandles {
    let client_sock = udp_socket();
    client_sock
        .configure_worker_io_lanes(2)
        .expect("configure listener send lanes");
    bind_test_socket_authority(&client_sock, SocketRole::Listener, 0);
    let listener_address = client_sock
        .local_addr()
        .expect("listener socket address")
        .as_socket()
        .expect("listener socket has IP address");
    let upstream_sock = udp_socket();
    upstream_sock
        .configure_worker_io_lanes(2)
        .expect("configure upstream send lanes");
    bind_test_socket_authority(&upstream_sock, SocketRole::Upstream, 0);
    let upstream_local_address = upstream_sock
        .local_addr()
        .expect("upstream socket address")
        .as_socket()
        .expect("upstream socket has IP address");
    let client_endpoint = LogicalEndpoint::from_socket_addr(client);
    let listener_endpoint = LogicalEndpoint::from_socket_addr(listener_address);
    let upstream_endpoint = LogicalEndpoint::from_socket_addr(upstream_peer);
    let upstream_local_endpoint = LogicalEndpoint::from_socket_addr(upstream_local_address);
    let listener_flow = SocketLegFlow::new(
        Some(FlowTuple::new(client_endpoint, listener_endpoint)),
        Some(FlowTuple::new(listener_endpoint, client_endpoint)),
    );
    let upstream_flow = SocketLegFlow::new(
        Some(FlowTuple::new(upstream_endpoint, upstream_local_endpoint)),
        Some(FlowTuple::new(upstream_local_endpoint, upstream_endpoint)),
    );
    let intent = match protocol {
        SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
        SupportedProtocol::ICMP => {
            ProtocolPolicyIntent::Icmp(pkthere_socket_policy::IcmpPolicyIntent::default())
        }
    };
    let listener_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Listener,
        intent,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let upstream_policy = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        intent,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let flow = match protocol {
        SupportedProtocol::UDP => ClientFlowKey::Udp(client_endpoint),
        SupportedProtocol::ICMP => ClientFlowKey::Icmp(client_endpoint),
    };
    SocketHandles::new(
        ListenerMetadata {
            flow: Some(flow),
            listener_flow,
            listen_local_filter: listener_endpoint,
            listen_local_kernel_addr: listener_address,
            evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                SocketRole::Listener,
                0,
                listener_address,
            ),
            sock_type: Type::DGRAM,
            policy: listener_policy,
            parser: crate::net::packet_headers::select_packet_parser(
                protocol,
                Domain::IPV4,
                listener_policy,
            )
            .expect("listener parser"),
        },
        client_sock,
        UpstreamMetadata {
            upstream_remote_filter: upstream_endpoint,
            upstream_local_filter: upstream_local_endpoint,
            upstream_local_kernel_addr: upstream_local_address,
            evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                SocketRole::Upstream,
                0,
                upstream_local_address,
            ),
            upstream_flow,
            sock_type: Type::DGRAM,
            policy: upstream_policy,
            parser: crate::net::packet_headers::select_packet_parser(
                protocol,
                Domain::IPV4,
                upstream_policy,
            )
            .expect("upstream parser"),
        },
        upstream_sock,
        StateVersion::INITIAL,
    )
}

pub(crate) fn unused_manager(upstream_peer: SocketAddr) -> SocketManager {
    let client_sock = udp_socket();
    let listener_address = client_sock
        .local_addr()
        .expect("manager listener address")
        .as_socket()
        .expect("manager listener has IP address");
    SocketManager::new(SocketManagerInit {
        socket_slot: 0,
        worker_io_lanes: 1,
        client_sock,
        listen_local_filter: LogicalEndpoint::from_socket_addr(listener_address),
        listen_local_kernel_addr: listener_address,
        listen_sock_type: Type::DGRAM,
        listen_target: listener_address.to_string(),
        listen_proto: SupportedProtocol::UDP,
        listen_policy: udp_policy(SocketRole::Listener),
        listen_worker_socket_policy: listener_worker_socket_policy(1, false),
        listen_debug_unconnected: false,
        upstream_remote_filter: LogicalEndpoint::from_socket_addr(upstream_peer),
        upstream_target: upstream_peer.to_string(),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_debug_unconnected: false,
        upstream_icmp_kernel_echo_self_handshake: false,
        upstream_worker_socket_policy: Default::default(),
        shared_upstream_identity: None,
        force_raw_icmp_wildcard_upstream: false,
        timeout_act: TimeoutAction::Drop,
        debug_handles: false,
    })
    .expect("create context socket manager")
}
