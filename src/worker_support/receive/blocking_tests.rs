use crate::cli::SupportedProtocol;
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::ManagedSocket;
use crate::net::payload::{BufferedPayload, PayloadEvent};
use pkthere_socket_policy::{PeerVerification, SocketRole};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[test]
fn unreadable_poll_does_not_pin_timed_control_state() {
    let flow_state = FlowRuntimeState::new();
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"pending");
    let buffered = BufferedPayload::from_event_at(&event, None, Instant::now());
    flow_state.begin_upstream_reply_id_handshake(
        2002,
        crate::net::framing_shim::SessionId::for_tests().get(),
        1,
        buffered,
    );

    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create socket");
    socket
        .bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .expect("bind socket");
    let local_bind = socket
        .local_addr()
        .expect("bound socket address")
        .as_socket()
        .expect("bound INET socket address");
    let managed =
        ManagedSocket::from_unconnected(socket, PeerVerification::RequirePeerAddr, local_bind)
            .expect("manage socket");
    managed
        .configure_worker_io_lanes(1)
        .expect("register the production worker I/O lane");
    managed
        .bind_authority_identity(SocketRole::Upstream, 0, 1, false)
        .expect("bind production receiver authority identity");
    let registry = crate::net::sock_mgr::ReceiverRegistry::new(
        crate::net::sock_mgr::ReceiverRole::Upstream,
        0,
        &managed,
    );
    let mut receiver = registry.claim(0).expect("claim production receiver slot");
    receiver
        .prepare_for_receive()
        .expect("prepare production receiver ownership and descriptor cache");
    let wake = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind wake socket");

    let readiness = receiver
        .wait_until_readable_or_wake(&wake, Duration::ZERO)
        .expect("poll empty packet and wake sockets");

    assert_eq!(readiness.flags(), (false, false));
    assert_eq!(
        flow_state.control_observation_count_for_tests(),
        0,
        "an empty readiness wait must not own a control observation"
    );
}
