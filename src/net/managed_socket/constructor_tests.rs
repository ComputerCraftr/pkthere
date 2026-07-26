use super::{AssociationState, ManagedSocket, ManagedSocketError};
use pkthere_socket_policy::PeerVerification;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn successful_connect_publishes_the_kernel_verified_association() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
    let peer = receiver.local_addr().expect("receiver address");
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create UDP sender");
    socket
        .bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
        .expect("bind UDP sender");
    let local_bind = socket
        .local_addr()
        .expect("sender local address")
        .as_socket()
        .expect("sender INET local address");
    let managed =
        ManagedSocket::from_unconnected(socket, PeerVerification::RequirePeerAddr, local_bind)
            .expect("wrap unconnected sender");
    managed.connect_unconnected(peer).expect("connect sender");
    assert_eq!(
        managed.association(),
        AssociationState::Connected { peer, epoch: 1 }
    );
}

#[test]
fn checked_constructors_reject_mismatched_kernel_association() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
    let peer = receiver.local_addr().expect("receiver address");
    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP sender");
    sender.connect(peer).expect("connect sender");
    let local_bind = sender.local_addr().expect("sender local address");

    assert!(matches!(
        ManagedSocket::from_unconnected(
            Socket::from(sender),
            PeerVerification::RequirePeerAddr,
            local_bind,
        ),
        Err(ManagedSocketError::UnexpectedInitialAssociation {
            expected_peer: None,
            observed_peer: Some(observed),
        }) if observed == peer
    ));
}

#[cfg(windows)]
#[test]
fn unbound_udp_constructor_defers_winsock_local_bind_inspection_until_connect() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
    let peer = receiver.local_addr().expect("receiver address");
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create UDP socket");
    let managed = ManagedSocket::from_unconnected(
        socket,
        PeerVerification::RequirePeerAddr,
        SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .expect("adopt unbound Winsock UDP socket");
    assert_eq!(
        managed.association(),
        AssociationState::Unconnected { epoch: 0 }
    );
    managed
        .connect_unconnected(peer)
        .expect("connect UDP socket");
    let realized = managed
        .local_addr()
        .expect("connected Winsock local address")
        .as_socket()
        .expect("connected Winsock INET local address");
    assert_ne!(realized.port(), 0);
    assert_eq!(
        managed
            .inner
            .association_state
            .lock()
            .expect("required local bind")
            .required_local_bind,
        realized
    );
}

#[test]
fn checked_connected_constructor_requires_the_exact_kernel_peer() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP receiver");
    let peer = receiver.local_addr().expect("receiver address");
    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP sender");
    sender.connect(peer).expect("connect sender");
    let local_bind = sender.local_addr().expect("sender local address");

    let managed = ManagedSocket::from_connected(Socket::from(sender), peer, local_bind)
        .expect("adopt connection");
    assert_eq!(
        managed.association(),
        AssociationState::Connected { peer, epoch: 0 }
    );
}
