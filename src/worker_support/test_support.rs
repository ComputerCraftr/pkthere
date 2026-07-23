use crate::net::managed_socket::ManagedSocket;
use pkthere_socket_policy::PeerVerification;
use socket2::Socket;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

pub(crate) fn udp_socket() -> ManagedSocket {
    ManagedSocket::from_unconnected(
        Socket::from(
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind UDP test socket"),
        ),
        PeerVerification::RequirePeerAddr,
    )
    .expect("wrap unconnected UDP test socket")
}
