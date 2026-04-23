use socket2::Socket;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

pub(crate) fn udp_socket() -> Socket {
    Socket::from(
        UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind UDP test socket"),
    )
}
