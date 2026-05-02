use crate::cli::SupportedProtocol;
use crate::net::params::CanonicalAddr;
use socket2::Socket;

use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketPeerRole {
    Client,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketPeerFilter {
    pub(crate) role: SocketPeerRole,
    pub(crate) proto: SupportedProtocol,
    pub(crate) expected: CanonicalAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceivedPacket {
    Accepted {
        len: usize,
        source: Option<SocketAddr>,
    },
    Filtered {
        source: SocketAddr,
    },
    UnsupportedSource,
}

#[inline]
pub(crate) fn peer_matches_filter(filter: SocketPeerFilter, source: SocketAddr) -> bool {
    let _role = filter.role;
    match filter.proto {
        SupportedProtocol::UDP => source == filter.expected.addr,
        SupportedProtocol::ICMP => match (source, filter.expected.addr) {
            (SocketAddr::V4(source), SocketAddr::V4(expected)) => source.ip() == expected.ip(),
            (SocketAddr::V6(source), SocketAddr::V6(expected)) => {
                source.ip() == expected.ip() && source.scope_id() == expected.scope_id()
            }
            _ => false,
        },
    }
}

#[inline]
pub(crate) fn recv_with_possible_peer_filter(
    sock: &Socket,
    connected: bool,
    buf: &mut [MaybeUninit<u8>],
    filter: Option<SocketPeerFilter>,
) -> io::Result<ReceivedPacket> {
    if connected {
        return sock
            .recv(buf)
            .map(|len| ReceivedPacket::Accepted { len, source: None });
    }

    sock.recv_from(buf).map(|(len, src_sa)| {
        let Some(source) = src_sa.as_socket() else {
            return ReceivedPacket::UnsupportedSource;
        };
        if filter.is_some_and(|filter| !peer_matches_filter(filter, source)) {
            ReceivedPacket::Filtered { source }
        } else {
            ReceivedPacket::Accepted {
                len,
                source: Some(source),
            }
        }
    })
}

#[cfg(unix)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & libc::POLLIN) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = WSAPOLLFD {
            fd: sock.as_raw_socket() as usize,
            events: POLLRDNORM as i16,
            revents: 0,
        };
        let rc = unsafe { WSAPoll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & (POLLRDNORM as i16)) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = unsafe { WSAGetLastError() };
        if err == WSAEINTR {
            continue;
        }
        if rc == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(err));
        }
        return Err(io::Error::other("unexpected WSAPoll return value"));
    }
}

#[cfg(not(any(unix, windows)))]
#[inline]
pub(crate) fn wait_socket_until_readable(_sock: &Socket, _timeout: Duration) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket readiness waiting is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        SocketPeerFilter, SocketPeerRole, peer_matches_filter, recv_with_possible_peer_filter,
    };
    use crate::cli::SupportedProtocol;
    use crate::net::params::CanonicalAddr;
    use crate::recv_buf::RecvBuf;
    use socket2::Socket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

    #[test]
    fn recv_buf_initialized_exposes_only_requested_length() {
        let mut buf = RecvBuf::<4>::new();
        let recv = buf.recv_buf_mut();
        recv[0].write(b'a');
        recv[1].write(b'b');
        recv[2].write(b'c');
        recv[3].write(b'd');
        assert_eq!(buf.initialized(2), b"ab");
        assert_eq!(buf.initialized(4), b"abcd");
    }

    #[test]
    fn udp_peer_filter_matches_full_socket_addr_for_both_roles() {
        let expected =
            CanonicalAddr::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444));
        for role in [SocketPeerRole::Client, SocketPeerRole::Upstream] {
            let filter = SocketPeerFilter {
                role,
                proto: SupportedProtocol::UDP,
                expected,
            };
            assert!(peer_matches_filter(filter, expected.addr));
            assert!(!peer_matches_filter(
                filter,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4445)
            ));
            assert!(!peer_matches_filter(
                filter,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 4444)
            ));
        }
    }

    #[test]
    fn icmp_peer_filter_matches_ip_not_port_for_both_roles() {
        let expected = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 9999)),
            4242,
        );
        for role in [SocketPeerRole::Client, SocketPeerRole::Upstream] {
            let filter = SocketPeerFilter {
                role,
                proto: SupportedProtocol::ICMP,
                expected,
            };
            assert!(peer_matches_filter(
                filter,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1)
            ));
            assert!(!peer_matches_filter(
                filter,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1)
            ));
        }
    }

    #[test]
    fn icmp_ipv6_peer_filter_preserves_scope() {
        let expected = CanonicalAddr::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 7)),
            4242,
        );
        let filter = SocketPeerFilter {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::ICMP,
            expected,
        };
        assert!(peer_matches_filter(
            filter,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 7))
        ));
        assert!(!peer_matches_filter(
            filter,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 8))
        ));
    }

    #[test]
    fn unconnected_recv_filters_wrong_udp_peer() {
        let recv_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44444));
        let recv = UdpSocket::bind(recv_addr).expect("bind recv socket");
        let sender = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            55555,
        )))
        .expect("bind sender");
        sender.send_to(b"x", recv_addr).expect("send packet");

        let recv = Socket::from(recv);
        let filter = SocketPeerFilter {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::UDP,
            expected: CanonicalAddr::from_socket_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                44446,
            )),
        };
        let mut buf = RecvBuf::<8>::new();
        let result = recv_with_possible_peer_filter(&recv, false, buf.recv_buf_mut(), Some(filter))
            .expect("recv with filter");
        assert!(matches!(result, super::ReceivedPacket::Filtered { .. }));
    }
}
