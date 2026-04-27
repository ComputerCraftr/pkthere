use socket2::SockAddr;
use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

// Shared protocol/packet limits
pub const MAX_WIRE_PAYLOAD: usize = 65535; // Used for receive buffer sizing

// Maximum safe user payloads (IPv4 = 65535 - 20 IP - 8 L4 - 1 Shim)
pub const MAX_SAFE_UDP_IPV4_PAYLOAD: usize = 65507;
pub const MAX_SAFE_ICMP_IPV4_PAYLOAD: usize = 65506;

// Maximum safe user payloads (IPv6 = 65535 - 8 L4 - 1 Shim)
pub const MAX_SAFE_UDP_IPV6_PAYLOAD: usize = 65527;
pub const MAX_SAFE_ICMP_IPV6_PAYLOAD: usize = 65526;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalAddr {
    pub addr: SocketAddr,
    pub id: u16, // Finalized OS port or ICMP Identifier
}

impl CanonicalAddr {
    pub fn new(addr: SocketAddr, id: u16) -> Self {
        Self { addr, id }
    }

    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self {
            id: addr.port(),
            addr,
        }
    }

    #[inline]
    pub fn as_sock_addr(self) -> SockAddr {
        let canonical = match self.addr {
            SocketAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(*addr.ip(), self.id)),
            SocketAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(
                *addr.ip(),
                self.id,
                addr.flowinfo(),
                addr.scope_id(),
            )),
        };
        SockAddr::from(canonical)
    }
}

impl fmt::Display for CanonicalAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr.ip(), self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalAddr;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn from_socket_addr_captures_os_port_verbatim() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242));
        let canonical = CanonicalAddr::from_socket_addr(addr);
        assert_eq!(canonical.addr, addr);
        assert_eq!(canonical.id, 4242);
    }

    #[test]
    fn as_sock_addr_rewrites_socket_port_to_canonical_id() {
        let canonical = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1111)),
            2222,
        );
        assert_eq!(
            canonical.as_sock_addr().as_socket().expect("sockaddr"),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2222))
        );
    }

    #[test]
    fn as_sock_addr_preserves_ipv6_flowinfo_and_scope() {
        let canonical = CanonicalAddr::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1111, 7, 9)),
            3333,
        );
        assert_eq!(
            canonical.as_sock_addr().as_socket().expect("sockaddr"),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3333, 7, 9))
        );
    }
}
