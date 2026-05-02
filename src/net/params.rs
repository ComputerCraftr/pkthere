use socket2::SockAddr;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

// Shared protocol/packet limits
pub(crate) const MAX_WIRE_PAYLOAD: usize = 65535; // Used for receive buffer sizing

// Maximum safe user payloads (IPv4 = 65535 - 20 IP - 8 L4 - 1 Shim)
pub(crate) const MAX_SAFE_UDP_IPV4_PAYLOAD: usize = 65507;
pub(crate) const MAX_SAFE_ICMP_IPV4_PAYLOAD: usize = 65506;

// Maximum safe user payloads (IPv6 = 65535 - 8 L4 - 1 Shim)
pub(crate) const MAX_SAFE_UDP_IPV6_PAYLOAD: usize = 65527;
pub(crate) const MAX_SAFE_ICMP_IPV6_PAYLOAD: usize = 65526;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CanonicalAddr {
    pub addr: SocketAddr,
    pub id: u16, // Finalized OS port or ICMP Identifier
}

impl CanonicalAddr {
    #[inline]
    pub fn new(addr: SocketAddr, id: u16) -> Self {
        let addr = match addr {
            SocketAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(*a.ip(), id)),
            SocketAddr::V6(a) => {
                SocketAddr::V6(SocketAddrV6::new(*a.ip(), id, a.flowinfo(), a.scope_id()))
            }
        };
        Self { addr, id }
    }

    #[inline]
    pub fn from_v4(ip: Ipv4Addr, id: u16) -> Self {
        Self {
            addr: SocketAddr::V4(SocketAddrV4::new(ip, id)),
            id,
        }
    }

    #[inline]
    pub fn from_v6(ip: Ipv6Addr, id: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self {
            addr: SocketAddr::V6(SocketAddrV6::new(ip, id, flowinfo, scope_id)),
            id,
        }
    }

    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self {
            id: addr.port(),
            addr,
        }
    }

    #[inline]
    pub fn from_sock_addr(sa: &SockAddr) -> Option<Self> {
        if let Some(v4) = sa.as_socket_ipv4() {
            Some(Self::from_v4(*v4.ip(), v4.port()))
        } else {
            sa.as_socket_ipv6()
                .map(|v6| Self::from_v6(*v6.ip(), v6.port(), v6.flowinfo(), v6.scope_id()))
        }
    }

    #[inline]
    pub fn from_sock_addr_with_id(sa: &SockAddr, id: u16) -> Option<Self> {
        if let Some(v4) = sa.as_socket_ipv4() {
            Some(Self::from_v4(*v4.ip(), id))
        } else {
            sa.as_socket_ipv6()
                .map(|v6| Self::from_v6(*v6.ip(), id, v6.flowinfo(), v6.scope_id()))
        }
    }

    #[inline]
    pub fn as_sock_addr(self) -> SockAddr {
        SockAddr::from(self.addr)
    }

    #[inline]
    pub fn with_resolved_ip(self, resolved: SocketAddr) -> Self {
        let addr = match (self.addr, resolved) {
            (SocketAddr::V4(_current), SocketAddr::V4(resolved)) => {
                SocketAddr::V4(SocketAddrV4::new(*resolved.ip(), self.id))
            }
            (SocketAddr::V6(current), SocketAddr::V6(resolved)) => {
                SocketAddr::V6(SocketAddrV6::new(
                    *resolved.ip(),
                    self.id,
                    current.flowinfo(),
                    current.scope_id(),
                ))
            }
            (_, SocketAddr::V4(resolved)) => {
                SocketAddr::V4(SocketAddrV4::new(*resolved.ip(), self.id))
            }
            (_, SocketAddr::V6(resolved)) => SocketAddr::V6(SocketAddrV6::new(
                *resolved.ip(),
                self.id,
                resolved.flowinfo(),
                resolved.scope_id(),
            )),
        };

        Self { addr, id: self.id }
    }
}

impl PartialEq for CanonicalAddr {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        if self.id != other.id {
            return false;
        }
        match (self.addr, other.addr) {
            (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
            (SocketAddr::V6(a), SocketAddr::V6(b)) => {
                a.ip() == b.ip()
                    && (a.scope_id() == 0 || b.scope_id() == 0 || a.scope_id() == b.scope_id())
            }
            _ => false,
        }
    }
}

impl Eq for CanonicalAddr {}

impl fmt::Display for CanonicalAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            SocketAddr::V4(addr) => write!(f, "{}:{}", addr.ip(), self.id),
            SocketAddr::V6(addr) => write!(f, "[{}]:{}", addr.ip(), self.id),
        }
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

    #[test]
    fn with_resolved_ip_preserves_canonical_id() {
        let canonical = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1111)),
            2222,
        );

        let refreshed = canonical.with_resolved_ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 2),
            9999,
        )));

        assert_eq!(refreshed.id, 2222);
        assert_eq!(
            refreshed.addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 2222))
        );
    }

    #[test]
    fn with_resolved_ip_preserves_ipv6_flowinfo_and_scope() {
        let canonical = CanonicalAddr::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1111, 7, 9)),
            3333,
        );

        let refreshed = canonical.with_resolved_ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
            4444,
            0,
            0,
        )));

        assert_eq!(refreshed.id, 3333);
        assert_eq!(
            refreshed.addr,
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
                3333,
                7,
                9,
            ))
        );
    }

    #[test]
    fn display_formats_ipv4_and_ipv6_canonical_addrs_unambiguously() {
        let v4 = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1111)),
            2222,
        );
        let v6 = CanonicalAddr::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1111, 0, 0)),
            3333,
        );

        assert_eq!(v4.to_string(), "127.0.0.1:2222");
        assert_eq!(v6.to_string(), "[::1]:3333");
    }
}
