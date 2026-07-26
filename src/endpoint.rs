use socket2::{Domain, SockAddr};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LogicalEndpoint {
    address: ScopedIp,
    id: EndpointId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ScopedIp {
    V4(Ipv4Addr),
    V6 { ip: Ipv6Addr, scope_id: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub(crate) struct EndpointId(u16);

impl LogicalEndpoint {
    #[inline]
    #[cfg(test)]
    pub(crate) const fn new(ip: IpAddr, id: u16) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::from_v4(ip, id),
            IpAddr::V6(ip) => Self::from_v6(ip, id, 0),
        }
    }

    #[inline]
    pub(crate) const fn from_v4(ip: Ipv4Addr, id: u16) -> Self {
        Self {
            address: ScopedIp::V4(ip),
            id: EndpointId(id),
        }
    }

    #[inline]
    pub(crate) const fn from_v6(ip: Ipv6Addr, id: u16, scope_id: u32) -> Self {
        Self {
            address: ScopedIp::V6 { ip, scope_id },
            id: EndpointId(id),
        }
    }

    #[inline]
    pub(crate) fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::from_socket_addr_with_id(addr, addr.port())
    }

    #[inline]
    pub(crate) fn from_socket_addr_with_id(addr: SocketAddr, id: u16) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::from_v4(*addr.ip(), id),
            SocketAddr::V6(addr) => Self::from_v6(*addr.ip(), id, addr.scope_id()),
        }
    }

    #[inline]
    pub(crate) const fn ip(self) -> IpAddr {
        match self.address {
            ScopedIp::V4(ip) => IpAddr::V4(ip),
            ScopedIp::V6 { ip, .. } => IpAddr::V6(ip),
        }
    }

    #[inline]
    pub(crate) const fn id(self) -> u16 {
        self.id.0
    }

    #[inline]
    pub(crate) const fn domain(self) -> Domain {
        match self.address {
            ScopedIp::V4(_) => Domain::IPV4,
            ScopedIp::V6 { .. } => Domain::IPV6,
        }
    }

    #[inline]
    pub(crate) const fn scope_id(self) -> u32 {
        match self.address {
            ScopedIp::V4(_) => 0,
            ScopedIp::V6 { scope_id, .. } => scope_id,
        }
    }

    #[inline]
    pub(crate) const fn with_id(self, id: u16) -> Self {
        Self {
            address: self.address,
            id: EndpointId(id),
        }
    }

    #[inline]
    pub(crate) fn with_resolved_ip(self, resolved: SocketAddr) -> Self {
        match (self.address, resolved) {
            (ScopedIp::V4(_), SocketAddr::V4(resolved)) => Self::from_v4(*resolved.ip(), self.id()),
            (ScopedIp::V6 { scope_id, .. }, SocketAddr::V6(resolved)) => Self::from_v6(
                *resolved.ip(),
                self.id(),
                if resolved.scope_id() == 0 {
                    scope_id
                } else {
                    resolved.scope_id()
                },
            ),
            (_, SocketAddr::V4(resolved)) => Self::from_v4(*resolved.ip(), self.id()),
            (_, SocketAddr::V6(resolved)) => {
                Self::from_v6(*resolved.ip(), self.id(), resolved.scope_id())
            }
        }
    }

    #[inline]
    pub(crate) const fn to_socket_addr(self) -> SocketAddr {
        match self.address {
            ScopedIp::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, self.id.0)),
            ScopedIp::V6 { ip, scope_id } => {
                SocketAddr::V6(SocketAddrV6::new(ip, self.id.0, 0, scope_id))
            }
        }
    }

    #[inline]
    pub(crate) fn to_sock_addr(self) -> SockAddr {
        SockAddr::from(self.to_socket_addr())
    }

    #[inline]
    pub(crate) fn matches_filter(self, candidate: Self) -> bool {
        if self.id.0 != candidate.id.0 {
            return false;
        }
        self.matches_ip_filter(candidate)
    }

    #[inline]
    pub(crate) fn matches_ip_filter(self, candidate: Self) -> bool {
        match (self.address, candidate.address) {
            (ScopedIp::V4(filter), ScopedIp::V4(candidate)) => filter == candidate,
            (
                ScopedIp::V6 {
                    ip: filter_ip,
                    scope_id: filter_scope,
                    ..
                },
                ScopedIp::V6 {
                    ip: candidate_ip,
                    scope_id: candidate_scope,
                    ..
                },
            ) => {
                filter_ip == candidate_ip && (filter_scope == 0 || filter_scope == candidate_scope)
            }
            _ => false,
        }
    }
}

impl fmt::Display for LogicalEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            ScopedIp::V4(ip) => write!(formatter, "{ip}:{}", self.id()),
            ScopedIp::V6 { ip, scope_id: 0 } => write!(formatter, "[{ip}]:{}", self.id()),
            ScopedIp::V6 { ip, scope_id } => {
                write!(formatter, "[{ip}%{scope_id}]:{}", self.id())
            }
        }
    }
}

#[cfg(test)]
mod tests;
