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
    V6 {
        ip: Ipv6Addr,
        flowinfo: u32,
        scope_id: u32,
    },
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
            IpAddr::V6(ip) => Self::from_v6(ip, id, 0, 0),
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
    pub(crate) const fn from_v6(ip: Ipv6Addr, id: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self {
            address: ScopedIp::V6 {
                ip,
                flowinfo,
                scope_id,
            },
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
            SocketAddr::V6(addr) => Self::from_v6(*addr.ip(), id, addr.flowinfo(), addr.scope_id()),
        }
    }

    #[inline]
    pub(crate) fn from_sock_addr(addr: &SockAddr) -> Option<Self> {
        addr.as_socket().map(Self::from_socket_addr)
    }

    #[inline]
    pub(crate) fn from_sock_addr_with_id(addr: &SockAddr, id: u16) -> Option<Self> {
        addr.as_socket()
            .map(|addr| Self::from_socket_addr_with_id(addr, id))
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
    pub(crate) fn domain(self) -> Domain {
        Domain::for_address(self.to_socket_addr())
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn flowinfo(self) -> u32 {
        match self.address {
            ScopedIp::V4(_) => 0,
            ScopedIp::V6 { flowinfo, .. } => flowinfo,
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
            (
                ScopedIp::V6 {
                    flowinfo, scope_id, ..
                },
                SocketAddr::V6(resolved),
            ) => Self::from_v6(
                *resolved.ip(),
                self.id(),
                if resolved.flowinfo() == 0 {
                    flowinfo
                } else {
                    resolved.flowinfo()
                },
                if resolved.scope_id() == 0 {
                    scope_id
                } else {
                    resolved.scope_id()
                },
            ),
            (_, SocketAddr::V4(resolved)) => Self::from_v4(*resolved.ip(), self.id()),
            (_, SocketAddr::V6(resolved)) => Self::from_v6(
                *resolved.ip(),
                self.id(),
                resolved.flowinfo(),
                resolved.scope_id(),
            ),
        }
    }

    #[inline]
    pub(crate) const fn to_socket_addr(self) -> SocketAddr {
        match self.address {
            ScopedIp::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, self.id.0)),
            ScopedIp::V6 {
                ip,
                flowinfo,
                scope_id,
            } => SocketAddr::V6(SocketAddrV6::new(ip, self.id.0, flowinfo, scope_id)),
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
            ScopedIp::V6 { ip, .. } => write!(formatter, "[{ip}]:{}", self.id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LogicalEndpoint;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    #[test]
    fn exact_equality_is_transitive_for_ipv6_scopes() {
        let first = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 3, 1);
        let second = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 3, 1);
        let third = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 3, 1);
        assert_eq!(first, first);
        assert_eq!(first, second);
        assert_eq!(second, first);
        assert_eq!(second, third);
        assert_eq!(first, third);

        let scope_zero = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0, 0);
        let scope_one = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0, 1);
        let scope_two = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0, 2);
        assert_ne!(scope_one, scope_zero);
        assert_ne!(scope_zero, scope_two);
        assert_ne!(scope_one, scope_two);
    }

    #[test]
    fn exact_hashing_distinguishes_ipv6_scope_and_flowinfo() {
        let endpoints = HashSet::from([
            LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0, 1),
            LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0, 2),
            LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1, 1),
        ]);
        assert_eq!(endpoints.len(), 3);
    }

    #[test]
    fn filter_scope_wildcard_is_directional_and_ignores_flowinfo() {
        let wildcard = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 9, 0);
        let scoped = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 4, 2);
        assert!(wildcard.matches_filter(scoped));
        assert!(!scoped.matches_filter(wildcard));
    }

    #[test]
    fn resolved_ip_preserves_id_and_missing_ipv6_metadata() {
        let endpoint = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 77, 3, 4);
        let resolved = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 999, 0, 0));
        let updated = endpoint.with_resolved_ip(resolved);
        assert_eq!(updated.id(), 77);
        assert_eq!(updated.flowinfo(), 3);
        assert_eq!(updated.scope_id(), 4);
    }

    #[test]
    fn udp_and_icmp_socket_projections_use_the_logical_id_once() {
        let udp_endpoint = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242);
        assert_eq!(
            udp_endpoint.to_socket_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242)
        );
        let icmp_endpoint = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 3131, 5, 7);
        assert_eq!(
            icmp_endpoint.to_socket_addr(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3131, 5, 7))
        );
        assert_eq!(
            icmp_endpoint
                .to_sock_addr()
                .as_socket()
                .expect("projected IP socket address"),
            icmp_endpoint.to_socket_addr()
        );
    }

    #[test]
    fn unspecified_addresses_and_zero_ids_are_exact_not_implicit_wildcards() {
        let filter = LogicalEndpoint::from_v4(Ipv4Addr::UNSPECIFIED, 0);
        let concrete = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 9);
        assert!(!filter.matches_filter(concrete));
    }
}
