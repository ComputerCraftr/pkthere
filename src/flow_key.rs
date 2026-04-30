use crate::cli::SupportedProtocol;
use crate::net::payload::PayloadEvent;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientFlowKey {
    Udp(SocketAddr),
    IcmpV4 {
        ip: std::net::Ipv4Addr,
        ident: u16,
    },
    IcmpV6 {
        ip: std::net::Ipv6Addr,
        ident: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

impl ClientFlowKey {
    pub fn from_wire(
        src: SocketAddr,
        listen_proto: SupportedProtocol,
        event: &PayloadEvent<'_>,
    ) -> io::Result<Self> {
        Ok(match listen_proto {
            SupportedProtocol::UDP => Self::Udp(src),
            SupportedProtocol::ICMP => {
                let transport_src_ident = match event {
                    PayloadEvent::UserPayload { icmp, .. } => {
                        icmp.as_ref()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "ICMP listen path requires ICMP metadata",
                                )
                            })?
                            .transport_src_ident
                    }
                    PayloadEvent::SessionControl { icmp, .. }
                    | PayloadEvent::CadencePacket { icmp } => icmp.transport_src_ident,
                };
                match src {
                    SocketAddr::V4(addr) => Self::IcmpV4 {
                        ip: *addr.ip(),
                        ident: transport_src_ident,
                    },
                    SocketAddr::V6(addr) => Self::IcmpV6 {
                        ip: *addr.ip(),
                        ident: transport_src_ident,
                        flowinfo: addr.flowinfo(),
                        scope_id: addr.scope_id(),
                    },
                }
            }
        })
    }

    #[inline]
    pub fn icmp_ident(self) -> Option<u16> {
        match self {
            Self::Udp(_) => None,
            Self::IcmpV4 { ident, .. } | Self::IcmpV6 { ident, .. } => Some(ident),
        }
    }

    #[inline]
    pub fn display_addr(self) -> SocketAddr {
        match self {
            Self::Udp(addr) => addr,
            Self::IcmpV4 { ip, ident } => SocketAddr::new(IpAddr::V4(ip), ident),
            Self::IcmpV6 {
                ip,
                ident,
                flowinfo,
                scope_id,
            } => SocketAddr::V6(SocketAddrV6::new(ip, ident, flowinfo, scope_id)),
        }
    }
}

impl fmt::Display for ClientFlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "{addr}"),
            Self::IcmpV4 { ip, ident } => write!(f, "{ip}#icmp:{ident}"),
            Self::IcmpV6 {
                ip,
                ident,
                scope_id,
                ..
            } => write!(f, "{ip}%{scope_id}#icmp:{ident}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClientFlowKey;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn udp_flow_key_uses_full_socket_addr() {
        let a = ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1000)));
        let b = ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)));
        assert_ne!(a, b);
    }

    #[test]
    fn icmp_flow_key_uses_ip_and_identifier() {
        let a = ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 10,
        };
        let b = ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 11,
        };
        let c = ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::new(127, 0, 0, 2),
            ident: 10,
        };
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn icmp_v6_flow_key_preserves_scope_and_flowinfo() {
        let a = ClientFlowKey::IcmpV6 {
            ip: Ipv6Addr::LOCALHOST,
            ident: 10,
            flowinfo: 1,
            scope_id: 2,
        };
        let b = ClientFlowKey::IcmpV6 {
            ip: Ipv6Addr::LOCALHOST,
            ident: 10,
            flowinfo: 1,
            scope_id: 3,
        };
        assert_ne!(a, b);
        assert_eq!(
            a.display_addr(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 10, 1, 2))
        );
    }
}
