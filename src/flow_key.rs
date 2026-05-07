use crate::cli::SupportedProtocol;
use crate::net::params::CanonicalAddr;
use crate::net::payload::PayloadEvent;
use std::fmt;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ClientFlowKey {
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
    pub fn from_validated_client_payload(
        c2u: bool,
        src: CanonicalAddr,
        listen_proto: SupportedProtocol,
        event: &PayloadEvent<'_>,
    ) -> Option<Self> {
        if !c2u {
            return None;
        }
        match listen_proto {
            SupportedProtocol::UDP => Some(Self::Udp(src.addr)),
            SupportedProtocol::ICMP => match event {
                PayloadEvent::UserPayload {
                    icmp: Some(icmp), ..
                } => Some(Self::from_icmp_source(src, icmp.logical_src_ident)),
                _ => None,
            },
        }
    }

    pub fn from_validated_c2u(
        src: CanonicalAddr,
        listen_proto: SupportedProtocol,
        event: &PayloadEvent<'_>,
    ) -> Option<Self> {
        Self::from_validated_client_payload(true, src, listen_proto, event)
    }

    fn from_icmp_source(src: CanonicalAddr, ident: u16) -> Self {
        match src.addr {
            SocketAddr::V4(addr) => Self::IcmpV4 {
                ip: *addr.ip(),
                ident,
            },
            SocketAddr::V6(addr) => Self::IcmpV6 {
                ip: *addr.ip(),
                ident,
                flowinfo: addr.flowinfo(),
                scope_id: addr.scope_id(),
            },
        }
    }

    #[inline]
    pub fn icmp_ident(self) -> Option<u16> {
        match self {
            Self::Udp(_) => None,
            Self::IcmpV4 { ident, .. } | Self::IcmpV6 { ident, .. } => Some(ident),
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
    use crate::cli::SupportedProtocol;
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::PayloadEvent;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

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
    }

    #[test]
    fn validated_icmp_flow_key_uses_payload_logical_source_id() {
        let src = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            100,
        );
        let event = PayloadEvent::user_payload(200, 1, SupportedProtocol::UDP, b"x", Some(200));

        assert_eq!(
            ClientFlowKey::from_validated_client_payload(
                true,
                src,
                SupportedProtocol::ICMP,
                &event
            ),
            Some(ClientFlowKey::IcmpV4 {
                ip: Ipv4Addr::new(127, 0, 0, 2),
                ident: 200,
            })
        );
    }

    #[test]
    fn validated_flow_key_does_not_lock_from_non_user_icmp_events() {
        let src = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            100,
        );
        let event = PayloadEvent::cadence_packet(100, 1);

        assert_eq!(
            ClientFlowKey::from_validated_client_payload(
                true,
                src,
                SupportedProtocol::ICMP,
                &event
            ),
            None
        );
    }

    #[test]
    fn validated_flow_key_does_not_lock_from_u2c_reflections() {
        let src = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            100,
        );
        let event = PayloadEvent::user_payload(100, 1, SupportedProtocol::UDP, b"x", Some(200));

        assert_eq!(
            ClientFlowKey::from_validated_client_payload(
                false,
                src,
                SupportedProtocol::ICMP,
                &event
            ),
            None
        );
    }
}
