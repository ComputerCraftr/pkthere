use crate::cli::SupportedProtocol;
use crate::net::params::CanonicalAddr;
use crate::net::payload::PayloadEvent;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FlowEndpoint {
    pub(crate) ip: IpAddr,
    pub(crate) id: u16,
    pub(crate) flowinfo: u32,
    pub(crate) scope_id: u32,
}

impl FlowEndpoint {
    #[inline]
    pub(crate) fn new(ip: IpAddr, id: u16) -> Self {
        Self {
            ip,
            id,
            flowinfo: 0,
            scope_id: 0,
        }
    }

    #[inline]
    pub(crate) fn from_canonical(canonical: CanonicalAddr) -> Self {
        match canonical.addr {
            SocketAddr::V4(addr) => Self::new(IpAddr::V4(*addr.ip()), canonical.id),
            SocketAddr::V6(addr) => Self {
                ip: IpAddr::V6(*addr.ip()),
                id: canonical.id,
                flowinfo: addr.flowinfo(),
                scope_id: addr.scope_id(),
            },
        }
    }

    #[inline]
    pub(crate) fn with_id(self, id: u16) -> Self {
        Self { id, ..self }
    }

    #[inline]
    pub(crate) fn canonical(self) -> CanonicalAddr {
        match self.ip {
            IpAddr::V4(ip) => CanonicalAddr::from_v4(ip, self.id),
            IpAddr::V6(ip) => CanonicalAddr::from_v6(ip, self.id, self.flowinfo, self.scope_id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FlowTuple {
    pub(crate) src: FlowEndpoint,
    pub(crate) dst: FlowEndpoint,
}

impl FlowTuple {
    #[inline]
    pub(crate) const fn new(src: FlowEndpoint, dst: FlowEndpoint) -> Self {
        Self { src, dst }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct SocketLegFlow {
    pub(crate) inbound: Option<FlowTuple>,
    pub(crate) outbound: Option<FlowTuple>,
}

impl SocketLegFlow {
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            inbound: None,
            outbound: None,
        }
    }

    #[inline]
    pub(crate) const fn new(inbound: Option<FlowTuple>, outbound: Option<FlowTuple>) -> Self {
        Self { inbound, outbound }
    }

    #[inline]
    pub(crate) fn outbound_destination(self) -> Option<CanonicalAddr> {
        self.outbound.map(|flow| flow.dst.canonical())
    }
}

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
    #[inline]
    pub(crate) const fn icmp_ident(self) -> Option<u16> {
        match self {
            Self::Udp(_) => None,
            Self::IcmpV4 { ident, .. } | Self::IcmpV6 { ident, .. } => Some(ident),
        }
    }

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
                } => Some(Self::from_icmp_source(src, icmp.negotiated_remote_reply_id)),
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

    pub(crate) fn locked_listener_flow_from_validated_c2u(
        src: CanonicalAddr,
        listen_local_recv: CanonicalAddr,
        explicit_listen_reply_id: Option<u16>,
        listen_proto: SupportedProtocol,
        event: &PayloadEvent<'_>,
    ) -> Option<(Self, SocketLegFlow)> {
        let key = Self::from_validated_c2u(src, listen_proto, event)?;
        let remote = match listen_proto {
            SupportedProtocol::UDP => FlowEndpoint::from_canonical(src),
            SupportedProtocol::ICMP => match event {
                PayloadEvent::UserPayload {
                    icmp: Some(icmp), ..
                } => FlowEndpoint::from_canonical(src).with_id(icmp.negotiated_remote_reply_id),
                _ => return None,
            },
        };
        let inbound_local = match listen_proto {
            SupportedProtocol::UDP => FlowEndpoint::from_canonical(listen_local_recv),
            SupportedProtocol::ICMP => match event {
                PayloadEvent::UserPayload {
                    icmp: Some(icmp), ..
                } => FlowEndpoint::from_canonical(listen_local_recv)
                    .with_id(icmp.inbound_header_ident),
                _ => return None,
            },
        };
        let outbound_local = match listen_proto {
            SupportedProtocol::UDP => FlowEndpoint::from_canonical(listen_local_recv),
            SupportedProtocol::ICMP => match event {
                PayloadEvent::UserPayload {
                    icmp: Some(icmp), ..
                } => FlowEndpoint::from_canonical(listen_local_recv)
                    .with_id(explicit_listen_reply_id.unwrap_or(icmp.inbound_header_ident)),
                _ => return None,
            },
        };
        let flow = SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(outbound_local, remote)),
        );
        Some((key, flow))
    }

    fn from_icmp_source(src: CanonicalAddr, ident: u16) -> Self {
        let endpoint = FlowEndpoint::from_canonical(src).with_id(ident);
        match endpoint.ip {
            IpAddr::V4(ip) => Self::IcmpV4 { ip, ident },
            IpAddr::V6(ip) => Self::IcmpV6 {
                ip,
                ident,
                flowinfo: endpoint.flowinfo,
                scope_id: endpoint.scope_id,
            },
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
    use super::{ClientFlowKey, FlowEndpoint};
    use crate::cli::SupportedProtocol;
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::PayloadEvent;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
    fn flow_endpoint_from_canonical_uses_canonical_id_not_socket_port() {
        let v4 = CanonicalAddr {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1111)),
            id: 2222,
        };
        let endpoint = FlowEndpoint::from_canonical(v4);
        assert_eq!(endpoint.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.id, 2222);

        let v6 = CanonicalAddr {
            addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3333, 4, 5)),
            id: 4444,
        };
        let endpoint = FlowEndpoint::from_canonical(v6);
        assert_eq!(endpoint.ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(endpoint.id, 4444);
        assert_eq!(endpoint.flowinfo, 4);
        assert_eq!(endpoint.scope_id, 5);
    }

    #[test]
    fn validated_icmp_flow_key_uses_negotiated_reply_id() {
        let src = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            100,
        );
        let event =
            PayloadEvent::user_payload(200, 100, 1, SupportedProtocol::UDP, b"x", Some(200));

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
    fn locked_icmp_listener_flow_splits_header_receive_id_from_shim_remote_id() {
        let src = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
            100,
        );
        let listen = CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1),
            1,
        );
        let event =
            PayloadEvent::user_payload(200, 100, 1, SupportedProtocol::UDP, b"x", Some(200));

        let (key, flow) = ClientFlowKey::locked_listener_flow_from_validated_c2u(
            src,
            listen,
            Some(300),
            SupportedProtocol::ICMP,
            &event,
        )
        .expect("locked ICMP flow");

        assert_eq!(
            key,
            ClientFlowKey::IcmpV4 {
                ip: Ipv4Addr::new(127, 0, 0, 2),
                ident: 200
            }
        );
        let inbound = flow.inbound.expect("inbound tuple");
        let outbound = flow.outbound.expect("outbound tuple");
        assert_eq!(inbound.src.id, 200);
        assert_eq!(inbound.dst.id, 100);
        assert_eq!(outbound.src.id, 300);
        assert_eq!(outbound.dst.id, 200);
        assert_eq!(flow.outbound_destination().expect("outbound dest").id, 200);
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
        let event =
            PayloadEvent::user_payload(100, 100, 1, SupportedProtocol::UDP, b"x", Some(200));

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
