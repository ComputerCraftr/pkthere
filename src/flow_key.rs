use crate::endpoint::LogicalEndpoint;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FlowTuple {
    pub(crate) src: LogicalEndpoint,
    pub(crate) dst: LogicalEndpoint,
}

impl FlowTuple {
    #[inline]
    pub(crate) const fn new(src: LogicalEndpoint, dst: LogicalEndpoint) -> Self {
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
    pub(crate) fn outbound_destination(self) -> Option<LogicalEndpoint> {
        self.outbound.map(|flow| flow.dst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ClientFlowKey {
    Udp(LogicalEndpoint),
    Icmp(LogicalEndpoint),
}

impl ClientFlowKey {
    #[inline]
    pub(crate) fn from_icmp_reply_id(source: LogicalEndpoint, ident: u16) -> Self {
        Self::Icmp(source.with_id(ident))
    }
}

impl fmt::Display for ClientFlowKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(endpoint) => write!(formatter, "{endpoint}"),
            Self::Icmp(endpoint) if endpoint.scope_id() == 0 => {
                write!(formatter, "{}#icmp:{}", endpoint.ip(), endpoint.id())
            }
            Self::Icmp(endpoint) => write!(
                formatter,
                "{}%{}#icmp:{}",
                endpoint.ip(),
                endpoint.scope_id(),
                endpoint.id()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClientFlowKey;
    use crate::endpoint::LogicalEndpoint;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn udp_flow_key_uses_full_logical_endpoint() {
        let a = ClientFlowKey::Udp(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000));
        let b = ClientFlowKey::Udp(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001));
        assert_ne!(a, b);
    }

    #[test]
    fn icmp_flow_key_uses_ip_and_identifier() {
        let a = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 10));
        let b = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 11));
        let c = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::new(127, 0, 0, 2), 10));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn icmp_v6_flow_key_preserves_scope_and_flowinfo() {
        let a = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 10, 1, 2));
        let b = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 10, 1, 3));
        assert_ne!(a, b);
    }
}
