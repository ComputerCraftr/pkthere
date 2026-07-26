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
mod tests;
