use super::kernels::{parse_ipv4_icmp_network, parse_ipv6_icmp_network, parse_network_transport};
use super::{
    DeclaredPacketExtent, IpVersion, Ipv4PacketLengthEncoding, NetworkParseOutcome,
    ParsedPacketHeaders, parse_icmp_v4_transport, parse_icmp_v6_transport, parse_ipv4_icmp_packet,
    parse_ipv6_icmp_packet, parse_udp_datagram_payload,
};
use crate::SupportedProtocol;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveHeaderMode {
    PayloadOnly,
    TransportHeaderOnly,
    IpHeaderIncluded,
}

pub type PacketParserFn = fn(&[u8]) -> ParsedPacketHeaders;

#[derive(Clone, Copy, Debug)]
pub struct ReceiveParserKernel {
    parse: PacketParserFn,
    name: &'static str,
    protocol: SupportedProtocol,
    version: IpVersion,
    mode: ReceiveHeaderMode,
    ipv4_length: Ipv4PacketLengthEncoding,
}

impl PartialEq for ReceiveParserKernel {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.protocol == other.protocol
            && self.version == other.version
            && self.mode == other.mode
            && self.ipv4_length == other.ipv4_length
    }
}

impl Eq for ReceiveParserKernel {}

impl ReceiveParserKernel {
    /// Validates packet structure, endpoint identity fields, and declared
    /// extents. It deliberately does not revalidate IPv4, UDP, ICMP, or
    /// ICMPv6 checksums: the selected receive-socket policy is the checksum
    /// integrity authority for packets delivered to these kernels.
    #[inline]
    pub fn parse_network(self, bytes: &[u8]) -> NetworkParseOutcome {
        match (self.protocol, self.version, self.mode) {
            (_, _, ReceiveHeaderMode::PayloadOnly | ReceiveHeaderMode::TransportHeaderOnly) => {
                NetworkParseOutcome::NotPresent
            }
            (SupportedProtocol::ICMP, IpVersion::V4, ReceiveHeaderMode::IpHeaderIncluded) => {
                parse_ipv4_icmp_network(bytes, self.ipv4_length)
            }
            (SupportedProtocol::ICMP, IpVersion::V6, ReceiveHeaderMode::IpHeaderIncluded) => {
                parse_ipv6_icmp_network(bytes)
            }
            _ => NetworkParseOutcome::NotPresent,
        }
    }

    #[inline]
    pub fn parse_transport(
        self,
        bytes: &[u8],
        network: NetworkParseOutcome,
    ) -> ParsedPacketHeaders {
        match network {
            NetworkParseOutcome::NotPresent => (self.parse)(bytes),
            NetworkParseOutcome::Valid(_) | NetworkParseOutcome::Rejected(_) => {
                parse_network_transport(bytes, network)
            }
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn parse(self, bytes: &[u8]) -> ParsedPacketHeaders {
        let network = self.parse_network(bytes);
        self.parse_transport(bytes, network)
    }

    #[inline]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[inline]
    pub const fn protocol(self) -> SupportedProtocol {
        self.protocol
    }

    #[inline]
    pub const fn version(self) -> IpVersion {
        self.version
    }

    #[inline]
    pub const fn mode(self) -> ReceiveHeaderMode {
        self.mode
    }

    #[inline]
    pub fn declared_extent(
        self,
        parsed: ParsedPacketHeaders,
        bytes: &[u8],
    ) -> Option<DeclaredPacketExtent> {
        parsed.declared_extent(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedReceiveLayout {
    pub protocol: SupportedProtocol,
    pub version: IpVersion,
    pub mode: ReceiveHeaderMode,
}

impl fmt::Display for UnsupportedReceiveLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported receive parser layout: protocol={}, version={:?}, mode={:?}",
            self.protocol, self.version, self.mode
        )
    }
}

impl std::error::Error for UnsupportedReceiveLayout {}

pub fn select_receive_parser(
    protocol: SupportedProtocol,
    version: IpVersion,
    mode: ReceiveHeaderMode,
    ipv4_length: Ipv4PacketLengthEncoding,
) -> Result<ReceiveParserKernel, UnsupportedReceiveLayout> {
    let (parse, name): (PacketParserFn, &'static str) = match (protocol, version, mode) {
        (SupportedProtocol::UDP, _, ReceiveHeaderMode::PayloadOnly) => {
            (parse_udp_datagram_payload, "udp-datagram-payload")
        }
        (SupportedProtocol::ICMP, IpVersion::V4, ReceiveHeaderMode::TransportHeaderOnly) => {
            (parse_icmp_v4_transport, "icmpv4-transport")
        }
        (SupportedProtocol::ICMP, IpVersion::V6, ReceiveHeaderMode::TransportHeaderOnly) => {
            (parse_icmp_v6_transport, "icmpv6-transport")
        }
        (SupportedProtocol::ICMP, IpVersion::V4, ReceiveHeaderMode::IpHeaderIncluded) => {
            (parse_ipv4_icmp_packet, "ipv4-icmp-packet")
        }
        (SupportedProtocol::ICMP, IpVersion::V6, ReceiveHeaderMode::IpHeaderIncluded) => {
            (parse_ipv6_icmp_packet, "ipv6-icmp-packet")
        }
        _ => {
            return Err(UnsupportedReceiveLayout {
                protocol,
                version,
                mode,
            });
        }
    };
    Ok(ReceiveParserKernel {
        parse,
        name,
        protocol,
        version,
        mode,
        ipv4_length,
    })
}

#[cfg(test)]
mod tests;
