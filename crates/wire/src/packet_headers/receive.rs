use super::{
    ParsedPacketHeaders, parse_icmp_v4_transport, parse_icmp_v6_transport, parse_ipv4_icmp_packet,
    parse_ipv6_icmp_packet, parse_udp_datagram_payload,
};
use crate::SupportedProtocol;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

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
}

impl PartialEq for ReceiveParserKernel {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.protocol == other.protocol
            && self.version == other.version
            && self.mode == other.mode
    }
}

impl Eq for ReceiveParserKernel {}

impl ReceiveParserKernel {
    #[inline]
    pub fn parse(self, bytes: &[u8]) -> ParsedPacketHeaders {
        (self.parse)(bytes)
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
    })
}

#[cfg(test)]
mod tests {
    use super::{IpVersion, ReceiveHeaderMode, select_receive_parser};
    use crate::SupportedProtocol;

    #[test]
    fn selector_covers_supported_layouts_and_rejects_cross_protocol_modes() {
        let cases = [
            (
                SupportedProtocol::UDP,
                IpVersion::V4,
                ReceiveHeaderMode::PayloadOnly,
                "udp-datagram-payload",
            ),
            (
                SupportedProtocol::UDP,
                IpVersion::V6,
                ReceiveHeaderMode::PayloadOnly,
                "udp-datagram-payload",
            ),
            (
                SupportedProtocol::ICMP,
                IpVersion::V4,
                ReceiveHeaderMode::TransportHeaderOnly,
                "icmpv4-transport",
            ),
            (
                SupportedProtocol::ICMP,
                IpVersion::V6,
                ReceiveHeaderMode::TransportHeaderOnly,
                "icmpv6-transport",
            ),
            (
                SupportedProtocol::ICMP,
                IpVersion::V4,
                ReceiveHeaderMode::IpHeaderIncluded,
                "ipv4-icmp-packet",
            ),
            (
                SupportedProtocol::ICMP,
                IpVersion::V6,
                ReceiveHeaderMode::IpHeaderIncluded,
                "ipv6-icmp-packet",
            ),
        ];
        for (protocol, version, mode, expected) in cases {
            assert_eq!(
                select_receive_parser(protocol, version, mode)
                    .expect("supported parser")
                    .name(),
                expected
            );
        }
        let mut combinations = 0;
        let mut supported = 0;
        for protocol in [SupportedProtocol::UDP, SupportedProtocol::ICMP] {
            for version in [IpVersion::V4, IpVersion::V6] {
                for mode in [
                    ReceiveHeaderMode::PayloadOnly,
                    ReceiveHeaderMode::TransportHeaderOnly,
                    ReceiveHeaderMode::IpHeaderIncluded,
                ] {
                    combinations += 1;
                    let expected = protocol == SupportedProtocol::UDP
                        && mode == ReceiveHeaderMode::PayloadOnly
                        || protocol == SupportedProtocol::ICMP
                            && mode != ReceiveHeaderMode::PayloadOnly;
                    assert_eq!(
                        select_receive_parser(protocol, version, mode).is_ok(),
                        expected,
                        "unexpected selector result for {protocol:?}/{version:?}/{mode:?}"
                    );
                    supported += usize::from(expected);
                }
            }
        }
        assert_eq!(combinations, 12);
        assert_eq!(supported, 6);

        let udp_v4 = select_receive_parser(
            SupportedProtocol::UDP,
            IpVersion::V4,
            ReceiveHeaderMode::PayloadOnly,
        )
        .expect("IPv4 UDP parser");
        let udp_v6 = select_receive_parser(
            SupportedProtocol::UDP,
            IpVersion::V6,
            ReceiveHeaderMode::PayloadOnly,
        )
        .expect("IPv6 UDP parser");
        assert_eq!(udp_v4.name(), udp_v6.name());
        assert_ne!(udp_v4, udp_v6);
        assert_eq!(udp_v4.version(), IpVersion::V4);
        assert_eq!(udp_v6.version(), IpVersion::V6);
    }
}
