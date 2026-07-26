use super::{IpVersion, Ipv4PacketLengthEncoding, ReceiveHeaderMode, select_receive_parser};
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
            select_receive_parser(
                protocol,
                version,
                mode,
                Ipv4PacketLengthEncoding::NetworkTotal,
            )
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
                    select_receive_parser(
                        protocol,
                        version,
                        mode,
                        Ipv4PacketLengthEncoding::NetworkTotal,
                    )
                    .is_ok(),
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
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("IPv4 UDP parser");
    let udp_v6 = select_receive_parser(
        SupportedProtocol::UDP,
        IpVersion::V6,
        ReceiveHeaderMode::PayloadOnly,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("IPv6 UDP parser");
    assert_eq!(udp_v4.name(), udp_v6.name());
    assert_ne!(udp_v4, udp_v6);
    assert_eq!(udp_v4.version(), IpVersion::V4);
    assert_eq!(udp_v6.version(), IpVersion::V6);
}
