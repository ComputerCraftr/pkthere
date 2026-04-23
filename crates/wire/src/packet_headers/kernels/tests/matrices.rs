use super::fixtures::{
    AcceptedIpPacketCase, Ipv6ExtensionCase, ipv4_icmp_packet, ipv4_icmp_packet_with_options,
    ipv4_udp_packet, ipv4_udp_packet_with_options, ipv6_icmp_packet, ipv6_icmp_packet_with_one_ext,
    ipv6_two_extension_headers_then_udp, ipv6_udp_packet, ipv6_udp_packet_with_ext_header,
    ipv6_udp_packet_with_one_ext, test_ipv4_dst, test_ipv4_src, test_ipv6_dst, test_ipv6_src,
    truncated_ipv6_extension_header, truncated_ipv6_extension_prefix_boundary,
};
use crate::packet_headers::{ParsedTransport, parse_packet_headers};
use std::net::IpAddr;

#[test]
fn parses_accepted_ip_packet_matrix() {
    let cases = [
        AcceptedIpPacketCase {
            name: "ipv4 udp payload",
            packet: ipv4_udp_packet(1111, 2222, b"udp!"),
            expected_transport: ParsedTransport::Ipv4Udp,
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
            expected_src_id: 1111,
            expected_dst_id: 2222,
            expected_payload_bounds: (28, 32),
        },
        AcceptedIpPacketCase {
            name: "ipv4 udp payload with ip options",
            packet: ipv4_udp_packet_with_options(5555, 6666, b"opts"),
            expected_transport: ParsedTransport::Ipv4Udp,
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
            expected_src_id: 5555,
            expected_dst_id: 6666,
            expected_payload_bounds: (32, 36),
        },
        AcceptedIpPacketCase {
            name: "ipv6 udp payload",
            packet: ipv6_udp_packet(3333, 4444, b"udp"),
            expected_transport: ParsedTransport::Ipv6Udp,
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
            expected_src_id: 3333,
            expected_dst_id: 4444,
            expected_payload_bounds: (48, 51),
        },
        AcceptedIpPacketCase {
            name: "ipv6 udp payload after one destination-options extension",
            packet: ipv6_udp_packet_with_one_ext(17, 7777, 8888, b"ext"),
            expected_transport: ParsedTransport::Ipv6Udp,
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
            expected_src_id: 7777,
            expected_dst_id: 8888,
            expected_payload_bounds: (56, 59),
        },
        AcceptedIpPacketCase {
            name: "ipv4 icmp payload with compact shim",
            packet: ipv4_icmp_packet(0x1234, 2, &[0x90, b'a', b'b', b'c']),
            expected_transport: ParsedTransport::Ipv4Icmp,
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
            expected_src_id: 0x1234,
            expected_dst_id: 0x1234,
            expected_payload_bounds: (29, 32),
        },
        AcceptedIpPacketCase {
            name: "ipv4 icmp payload with ip options and shim",
            packet: ipv4_icmp_packet_with_options(0x2468, 0x1357, &[0x80, 0xca, 0xfe]),
            expected_transport: ParsedTransport::Ipv4Icmp,
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
            expected_src_id: 0xcafe,
            expected_dst_id: 0x2468,
            expected_payload_bounds: (35, 35),
        },
        AcceptedIpPacketCase {
            name: "ipv6 icmp payload with compact shim",
            packet: ipv6_icmp_packet(0xbeef, 42, &[0x90, b'd', b'a', b't', b'a']),
            expected_transport: ParsedTransport::Ipv6Icmp,
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
            expected_src_id: 0xbeef,
            expected_dst_id: 0xbeef,
            expected_payload_bounds: (49, 53),
        },
        AcceptedIpPacketCase {
            name: "ipv6 icmp payload after one destination-options extension and shim",
            packet: ipv6_icmp_packet_with_one_ext(58, 0x3456, 0x789a, &[0x80, 0xde, 0xad]),
            expected_transport: ParsedTransport::Ipv6Icmp,
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
            expected_src_id: 0xdead,
            expected_dst_id: 0x3456,
            expected_payload_bounds: (59, 59),
        },
        AcceptedIpPacketCase {
            name: "ipv4 icmp payload with explicit source shim",
            packet: ipv4_icmp_packet(0x4321, 0x8765, &[0x80, 0xab, 0xcd]),
            expected_transport: ParsedTransport::Ipv4Icmp,
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
            expected_src_id: 0xabcd,
            expected_dst_id: 0x4321,
            expected_payload_bounds: (31, 31),
        },
        AcceptedIpPacketCase {
            name: "ipv6 icmp payload with explicit source shim",
            packet: ipv6_icmp_packet(0x4321, 0x8765, &[0x80, 0xab, 0xcd]),
            expected_transport: ParsedTransport::Ipv6Icmp,
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
            expected_src_id: 0xabcd,
            expected_dst_id: 0x4321,
            expected_payload_bounds: (51, 51),
        },
    ];

    for case in cases {
        let parsed = parse_packet_headers(&case.packet);
        assert_eq!(parsed.transport, case.expected_transport, "{}", case.name);
        assert_eq!(parsed.src_ip, Some(case.expected_src_ip), "{}", case.name);
        assert_eq!(parsed.dst_ip, Some(case.expected_dst_ip), "{}", case.name);
        assert_eq!(
            parsed.payload_bounds, case.expected_payload_bounds,
            "{}",
            case.name
        );

        match case.expected_transport {
            ParsedTransport::Ipv4Udp | ParsedTransport::Ipv6Udp => {
                let udp = parsed.udp.expect(case.name);
                assert_eq!(udp.src_port, case.expected_src_id, "{}", case.name);
                assert_eq!(udp.dst_port, case.expected_dst_id, "{}", case.name);
                assert!(parsed.icmp.is_none(), "{}", case.name);
            }
            ParsedTransport::Ipv4Icmp | ParsedTransport::Ipv6Icmp => {
                let icmp = parsed.icmp.expect(case.name);
                assert_eq!(
                    icmp.identity.source_id,
                    Some(case.expected_src_id),
                    "{}",
                    case.name
                );
                assert_eq!(
                    icmp.identity.destination_id, case.expected_dst_id,
                    "{}",
                    case.name
                );
                assert!(parsed.udp.is_none(), "{}", case.name);
            }
            other => panic!("unexpected transport in accepted matrix: {other:?}"),
        }
    }
}

#[test]
fn ipv6_extension_matrix_handles_supported_and_unsupported_chains() {
    let cases = [
        Ipv6ExtensionCase {
            name: "one destination-options extension before udp",
            packet: ipv6_udp_packet_with_one_ext(17, 7777, 8888, b"ext"),
            expected_transport: ParsedTransport::Ipv6Udp,
            expected_src_id: Some(7777),
            expected_dst_id: Some(8888),
            expected_payload_bounds: (56, 59),
        },
        Ipv6ExtensionCase {
            name: "one hop-by-hop extension before udp",
            packet: ipv6_udp_packet_with_ext_header(0, 17, 7777, 8888, b"hbh"),
            expected_transport: ParsedTransport::Ipv6Udp,
            expected_src_id: Some(7777),
            expected_dst_id: Some(8888),
            expected_payload_bounds: (56, 59),
        },
        Ipv6ExtensionCase {
            name: "one routing extension before udp",
            packet: ipv6_udp_packet_with_ext_header(43, 17, 7777, 8888, b"rtg"),
            expected_transport: ParsedTransport::Ipv6Udp,
            expected_src_id: Some(7777),
            expected_dst_id: Some(8888),
            expected_payload_bounds: (56, 59),
        },
        Ipv6ExtensionCase {
            name: "one destination-options extension before icmpv6",
            packet: ipv6_icmp_packet_with_one_ext(58, 0x3456, 0x789a, &[0x80, 0xde, 0xad]),
            expected_transport: ParsedTransport::Ipv6Icmp,
            expected_src_id: Some(0xdead),
            expected_dst_id: Some(0x3456),
            expected_payload_bounds: (59, 59),
        },
        Ipv6ExtensionCase {
            name: "two extension headers are unsupported",
            packet: ipv6_two_extension_headers_then_udp(),
            expected_transport: ParsedTransport::Unsupported,
            expected_src_id: None,
            expected_dst_id: None,
            expected_payload_bounds: (0, 0),
        },
        Ipv6ExtensionCase {
            name: "truncated first extension header is malformed",
            packet: truncated_ipv6_extension_header(),
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_dst_id: None,
            expected_payload_bounds: (0, 0),
        },
        Ipv6ExtensionCase {
            name: "first extension prefix one byte short is malformed",
            packet: truncated_ipv6_extension_prefix_boundary(47),
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_dst_id: None,
            expected_payload_bounds: (0, 0),
        },
    ];

    for case in cases {
        let parsed = parse_packet_headers(&case.packet);
        assert_eq!(parsed.transport, case.expected_transport, "{}", case.name);
        assert_eq!(
            parsed.src_ip,
            Some(IpAddr::V6(test_ipv6_src())),
            "{}",
            case.name
        );
        assert_eq!(
            parsed.dst_ip,
            Some(IpAddr::V6(test_ipv6_dst())),
            "{}",
            case.name
        );
        assert_eq!(
            parsed.payload_bounds, case.expected_payload_bounds,
            "{}",
            case.name
        );

        match case.expected_transport {
            ParsedTransport::Ipv6Udp => {
                let udp = parsed.udp.expect(case.name);
                assert_eq!(Some(udp.src_port), case.expected_src_id, "{}", case.name);
                assert_eq!(Some(udp.dst_port), case.expected_dst_id, "{}", case.name);
                assert!(parsed.icmp.is_none(), "{}", case.name);
            }
            ParsedTransport::Ipv6Icmp => {
                let icmp = parsed.icmp.expect(case.name);
                assert_eq!(
                    icmp.identity.source_id, case.expected_src_id,
                    "{}",
                    case.name
                );
                assert_eq!(
                    Some(icmp.identity.destination_id),
                    case.expected_dst_id,
                    "{}",
                    case.name
                );
                assert!(parsed.udp.is_none(), "{}", case.name);
            }
            ParsedTransport::Unsupported | ParsedTransport::Malformed => {
                assert!(parsed.udp.is_none(), "{}", case.name);
                assert!(parsed.icmp.is_none(), "{}", case.name);
            }
            other => panic!("unexpected transport in ipv6 extension matrix: {other:?}"),
        }
    }
}
