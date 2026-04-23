use super::{
    FragmentCase, IcmpEchoCase, IcmpShimCase, IpAddr, ParsedTransport, TruncatedIpTransportCase,
    headerless_icmp_packet, icmp_echo, ipv4_icmp_packet, ipv4_udp_fragment_packet,
    ipv6_fragment_header_packet, ipv6_icmp_packet, parse_packet_headers, test_ipv4_dst,
    test_ipv4_src, test_ipv6_dst, test_ipv6_src,
};

#[test]
fn parses_headerless_icmp_echo() {
    let mut packet = Vec::from(icmp_echo(0x0102, 0x0304, true));
    packet.push(0x90); // SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER
    packet.extend_from_slice(b"xy");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::HeaderlessIcmp);
    assert_eq!(parsed.icmp.expect("icmp").identity.destination_id, 0x0102);
    assert_eq!(parsed.payload_bounds, (9, 11));
}

#[test]
fn truncated_headers_are_malformed_without_payload_bounds() {
    for packet in [&[0u8; 0][..], &[0x45, 0, 0, 0][..], &[8, 0, 0, 0][..]] {
        let parsed = parse_packet_headers(packet);
        assert_eq!(parsed.transport, ParsedTransport::Malformed);
        assert_eq!(parsed.payload_bounds, (0, 0));
        assert!(parsed.icmp.is_none());
        assert!(parsed.udp.is_none());
    }
}

#[test]
fn truncated_supported_protocol_matrix_is_malformed() {
    let mut cases: Vec<(&'static str, Vec<u8>)> = Vec::new();

    let mut v4_icmp = vec![0u8; 20];
    v4_icmp[0] = 0x45;
    v4_icmp[9] = 1;
    cases.push(("truncated v4 icmp", v4_icmp));

    let mut v4_udp = vec![0u8; 20];
    v4_udp[0] = 0x45;
    v4_udp[9] = 17;
    cases.push(("truncated v4 udp", v4_udp));

    let mut v6_icmp = vec![0u8; 40];
    v6_icmp[0] = 0x60;
    v6_icmp[6] = 58;
    cases.push(("truncated v6 icmp", v6_icmp));

    let mut v6_udp = vec![0u8; 40];
    v6_udp[0] = 0x60;
    v6_udp[6] = 17;
    cases.push(("truncated v6 udp", v6_udp));

    for len in 1..8 {
        let mut hdrless = vec![0u8; len];
        hdrless[0] = 8;
        cases.push(("truncated headerless icmp", hdrless));
    }

    for (name, packet) in cases {
        let parsed = parse_packet_headers(&packet);
        assert_eq!(
            parsed.transport,
            ParsedTransport::Malformed,
            "{name} len {}",
            packet.len()
        );
        assert_eq!(parsed.payload_bounds, (0, 0), "{name} len {}", packet.len());
        assert!(parsed.icmp.is_none(), "{name} len {}", packet.len());
        assert!(parsed.udp.is_none(), "{name} len {}", packet.len());
    }
}

#[test]
fn truncated_ip_transport_matrix_preserves_ip_metadata() {
    let cases = [
        TruncatedIpTransportCase {
            name: "truncated ipv4 icmp",
            packet: {
                let mut packet = vec![0u8; 20];
                packet[0] = 0x45;
                packet[9] = 1;
                packet[12..16].copy_from_slice(&test_ipv4_src().octets());
                packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
                packet
            },
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
        },
        TruncatedIpTransportCase {
            name: "truncated ipv4 udp",
            packet: {
                let mut packet = vec![0u8; 20];
                packet[0] = 0x45;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&test_ipv4_src().octets());
                packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
                packet
            },
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
        },
        TruncatedIpTransportCase {
            name: "truncated ipv6 icmp",
            packet: {
                let mut packet = vec![0u8; 40];
                packet[0] = 0x60;
                packet[6] = 58;
                packet[8..24].copy_from_slice(&test_ipv6_src().octets());
                packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
                packet
            },
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
        },
        TruncatedIpTransportCase {
            name: "truncated ipv6 udp",
            packet: {
                let mut packet = vec![0u8; 40];
                packet[0] = 0x60;
                packet[6] = 17;
                packet[8..24].copy_from_slice(&test_ipv6_src().octets());
                packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
                packet
            },
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
        },
    ];

    for case in cases {
        let parsed = parse_packet_headers(&case.packet);
        assert_eq!(
            parsed.transport,
            ParsedTransport::Malformed,
            "{}",
            case.name
        );
        assert_eq!(parsed.src_ip, Some(case.expected_src_ip), "{}", case.name);
        assert_eq!(parsed.dst_ip, Some(case.expected_dst_ip), "{}", case.name);
        assert_eq!(parsed.payload_bounds, (0, 0), "{}", case.name);
        assert!(parsed.icmp.is_none(), "{}", case.name);
        assert!(parsed.udp.is_none(), "{}", case.name);
    }
}

#[test]
fn fragment_matrix_is_unsupported_and_preserves_ip_metadata() {
    let cases = [
        FragmentCase {
            name: "ipv4 initial fragment with more-fragments flag",
            packet: ipv4_udp_fragment_packet(0x2000),
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
        },
        FragmentCase {
            name: "ipv4 non-initial fragment with offset",
            packet: ipv4_udp_fragment_packet(0x0001),
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
        },
        FragmentCase {
            name: "ipv4 fragment with more-fragments flag and offset",
            packet: ipv4_udp_fragment_packet(0x2001),
            expected_src_ip: IpAddr::V4(test_ipv4_src()),
            expected_dst_ip: IpAddr::V4(test_ipv4_dst()),
        },
        FragmentCase {
            name: "ipv6 fragment header before udp",
            packet: ipv6_fragment_header_packet(17),
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
        },
        FragmentCase {
            name: "ipv6 fragment header before icmpv6",
            packet: ipv6_fragment_header_packet(58),
            expected_src_ip: IpAddr::V6(test_ipv6_src()),
            expected_dst_ip: IpAddr::V6(test_ipv6_dst()),
        },
    ];

    for case in cases {
        let parsed = parse_packet_headers(&case.packet);
        assert_eq!(
            parsed.transport,
            ParsedTransport::Unsupported,
            "{}",
            case.name
        );
        assert_eq!(parsed.src_ip, Some(case.expected_src_ip), "{}", case.name);
        assert_eq!(parsed.dst_ip, Some(case.expected_dst_ip), "{}", case.name);
        assert_eq!(parsed.payload_bounds, (0, 0), "{}", case.name);
        assert!(parsed.icmp.is_none(), "{}", case.name);
        assert!(parsed.udp.is_none(), "{}", case.name);
    }
}

#[test]
fn unsupported_transport_has_no_stale_fields() {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[9] = 6;
    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::Unsupported);
    assert_eq!(parsed.payload_bounds, (0, 0));
    assert!(parsed.icmp.is_none());
    assert!(parsed.udp.is_none());
}

#[test]
fn parses_headerless_icmp_echo_type_matrix() {
    let cases = [
        IcmpEchoCase {
            icmp_type: 8,
            code: 0,
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_is_req: Some(true),
        },
        IcmpEchoCase {
            icmp_type: 0,
            code: 0,
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_is_req: Some(false),
        },
        IcmpEchoCase {
            icmp_type: 128,
            code: 0,
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_is_req: Some(true),
        },
        IcmpEchoCase {
            icmp_type: 129,
            code: 0,
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_is_req: Some(false),
        },
        IcmpEchoCase {
            icmp_type: 8,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 0,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 128,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 129,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 3,
            code: 0,
            expected_transport: ParsedTransport::Unsupported,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 11,
            code: 0,
            expected_transport: ParsedTransport::Unsupported,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 133,
            code: 0,
            expected_transport: ParsedTransport::Unsupported,
            expected_is_req: None,
        },
    ];

    for case in cases {
        let packet = headerless_icmp_packet(case.icmp_type, case.code);
        let parsed = parse_packet_headers(&packet);

        assert_eq!(
            parsed.transport, case.expected_transport,
            "type {} code {}",
            case.icmp_type, case.code
        );

        match case.expected_is_req {
            Some(is_req) => {
                let icmp = parsed.icmp.expect("icmp");
                assert_eq!(
                    icmp.identity.destination_id, 0x1111,
                    "type {}",
                    case.icmp_type
                );
                assert_eq!(icmp.identity.source_id, None, "type {}", case.icmp_type);
                assert_eq!(icmp.seq, 0x2222, "type {}", case.icmp_type);
                assert_eq!(icmp.is_req, is_req, "type {}", case.icmp_type);
                assert_eq!(parsed.payload_bounds, (8, 8), "type {}", case.icmp_type);
            }
            None => {
                assert!(parsed.icmp.is_none(), "type {}", case.icmp_type);
                assert_eq!(parsed.payload_bounds, (0, 0), "type {}", case.icmp_type);
            }
        }
    }
}

#[test]
fn parses_ip_icmp_echo_type_code_matrix() {
    let cases = [
        IcmpEchoCase {
            icmp_type: 8,
            code: 0,
            expected_transport: ParsedTransport::Ipv4Icmp,
            expected_is_req: Some(true),
        },
        IcmpEchoCase {
            icmp_type: 8,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 3,
            code: 0,
            expected_transport: ParsedTransport::Unsupported,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 128,
            code: 0,
            expected_transport: ParsedTransport::Ipv6Icmp,
            expected_is_req: Some(true),
        },
        IcmpEchoCase {
            icmp_type: 128,
            code: 1,
            expected_transport: ParsedTransport::Malformed,
            expected_is_req: None,
        },
        IcmpEchoCase {
            icmp_type: 133,
            code: 0,
            expected_transport: ParsedTransport::Unsupported,
            expected_is_req: None,
        },
    ];

    for case in cases {
        let (mut packet, icmp_off) = if case.icmp_type >= 128 {
            (ipv6_icmp_packet(0x1111, 0x2222, &[]), 40)
        } else {
            (ipv4_icmp_packet(0x1111, 0x2222, &[]), 20)
        };
        packet[icmp_off] = case.icmp_type;
        packet[icmp_off + 1] = case.code;

        let parsed = parse_packet_headers(&packet);
        assert_eq!(
            parsed.transport, case.expected_transport,
            "type {} code {}",
            case.icmp_type, case.code
        );

        match case.expected_is_req {
            Some(is_req) => {
                let icmp = parsed.icmp.expect("icmp");
                assert_eq!(
                    icmp.identity.destination_id, 0x1111,
                    "type {}",
                    case.icmp_type
                );
                assert_eq!(icmp.identity.source_id, None, "type {}", case.icmp_type);
                assert_eq!(icmp.seq, 0x2222, "type {}", case.icmp_type);
                assert_eq!(icmp.is_req, is_req, "type {}", case.icmp_type);
            }
            None => {
                assert!(parsed.icmp.is_none(), "type {}", case.icmp_type);
                assert_eq!(parsed.payload_bounds, (0, 0), "type {}", case.icmp_type);
            }
        }
    }
}

#[test]
fn parses_headerless_icmp_shim_matrix() {
    let cases = [
        IcmpShimCase {
            name: "zero length payload has no shim",
            suffix: &[],
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_src_id: None,
            expected_payload_bounds: (8, 8),
        },
        IcmpShimCase {
            name: "payload zero byte is not a shim (rejected as Malformed)",
            suffix: &[0x00, 0xaa, 0xbb],
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_payload_bounds: (0, 0),
        },
        IcmpShimCase {
            name: "low shim bits set is invalid shim (rejected as Malformed)",
            suffix: &[0x41, 0xaa, 0xbb],
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_payload_bounds: (0, 0),
        },
        IcmpShimCase {
            name: "reuse ident shim flag is a valid 1-byte shim and falls back to ident",
            suffix: &[0x90, 0xaa, 0xbb],
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_src_id: Some(0x1234),
            expected_payload_bounds: (9, 11),
        },
        IcmpShimCase {
            name: "explicit source shim with no source bytes is malformed",
            suffix: &[0x80],
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_payload_bounds: (0, 0),
        },
        IcmpShimCase {
            name: "explicit source shim with one source byte is malformed",
            suffix: &[0x80, 0xaa],
            expected_transport: ParsedTransport::Malformed,
            expected_src_id: None,
            expected_payload_bounds: (0, 0),
        },
        IcmpShimCase {
            name: "explicit source shim reads following source id",
            suffix: &[0x80, 0x20, 0x02],
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_src_id: Some(0x2002),
            expected_payload_bounds: (11, 11),
        },
        IcmpShimCase {
            name: "explicit source shim can encode zero source id",
            suffix: &[0x80, 0x00, 0x00],
            expected_transport: ParsedTransport::HeaderlessIcmp,
            expected_src_id: Some(0x0000),
            expected_payload_bounds: (11, 11),
        },
    ];

    for case in cases {
        let mut packet = icmp_echo(0x1234, 0x5678, true).to_vec();
        packet.extend_from_slice(case.suffix);

        let parsed = parse_packet_headers(&packet);

        assert_eq!(parsed.transport, case.expected_transport, "{}", case.name);
        assert_eq!(
            parsed.payload_bounds, case.expected_payload_bounds,
            "{}",
            case.name
        );

        if matches!(case.expected_transport, ParsedTransport::HeaderlessIcmp) {
            let icmp = parsed.icmp.expect(case.name);
            assert_eq!(icmp.identity.destination_id, 0x1234, "{}", case.name);
            assert_eq!(
                icmp.identity.source_id, case.expected_src_id,
                "{}",
                case.name
            );
            assert_eq!(icmp.seq, 0x5678, "{}", case.name);
            assert!(icmp.is_req, "{}", case.name);
        } else {
            assert!(parsed.icmp.is_none(), "{}", case.name);
        }
    }
}

#[test]
fn udp_src_and_dst_are_not_confused_with_icmp_ids() {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[9] = 17;
    packet[20..22].copy_from_slice(&0xaaaa_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&0xbbbb_u16.to_be_bytes());

    let parsed = parse_packet_headers(&packet);
    let udp = parsed.udp.expect("udp");
    assert_eq!(parsed.transport, ParsedTransport::Ipv4Udp);
    assert_eq!(udp.src_port, 0xaaaa);
    assert_eq!(udp.dst_port, 0xbbbb);
    assert!(parsed.icmp.is_none());
    assert_eq!(parsed.payload_bounds, (28, 28));
}
