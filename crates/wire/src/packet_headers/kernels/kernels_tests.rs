use crate::SupportedProtocol;
use crate::packet_headers::{
    IpMalformedReason, IpUnsupportedReason, IpVersion, Ipv4PacketLengthEncoding,
    NetworkParseOutcome, ParsedNetworkHeader, ParsedNetworkLayer, ParsedPacketHeaders,
    ParsedTransport, ReceiveHeaderMode, parse_icmp_v4_transport, parse_icmp_v6_transport,
    parse_ipv4_icmp_packet, parse_ipv6_icmp_packet, select_receive_parser,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn icmp_echo(icmp_type: u8, ident: u16, seq: u16) -> [u8; 8] {
    let mut header = [icmp_type, 0, 0, 0, 0, 0, 0, 0];
    header[4..6].copy_from_slice(&ident.to_be_bytes());
    header[6..8].copy_from_slice(&seq.to_be_bytes());
    header
}

fn ip_packet(version: u8, icmp_type: u8, ident: u16, seq: u16, shim: &[u8]) -> Vec<u8> {
    let ip_len = if version == 4 { 20 } else { 40 };
    let mut packet = vec![0; ip_len + 8 + shim.len()];
    packet[0] = version << 4 | if version == 4 { 5 } else { 0 };
    packet[if version == 4 { 9 } else { 6 }] = if version == 4 { 1 } else { 58 };
    if version == 4 {
        packet[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
    } else {
        packet[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6).octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 7, 8, 9, 10, 11, 12).octets());
    }
    packet[ip_len..ip_len + 8].copy_from_slice(&icmp_echo(icmp_type, ident, seq));
    packet[ip_len + 8..].copy_from_slice(shim);
    if version == 4 {
        let total_len = u16::try_from(packet.len()).expect("test IPv4 packet length");
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    } else {
        let payload_len = u16::try_from(packet.len() - 40).expect("test IPv6 payload length");
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }
    packet
}

fn ipv4_packet_with_ihl(ihl_words: u8, payload: &[u8]) -> Vec<u8> {
    let header_len = usize::from(ihl_words) * 4;
    let stored_header_len = header_len.max(20);
    let mut packet = vec![0; stored_header_len + 8 + payload.len()];
    let packet_len = u16::try_from(packet.len()).expect("test IPv4 packet length");
    packet[0] = 0x40 | ihl_words;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
    if ihl_words >= 5 {
        packet[header_len..header_len + 8].copy_from_slice(&icmp_echo(8, 0x1234, 9));
        packet[header_len + 8..].copy_from_slice(payload);
    }
    packet
}

fn compact_data(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push(0x90);
    frame.extend_from_slice(&1_u64.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn explicit_data(source_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(11 + payload.len());
    frame.push(0x80);
    frame.extend_from_slice(&source_id.to_be_bytes());
    frame.extend_from_slice(&1_u64.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub(super) fn ipv6_packet_with_extension(extension: u8, next: u8, extension_len: u8) -> Vec<u8> {
    let transport = [
        icmp_echo(128, 0x4567, 10).as_slice(),
        explicit_data(0x3456, b"ext").as_slice(),
    ]
    .concat();
    let extension_bytes = (usize::from(extension_len) + 1) * 8;
    let mut packet = vec![0_u8; 40 + extension_bytes + transport.len()];
    packet[0] = 0x6a;
    packet[1] = 0xbc;
    packet[2] = 0xde;
    packet[4..6].copy_from_slice(
        &u16::try_from(extension_bytes + transport.len())
            .expect("test IPv6 payload length")
            .to_be_bytes(),
    );
    packet[6] = extension;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6).octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 7, 8, 9, 10, 11, 12).octets());
    packet[40] = next;
    packet[41] = extension_len;
    packet[40 + extension_bytes..].copy_from_slice(&transport);
    packet
}

pub(super) fn production_ip_parser(
    version: IpVersion,
) -> crate::packet_headers::ReceiveParserKernel {
    select_receive_parser(
        SupportedProtocol::ICMP,
        version,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("production RAW ICMP parser")
}

#[test]
fn production_ipv6_parser_preserves_flow_label_as_packet_metadata() {
    let kernel = production_ip_parser(IpVersion::V6);
    let mut first = ipv6_packet_with_extension(0, 58, 0);
    let mut second = first.clone();
    for (packet, flow_label) in [(&mut first, 1_u32), (&mut second, 0x000f_ffff)] {
        packet[0] = packet[0] & 0xf0 | ((flow_label >> 16) as u8 & 0x0f);
        packet[1] = (flow_label >> 8) as u8;
        packet[2] = flow_label as u8;
    }

    let first = kernel.parse(&first);
    let second = kernel.parse(&second);
    let header = |parsed: ParsedPacketHeaders| match parsed.network {
        ParsedNetworkLayer::Valid(header) => header,
        other => panic!("expected valid IPv6 packet, got {other:?}"),
    };
    let first_header = header(first);
    let second_header = header(second);
    assert_eq!(first_header.ipv6_flow_label, Some(1));
    assert_eq!(second_header.ipv6_flow_label, Some(0x000f_ffff));
    assert_eq!(first_header.source, second_header.source);
    assert_eq!(first_header.destination, second_header.destination);
    assert_eq!(first.icmp, second.icmp);
}

fn scalar_ipv4_network_oracle(bytes: &[u8]) -> ParsedNetworkLayer {
    if bytes.is_empty() {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::MissingHeader);
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return match version {
            6 => ParsedNetworkLayer::UnexpectedVersion {
                expected: IpVersion::V4,
                observed: Some(IpVersion::V6),
            },
            observed_nibble => {
                ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidVersion { observed_nibble })
            }
        };
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < 20 {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidHeaderLength);
    }
    if bytes.len() < 20 || bytes.len() < header_len {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedHeader);
    }
    let packet_end = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if packet_end < header_len {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidPacketLength);
    }
    if packet_end > bytes.len() {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated);
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let header = ParsedNetworkHeader {
        version: IpVersion::V4,
        source: IpAddr::V4(source),
        destination: IpAddr::V4(destination),
        ipv6_flow_label: None,
        protocol: bytes[9],
        packet_end,
        transport_offset: header_len,
    };
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    if fragment & 0x8000 != 0 {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::ReservedIpv4Flag);
    }
    if fragment & 0x3fff != 0 {
        return ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::Fragmented,
        };
    }
    ParsedNetworkLayer::Valid(header)
}

fn network_layer(outcome: NetworkParseOutcome) -> ParsedNetworkLayer {
    match outcome {
        NetworkParseOutcome::Valid(packet) => ParsedNetworkLayer::Valid(packet.header),
        NetworkParseOutcome::Rejected(layer) => layer,
        NetworkParseOutcome::NotPresent => panic!("IPv4 header parser always has an L3 outcome"),
    }
}

#[test]
fn production_ipv4_kernel_matches_independent_scalar_oracle() {
    let parser = production_ip_parser(IpVersion::V4);
    let mut state = 0x6d_5a_56_da_u32;
    for length in 0..=96 {
        for _ in 0..64 {
            let mut packet = vec![0_u8; length];
            for byte in &mut packet {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            assert_eq!(
                network_layer(parser.parse_network(&packet)),
                scalar_ipv4_network_oracle(&packet),
                "scalar mismatch for capture length {length}: {packet:02x?}"
            );
        }
    }
}

fn assert_rejected_layer_three(
    parsed: ParsedPacketHeaders,
    expected: ParsedNetworkLayer,
    label: &str,
) {
    assert_eq!(parsed.network, expected, "{label}");
    assert_eq!(parsed.transport, ParsedTransport::NotParsed, "{label}");
    assert!(parsed.source_ip().is_none(), "{label}");
    assert!(parsed.destination_ip().is_none(), "{label}");
    assert!(parsed.icmp.is_none(), "{label}");
    assert!(parsed.udp.is_none(), "{label}");
    assert_eq!(parsed.packet_bounds, (0, 0), "{label}");
    assert_eq!(parsed.transport_bounds, (0, 0), "{label}");
    assert_eq!(parsed.payload_bounds, (0, 0), "{label}");
}

#[test]
fn production_selector_executes_every_supported_kernel() {
    let v4_transport = [
        icmp_echo(8, 0x1234, 7).as_slice(),
        compact_data(b"x").as_slice(),
    ]
    .concat();
    let v6_transport = [
        icmp_echo(129, 0x2345, 8).as_slice(),
        explicit_data(0x3456, b"v").as_slice(),
    ]
    .concat();
    let v4_packet = ip_packet(4, 8, 0x3456, 9, &compact_data(b"y"));
    let v6_packet = ip_packet(6, 128, 0x4567, 10, &compact_data(b"z"));

    for (
        packet,
        version,
        mode,
        expected_transport,
        expected_src,
        expected_dst,
        expected_source_id,
        expected_destination_id,
        expected_sequence,
        expected_payload,
    ) in [
        (
            v4_transport,
            IpVersion::V4,
            ReceiveHeaderMode::TransportHeaderOnly,
            ParsedTransport::Icmp,
            None,
            None,
            0x1234,
            0x1234,
            7,
            b"x".as_slice(),
        ),
        (
            v6_transport,
            IpVersion::V6,
            ReceiveHeaderMode::TransportHeaderOnly,
            ParsedTransport::Icmp,
            None,
            None,
            0x3456,
            0x2345,
            8,
            b"v".as_slice(),
        ),
        (
            v4_packet,
            IpVersion::V4,
            ReceiveHeaderMode::IpHeaderIncluded,
            ParsedTransport::Icmp,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
            0x3456,
            0x3456,
            9,
            b"y".as_slice(),
        ),
        (
            v6_packet,
            IpVersion::V6,
            ReceiveHeaderMode::IpHeaderIncluded,
            ParsedTransport::Icmp,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6))),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 7, 8, 9, 10, 11, 12,
            ))),
            0x4567,
            0x4567,
            10,
            b"z".as_slice(),
        ),
    ] {
        let kernel = select_receive_parser(
            SupportedProtocol::ICMP,
            version,
            mode,
            Ipv4PacketLengthEncoding::NetworkTotal,
        )
        .expect("production parser layout");
        let parsed = kernel.parse(&packet);
        assert_eq!(parsed.transport, expected_transport);
        assert_eq!(parsed.source_ip(), expected_src);
        assert_eq!(parsed.destination_ip(), expected_dst);
        let icmp = parsed.icmp.expect("production kernel parsed ICMP");
        assert_eq!(icmp.identity.source_id, Some(expected_source_id));
        assert_eq!(icmp.identity.destination_id, expected_destination_id);
        assert_eq!(icmp.session_id, 1);
        assert_eq!(icmp.seq, expected_sequence);
        assert_eq!(
            &packet[parsed.payload_bounds.0..parsed.payload_bounds.1],
            expected_payload
        );
    }

    let payload = b"opaque UDP datagram";
    let parsed = select_receive_parser(
        SupportedProtocol::UDP,
        IpVersion::V4,
        ReceiveHeaderMode::PayloadOnly,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("production UDP parser")
    .parse(payload);
    assert_eq!(parsed.transport, ParsedTransport::UdpDatagram);
    assert_eq!(parsed.payload_bounds, (0, payload.len()));
    assert!(parsed.source_ip().is_none() && parsed.destination_ip().is_none());
    assert!(parsed.udp.is_none() && parsed.icmp.is_none());
}

#[test]
fn specialized_icmp_kernels_reject_other_families_and_layouts() {
    let v4_transport = icmp_echo(8, 0x1234, 1);
    let v6_transport = icmp_echo(128, 0x1234, 1);
    let v4_packet = ip_packet(4, 8, 0x1234, 1, &[]);
    let v6_packet = ip_packet(6, 128, 0x1234, 1, &[]);

    assert!(parse_icmp_v4_transport(&v6_transport).icmp.is_none());
    assert!(parse_icmp_v6_transport(&v4_transport).icmp.is_none());
    assert!(parse_ipv4_icmp_packet(&v6_packet).icmp.is_none());
    assert!(parse_ipv6_icmp_packet(&v4_packet).icmp.is_none());
    assert!(parse_icmp_v4_transport(&v4_packet).icmp.is_none());
    assert!(parse_ipv4_icmp_packet(&v4_transport).icmp.is_none());
}

#[test]
fn production_icmp_kernels_are_safe_at_every_truncation_boundary() {
    let cases = [
        (
            [
                icmp_echo(8, 1, 1).as_slice(),
                compact_data(b"v4").as_slice(),
            ]
            .concat(),
            IpVersion::V4,
            ReceiveHeaderMode::TransportHeaderOnly,
        ),
        (
            [
                icmp_echo(128, 1, 1).as_slice(),
                compact_data(b"v6").as_slice(),
            ]
            .concat(),
            IpVersion::V6,
            ReceiveHeaderMode::TransportHeaderOnly,
        ),
        (
            ip_packet(4, 8, 1, 1, &compact_data(b"v4")),
            IpVersion::V4,
            ReceiveHeaderMode::IpHeaderIncluded,
        ),
        (
            ip_packet(6, 128, 1, 1, &compact_data(b"v6")),
            IpVersion::V6,
            ReceiveHeaderMode::IpHeaderIncluded,
        ),
    ];

    for (packet, version, receive_header) in cases {
        let parser = select_receive_parser(
            SupportedProtocol::ICMP,
            version,
            receive_header,
            Ipv4PacketLengthEncoding::NetworkTotal,
        )
        .expect("production truncation parser");
        let has_ip_header = matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6));
        for end in 0..=packet.len() {
            let specialized = parser.parse(&packet[..end]);
            if has_ip_header && end < packet.len() {
                assert!(
                    !matches!(specialized.network, ParsedNetworkLayer::Valid(_)),
                    "truncated IP capture became valid at {end}"
                );
                assert!(specialized.icmp.is_none());
                continue;
            }
            if let Some(icmp) = specialized.icmp {
                assert!(specialized.payload_bounds.0 <= specialized.payload_bounds.1);
                assert!(specialized.payload_bounds.1 <= end);
                assert_eq!(icmp.identity.destination_id, 1);
                assert_eq!(icmp.seq, 1);
            }
            if end == packet.len() {
                assert_eq!(specialized.transport, ParsedTransport::Icmp);
                assert_eq!(specialized.icmp.expect("complete ICMP").session_id, 1);
            }
        }
    }
}

#[test]
fn production_kernels_define_declared_extents_without_capture_padding() {
    let mut packet = ip_packet(4, 8, 0x1234, 9, &compact_data(b"payload"));
    let declared_len = packet.len();
    packet.extend_from_slice(&[0xaa; 16]);

    let kernel = select_receive_parser(
        SupportedProtocol::ICMP,
        IpVersion::V4,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("production IPv4 parser");
    let parsed = kernel.parse(&packet);
    let extent = kernel
        .declared_extent(parsed, &packet)
        .expect("declared IPv4 extent");
    assert_eq!(extent.packet, 0..declared_len);
    assert_eq!(&packet[extent.payload], b"payload");

    let mut ipv6_packet = ip_packet(6, 128, 0x1234, 9, &compact_data(b"v6-payload"));
    let ipv6_declared_len = ipv6_packet.len();
    ipv6_packet.extend_from_slice(&[0xbb; 16]);
    let ipv6_kernel = production_ip_parser(IpVersion::V6);
    let parsed = ipv6_kernel.parse(&ipv6_packet);
    let extent = ipv6_kernel
        .declared_extent(parsed, &ipv6_packet)
        .expect("declared IPv6 extent");
    assert_eq!(extent.packet, 0..ipv6_declared_len);
    assert_eq!(&ipv6_packet[extent.payload], b"v6-payload");

    let mut darwin_packet = packet[..declared_len].to_vec();
    let host_payload_len = u16::try_from(declared_len - 20).expect("Darwin IPv4 payload length");
    darwin_packet[2..4].copy_from_slice(&host_payload_len.to_ne_bytes());
    let darwin_kernel = select_receive_parser(
        SupportedProtocol::ICMP,
        IpVersion::V4,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::DarwinHostPayload,
    )
    .expect("production Darwin IPv4 parser");
    let parsed = darwin_kernel.parse(&darwin_packet);
    let extent = darwin_kernel
        .declared_extent(parsed, &darwin_packet)
        .expect("declared Darwin IPv4 extent");
    assert_eq!(extent.packet, 0..declared_len);
    assert_eq!(&darwin_packet[extent.payload], b"payload");
}

#[test]
fn production_ipv6_parser_accepts_one_supported_extension_with_exact_identity_and_extent() {
    for extension in [0, 43, 60] {
        let packet = ipv6_packet_with_extension(extension, 58, 0);
        let kernel = production_ip_parser(IpVersion::V6);
        let parsed = kernel.parse(&packet);
        assert_eq!(parsed.transport, ParsedTransport::Icmp);
        assert_eq!(
            parsed.source_ip(),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)))
        );
        assert_eq!(
            parsed.destination_ip(),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 7, 8, 9, 10, 11, 12
            )))
        );
        let network = match parsed.network {
            ParsedNetworkLayer::Valid(header) => header,
            other => panic!("expected valid IPv6 network layer, got {other:?}"),
        };
        assert_eq!(network.ipv6_flow_label, Some(0x0a_bc_de));
        let icmp = parsed.icmp.expect("ICMP after one extension");
        assert_eq!(icmp.identity.source_id, Some(0x3456));
        assert_eq!(icmp.identity.destination_id, 0x4567);
        assert_eq!(icmp.session_id, 1);
        assert_eq!(icmp.seq, 10);
        let extent = kernel
            .declared_extent(parsed, &packet)
            .expect("declared IPv6 extent");
        assert_eq!(extent.packet, 0..packet.len());
        assert_eq!(&packet[extent.payload], b"ext");
    }
}

#[test]
fn production_ipv6_parser_rejects_extension_chains_fragments_and_truncations() {
    let kernel = production_ip_parser(IpVersion::V6);
    for extension in [0, 43, 60] {
        let complete = ipv6_packet_with_extension(extension, 58, 0);
        for end in 40..48 {
            let parsed = kernel.parse(&complete[..end]);
            assert_eq!(
                parsed.network,
                ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated),
                "truncated extension {extension} at {end}"
            );
            assert!(parsed.icmp.is_none());
        }

        let chained = ipv6_packet_with_extension(extension, 60, 0);
        let parsed = kernel.parse(&chained);
        let chained_header = match parsed.network {
            ParsedNetworkLayer::Unsupported {
                header,
                reason: IpUnsupportedReason::ExtensionChain,
            } => header,
            other => panic!("expected unsupported extension chain, got {other:?}"),
        };
        assert_eq!(chained_header.version, IpVersion::V6);
        assert_eq!(chained_header.protocol, 60);
        assert_eq!(chained_header.transport_offset, 48);
        assert!(parsed.icmp.is_none());

        let fragment_after_extension = ipv6_packet_with_extension(extension, 44, 0);
        let parsed = kernel.parse(&fragment_after_extension);
        let fragment_header = match parsed.network {
            ParsedNetworkLayer::Unsupported {
                header,
                reason: IpUnsupportedReason::Fragmented,
            } => header,
            other => panic!("expected fragment after extension, got {other:?}"),
        };
        assert_eq!(fragment_header.version, IpVersion::V6);
        assert_eq!(fragment_header.protocol, 44);
        assert_eq!(fragment_header.transport_offset, 48);
        assert!(parsed.icmp.is_none());

        let mut malformed_length = complete;
        malformed_length[41] = 3;
        let parsed = kernel.parse(&malformed_length);
        assert_eq!(
            parsed.network,
            ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedExtension)
        );
        assert!(parsed.icmp.is_none());
    }

    let mut direct_fragment = ip_packet(6, 128, 0x4567, 10, &compact_data(b"fragment"));
    direct_fragment[6] = 44;
    let parsed = kernel.parse(&direct_fragment);
    let fragment_header = match parsed.network {
        ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::Fragmented,
        } => header,
        other => panic!("expected direct IPv6 fragment, got {other:?}"),
    };
    assert_eq!(fragment_header.version, IpVersion::V6);
    assert_eq!(fragment_header.protocol, 44);
    assert_eq!(fragment_header.transport_offset, 40);
    assert!(parsed.icmp.is_none());
}

#[test]
fn production_ipv6_parser_classifies_routing_security_jumbogram_and_no_next_header() {
    let kernel = production_ip_parser(IpVersion::V6);

    let mut routing = ipv6_packet_with_extension(43, 58, 0);
    routing[43] = 1;
    assert!(matches!(
        kernel.parse(&routing).network,
        ParsedNetworkLayer::Unsupported {
            reason: IpUnsupportedReason::RoutingHeaderWithSegments,
            ..
        }
    ));

    for (next_header, expected) in [
        (51, IpUnsupportedReason::AuthenticationHeader),
        (50, IpUnsupportedReason::EncryptedPayload),
    ] {
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = next_header;
        assert!(matches!(
            kernel.parse(&packet).network,
            ParsedNetworkLayer::Unsupported { reason, .. } if reason == expected
        ));
    }

    let mut jumbogram = vec![0_u8; 40];
    jumbogram[0] = 0x60;
    jumbogram[6] = 58;
    assert!(matches!(
        kernel.parse(&jumbogram).network,
        ParsedNetworkLayer::Unsupported {
            reason: IpUnsupportedReason::Jumbogram,
            ..
        }
    ));

    let mut no_next = vec![0_u8; 41];
    no_next[0] = 0x60;
    no_next[4..6].copy_from_slice(&1_u16.to_be_bytes());
    no_next[6] = 59;
    let parsed = kernel.parse(&no_next);
    assert!(matches!(parsed.network, ParsedNetworkLayer::Valid(_)));
    assert_eq!(parsed.transport, ParsedTransport::UnrelatedProtocol);
}

#[test]
fn production_ipv4_parser_rejects_every_fragment_shape_and_preserves_addresses() {
    let kernel = production_ip_parser(IpVersion::V4);
    for fragment_field in [0x2000_u16, 0x0001, 0x2001] {
        let mut packet = ip_packet(4, 8, 0x3456, 9, &compact_data(b"fragment"));
        packet[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        let parsed = kernel.parse(&packet);
        let header = match parsed.network {
            ParsedNetworkLayer::Unsupported {
                header,
                reason: IpUnsupportedReason::Fragmented,
            } => header,
            other => panic!("expected IPv4 fragment, got {other:?}"),
        };
        assert_eq!(header.version, IpVersion::V4);
        assert_eq!(header.protocol, 1);
        assert_eq!(header.transport_offset, 20);
        assert!(parsed.icmp.is_none());
        assert_eq!(
            parsed.source_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            parsed.destination_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );
    }
}

#[test]
fn production_ipv4_parser_distinguishes_reserved_flag_from_df_and_fragments() {
    let kernel = production_ip_parser(IpVersion::V4);
    let mut reserved = ip_packet(4, 8, 0x1234, 1, &compact_data(b"reserved"));
    reserved[6] = 0x80;
    assert_rejected_layer_three(
        kernel.parse(&reserved),
        ParsedNetworkLayer::Malformed(IpMalformedReason::ReservedIpv4Flag),
        "IPv4 reserved flag",
    );

    let mut dont_fragment = ip_packet(4, 8, 0x1234, 1, &compact_data(b"df"));
    dont_fragment[6] = 0x40;
    assert_eq!(
        kernel.parse(&dont_fragment).transport,
        ParsedTransport::Icmp
    );
}

#[test]
fn network_stage_returns_authority_before_transport_parsing() {
    let kernel = production_ip_parser(IpVersion::V4);
    let mut packet = ip_packet(4, 8, 0x1234, 1, &[0xff]);
    packet[12..16].copy_from_slice(&[203, 0, 113, 99]);
    let network = kernel.parse_network(&packet);
    let crate::packet_headers::NetworkParseOutcome::Valid(validated) = network else {
        panic!("valid IPv4 header must produce a validated network token");
    };
    assert_eq!(
        validated.header.source,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99))
    );
    let parsed = kernel.parse_transport(&packet, network);
    assert_eq!(parsed.transport, ParsedTransport::MalformedIcmp);
}

#[test]
fn invalid_version_nibbles_never_publish_a_fixed_family_header() {
    for (expected, mut packet) in [
        (
            IpVersion::V4,
            ip_packet(4, 8, 0x1234, 1, &compact_data(b"v4")),
        ),
        (
            IpVersion::V6,
            ip_packet(6, 128, 0x1234, 1, &compact_data(b"v6")),
        ),
    ] {
        let kernel = production_ip_parser(expected);
        for nibble in 0_u8..=15 {
            if matches!((expected, nibble), (IpVersion::V4, 4) | (IpVersion::V6, 6)) {
                continue;
            }
            packet[0] = nibble << 4 | if expected == IpVersion::V4 { 5 } else { 0 };
            let observed = match nibble {
                4 => Some(IpVersion::V4),
                6 => Some(IpVersion::V6),
                _ => None,
            };
            let expected_layer = match observed {
                Some(observed) => ParsedNetworkLayer::UnexpectedVersion {
                    expected,
                    observed: Some(observed),
                },
                None => ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidVersion {
                    observed_nibble: nibble,
                }),
            };
            assert_rejected_layer_three(
                kernel.parse(&packet),
                expected_layer,
                &format!("{expected:?} parser, version nibble {nibble}"),
            );
        }
    }
}

#[test]
fn malformed_ip_bases_publish_no_endpoints_extents_or_transport() {
    let v4 = production_ip_parser(IpVersion::V4);
    let mut short_v4 = vec![0_u8; 19];
    short_v4[0] = 0x45;
    let mut invalid_ihl = ipv4_packet_with_ihl(4, &[]);
    invalid_ihl[0] = 0x44;
    let oversized_ihl = ipv4_packet_with_ihl(15, &[])[..59].to_vec();
    let mut short_declared = ipv4_packet_with_ihl(5, &compact_data(b"x"));
    short_declared[2..4].copy_from_slice(&19_u16.to_be_bytes());
    let mut long_declared = ipv4_packet_with_ihl(5, &compact_data(b"x"));
    long_declared[2..4].copy_from_slice(&u16::MAX.to_be_bytes());

    for (label, packet, expected) in [
        (
            "empty IPv4 capture",
            Vec::new(),
            ParsedNetworkLayer::Malformed(IpMalformedReason::MissingHeader),
        ),
        (
            "truncated IPv4 base",
            short_v4,
            ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedHeader),
        ),
        (
            "invalid IPv4 IHL",
            invalid_ihl,
            ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidHeaderLength),
        ),
        (
            "truncated IPv4 options",
            oversized_ihl,
            ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedHeader),
        ),
        (
            "IPv4 length below IHL",
            short_declared,
            ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidPacketLength),
        ),
        (
            "IPv4 length beyond capture",
            long_declared,
            ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated),
        ),
    ] {
        assert_rejected_layer_three(v4.parse(&packet), expected, label);
    }

    let v6 = production_ip_parser(IpVersion::V6);
    let mut short_v6 = vec![0_u8; 39];
    short_v6[0] = 0x60;
    let mut long_v6 = ip_packet(6, 128, 0x1234, 1, &compact_data(b"x"));
    long_v6[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    for (label, packet, expected) in [
        (
            "truncated IPv6 base",
            short_v6,
            ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedHeader),
        ),
        (
            "IPv6 length beyond capture",
            long_v6,
            ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated),
        ),
    ] {
        assert_rejected_layer_three(v6.parse(&packet), expected, label);
    }
}

#[test]
fn every_valid_ipv4_ihl_selects_its_exact_transport_offset() {
    let kernel = production_ip_parser(IpVersion::V4);
    for ihl_words in 0_u8..=15 {
        let packet = ipv4_packet_with_ihl(ihl_words, &compact_data(b"ihl"));
        let parsed = kernel.parse(&packet);
        if ihl_words < 5 {
            assert_rejected_layer_three(
                parsed,
                ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidHeaderLength),
                &format!("IHL {ihl_words}"),
            );
            continue;
        }
        let header = match parsed.network {
            ParsedNetworkLayer::Valid(header) => header,
            other => panic!("IHL {ihl_words} did not produce valid IPv4: {other:?}"),
        };
        assert_eq!(header.version, IpVersion::V4);
        assert_eq!(header.transport_offset, usize::from(ihl_words) * 4);
        assert_eq!(header.packet_end, packet.len());
        assert_eq!(parsed.transport, ParsedTransport::Icmp);
        assert_eq!(
            &packet[parsed.payload_bounds.0..parsed.payload_bounds.1],
            b"ihl"
        );
    }
}

#[test]
fn valid_unrelated_protocol_never_inspects_transport_bytes() {
    let v4 = production_ip_parser(IpVersion::V4);
    let mut ipv4_header_only = ipv4_packet_with_ihl(5, &[]);
    ipv4_header_only.truncate(20);
    ipv4_header_only[2..4].copy_from_slice(&20_u16.to_be_bytes());
    ipv4_header_only[9] = 17;
    let parsed = v4.parse(&ipv4_header_only);
    assert!(matches!(parsed.network, ParsedNetworkLayer::Valid(_)));
    assert_eq!(parsed.transport, ParsedTransport::UnrelatedProtocol);
    assert!(parsed.icmp.is_none());

    let v6 = production_ip_parser(IpVersion::V6);
    let mut ipv6_header_only = vec![0_u8; 41];
    ipv6_header_only[0] = 0x60;
    ipv6_header_only[4..6].copy_from_slice(&1_u16.to_be_bytes());
    ipv6_header_only[6] = 17;
    let parsed = v6.parse(&ipv6_header_only);
    assert!(matches!(parsed.network, ParsedNetworkLayer::Valid(_)));
    assert_eq!(parsed.transport, ParsedTransport::UnrelatedProtocol);
    assert!(parsed.icmp.is_none());
}

#[test]
fn production_ip_kernels_classify_layer_three_before_transport() {
    let v4 = production_ip_parser(IpVersion::V4);
    let mut malformed_length = ip_packet(4, 8, 0x1234, 1, &[0x01]);
    malformed_length[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
    let parsed = v4.parse(&malformed_length);
    assert_eq!(
        parsed.network,
        ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated)
    );
    assert!(parsed.icmp.is_none());

    let mut unrelated_protocol = ip_packet(4, 8, 0x1234, 1, &compact_data(b"x"));
    unrelated_protocol[9] = 17;
    let parsed = v4.parse(&unrelated_protocol);
    assert!(matches!(parsed.network, ParsedNetworkLayer::Valid(_)));
    assert_eq!(parsed.transport, ParsedTransport::UnrelatedProtocol);
    assert!(parsed.icmp.is_none());

    let headerless = [
        icmp_echo(8, 0x1234, 1).as_slice(),
        compact_data(b"x").as_slice(),
    ]
    .concat();
    let parsed = v4.parse(&headerless);
    assert_eq!(
        parsed.network,
        ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidVersion { observed_nibble: 0 })
    );
    assert!(parsed.icmp.is_none());

    let wrong_family = v4.parse(&ip_packet(6, 128, 0x1234, 1, &compact_data(b"x")));
    assert_eq!(
        wrong_family.network,
        ParsedNetworkLayer::UnexpectedVersion {
            expected: IpVersion::V4,
            observed: Some(IpVersion::V6),
        }
    );
    assert!(wrong_family.icmp.is_none());
}

#[test]
fn selected_ipv4_length_encoding_is_applied_before_transport_parsing() {
    let network_kernel = select_receive_parser(
        SupportedProtocol::ICMP,
        IpVersion::V4,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("network-order IPv4 kernel");
    let darwin_kernel = select_receive_parser(
        SupportedProtocol::ICMP,
        IpVersion::V4,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::DarwinHostPayload,
    )
    .expect("Darwin IPv4 kernel");
    let mut network_packet = ip_packet(4, 8, 0x1234, 1, &compact_data(b"x"));
    let mut darwin_packet = network_packet.clone();
    let payload_len = u16::try_from(darwin_packet.len() - 20).expect("IPv4 payload length");
    darwin_packet[2..4].copy_from_slice(&payload_len.to_ne_bytes());

    assert_eq!(
        network_kernel.parse(&network_packet).transport,
        ParsedTransport::Icmp
    );
    assert_eq!(
        darwin_kernel.parse(&darwin_packet).transport,
        ParsedTransport::Icmp
    );

    network_packet[2..4].copy_from_slice(&payload_len.to_ne_bytes());
    assert!(matches!(
        network_kernel.parse(&network_packet).network,
        ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated)
    ));
}

#[test]
fn every_reserved_shim_bit_is_rejected_by_each_production_icmp_layout() {
    for reserved_bit in [0x01, 0x02, 0x08, 0x20, 0x40] {
        for (packet, version, receive_header) in [
            (
                [icmp_echo(8, 0x1234, 1).as_slice(), &[reserved_bit | 0x10]].concat(),
                IpVersion::V4,
                ReceiveHeaderMode::TransportHeaderOnly,
            ),
            (
                [icmp_echo(128, 0x1234, 1).as_slice(), &[reserved_bit | 0x10]].concat(),
                IpVersion::V6,
                ReceiveHeaderMode::TransportHeaderOnly,
            ),
            (
                ip_packet(4, 8, 0x1234, 1, &[reserved_bit | 0x10]),
                IpVersion::V4,
                ReceiveHeaderMode::IpHeaderIncluded,
            ),
            (
                ip_packet(6, 128, 0x1234, 1, &[reserved_bit | 0x10]),
                IpVersion::V6,
                ReceiveHeaderMode::IpHeaderIncluded,
            ),
        ] {
            let parser = select_receive_parser(
                SupportedProtocol::ICMP,
                version,
                receive_header,
                Ipv4PacketLengthEncoding::NetworkTotal,
            )
            .expect("production reserved-bit parser");
            let parsed = parser.parse(&packet);
            assert_eq!(parsed.transport, ParsedTransport::MalformedIcmp);
            assert_eq!(
                parsed.icmp_malformed_reason,
                Some(crate::packet_headers::IcmpMalformedReason::InvalidShimFlags),
                "reserved shim bit {reserved_bit:#04x}"
            );
        }
    }
}
