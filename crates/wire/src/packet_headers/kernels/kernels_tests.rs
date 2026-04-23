use crate::packet_headers::{
    ParsedPacketHeaders, ParsedTransport, parse_icmp_v4_transport, parse_icmp_v6_transport,
    parse_ipv4_icmp_packet, parse_ipv6_icmp_packet, parse_packet_headers,
    parse_udp_datagram_payload,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

type ParserFn = fn(&[u8]) -> ParsedPacketHeaders;

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
    packet
}

#[test]
fn specialized_kernels_match_generic_parser_for_their_wire_layouts() {
    let v4_transport = [icmp_echo(8, 0x1234, 7).as_slice(), &[0x90, b'x']].concat();
    let v6_transport = [icmp_echo(129, 0x2345, 8).as_slice(), &[0x80, 0x34, 0x56]].concat();
    let v4_packet = ip_packet(4, 8, 0x3456, 9, &[0x90, b'y']);
    let v6_packet = ip_packet(6, 128, 0x4567, 10, &[0x90, b'z']);

    for (packet, parser, expected_src, expected_dst) in [
        (
            v4_transport,
            parse_icmp_v4_transport as fn(&[u8]) -> ParsedPacketHeaders,
            None,
            None,
        ),
        (v6_transport, parse_icmp_v6_transport, None, None),
        (
            v4_packet,
            parse_ipv4_icmp_packet,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        ),
        (
            v6_packet,
            parse_ipv6_icmp_packet,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6))),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 7, 8, 9, 10, 11, 12,
            ))),
        ),
    ] {
        let parsed = parser(&packet);
        assert_eq!(parsed, parse_packet_headers(&packet));
        assert_eq!(parsed.src_ip, expected_src);
        assert_eq!(parsed.dst_ip, expected_dst);
    }

    let payload = b"opaque UDP datagram";
    let parsed = parse_udp_datagram_payload(payload);
    assert_eq!(parsed.transport, ParsedTransport::UdpDatagram);
    assert_eq!(parsed.payload_bounds, (0, payload.len()));
    assert!(parsed.src_ip.is_none() && parsed.dst_ip.is_none());
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
fn specialized_icmp_kernels_match_oracle_at_every_truncation_boundary() {
    let cases: [(Vec<u8>, ParserFn); 4] = [
        (
            [icmp_echo(8, 1, 1).as_slice(), &[0x90]].concat(),
            parse_icmp_v4_transport,
        ),
        (
            [icmp_echo(128, 1, 1).as_slice(), &[0x90]].concat(),
            parse_icmp_v6_transport,
        ),
        (ip_packet(4, 8, 1, 1, &[0x90]), parse_ipv4_icmp_packet),
        (ip_packet(6, 128, 1, 1, &[0x90]), parse_ipv6_icmp_packet),
    ];

    for (packet, parser) in cases {
        for end in 0..=packet.len() {
            let specialized = parser(&packet[..end]);
            let oracle = parse_packet_headers(&packet[..end]);
            assert_eq!(specialized.icmp, oracle.icmp, "ICMP mismatch at {end}");
            assert_eq!(
                specialized.payload_bounds, oracle.payload_bounds,
                "payload bounds mismatch at {end}"
            );
            if oracle.icmp.is_some() {
                assert_eq!(specialized.transport, oracle.transport);
            }
        }
    }
}
