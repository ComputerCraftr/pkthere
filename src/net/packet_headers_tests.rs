use crate::net::packet_headers::{ParsedTransport, parse_packet_headers};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn icmp_echo(ident: u16, seq: u16, is_req: bool) -> [u8; 8] {
    let mut hdr = [if is_req { 8 } else { 0 }, 0, 0, 0, 0, 0, 0, 0];
    hdr[4..6].copy_from_slice(&ident.to_be_bytes());
    hdr[6..8].copy_from_slice(&seq.to_be_bytes());
    hdr
}

#[test]
fn parses_ipv4_icmp_echo_with_ip_header() {
    let mut packet = vec![0u8; 31];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 2).octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 3).octets());
    packet[20..28].copy_from_slice(&icmp_echo(0x1234, 2, true));
    packet[28..].copy_from_slice(b"abc");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::Ipv4Icmp);
    assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
    assert_eq!(parsed.icmp.expect("icmp").ident, 0x1234);
    assert_eq!(parsed.payload_bounds, (28, 31));
}

#[test]
fn parses_ipv6_icmp_echo_with_ip_header() {
    let mut packet = vec![0u8; 52];
    packet[0] = 0x60;
    packet[6] = 58;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    let mut echo = icmp_echo(0xbeef, 42, false);
    echo[0] = 129; // Echo Reply for IPv6
    packet[40..48].copy_from_slice(&echo);
    packet[48..].copy_from_slice(b"data");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::Ipv6Icmp);
    assert_eq!(parsed.icmp.expect("icmp").seq, 42);
    assert_eq!(parsed.payload_bounds, (48, 52));
}

#[test]
fn parses_headerless_icmp_echo() {
    let mut packet = Vec::from(icmp_echo(0x0102, 0x0304, true));
    packet.extend_from_slice(b"xy");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::HeaderlessIcmp);
    assert_eq!(parsed.icmp.expect("icmp").ident, 0x0102);
    assert_eq!(parsed.payload_bounds, (8, 10));
}

#[test]
fn parses_ipv4_udp_header() {
    let mut packet = vec![0u8; 32];
    packet[0] = 0x45; // IPv4
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 2).octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 3).octets());
    packet[20..22].copy_from_slice(&1111u16.to_be_bytes());
    packet[22..24].copy_from_slice(&2222u16.to_be_bytes());
    packet[28..].copy_from_slice(b"udp!");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::Ipv4Udp);
    assert_eq!(parsed.udp.expect("udp").src_port, 1111);
    assert_eq!(parsed.udp.expect("udp").dst_port, 2222);
    assert_eq!(parsed.payload_bounds, (28, 32));
}

#[test]
fn parses_ipv6_udp_header() {
    let mut packet = vec![0u8; 51];
    packet[0] = 0x60; // IPv6
    packet[6] = 17; // UDP
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[40..42].copy_from_slice(&3333u16.to_be_bytes());
    packet[42..44].copy_from_slice(&4444u16.to_be_bytes());
    packet[48..].copy_from_slice(b"udp");

    let parsed = parse_packet_headers(&packet);
    assert_eq!(parsed.transport, ParsedTransport::Ipv6Udp);
    assert_eq!(parsed.udp.expect("udp").src_port, 3333);
    assert_eq!(parsed.udp.expect("udp").dst_port, 4444);
    assert_eq!(parsed.payload_bounds, (48, 51));
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
