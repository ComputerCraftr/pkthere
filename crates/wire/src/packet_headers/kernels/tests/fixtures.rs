use crate::packet_headers::{ParsedTransport, parse_packet_headers};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
fn icmp_echo(logical_dst_id: u16, seq: u16, is_req: bool) -> [u8; 8] {
    let mut hdr = [if is_req { 8 } else { 0 }, 0, 0, 0, 0, 0, 0, 0];
    hdr[4..6].copy_from_slice(&logical_dst_id.to_be_bytes());
    hdr[6..8].copy_from_slice(&seq.to_be_bytes());
    hdr
}
fn ipv6_icmp_echo(logical_dst_id: u16, seq: u16, is_req: bool) -> [u8; 8] {
    let mut hdr = icmp_echo(logical_dst_id, seq, is_req);
    hdr[0] = if is_req { 128 } else { 129 };
    hdr
}
#[derive(Clone, Copy)]
struct IcmpEchoCase {
    icmp_type: u8,
    code: u8,
    pub(super) expected_transport: ParsedTransport,
    expected_is_req: Option<bool>,
}
#[derive(Clone, Copy)]
struct IcmpShimCase {
    pub(super) name: &'static str,
    suffix: &'static [u8],
    pub(super) expected_transport: ParsedTransport,
    pub(super) expected_src_id: Option<u16>,
    pub(super) expected_payload_bounds: (usize, usize),
}
#[derive(Clone)]
pub(super) struct AcceptedIpPacketCase {
    pub(super) name: &'static str,
    pub(super) packet: Vec<u8>,
    pub(super) expected_transport: ParsedTransport,
    pub(super) expected_src_ip: IpAddr,
    pub(super) expected_dst_ip: IpAddr,
    pub(super) expected_src_id: u16,
    pub(super) expected_dst_id: u16,
    pub(super) expected_payload_bounds: (usize, usize),
}
#[derive(Clone)]
struct TruncatedIpTransportCase {
    pub(super) name: &'static str,
    pub(super) packet: Vec<u8>,
    pub(super) expected_src_ip: IpAddr,
    pub(super) expected_dst_ip: IpAddr,
}

#[derive(Clone)]
struct FragmentCase {
    pub(super) name: &'static str,
    pub(super) packet: Vec<u8>,
    pub(super) expected_src_ip: IpAddr,
    pub(super) expected_dst_ip: IpAddr,
}

#[derive(Clone)]
pub(super) struct Ipv6ExtensionCase {
    pub(super) name: &'static str,
    pub(super) packet: Vec<u8>,
    pub(super) expected_transport: ParsedTransport,
    pub(super) expected_src_id: Option<u16>,
    pub(super) expected_dst_id: Option<u16>,
    pub(super) expected_payload_bounds: (usize, usize),
}

pub(super) const fn test_ipv4_src() -> Ipv4Addr {
    Ipv4Addr::new(10, 20, 30, 40)
}

pub(super) const fn test_ipv4_dst() -> Ipv4Addr {
    Ipv4Addr::new(50, 60, 70, 80)
}

pub(super) const fn test_ipv6_src() -> Ipv6Addr {
    Ipv6Addr::new(
        0x1020, 0x3040, 0x5060, 0x7080, 0x90a0, 0xb0c0, 0xd0e0, 0xf001,
    )
}

pub(super) const fn test_ipv6_dst() -> Ipv6Addr {
    Ipv6Addr::new(
        0x1122, 0x3344, 0x5566, 0x7788, 0x99aa, 0xbbcc, 0xddee, 0xff10,
    )
}

fn headerless_icmp_packet(icmp_type: u8, code: u8) -> Vec<u8> {
    let mut packet = icmp_echo(0x1111, 0x2222, true).to_vec();
    packet[0] = icmp_type;
    packet[1] = code;
    packet
}

pub(super) fn ipv4_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 28 + payload.len()];
    packet[0] = 0x45;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&test_ipv4_src().octets());
    packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

pub(super) fn ipv6_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 48 + payload.len()];
    packet[0] = 0x60;
    packet[6] = 17;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40..42].copy_from_slice(&src_port.to_be_bytes());
    packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    packet
}

pub(super) fn ipv4_icmp_packet(logical_dst_id: u16, seq: u16, suffix: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 28 + suffix.len()];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&test_ipv4_src().octets());
    packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
    packet[20..28].copy_from_slice(&icmp_echo(logical_dst_id, seq, true));
    packet[28..].copy_from_slice(suffix);
    packet
}

pub(super) fn ipv4_udp_packet_with_options(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ihl_bytes = 24usize;
    let mut packet = vec![0u8; ihl_bytes + 8 + payload.len()];
    packet[0] = 0x46;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&test_ipv4_src().octets());
    packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
    packet[20..24].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    packet[ihl_bytes..ihl_bytes + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[ihl_bytes + 2..ihl_bytes + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[ihl_bytes + 8..].copy_from_slice(payload);
    packet
}

pub(super) fn ipv4_icmp_packet_with_options(
    logical_dst_id: u16,
    seq: u16,
    suffix: &[u8],
) -> Vec<u8> {
    let ihl_bytes = 24usize;
    let mut packet = vec![0u8; ihl_bytes + 8 + suffix.len()];
    packet[0] = 0x46;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&test_ipv4_src().octets());
    packet[16..20].copy_from_slice(&test_ipv4_dst().octets());
    packet[20..24].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    packet[ihl_bytes..ihl_bytes + 8].copy_from_slice(&icmp_echo(logical_dst_id, seq, true));
    packet[ihl_bytes + 8..].copy_from_slice(suffix);
    packet
}

fn ipv4_udp_fragment_packet(fragment_field: u16) -> Vec<u8> {
    let mut packet = ipv4_udp_packet(1111, 2222, b"frag");
    packet[6..8].copy_from_slice(&fragment_field.to_be_bytes());
    packet
}

fn ipv6_fragment_header_packet(next_after_fragment: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[6] = 44;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40] = next_after_fragment;
    packet
}

pub(super) fn ipv6_udp_packet_with_one_ext(
    ext_next: u8,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    ipv6_udp_packet_with_ext_header(60, ext_next, src_port, dst_port, payload)
}

pub(super) fn ipv6_udp_packet_with_ext_header(
    ext_header: u8,
    ext_next: u8,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 56 + payload.len()];
    packet[0] = 0x60;
    packet[6] = ext_header;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40] = ext_next;
    packet[41] = 0;
    packet[48..50].copy_from_slice(&src_port.to_be_bytes());
    packet[50..52].copy_from_slice(&dst_port.to_be_bytes());
    packet[56..].copy_from_slice(payload);
    packet
}

pub(super) fn ipv6_icmp_packet_with_one_ext(
    ext_next: u8,
    logical_dst_id: u16,
    seq: u16,
    suffix: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 56 + suffix.len()];
    packet[0] = 0x60;
    packet[6] = 60;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40] = ext_next;
    packet[41] = 0;
    packet[48..56].copy_from_slice(&ipv6_icmp_echo(logical_dst_id, seq, true));
    packet[56..].copy_from_slice(suffix);
    packet
}

pub(super) fn ipv6_two_extension_headers_then_udp() -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    packet[0] = 0x60;
    packet[6] = 60;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40] = 60;
    packet[41] = 0;
    packet[48] = 17;
    packet[49] = 0;
    packet[56..58].copy_from_slice(&7777u16.to_be_bytes());
    packet[58..60].copy_from_slice(&8888u16.to_be_bytes());
    packet
}

pub(super) fn truncated_ipv6_extension_header() -> Vec<u8> {
    let mut packet = vec![0u8; 44];
    packet[0] = 0x60;
    packet[6] = 60;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40] = 17;
    packet[41] = 0;
    packet
}

pub(super) fn truncated_ipv6_extension_prefix_boundary(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x60;
    packet[6] = 60;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    if len > 40 {
        packet[40] = 17;
    }
    if len > 41 {
        packet[41] = 0;
    }
    packet
}

pub(super) fn ipv6_icmp_packet(logical_dst_id: u16, seq: u16, suffix: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 48 + suffix.len()];
    packet[0] = 0x60;
    packet[6] = 58;
    packet[8..24].copy_from_slice(&test_ipv6_src().octets());
    packet[24..40].copy_from_slice(&test_ipv6_dst().octets());
    packet[40..48].copy_from_slice(&ipv6_icmp_echo(logical_dst_id, seq, true));
    packet[48..].copy_from_slice(suffix);
    packet
}

#[path = "fixtures/parser_cases.rs"]
mod parser_cases;
