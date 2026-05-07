#[path = "../../src/net/byte_order.rs"]
mod byte_order;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParsedTransport {
    HeaderlessIcmp,
    Ipv4Icmp,
    Ipv6Icmp,
    Ipv4Udp,
    Ipv6Udp,
    Unsupported,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedIcmpEcho {
    pub(crate) ident: u16,
    pub(crate) seq: u16,
    pub(crate) is_req: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedUdpHeader {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedPacketHeaders {
    pub(crate) transport: ParsedTransport,
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_ip: Option<IpAddr>,
    pub(crate) src_ip_bounds: (usize, usize),
    pub(crate) dst_ip_bounds: (usize, usize),
    pub(crate) udp: Option<ParsedUdpHeader>,
    pub(crate) icmp: Option<ParsedIcmpEcho>,
    pub(crate) payload_bounds: (usize, usize),
}

#[inline]
pub(crate) const fn parse_packet_headers(payload: &[u8]) -> ParsedPacketHeaders {
    let n = payload.len();
    let has0 = (n >= 1) as usize;

    let b0 = byte_at(payload, 0, has0);
    let ver = (b0 >> 4) as usize;
    let ihl = ((b0 as usize) & 0x0f) << 2;

    let is_v4 = (ver == 4) as usize;
    let is_v6 = (ver == 6) as usize;
    let sane_ihl = (ihl >= 20) as usize;
    let has_v4_proto = (n >= 10) as usize;
    let has_v6_next = (n >= 7) as usize;
    let v4_proto = byte_at(payload, 9, has_v4_proto);
    let v6_next = byte_at(payload, 6, has_v6_next);

    let room_v4_base = (n >= ihl) as usize;
    let room_v6_base = (n >= 40) as usize;
    let valid_v4 = is_v4 & sane_ihl & room_v4_base;
    let valid_v6 = is_v6 & room_v6_base;

    let v4_icmp = valid_v4 & (v4_proto == 1) as usize & (n >= ihl + 8) as usize;
    let v4_udp = valid_v4 & (v4_proto == 17) as usize & (n >= ihl + 8) as usize;
    let v6_icmp = valid_v6 & (v6_next == 58) as usize & (n >= 48) as usize;
    let v6_udp = valid_v6 & (v6_next == 17) as usize & (n >= 48) as usize;
    let with_ip_header = v4_icmp | v4_udp | v6_icmp | v6_udp;

    let transport_off = (ihl * (v4_icmp | v4_udp)) | (40usize * (v6_icmp | v6_udp));
    let maybe_headerless =
        ((with_ip_header == 0) as usize) & ((valid_v4 == 0) as usize) & ((valid_v6 == 0) as usize);
    let headerless_icmp = maybe_headerless & (n >= 8) as usize;
    let icmp_off = transport_off * (v4_icmp | v6_icmp);
    let headerless_icmp_off = 0usize;
    let effective_icmp_off = icmp_off | (headerless_icmp_off * headerless_icmp);
    let have_icmp = v4_icmp | v6_icmp | headerless_icmp;

    let icmp_type = byte_at(payload, effective_icmp_off, have_icmp);
    let icmp_code = byte_at(payload, effective_icmp_off + 1, have_icmp);
    let icmp_type_ok = (icmp_type == 8) as usize
        | (icmp_type == 0) as usize
        | (icmp_type == 128) as usize
        | (icmp_type == 129) as usize;
    let icmp_ok = have_icmp & (icmp_code == 0) as usize & icmp_type_ok;

    let ident = read_be16(payload, effective_icmp_off + 4, icmp_ok);
    let seq = read_be16(payload, effective_icmp_off + 6, icmp_ok);
    let is_req = (((icmp_type == 8) as usize) | ((icmp_type == 128) as usize)) != 0;

    let udp_off = transport_off * (v4_udp | v6_udp);
    let udp_ok = v4_udp | v6_udp;
    let udp_src = read_be16(payload, udp_off, udp_ok);
    let udp_dst = read_be16(payload, udp_off + 2, udp_ok);

    let src_ip_bounds = (12 * valid_v4 | 8 * valid_v6, 16 * valid_v4 | 24 * valid_v6);
    let dst_ip_bounds = (16 * valid_v4 | 24 * valid_v6, 20 * valid_v4 | 40 * valid_v6);
    let src_ip = parse_ip(payload, valid_v4, valid_v6, src_ip_bounds);
    let dst_ip = parse_ip(payload, valid_v4, valid_v6, dst_ip_bounds);

    let payload_start =
        ((effective_icmp_off + 8) * icmp_ok) | ((udp_off + 8) * ((icmp_ok == 0) as usize) * udp_ok);
    let payload_end = n * ((icmp_ok | udp_ok) != 0) as usize;
    let payload_bounds = (payload_start, payload_end);

    let known_transport = icmp_ok | udp_ok;
    let malformed_candidate = ((n == 0) as usize)
        | (is_v4 & ((valid_v4 == 0) as usize))
        | (is_v6 & ((valid_v6 == 0) as usize))
        | (maybe_headerless & icmp_type_ok);
    let malformed = ((known_transport == 0) as usize) & malformed_candidate;
    let transport_code = ((icmp_ok & headerless_icmp) * 1)
        | ((icmp_ok & v4_icmp) * 2)
        | ((icmp_ok & v6_icmp) * 3)
        | ((udp_ok & v4_udp) * 4)
        | ((udp_ok & v6_udp) * 5)
        | (malformed * 6);
    let transport = [
        ParsedTransport::Unsupported,
        ParsedTransport::HeaderlessIcmp,
        ParsedTransport::Ipv4Icmp,
        ParsedTransport::Ipv6Icmp,
        ParsedTransport::Ipv4Udp,
        ParsedTransport::Ipv6Udp,
        ParsedTransport::Malformed,
    ][transport_code];

    ParsedPacketHeaders {
        transport,
        src_ip,
        dst_ip,
        src_ip_bounds,
        dst_ip_bounds,
        udp: [
            None,
            Some(ParsedUdpHeader {
                src_port: udp_src,
                dst_port: udp_dst,
            }),
        ][udp_ok],
        icmp: [None, Some(ParsedIcmpEcho { ident, seq, is_req })][icmp_ok],
        payload_bounds,
    }
}

#[inline]
const fn read_be16(buf: &[u8], off: usize, ok: usize) -> u16 {
    let b0 = byte_at(buf, off, ok);
    let b1 = byte_at(buf, off + 1, ok);
    byte_order::be16_16(b0, b1)
}

#[inline]
const fn byte_at(buf: &[u8], off: usize, ok: usize) -> u8 {
    if ok != 0 { buf[off] } else { 0 }
}

#[inline]
const fn parse_ip(
    payload: &[u8],
    valid_v4: usize,
    valid_v6: usize,
    bounds: (usize, usize),
) -> Option<IpAddr> {
    let (start, end) = bounds;
    let v4_ok = valid_v4 & ((end - start == 4) as usize);
    let v6_ok = valid_v6 & ((end - start == 16) as usize);
    let v4 = IpAddr::V4(Ipv4Addr::new(
        byte_at(payload, start, v4_ok),
        byte_at(payload, start + 1, v4_ok),
        byte_at(payload, start + 2, v4_ok),
        byte_at(payload, start + 3, v4_ok),
    ));
    let v6 = IpAddr::V6(Ipv6Addr::new(
        read_be16(payload, start, v6_ok),
        read_be16(payload, start + 2, v6_ok),
        read_be16(payload, start + 4, v6_ok),
        read_be16(payload, start + 6, v6_ok),
        read_be16(payload, start + 8, v6_ok),
        read_be16(payload, start + 10, v6_ok),
        read_be16(payload, start + 12, v6_ok),
        read_be16(payload, start + 14, v6_ok),
    ));
    [None, Some(v4), Some(v6)][v4_ok | (v6_ok * 2)]
}
