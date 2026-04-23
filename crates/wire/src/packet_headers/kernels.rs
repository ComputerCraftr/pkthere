use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedTransport {
    UdpDatagram,
    HeaderlessIcmp,
    Ipv4Icmp,
    Ipv6Icmp,
    Ipv4Udp,
    Ipv6Udp,
    Unsupported,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpMalformedReason {
    TruncatedEchoHeader,
    InvalidEchoTypeOrCode,
    InvalidShimFlags,
    TruncatedSourceId,
    IllegalFrameFlags,
    SessionControlMissingReplyId,
    SessionControlReplyIdLength,
}

// Public within the crate because send/admission code must agree with the
// parser on the ICMP tunnel shim wire format.
pub const SHIM_IS_DATA: u8 = 0x80;
pub const SHIM_NEGOTIATE_REPLY_ID: u8 = 0x40;
pub const SHIM_ACK_REPLY_ID: u8 = 0x20;
pub const SHIM_SOURCE_ID_EQUALS_HEADER: u8 = 0x10;
pub const SHIM_HAS_REPLY_ID: u8 = 0x08;
const SHIM_ALLOWED_BITS: u8 = SHIM_IS_DATA
    | SHIM_NEGOTIATE_REPLY_ID
    | SHIM_ACK_REPLY_ID
    | SHIM_SOURCE_ID_EQUALS_HEADER
    | SHIM_HAS_REPLY_ID;

// IP protocol numbers parsed from IPv4 Protocol / IPv6 Next Header fields.
const PROTO_ICMP_V4: usize = 1;
const PROTO_ICMP_V6: usize = 58;
const PROTO_UDP: usize = 17;

// Base transport/header lengths.
const IPV4_MIN_LEN: usize = 20;
const IPV6_MIN_LEN: usize = 40;
const ICMP_MIN_LEN: usize = 8;
const UDP_MIN_LEN: usize = 8;

// IPv6 extension traversal offsets.
const IPV6_EXT_MIN_LEN: usize = 8;
const IPV6_FIRST_EXT_OFF: usize = IPV6_MIN_LEN;

// IPv4 fixed header field offsets.
const IPV4_FRAG_HI_OFF: usize = 6;
const IPV4_FRAG_LO_OFF: usize = 7;
const IPV4_PROTO_OFF: usize = 9;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;

// IPv6 fixed header/address offsets.
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_ADDR_SEG2_OFF: usize = 4;
const IPV6_ADDR_SEG3_OFF: usize = 6;
const IPV6_ADDR_SEG4_OFF: usize = 8;
const IPV6_ADDR_SEG5_OFF: usize = 10;
const IPV6_ADDR_SEG6_OFF: usize = 12;
const IPV6_ADDR_SEG7_OFF: usize = 14;

// ICMP Echo and tunnel shim offsets.
const ICMP_CODE_OFF: usize = 1;
const ICMP_IDENT_OFF: usize = 4;
const ICMP_SEQ_OFF: usize = 6;
const ICMP_PAYLOAD_OFF: usize = ICMP_MIN_LEN;
const ICMP_SHIM_FLAGS_LEN: usize = 1;
const ICMP_EXPLICIT_SOURCE_SHIM_LEN: usize = 3;

// UDP fixed header offsets.
const UDP_SRC_OFF: usize = 0;
const UDP_DST_OFF: usize = 2;
const UDP_PAYLOAD_OFF: usize = UDP_MIN_LEN;

// IPv6 extension Next Header values relevant to this shallow parser.
const IPV6_EXT_HOP_BY_HOP: usize = 0;
const IPV6_EXT_ROUTING: usize = 43;
const IPV6_EXT_FRAGMENT: usize = 44;
const IPV6_EXT_DEST_OPTS: usize = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireIcmpIdentity {
    pub source_id: Option<u16>,
    pub destination_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedIcmpEcho {
    pub identity: WireIcmpIdentity,
    pub seq: u16,
    pub is_req: bool,
    pub shim_flags: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedUdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacketHeaders {
    pub transport: ParsedTransport,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub udp: Option<ParsedUdpHeader>,
    pub icmp: Option<ParsedIcmpEcho>,
    pub payload_bounds: (usize, usize),
    pub icmp_malformed_reason: Option<IcmpMalformedReason>,
}

static DUMMY_BUF: [u8; 1] = [0];

#[inline]
pub const fn parse_packet_headers(payload: &[u8]) -> ParsedPacketHeaders {
    let n = payload.len();
    let non_empty = bool01(n != 0);
    let b = [&DUMMY_BUF, payload][non_empty];

    // 1. Base Length Gates
    let enough_for_base_icmp = has_len(n, ICMP_MIN_LEN);
    let enough_for_v6_base = has_len(n, IPV6_MIN_LEN);

    // 2. Base IP Header Validation
    let b0 = byte_at(b, 0, non_empty);
    let ver = (b0 >> 4) as usize;
    let ihl = ((b0 as usize) & 0x0f) << 2;
    let is_v4 = (ver == 4) as usize;
    let is_v6 = (ver == 6) as usize;
    let sane_ihl = (ihl >= IPV4_MIN_LEN) as usize;

    let enough_for_v4_base = has_len(n, ihl);
    let valid_v4_base = is_v4 & sane_ihl & enough_for_v4_base;
    let valid_v6_base = is_v6 & enough_for_v6_base;
    let valid_ip_base = valid_v4_base | valid_v6_base;

    let base_proto_or_frag_hi = byte_at(b, IPV4_FRAG_HI_OFF, valid_ip_base);
    let v6_next0 = base_proto_or_frag_hi as usize;
    let v6_ext0 = valid_v6_base & is_skippable_v6_ext(v6_next0);
    let v6_ext0_prefix_ok = v6_ext0 & has_len(n, IPV6_FIRST_EXT_OFF + IPV6_EXT_MIN_LEN);

    let frag_lo_or_ext_next_off = select2_usize(
        IPV4_FRAG_LO_OFF,
        valid_v4_base,
        IPV6_FIRST_EXT_OFF,
        v6_ext0_prefix_ok,
    );
    let proto_or_ext_len_off = select2_usize(
        IPV4_PROTO_OFF,
        valid_v4_base,
        IPV6_FIRST_EXT_OFF + 1,
        v6_ext0_prefix_ok,
    );
    let v4_or_ext0_prefix_ok = valid_v4_base | v6_ext0_prefix_ok;
    let frag_lo_or_ext_next = byte_at(b, frag_lo_or_ext_next_off, v4_or_ext0_prefix_ok);
    let proto_or_ext_len = byte_at(b, proto_or_ext_len_off, v4_or_ext0_prefix_ok);

    let (v4_proto, v4_is_fragment) = parse_v4_proto_and_fragment(
        (proto_or_ext_len as usize) * valid_v4_base,
        base_proto_or_frag_hi,
        frag_lo_or_ext_next,
        valid_v4_base,
    );

    // 3. IPv4/IPv6 Transport Identification
    let (is_v4_icmp, is_v4_udp) =
        parse_v4_transport_candidate(valid_v4_base, v4_proto, v4_is_fragment);

    let v6_ext0_next = (frag_lo_or_ext_next as usize) * v6_ext0_prefix_ok;
    let v6_ext0_len_units = (proto_or_ext_len as usize) * v6_ext0_prefix_ok;

    let (v6_off1, v6_ext0_full, v6_ext0_truncated) = finish_v6_ext_step(
        n,
        IPV6_FIRST_EXT_OFF,
        v6_ext0,
        v6_ext0_prefix_ok,
        v6_ext0_len_units,
    );

    let (
        v6_transport_proto,
        v6_transport_off,
        valid_v6_transport_base,
        unsupported_v6_fragment,
        v6_ext_truncated,
    ) = parse_v6_transport_candidate(
        v6_next0,
        valid_v6_base,
        v6_ext0,
        v6_ext0_next,
        v6_off1,
        v6_ext0_full,
        v6_ext0_truncated,
    );

    let is_v6_icmp = valid_v6_transport_base & ((v6_transport_proto == PROTO_ICMP_V6) as usize);
    let is_v6_udp = valid_v6_transport_base & ((v6_transport_proto == PROTO_UDP) as usize);

    let looks_like_v4_transport = is_v4_icmp | is_v4_udp;
    let looks_like_v6_transport = is_v6_icmp | is_v6_udp;

    // 4. Final Transport Validation
    let has_v4_transport_room = has_len(n, ihl + UDP_MIN_LEN);
    let has_v6_transport_room = has_len(n, v6_transport_off + UDP_MIN_LEN);

    let v4_trans_ok = looks_like_v4_transport & has_v4_transport_room;
    let v6_trans_ok = looks_like_v6_transport & has_v6_transport_room;

    let v4_icmp = v4_trans_ok & is_v4_icmp;
    let v4_udp = v4_trans_ok & is_v4_udp;
    let v6_icmp = v6_trans_ok & is_v6_icmp;
    let v6_udp = v6_trans_ok & is_v6_udp;
    let v4_known_transport = v4_icmp | v4_udp;
    let v6_known_transport = v6_icmp | v6_udp;

    let transport_off = select2_usize(
        ihl,
        v4_known_transport,
        v6_transport_off,
        v6_known_transport,
    );
    let maybe_headerless = not01(valid_ip_base);
    let headerless_icmp = maybe_headerless & enough_for_base_icmp;

    let icmp_off = transport_off; // headerless_icmp_off is always 0
    let have_icmp = v4_icmp | v6_icmp | headerless_icmp;

    // 5. ICMP Specifics
    let (icmp_ok, icmp_type_ok, icmp_is_req, icmp_seq) =
        parse_icmp_echo_base(b, icmp_off, have_icmp);
    let is_req = icmp_is_req != 0;

    let payload_off = icmp_off + ICMP_PAYLOAD_OFF;
    let has_payload = has_len(n, payload_off + ICMP_SHIM_FLAGS_LEN);
    let icmp_with_payload = icmp_ok & has_payload;

    let (has_shim, explicit_icmp_src, malformed_shim, shim_flags, shim_reason) =
        parse_icmp_shim(b, n, payload_off, icmp_with_payload);

    let icmp_parse_ok = icmp_ok & not01(malformed_shim);

    let udp_off = transport_off;
    let udp_ok = v4_udp | v6_udp;
    let known_transport = icmp_parse_ok | udp_ok;

    let implicit_icmp_src = icmp_parse_ok & not01(explicit_icmp_src);
    let icmp_ident_off = icmp_off + ICMP_IDENT_OFF;
    let udp_src_off = udp_off + UDP_SRC_OFF;
    let udp_dst_off = udp_off + UDP_DST_OFF;
    let explicit_icmp_src_off = payload_off + ICMP_SHIM_FLAGS_LEN;

    let transport_src_off = select3_usize(
        udp_src_off,
        udp_ok,
        icmp_ident_off,
        implicit_icmp_src,
        explicit_icmp_src_off,
        explicit_icmp_src,
    );
    let transport_dst_off = select2_usize(udp_dst_off, udp_ok, icmp_ident_off, icmp_parse_ok);

    let transport_src_ok = udp_ok | implicit_icmp_src | explicit_icmp_src;
    let transport_src_id = read_be16(b, transport_src_off, transport_src_ok);
    let transport_dst_id = read_be16(b, transport_dst_off, known_transport);

    let src_ip_off = select2_usize(
        IPV4_SRC_IP_OFF,
        valid_v4_base,
        IPV6_SRC_IP_OFF,
        valid_v6_base,
    );
    let dst_ip_off = select2_usize(
        IPV4_DST_IP_OFF,
        valid_v4_base,
        IPV6_DST_IP_OFF,
        valid_v6_base,
    );
    let src_ip = parse_detected_ip_at(b, src_ip_off, valid_v4_base, valid_v6_base);
    let dst_ip = parse_detected_ip_at(b, dst_ip_off, valid_v4_base, valid_v6_base);

    // Adjust ICMP payload bounds to skip the shim header (1 or 3 bytes).
    let shim_len = select2_usize(
        ICMP_SHIM_FLAGS_LEN,
        implicit_icmp_src,
        ICMP_EXPLICIT_SOURCE_SHIM_LEN,
        explicit_icmp_src,
    );
    let payload_start = select3_usize(
        payload_off + shim_len,
        has_shim,
        payload_off,
        icmp_parse_ok & not01(has_payload),
        udp_off + UDP_PAYLOAD_OFF,
        udp_ok,
    );
    let payload_end = select1_usize(n, known_transport);
    let payload_bounds = (payload_start, payload_end);

    let too_short = not01(enough_for_base_icmp);
    let invalid_v4_base = is_v4 & not01(valid_v4_base);
    let invalid_v6_base = is_v6 & not01(valid_v6_base);
    let v4_truncated = looks_like_v4_transport & not01(has_v4_transport_room);
    let v6_truncated = looks_like_v6_transport & not01(has_v6_transport_room);
    let malformed_icmp_echo = have_icmp & icmp_type_ok & not01(icmp_ok);

    let malformed_candidate = too_short
        | invalid_v4_base
        | invalid_v6_base
        | v6_ext_truncated
        | v4_truncated
        | v6_truncated
        | malformed_shim
        | malformed_icmp_echo;

    let malformed = bool01(known_transport == 0) & malformed_candidate;

    let transport_code = (icmp_parse_ok & headerless_icmp)
        | ((icmp_parse_ok & v4_icmp) << 1)
        | ((icmp_parse_ok & v6_icmp) * 3)
        | (v4_udp << 2)
        | (v6_udp * 5)
        | (malformed * 6);

    // IPv4 fragments are intentionally unsupported without reassembly:
    // nonzero fragment offsets may not contain a transport header, while
    // MF=1 initial fragments contain only a partial transport payload.
    let unsupported_fragment = v4_is_fragment | unsupported_v6_fragment;
    let transport_code = transport_code * not01(unsupported_fragment);

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
        udp: [
            None,
            Some(ParsedUdpHeader {
                src_port: transport_src_id,
                dst_port: transport_dst_id,
            }),
        ][udp_ok],
        icmp: [
            None,
            Some(ParsedIcmpEcho {
                identity: WireIcmpIdentity {
                    source_id: [None, Some(transport_src_id)][has_shim],
                    destination_id: transport_dst_id,
                },
                seq: icmp_seq,
                is_req,
                shim_flags: [None, Some(shim_flags)][has_shim],
            }),
        ][icmp_parse_ok],
        payload_bounds,
        icmp_malformed_reason: first_icmp_malformed_reason(
            too_short | v4_truncated | v6_truncated,
            malformed_icmp_echo,
            shim_reason,
        ),
    }
}

#[inline]
pub const fn parse_udp_datagram_payload(payload: &[u8]) -> ParsedPacketHeaders {
    ParsedPacketHeaders {
        transport: ParsedTransport::UdpDatagram,
        src_ip: None,
        dst_ip: None,
        udp: None,
        icmp: None,
        payload_bounds: (0, payload.len()),
        icmp_malformed_reason: None,
    }
}

#[inline]
pub const fn parse_icmp_v4_transport(payload: &[u8]) -> ParsedPacketHeaders {
    parse_fixed_icmp_transport(payload, 8, 0)
}

#[inline]
pub const fn parse_icmp_v6_transport(payload: &[u8]) -> ParsedPacketHeaders {
    parse_fixed_icmp_transport(payload, 128, 129)
}

#[inline]
const fn parse_fixed_icmp_transport(
    payload: &[u8],
    request_type: u8,
    reply_type: u8,
) -> ParsedPacketHeaders {
    let n = payload.len();
    let non_empty = bool01(n != 0);
    let b = [&DUMMY_BUF, payload][non_empty];
    let icmp = parse_fixed_icmp_at(b, n, 0, 1, request_type, reply_type);
    let malformed = not01(icmp.parse_ok)
        & (not01(icmp.enough)
            | (icmp.enough & icmp.type_ok & not01(icmp.header_ok))
            | icmp.malformed_shim);
    let transport = [
        ParsedTransport::Unsupported,
        ParsedTransport::HeaderlessIcmp,
        ParsedTransport::Malformed,
    ][icmp.parse_ok | (malformed * 2)];

    ParsedPacketHeaders {
        transport,
        src_ip: None,
        dst_ip: None,
        udp: None,
        icmp: [
            None,
            Some(ParsedIcmpEcho {
                identity: WireIcmpIdentity {
                    source_id: [None, Some(icmp.logical_src_id)][icmp.has_shim],
                    destination_id: icmp.logical_dst_id,
                },
                seq: icmp.seq,
                is_req: icmp.is_req != 0,
                shim_flags: [None, Some(icmp.shim_flags)][icmp.has_shim],
            }),
        ][icmp.parse_ok],
        payload_bounds: (
            select1_usize(icmp.payload_start, icmp.parse_ok),
            select1_usize(n, icmp.parse_ok),
        ),
        icmp_malformed_reason: icmp.malformed_reason,
    }
}

#[inline]
pub const fn parse_ipv4_icmp_packet(payload: &[u8]) -> ParsedPacketHeaders {
    let n = payload.len();
    let non_empty = bool01(n != 0);
    let b = [&DUMMY_BUF, payload][non_empty];
    let b0 = byte_at(b, 0, non_empty);
    let is_v4 = ((b0 >> 4) == 4) as usize;
    let ihl = ((b0 as usize) & 0x0f) << 2;
    let sane_ihl = (ihl >= IPV4_MIN_LEN) as usize;
    let base_ok = is_v4 & sane_ihl & has_len(n, ihl);
    let proto = byte_at(b, IPV4_PROTO_OFF, base_ok) as usize;
    let frag_hi = byte_at(b, IPV4_FRAG_HI_OFF, base_ok);
    let frag_lo = byte_at(b, IPV4_FRAG_LO_OFF, base_ok);
    let (_, fragmented) = parse_v4_proto_and_fragment(proto, frag_hi, frag_lo, base_ok);
    let candidate = base_ok & (proto == PROTO_ICMP_V4) as usize & not01(fragmented);
    parse_fixed_ip_icmp(
        payload,
        b,
        ihl,
        FixedIpIcmpLayout {
            request_type: 8,
            reply_type: 0,
            accepted_transport: ParsedTransport::Ipv4Icmp,
        },
        FixedIpEvidence {
            candidate,
            malformed_base: is_v4 & not01(base_ok),
            unsupported_fragment: fragmented,
            src_ip: parse_ipv4_at(b, IPV4_SRC_IP_OFF, base_ok),
            dst_ip: parse_ipv4_at(b, IPV4_DST_IP_OFF, base_ok),
        },
    )
}

#[inline]
pub const fn parse_ipv6_icmp_packet(payload: &[u8]) -> ParsedPacketHeaders {
    let n = payload.len();
    let non_empty = bool01(n != 0);
    let b = [&DUMMY_BUF, payload][non_empty];
    let b0 = byte_at(b, 0, non_empty);
    let is_v6 = ((b0 >> 4) == 6) as usize;
    let base_ok = is_v6 & has_len(n, IPV6_MIN_LEN);
    let next0 = byte_at(b, IPV4_FRAG_HI_OFF, base_ok) as usize;
    let ext0 = base_ok & is_skippable_v6_ext(next0);
    let ext_prefix = ext0 & has_len(n, IPV6_FIRST_EXT_OFF + IPV6_EXT_MIN_LEN);
    let ext_next = byte_at(b, IPV6_FIRST_EXT_OFF, ext_prefix) as usize;
    let ext_len = byte_at(b, IPV6_FIRST_EXT_OFF + 1, ext_prefix) as usize;
    let (off1, ext_full, ext_truncated) =
        finish_v6_ext_step(n, IPV6_FIRST_EXT_OFF, ext0, ext_prefix, ext_len);
    let (proto, off, transport_base, fragmented, ext_truncated) = parse_v6_transport_candidate(
        next0,
        base_ok,
        ext0,
        ext_next,
        off1,
        ext_full,
        ext_truncated,
    );
    let candidate = transport_base & (proto == PROTO_ICMP_V6) as usize;
    parse_fixed_ip_icmp(
        payload,
        b,
        off,
        FixedIpIcmpLayout {
            request_type: 128,
            reply_type: 129,
            accepted_transport: ParsedTransport::Ipv6Icmp,
        },
        FixedIpEvidence {
            candidate,
            malformed_base: (is_v6 & not01(base_ok)) | ext_truncated,
            unsupported_fragment: fragmented,
            src_ip: parse_ipv6_at(b, IPV6_SRC_IP_OFF, base_ok),
            dst_ip: parse_ipv6_at(b, IPV6_DST_IP_OFF, base_ok),
        },
    )
}

#[inline]
const fn parse_fixed_ip_icmp(
    payload: &[u8],
    b: &[u8],
    icmp_off: usize,
    layout: FixedIpIcmpLayout,
    evidence: FixedIpEvidence,
) -> ParsedPacketHeaders {
    let n = payload.len();
    let icmp = parse_fixed_icmp_at(
        b,
        n,
        icmp_off,
        evidence.candidate,
        layout.request_type,
        layout.reply_type,
    );
    let parse_ok = icmp.parse_ok & not01(evidence.unsupported_fragment);
    let malformed = not01(parse_ok)
        & not01(evidence.unsupported_fragment)
        & (evidence.malformed_base
            | (evidence.candidate & not01(icmp.enough))
            | (icmp.have_header & icmp.type_ok & not01(icmp.header_ok))
            | icmp.malformed_shim);
    let transport = [
        ParsedTransport::Unsupported,
        layout.accepted_transport,
        ParsedTransport::Malformed,
    ][parse_ok | (malformed * 2)];

    ParsedPacketHeaders {
        transport,
        src_ip: evidence.src_ip,
        dst_ip: evidence.dst_ip,
        udp: None,
        icmp: [
            None,
            Some(ParsedIcmpEcho {
                identity: WireIcmpIdentity {
                    source_id: [None, Some(icmp.logical_src_id)][icmp.has_shim],
                    destination_id: icmp.logical_dst_id,
                },
                seq: icmp.seq,
                is_req: icmp.is_req != 0,
                shim_flags: [None, Some(icmp.shim_flags)][icmp.has_shim],
            }),
        ][parse_ok],
        payload_bounds: (
            select1_usize(icmp.payload_start, parse_ok),
            select1_usize(n, parse_ok),
        ),
        icmp_malformed_reason: icmp.malformed_reason,
    }
}

#[derive(Clone, Copy)]
struct FixedIpIcmpLayout {
    request_type: u8,
    reply_type: u8,
    accepted_transport: ParsedTransport,
}

#[derive(Clone, Copy)]
struct FixedIpEvidence {
    candidate: usize,
    malformed_base: usize,
    unsupported_fragment: usize,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
}

#[derive(Clone, Copy)]
struct FixedIcmpParse {
    parse_ok: usize,
    enough: usize,
    have_header: usize,
    type_ok: usize,
    header_ok: usize,
    malformed_shim: usize,
    malformed_reason: Option<IcmpMalformedReason>,
    has_shim: usize,
    shim_flags: u8,
    logical_src_id: u16,
    logical_dst_id: u16,
    seq: u16,
    is_req: usize,
    payload_start: usize,
}

#[inline]
const fn parse_fixed_icmp_at(
    b: &[u8],
    n: usize,
    icmp_off: usize,
    candidate: usize,
    request_type: u8,
    reply_type: u8,
) -> FixedIcmpParse {
    let enough = has_len(n, icmp_off + ICMP_MIN_LEN);
    let have_header = candidate & enough;
    let icmp_type = byte_at(b, icmp_off, have_header);
    let icmp_code = byte_at(b, icmp_off + ICMP_CODE_OFF, have_header);
    let is_req = (icmp_type == request_type) as usize;
    let is_reply = (icmp_type == reply_type) as usize;
    let type_ok = is_req | is_reply;
    let header_ok = have_header & type_ok & (icmp_code == 0) as usize;
    let payload_off = icmp_off + ICMP_PAYLOAD_OFF;
    let has_payload = has_len(n, payload_off + ICMP_SHIM_FLAGS_LEN);
    let (has_shim, explicit_src, malformed_shim, shim_flags, shim_reason) =
        parse_icmp_shim(b, n, payload_off, header_ok & has_payload);
    let parse_ok = header_ok & not01(malformed_shim);
    let implicit_src = parse_ok & not01(explicit_src);
    let src_off = select2_usize(
        icmp_off + ICMP_IDENT_OFF,
        implicit_src,
        payload_off + ICMP_SHIM_FLAGS_LEN,
        explicit_src,
    );
    let shim_len = select2_usize(
        ICMP_SHIM_FLAGS_LEN,
        implicit_src,
        ICMP_EXPLICIT_SOURCE_SHIM_LEN,
        explicit_src,
    );
    let payload_start = select2_usize(
        payload_off + shim_len,
        has_shim,
        payload_off,
        parse_ok & not01(has_payload),
    );

    FixedIcmpParse {
        parse_ok,
        enough,
        have_header,
        type_ok,
        header_ok,
        malformed_shim,
        malformed_reason: first_icmp_malformed_reason(
            candidate & not01(enough),
            have_header & type_ok & not01(header_ok),
            shim_reason,
        ),
        has_shim,
        shim_flags,
        logical_src_id: read_be16(b, src_off, implicit_src | explicit_src),
        logical_dst_id: read_be16(b, icmp_off + ICMP_IDENT_OFF, parse_ok),
        seq: read_be16(b, icmp_off + ICMP_SEQ_OFF, parse_ok),
        is_req,
        payload_start,
    }
}

#[inline]
const fn read_be16(buf: &[u8], off: usize, ok: usize) -> u16 {
    let b0 = byte_at(buf, off, ok);
    let b1 = byte_at(buf, off + 1, ok);
    crate::be16_16(b0, b1)
}

#[inline]
const fn byte_at(buf: &[u8], off: usize, ok: usize) -> u8 {
    // Truly branchless and safe read.
    // If ok is 0, we read index 0 (safe because buf is always >= 1 byte).
    // Bitwise mask then returns 0.
    let mask = 0u8.wrapping_sub((ok != 0) as u8);
    buf[off * ((ok != 0) as usize)] & mask
}

#[inline]
const fn select1_usize(value: usize, ok: usize) -> usize {
    value * ok
}

#[inline]
const fn select2_usize(a: usize, a_ok: usize, b: usize, b_ok: usize) -> usize {
    (a * a_ok) | (b * b_ok)
}

#[inline]
const fn select3_usize(
    a: usize,
    a_ok: usize,
    b: usize,
    b_ok: usize,
    c: usize,
    c_ok: usize,
) -> usize {
    (a * a_ok) | (b * b_ok) | (c * c_ok)
}

#[inline]
const fn bool01(v: bool) -> usize {
    v as usize
}

#[inline]
const fn not01(v: usize) -> usize {
    bool01(v == 0)
}

#[inline]
const fn has_len(actual: usize, required: usize) -> usize {
    bool01(actual >= required)
}

#[inline]
const fn parse_v4_transport_candidate(
    valid_v4_base: usize,
    v4_proto: usize,
    v4_is_fragment: usize,
) -> (usize, usize) {
    let valid_v4_transport_base = valid_v4_base & not01(v4_is_fragment);
    let is_v4_icmp = valid_v4_transport_base & (v4_proto == PROTO_ICMP_V4) as usize;
    let is_v4_udp = valid_v4_transport_base & (v4_proto == PROTO_UDP) as usize;
    (is_v4_icmp, is_v4_udp)
}

#[inline]
const fn parse_icmp_echo_base(
    b: &[u8],
    icmp_off: usize,
    have_icmp: usize,
) -> (usize, usize, usize, u16) {
    let icmp_type = byte_at(b, icmp_off, have_icmp);
    let icmp_code = byte_at(b, icmp_off + ICMP_CODE_OFF, have_icmp);
    let icmp_v4_req = (icmp_type == 8) as usize;
    let icmp_v4_reply = (icmp_type == 0) as usize;
    let icmp_v6_req = (icmp_type == 128) as usize;
    let icmp_v6_reply = (icmp_type == 129) as usize;
    let icmp_is_req = icmp_v4_req | icmp_v6_req;
    let icmp_is_reply = icmp_v4_reply | icmp_v6_reply;
    let icmp_type_ok = icmp_is_req | icmp_is_reply;
    let icmp_ok = have_icmp & (icmp_code == 0) as usize & icmp_type_ok;
    let icmp_seq = read_be16(b, icmp_off + ICMP_SEQ_OFF, icmp_ok);
    (icmp_ok, icmp_type_ok, icmp_is_req, icmp_seq)
}

#[inline]
const fn parse_icmp_shim(
    b: &[u8],
    n: usize,
    payload_off: usize,
    icmp_with_payload: usize,
) -> (usize, usize, usize, u8, Option<IcmpMalformedReason>) {
    let shim_flags = byte_at(b, payload_off, icmp_with_payload);

    let shim_low_bits_clear = ((shim_flags & !SHIM_ALLOWED_BITS) == 0) as usize;
    let shim_has_known_flag = ((shim_flags & SHIM_ALLOWED_BITS) != 0) as usize;
    let shim_uses_header_id = ((shim_flags & SHIM_SOURCE_ID_EQUALS_HEADER) != 0) as usize;
    let shim_is_data = ((shim_flags & SHIM_IS_DATA) != 0) as usize;
    let shim_has_reply_id = ((shim_flags & SHIM_HAS_REPLY_ID) != 0) as usize;
    let shim_has_negotiation_flags =
        ((shim_flags & (SHIM_NEGOTIATE_REPLY_ID | SHIM_ACK_REPLY_ID)) != 0) as usize;

    let explicit_shim_has_src_bytes = has_len(n, payload_off + ICMP_EXPLICIT_SOURCE_SHIM_LEN);
    let basic_flags_ok = shim_low_bits_clear & shim_has_known_flag;
    let source_shape_ok = shim_uses_header_id | explicit_shim_has_src_bytes;
    let source_field_len =
        [ICMP_EXPLICIT_SOURCE_SHIM_LEN, ICMP_SHIM_FLAGS_LEN][shim_uses_header_id];
    let session_reply_body_len = n.saturating_sub(payload_off + source_field_len);
    let illegal_data_flags = basic_flags_ok
        & source_shape_ok
        & shim_is_data
        & (shim_has_reply_id | shim_has_negotiation_flags);
    let session_missing_reply_id =
        basic_flags_ok & source_shape_ok & not01(shim_is_data) & not01(shim_has_reply_id);
    let session_reply_id_length_invalid = basic_flags_ok
        & source_shape_ok
        & not01(shim_is_data)
        & shim_has_reply_id
        & ((session_reply_body_len != 2) as usize);
    let shim_is_valid = basic_flags_ok
        & source_shape_ok
        & not01(illegal_data_flags)
        & not01(session_missing_reply_id)
        & not01(session_reply_id_length_invalid);

    let has_shim = icmp_with_payload & shim_is_valid;
    let explicit_icmp_src = has_shim & not01(shim_uses_header_id);
    let malformed_shim = icmp_with_payload & not01(shim_is_valid);
    let invalid_flags = icmp_with_payload & not01(basic_flags_ok);
    let truncated_source = icmp_with_payload
        & basic_flags_ok
        & not01(shim_uses_header_id)
        & not01(explicit_shim_has_src_bytes);
    let illegal_frame = icmp_with_payload & basic_flags_ok & source_shape_ok & illegal_data_flags;
    let missing_reply = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & session_missing_reply_id;
    let invalid_reply_length = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & not01(missing_reply)
        & session_reply_id_length_invalid;
    let reason_code = invalid_flags
        | (truncated_source * 2)
        | (illegal_frame * 3)
        | (missing_reply * 4)
        | (invalid_reply_length * 5);
    let reason = [
        None,
        Some(IcmpMalformedReason::InvalidShimFlags),
        Some(IcmpMalformedReason::TruncatedSourceId),
        Some(IcmpMalformedReason::IllegalFrameFlags),
        Some(IcmpMalformedReason::SessionControlMissingReplyId),
        Some(IcmpMalformedReason::SessionControlReplyIdLength),
    ][reason_code];

    (
        has_shim,
        explicit_icmp_src,
        malformed_shim,
        shim_flags,
        reason,
    )
}

#[inline]
const fn first_icmp_malformed_reason(
    truncated_echo: usize,
    invalid_echo: usize,
    shim_reason: Option<IcmpMalformedReason>,
) -> Option<IcmpMalformedReason> {
    let invalid_echo = invalid_echo & not01(truncated_echo);
    [
        shim_reason,
        Some(IcmpMalformedReason::TruncatedEchoHeader),
        Some(IcmpMalformedReason::InvalidEchoTypeOrCode),
    ][truncated_echo | (invalid_echo * 2)]
}

#[inline]
const fn is_skippable_v6_ext(next: usize) -> usize {
    ((next == IPV6_EXT_HOP_BY_HOP) as usize)
        | ((next == IPV6_EXT_ROUTING) as usize)
        | ((next == IPV6_EXT_DEST_OPTS) as usize)
}

#[inline]
const fn parse_v4_proto_and_fragment(
    proto: usize,
    frag_hi: u8,
    frag_lo: u8,
    valid_v4: usize,
) -> (usize, usize) {
    let fragment_field = crate::be16_16(frag_hi, frag_lo);
    // 0x3fff covers MF + fragment offset bits.
    let is_fragment = valid_v4 & bool01((fragment_field & 0x3fff) != 0);
    (proto, is_fragment)
}

// Resolves only the accepted IPv6 transport candidate:
//   IPv6 -> transport
//   IPv6 -> one skippable extension -> transport
// Deeper extension chains are intentionally unsupported.
#[inline]
const fn parse_v6_transport_candidate(
    next0: usize,
    valid_v6: usize,
    ext0: usize,
    ext0_next: usize,
    off1: usize,
    ext0_full: usize,
    ext0_truncated: usize,
) -> (usize, usize, usize, usize, usize) {
    let fragment0 = valid_v6 & bool01(next0 == IPV6_EXT_FRAGMENT);
    let direct = valid_v6 & not01(ext0) & not01(fragment0);
    let fragment1 = ext0_full & bool01(ext0_next == IPV6_EXT_FRAGMENT);
    let ext1 = ext0_full & is_skippable_v6_ext(ext0_next);
    let after_ext0 = ext0_full & not01(ext1) & not01(fragment1);

    let transport_proto = select2_usize(next0, direct, ext0_next, after_ext0);
    let transport_off = select2_usize(IPV6_MIN_LEN, direct, off1, after_ext0);
    let valid_transport = direct | after_ext0;
    let unsupported_fragment = fragment0 | fragment1;
    let truncated = ext0_truncated;

    (
        transport_proto,
        transport_off,
        valid_transport,
        unsupported_fragment,
        truncated,
    )
}

#[inline]
const fn finish_v6_ext_step(
    n: usize,
    off: usize,
    ext_ok: usize,
    prefix_ok: usize,
    len_units: usize,
) -> (usize, usize, usize) {
    let len = (len_units + 1) << 3;
    let next_off = off + len;
    let full = prefix_ok & has_len(n, next_off);
    let truncated = ext_ok & ((full == 0) as usize);
    (next_off, full, truncated)
}

#[inline]
const fn parse_detected_ip_at(
    payload: &[u8],
    off: usize,
    valid_v4: usize,
    valid_v6: usize,
) -> Option<IpAddr> {
    let v4 = parse_ipv4_at(payload, off, valid_v4);
    let v6 = parse_ipv6_at(payload, off, valid_v6);
    [None, v4, v6][valid_v4 | (valid_v6 * 2)]
}

#[inline]
const fn parse_ipv4_at(payload: &[u8], off: usize, valid: usize) -> Option<IpAddr> {
    let addr = IpAddr::V4(Ipv4Addr::new(
        byte_at(payload, off, valid),
        byte_at(payload, off + 1, valid),
        byte_at(payload, off + 2, valid),
        byte_at(payload, off + 3, valid),
    ));
    [None, Some(addr)][valid]
}

#[cfg(test)]
mod kernels_tests;
#[cfg(test)]
mod malformed_tests;
#[cfg(test)]
mod tests;

#[inline]
const fn parse_ipv6_at(payload: &[u8], off: usize, valid: usize) -> Option<IpAddr> {
    let addr = IpAddr::V6(Ipv6Addr::new(
        read_be16(payload, off, valid),
        read_be16(payload, off + 2, valid),
        read_be16(payload, off + IPV6_ADDR_SEG2_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG3_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG4_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG5_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG6_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG7_OFF, valid),
    ));
    [None, Some(addr)][valid]
}
