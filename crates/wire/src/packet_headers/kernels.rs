use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub const SHIM_IS_DATA: u8 = 0x80;
pub const SHIM_SOURCE_ID_EQUALS_HEADER: u8 = 0x10;
pub const SHIM_IS_CADENCE: u8 = 0x04;
pub const ICMP_TUNNEL_CONTROL_VERSION: u8 = 3;
pub const ICMP_CONTROL_NEGOTIATE: u8 = 0x01;
pub const ICMP_CONTROL_NEGOTIATE_ACK: u8 = 0x02;
pub const ICMP_CONTROL_RESET_REQUIRED: u8 = 0x03;
pub const ICMP_CONTROL_CHALLENGE_NEGOTIATE: u8 = 0x04;
pub const ICMP_CONTROL_CHALLENGE_ACK: u8 = 0x05;
pub const ICMP_CONTROL_GENERATION_ADVANCE: u8 = 0x06;
pub const ICMP_CONTROL_GENERATION_ADVANCE_ACK: u8 = 0x07;
pub const ICMP_CONTROL_SESSION_ACTIVATED: u8 = 0x08;
const SHIM_ALLOWED_BITS: u8 = SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER | SHIM_IS_CADENCE;

// IP protocol numbers parsed from IPv4 Protocol / IPv6 Next Header fields.
const PROTO_ICMP_V4: usize = 1;
const PROTO_ICMP_V6: usize = 58;

// Base transport/header lengths.
const IPV4_MIN_LEN: usize = 20;
const IPV6_MIN_LEN: usize = 40;
const ICMP_MIN_LEN: usize = 8;
const IP_VERSION_OFF: usize = 0;

// IPv6 extension traversal offsets.
const IPV6_EXT_MIN_LEN: usize = 8;
const IPV6_FIRST_EXT_OFF: usize = IPV6_MIN_LEN;

// IPv4 fixed header field offsets.
const IPV4_TOTAL_LENGTH_OFF: usize = 2;
const IPV4_FRAG_HI_OFF: usize = 6;
const IPV4_FRAG_LO_OFF: usize = 7;
const IPV4_PROTO_OFF: usize = 9;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;

// IPv6 fixed header/address offsets.
const IPV6_PAYLOAD_LENGTH_OFF: usize = 4;
const IPV6_NEXT_HEADER_OFF: usize = 6;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_ADDR_SEG2_OFF: usize = 4;
const IPV6_ADDR_SEG3_OFF: usize = 6;
const IPV6_ADDR_SEG4_OFF: usize = 8;
const IPV6_ADDR_SEG5_OFF: usize = 10;
const IPV6_ADDR_SEG6_OFF: usize = 12;
const IPV6_ADDR_SEG7_OFF: usize = 14;
const IPV6_EXT_NEXT_HEADER_OFF: usize = 0;
const IPV6_EXT_LENGTH_OFF: usize = 1;

// ICMP Echo and tunnel shim offsets.
const ICMP_CODE_OFF: usize = 1;
const ICMP_IDENT_OFF: usize = 4;
const ICMP_SEQ_OFF: usize = 6;
const ICMP_PAYLOAD_OFF: usize = ICMP_MIN_LEN;
const ICMP_SHIM_FLAGS_LEN: usize = 1;
const ICMP_EXPLICIT_SOURCE_SHIM_LEN: usize = 3;
pub const ICMP_TUNNEL_SESSION_ID_LEN: usize = size_of::<u64>();
pub const ICMP_TUNNEL_POOL_GENERATION_LEN: usize = size_of::<u64>();
pub const ICMP_TUNNEL_SESSION_ORDINAL_LEN: usize = size_of::<u32>();
pub const ICMP_TUNNEL_RESET_CHALLENGE_LEN: usize = size_of::<u64>();
pub const ICMP_TUNNEL_SESSION_KEY_LEN: usize =
    ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN + ICMP_TUNNEL_SESSION_ID_LEN;
pub const ICMP_TUNNEL_CONTROL_HEADER_LEN: usize = size_of::<u8>() + size_of::<u8>();
pub const ICMP_TUNNEL_NEGOTIATE_BODY_LEN: usize =
    ICMP_TUNNEL_CONTROL_HEADER_LEN + size_of::<u16>() + ICMP_TUNNEL_SESSION_KEY_LEN;
pub const ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN: usize = ICMP_TUNNEL_CONTROL_HEADER_LEN
    + size_of::<u8>()
    + ICMP_TUNNEL_SESSION_ID_LEN
    + size_of::<u16>()
    + ICMP_TUNNEL_POOL_GENERATION_LEN
    + ICMP_TUNNEL_RESET_CHALLENGE_LEN;
pub const ICMP_TUNNEL_CHALLENGE_BODY_LEN: usize = ICMP_TUNNEL_CONTROL_HEADER_LEN
    + size_of::<u16>()
    + ICMP_TUNNEL_RESET_CHALLENGE_LEN
    + ICMP_TUNNEL_POOL_GENERATION_LEN
    + size_of::<u8>()
    + ICMP_TUNNEL_SESSION_KEY_LEN
    + size_of::<u16>()
    + ICMP_TUNNEL_SESSION_KEY_LEN;
pub const ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN: usize =
    ICMP_TUNNEL_CONTROL_HEADER_LEN + ICMP_TUNNEL_SESSION_KEY_LEN + ICMP_TUNNEL_POOL_GENERATION_LEN;
pub const ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN: usize =
    ICMP_TUNNEL_CONTROL_HEADER_LEN + ICMP_TUNNEL_SESSION_KEY_LEN + size_of::<u16>();
pub const ICMP_TUNNEL_CONTROL_BODY_LEN: usize = ICMP_TUNNEL_CHALLENGE_BODY_LEN;
const _: () = assert!(ICMP_TUNNEL_NEGOTIATE_BODY_LEN == 24);
const _: () = assert!(ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN == 29);
const _: () = assert!(ICMP_TUNNEL_CHALLENGE_BODY_LEN == 63);
const _: () = assert!(ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN == 30);
const _: () = assert!(ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN == 24);

// IPv6 extension Next Header values relevant to this shallow parser.
const IPV6_EXT_HOP_BY_HOP: usize = 0;
const IPV6_EXT_ROUTING: usize = 43;
const IPV6_EXT_FRAGMENT: usize = 44;
const IPV6_EXT_ENCAPSULATING_SECURITY_PAYLOAD: usize = 50;
const IPV6_EXT_AUTHENTICATION: usize = 51;
const IPV6_EXT_DEST_OPTS: usize = 60;
const IPV6_ROUTING_SEGMENTS_LEFT_OFF: usize = 3;

mod model;
pub use model::{
    IcmpMalformedReason, IpMalformedReason, IpUnsupportedReason, IpVersion, NetworkParseOutcome,
    ParsedIcmpEcho, ParsedNetworkHeader, ParsedNetworkLayer, ParsedPacketHeaders, ParsedTransport,
    ParsedUdpHeader, ValidatedNetworkPacket, WireIcmpIdentity,
};

mod extent;
pub use extent::{DeclaredPacketExtent, Ipv4PacketLengthEncoding};

static DUMMY_BUF: [u8; 1] = [0];

#[derive(Clone, Copy)]
struct KernelInput<'a> {
    bytes: &'a [u8],
    captured_len: usize,
    version_nibble: u8,
}

impl<'a> KernelInput<'a> {
    #[inline]
    const fn new(payload: &'a [u8]) -> Self {
        let captured_len = payload.len();
        let non_empty = bool01(captured_len != 0);
        let bytes = [&DUMMY_BUF, payload][non_empty];
        Self {
            bytes,
            captured_len,
            version_nibble: byte_at(bytes, IP_VERSION_OFF, non_empty) >> 4,
        }
    }
}

#[inline]
pub const fn parse_udp_datagram_payload(payload: &[u8]) -> ParsedPacketHeaders {
    ParsedPacketHeaders {
        network: ParsedNetworkLayer::NotPresent,
        transport: ParsedTransport::UdpDatagram,
        udp: None,
        icmp: None,
        packet_bounds: (0, payload.len()),
        transport_bounds: (0, payload.len()),
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
    let input = KernelInput::new(payload);
    let n = input.captured_len;
    let icmp = parse_fixed_icmp_at(input.bytes, n, 0, 1, request_type, reply_type);
    let malformed = not01(icmp.parse_ok)
        & (not01(icmp.enough)
            | (icmp.enough & icmp.type_ok & not01(icmp.header_ok))
            | icmp.malformed_shim);
    let unrelated = not01(icmp.parse_ok | malformed);
    let transport = [
        ParsedTransport::NotParsed,
        ParsedTransport::Icmp,
        ParsedTransport::MalformedIcmp,
        ParsedTransport::UnrelatedIcmp,
    ][icmp.parse_ok | (malformed * 2) | (unrelated * 3)];
    let transport_end = select1_usize(n, icmp.parse_ok);

    ParsedPacketHeaders {
        network: ParsedNetworkLayer::NotPresent,
        transport,
        udp: None,
        icmp: parsed_icmp(icmp, icmp.parse_ok),
        packet_bounds: (0, n),
        transport_bounds: (0, transport_end),
        payload_bounds: (
            select1_usize(icmp.payload_start, icmp.parse_ok),
            transport_end,
        ),
        icmp_malformed_reason: icmp.malformed_reason,
    }
}

#[inline]
pub const fn parse_ipv4_icmp_packet(payload: &[u8]) -> ParsedPacketHeaders {
    parse_ipv4_icmp_packet_with_length(payload, Ipv4PacketLengthEncoding::NetworkTotal)
}

#[inline]
pub(crate) const fn parse_ipv4_icmp_packet_with_length(
    payload: &[u8],
    length_encoding: Ipv4PacketLengthEncoding,
) -> ParsedPacketHeaders {
    parse_network_transport(payload, parse_ipv4_icmp_network(payload, length_encoding))
}

#[inline]
pub(crate) const fn parse_ipv4_icmp_network(
    payload: &[u8],
    length_encoding: Ipv4PacketLengthEncoding,
) -> NetworkParseOutcome {
    let input = KernelInput::new(payload);
    let n = input.captured_len;
    let b = input.bytes;
    if n == 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::MissingHeader,
        ));
    }
    let b0 = byte_at(b, IP_VERSION_OFF, 1);
    let version_nibble = input.version_nibble;
    let is_v4 = (version_nibble == 4) as usize;
    if is_v4 == 0 {
        return NetworkParseOutcome::Rejected(unexpected_or_missing_version(
            IpVersion::V4,
            version_nibble,
        ));
    }
    let ihl = ((b0 as usize) & 0x0f) << 2;
    let sane_ihl = (ihl >= IPV4_MIN_LEN) as usize;
    let has_base = has_len(n, IPV4_MIN_LEN);
    let has_ihl = has_len(n, ihl);
    if sane_ihl == 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::InvalidHeaderLength,
        ));
    }
    if has_base == 0 || has_ihl == 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::TruncatedHeader,
        ));
    }
    let structural_ok = is_v4 & sane_ihl & has_base & has_ihl;
    let declared = read_ipv4_declared_length(b, structural_ok, length_encoding);
    let packet_end = match length_encoding {
        Ipv4PacketLengthEncoding::NetworkTotal => declared,
        Ipv4PacketLengthEncoding::DarwinHostPayload => ihl + declared,
    };
    if packet_end < ihl {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::InvalidPacketLength,
        ));
    }
    if packet_end > n {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::CaptureTruncated,
        ));
    }
    let length_ok = structural_ok;
    let base_ok = structural_ok & length_ok;
    let proto = byte_at(b, IPV4_PROTO_OFF, base_ok) as usize;
    let frag_hi = byte_at(b, IPV4_FRAG_HI_OFF, base_ok);
    let frag_lo = byte_at(b, IPV4_FRAG_LO_OFF, base_ok);
    let fragmented = ipv4_fragment_mask(frag_hi, frag_lo, base_ok);
    let reserved_flag = ipv4_reserved_flag_mask(frag_hi, base_ok);
    let header = ParsedNetworkHeader {
        version: IpVersion::V4,
        source: parse_ipv4_at(b, IPV4_SRC_IP_OFF, base_ok),
        destination: parse_ipv4_at(b, IPV4_DST_IP_OFF, base_ok),
        ipv6_flow_label: None,
        protocol: proto as u8,
        packet_end,
        transport_offset: ihl,
    };
    if reserved_flag != 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::ReservedIpv4Flag,
        ));
    }
    if fragmented != 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::Fragmented,
        });
    }
    NetworkParseOutcome::Valid(ValidatedNetworkPacket {
        header,
        expected_transport: proto == PROTO_ICMP_V4,
        request_type: 8,
        reply_type: 0,
        captured_len: n,
    })
}

#[inline]
pub const fn parse_ipv6_icmp_packet(payload: &[u8]) -> ParsedPacketHeaders {
    parse_network_transport(payload, parse_ipv6_icmp_network(payload))
}

#[inline]
pub(crate) const fn parse_ipv6_icmp_network(payload: &[u8]) -> NetworkParseOutcome {
    let input = KernelInput::new(payload);
    let n = input.captured_len;
    let b = input.bytes;
    if n == 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::MissingHeader,
        ));
    }
    let version_nibble = input.version_nibble;
    let is_v6 = (version_nibble == 6) as usize;
    if is_v6 == 0 {
        return NetworkParseOutcome::Rejected(unexpected_or_missing_version(
            IpVersion::V6,
            version_nibble,
        ));
    }
    let has_base = has_len(n, IPV6_MIN_LEN);
    if has_base == 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::TruncatedHeader,
        ));
    }
    let structural_ok = is_v6 & has_base;
    let payload_len = read_be16(b, IPV6_PAYLOAD_LENGTH_OFF, structural_ok) as usize;
    if payload_len == 0 {
        let header = ParsedNetworkHeader {
            version: IpVersion::V6,
            source: parse_ipv6_at(b, IPV6_SRC_IP_OFF, structural_ok),
            destination: parse_ipv6_at(b, IPV6_DST_IP_OFF, structural_ok),
            ipv6_flow_label: Some(parse_ipv6_flow_label(b, structural_ok)),
            protocol: byte_at(b, IPV6_NEXT_HEADER_OFF, structural_ok),
            packet_end: IPV6_MIN_LEN,
            transport_offset: IPV6_MIN_LEN,
        };
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::Jumbogram,
        });
    }
    let packet_end = IPV6_MIN_LEN + payload_len;
    if packet_end > n {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::CaptureTruncated,
        ));
    }
    let base_ok = structural_ok;
    let next0 = byte_at(b, IPV6_NEXT_HEADER_OFF, base_ok) as usize;
    if next0 == IPV6_EXT_AUTHENTICATION {
        return NetworkParseOutcome::Rejected(ipv6_unsupported_base(
            b,
            packet_end,
            next0,
            IpUnsupportedReason::AuthenticationHeader,
        ));
    }
    if next0 == IPV6_EXT_ENCAPSULATING_SECURITY_PAYLOAD {
        return NetworkParseOutcome::Rejected(ipv6_unsupported_base(
            b,
            packet_end,
            next0,
            IpUnsupportedReason::EncryptedPayload,
        ));
    }
    let ext0 = base_ok & is_skippable_v6_ext(next0);
    let ext_prefix = ext0 & has_len(packet_end, IPV6_FIRST_EXT_OFF + IPV6_EXT_MIN_LEN);
    let ext_next = byte_at(b, IPV6_FIRST_EXT_OFF + IPV6_EXT_NEXT_HEADER_OFF, ext_prefix) as usize;
    let ext_len = byte_at(b, IPV6_FIRST_EXT_OFF + IPV6_EXT_LENGTH_OFF, ext_prefix) as usize;
    let extension =
        parse_ipv6_extension_extent(packet_end, IPV6_FIRST_EXT_OFF, ext0, ext_prefix, ext_len);
    let transport = parse_ipv6_transport_evidence(
        next0,
        base_ok,
        ext0,
        ext_next,
        extension.next_offset,
        extension.complete,
        extension.truncated,
    );
    let header = ParsedNetworkHeader {
        version: IpVersion::V6,
        source: parse_ipv6_at(b, IPV6_SRC_IP_OFF, base_ok),
        destination: parse_ipv6_at(b, IPV6_DST_IP_OFF, base_ok),
        ipv6_flow_label: Some(parse_ipv6_flow_label(b, base_ok)),
        protocol: transport.protocol as u8,
        packet_end,
        transport_offset: transport.offset,
    };
    if transport.extension_truncated != 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Malformed(
            IpMalformedReason::TruncatedExtension,
        ));
    }
    if next0 == IPV6_EXT_ROUTING
        && extension.complete != 0
        && byte_at(
            b,
            IPV6_FIRST_EXT_OFF + IPV6_ROUTING_SEGMENTS_LEFT_OFF,
            extension.complete,
        ) != 0
    {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::RoutingHeaderWithSegments,
        });
    }
    if transport.fragmented != 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::Fragmented,
        });
    }
    if transport.extension_chain != 0 {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::ExtensionChain,
        });
    }
    if transport.protocol == IPV6_EXT_AUTHENTICATION {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::AuthenticationHeader,
        });
    }
    if transport.protocol == IPV6_EXT_ENCAPSULATING_SECURITY_PAYLOAD {
        return NetworkParseOutcome::Rejected(ParsedNetworkLayer::Unsupported {
            header,
            reason: IpUnsupportedReason::EncryptedPayload,
        });
    }
    NetworkParseOutcome::Valid(ValidatedNetworkPacket {
        header,
        expected_transport: transport.transport_candidate != 0
            && transport.protocol == PROTO_ICMP_V6,
        request_type: 128,
        reply_type: 129,
        captured_len: n,
    })
}

#[inline]
const fn ipv6_unsupported_base(
    b: &[u8],
    packet_end: usize,
    protocol: usize,
    reason: IpUnsupportedReason,
) -> ParsedNetworkLayer {
    ParsedNetworkLayer::Unsupported {
        header: ParsedNetworkHeader {
            version: IpVersion::V6,
            source: parse_ipv6_at(b, IPV6_SRC_IP_OFF, 1),
            destination: parse_ipv6_at(b, IPV6_DST_IP_OFF, 1),
            ipv6_flow_label: Some(parse_ipv6_flow_label(b, 1)),
            protocol: protocol as u8,
            packet_end,
            transport_offset: IPV6_MIN_LEN,
        },
        reason,
    }
}

#[inline]
const fn parse_ipv6_flow_label(bytes: &[u8], valid: usize) -> u32 {
    ((byte_at(bytes, 0, valid) as u32 & 0x0f) << 16)
        | ((byte_at(bytes, 1, valid) as u32) << 8)
        | byte_at(bytes, 2, valid) as u32
}

#[inline]
pub(crate) const fn parse_network_transport(
    payload: &[u8],
    network: NetworkParseOutcome,
) -> ParsedPacketHeaders {
    match network {
        NetworkParseOutcome::Valid(validated) => {
            if validated.captured_len != payload.len() {
                return ParsedPacketHeaders::network_only(ParsedNetworkLayer::Malformed(
                    IpMalformedReason::CaptureTruncated,
                ));
            }
            parse_fixed_ip_icmp(
                KernelInput::new(payload).bytes,
                ParsedNetworkLayer::Valid(validated.header),
                Some(validated.header),
                FixedIpEvidence {
                    candidate: validated.expected_transport as usize,
                    request_type: validated.request_type,
                    reply_type: validated.reply_type,
                },
            )
        }
        NetworkParseOutcome::Rejected(network) => ParsedPacketHeaders::network_only(network),
        NetworkParseOutcome::NotPresent => ParsedPacketHeaders::network_only(
            ParsedNetworkLayer::Malformed(IpMalformedReason::MissingHeader),
        ),
    }
}

#[inline]
const fn parse_fixed_ip_icmp(
    b: &[u8],
    network: ParsedNetworkLayer,
    header: Option<ParsedNetworkHeader>,
    evidence: FixedIpEvidence,
) -> ParsedPacketHeaders {
    let (packet_end, transport_offset) = match header {
        Some(header) => (header.packet_end, header.transport_offset),
        None => (0, 0),
    };
    let icmp = parse_fixed_icmp_at(
        b,
        packet_end,
        transport_offset,
        evidence.candidate,
        evidence.request_type,
        evidence.reply_type,
    );
    let network_valid = matches!(network, ParsedNetworkLayer::Valid(_)) as usize;
    let parse_ok = icmp.parse_ok & network_valid;
    let malformed = network_valid
        & not01(parse_ok)
        & (evidence.candidate & not01(icmp.enough)
            | (icmp.have_header & icmp.type_ok & not01(icmp.header_ok))
            | icmp.malformed_shim);
    let unrelated_protocol = network_valid & not01(evidence.candidate) & not01(malformed);
    let unrelated_icmp = network_valid & evidence.candidate & not01(parse_ok | malformed);
    let transport = [
        ParsedTransport::NotParsed,
        ParsedTransport::Icmp,
        ParsedTransport::MalformedIcmp,
        ParsedTransport::UnrelatedProtocol,
        ParsedTransport::UnrelatedIcmp,
    ][parse_ok | (malformed * 2) | (unrelated_protocol * 3) | (unrelated_icmp * 4)];
    let packet_end = select1_usize(packet_end, network_valid);
    let transport_start = select1_usize(transport_offset, network_valid);
    let transport_end = packet_end;

    ParsedPacketHeaders {
        network,
        transport,
        udp: None,
        icmp: parsed_icmp(icmp, parse_ok),
        packet_bounds: (0, packet_end),
        transport_bounds: (transport_start, transport_end),
        payload_bounds: (
            select1_usize(icmp.payload_start, parse_ok),
            select1_usize(transport_end, parse_ok),
        ),
        icmp_malformed_reason: icmp.malformed_reason,
    }
}

#[derive(Clone, Copy)]
struct FixedIpEvidence {
    candidate: usize,
    request_type: u8,
    reply_type: u8,
}

#[inline]
const fn unexpected_or_missing_version(
    expected: IpVersion,
    version_nibble: u8,
) -> ParsedNetworkLayer {
    let observed = match version_nibble {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    };
    match observed {
        Some(observed) => ParsedNetworkLayer::UnexpectedVersion {
            expected,
            observed: Some(observed),
        },
        None => ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidVersion {
            observed_nibble: version_nibble,
        }),
    }
}

#[inline]
const fn read_ipv4_declared_length(
    payload: &[u8],
    valid: usize,
    encoding: Ipv4PacketLengthEncoding,
) -> usize {
    let bytes = [
        byte_at(payload, IPV4_TOTAL_LENGTH_OFF, valid),
        byte_at(payload, IPV4_TOTAL_LENGTH_OFF + 1, valid),
    ];
    match encoding {
        Ipv4PacketLengthEncoding::NetworkTotal => u16::from_be_bytes(bytes) as usize,
        Ipv4PacketLengthEncoding::DarwinHostPayload => u16::from_ne_bytes(bytes) as usize,
    }
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
    session_id: u64,
    seq: u16,
    is_req: usize,
    payload_start: usize,
}

#[inline]
const fn parsed_icmp(icmp: FixedIcmpParse, parse_ok: usize) -> Option<ParsedIcmpEcho> {
    [
        None,
        Some(ParsedIcmpEcho {
            identity: WireIcmpIdentity {
                source_id: [None, Some(icmp.logical_src_id)][icmp.has_shim],
                destination_id: icmp.logical_dst_id,
            },
            session_id: icmp.session_id,
            seq: icmp.seq,
            is_req: icmp.is_req != 0,
            shim_flags: [None, Some(icmp.shim_flags)][icmp.has_shim],
        }),
    ][parse_ok]
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
    let shim = parse_icmp_shim(b, n, payload_off, header_ok & has_payload);
    let parse_ok = header_ok & not01(shim.malformed);
    let implicit_src = parse_ok & not01(shim.explicit_source);
    let src_off = select2_usize(
        icmp_off + ICMP_IDENT_OFF,
        implicit_src,
        payload_off + ICMP_SHIM_FLAGS_LEN,
        shim.explicit_source,
    );
    let payload_start = select2_usize(
        shim.payload_start,
        shim.has_shim,
        payload_off,
        parse_ok & not01(has_payload),
    );

    FixedIcmpParse {
        parse_ok,
        enough,
        have_header,
        type_ok,
        header_ok,
        malformed_shim: shim.malformed,
        malformed_reason: first_icmp_malformed_reason(
            candidate & not01(enough),
            have_header & type_ok & not01(header_ok),
            shim.reason,
        ),
        has_shim: shim.has_shim,
        shim_flags: shim.flags,
        logical_src_id: read_be16(b, src_off, implicit_src | shim.explicit_source),
        logical_dst_id: read_be16(b, icmp_off + ICMP_IDENT_OFF, parse_ok),
        session_id: shim.session_id,
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
const fn read_be64(buf: &[u8], off: usize, ok: usize) -> u64 {
    let mut value = 0_u64;
    let mut index = 0;
    while index < ICMP_TUNNEL_SESSION_ID_LEN {
        value = (value << 8) | byte_at(buf, off + index, ok) as u64;
        index += 1;
    }
    value
}

#[inline]
const fn byte_at(buf: &[u8], off: usize, ok: usize) -> u8 {
    // Keep every read safe even if an upstream candidate mask is stale.
    // Invalid reads select the guaranteed byte at index zero and mask it out.
    let valid = ((ok != 0) as usize) & ((off < buf.len()) as usize);
    let mask = 0u8.wrapping_sub(valid as u8);
    buf[off * valid] & mask
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

mod control;
pub use control::icmp_control_body_len;
use control::{control_session_id_offset, read_control_reply_id};

mod shim;
use shim::parse_icmp_shim;

mod tail;
use tail::{
    first_icmp_malformed_reason, ipv4_fragment_mask, ipv4_reserved_flag_mask, is_skippable_v6_ext,
    parse_ipv4_at, parse_ipv6_at, parse_ipv6_extension_extent, parse_ipv6_transport_evidence,
};

#[cfg(test)]
mod kernels_tests;
#[cfg(test)]
mod malformed_tests;
#[cfg(test)]
mod scalar_oracle_tests;
