//! Packet-header models and specialized branchless receive kernels.

mod kernels;
mod receive;

pub use kernels::{
    DeclaredPacketExtent, ICMP_CONTROL_CHALLENGE_ACK, ICMP_CONTROL_CHALLENGE_NEGOTIATE,
    ICMP_CONTROL_GENERATION_ADVANCE, ICMP_CONTROL_GENERATION_ADVANCE_ACK, ICMP_CONTROL_NEGOTIATE,
    ICMP_CONTROL_NEGOTIATE_ACK, ICMP_CONTROL_RESET_REQUIRED, ICMP_CONTROL_SESSION_ACTIVATED,
    ICMP_TUNNEL_CHALLENGE_BODY_LEN, ICMP_TUNNEL_CONTROL_BODY_LEN, ICMP_TUNNEL_CONTROL_HEADER_LEN,
    ICMP_TUNNEL_CONTROL_VERSION, ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN,
    ICMP_TUNNEL_NEGOTIATE_BODY_LEN, ICMP_TUNNEL_POOL_GENERATION_LEN,
    ICMP_TUNNEL_RESET_CHALLENGE_LEN, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
    ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN, ICMP_TUNNEL_SESSION_ID_LEN,
    ICMP_TUNNEL_SESSION_KEY_LEN, ICMP_TUNNEL_SESSION_ORDINAL_LEN, IcmpMalformedReason,
    IpMalformedReason, IpUnsupportedReason, IpVersion, Ipv4PacketLengthEncoding,
    NetworkParseOutcome, ParsedIcmpEcho, ParsedNetworkHeader, ParsedNetworkLayer,
    ParsedPacketHeaders, ParsedTransport, ParsedUdpHeader, SHIM_IS_CADENCE, SHIM_IS_DATA,
    SHIM_SOURCE_ID_EQUALS_HEADER, ValidatedNetworkPacket, WireIcmpIdentity, icmp_control_body_len,
    parse_icmp_v4_transport, parse_icmp_v6_transport, parse_ipv4_icmp_packet,
    parse_ipv6_icmp_packet, parse_udp_datagram_payload,
};
pub use receive::{
    PacketParserFn, ReceiveHeaderMode, ReceiveParserKernel, UnsupportedReceiveLayout,
    select_receive_parser,
};
