//! Packet-header models and specialized branchless receive kernels.

mod kernels;
mod receive;

pub use kernels::{
    IcmpMalformedReason, ParsedIcmpEcho, ParsedPacketHeaders, ParsedTransport, ParsedUdpHeader,
    SHIM_ACK_REPLY_ID, SHIM_HAS_REPLY_ID, SHIM_IS_DATA, SHIM_NEGOTIATE_REPLY_ID,
    SHIM_SOURCE_ID_EQUALS_HEADER, WireIcmpIdentity, parse_icmp_v4_transport,
    parse_icmp_v6_transport, parse_ipv4_icmp_packet, parse_ipv6_icmp_packet, parse_packet_headers,
    parse_udp_datagram_payload,
};
pub use receive::{
    IpVersion, PacketParserFn, ReceiveHeaderMode, ReceiveParserKernel, UnsupportedReceiveLayout,
    select_receive_parser,
};
