pub(crate) use pkthere_wire::packet_headers::{
    ICMP_CONTROL_CHALLENGE_ACK, ICMP_CONTROL_CHALLENGE_NEGOTIATE, ICMP_CONTROL_GENERATION_ADVANCE,
    ICMP_CONTROL_GENERATION_ADVANCE_ACK, ICMP_CONTROL_NEGOTIATE, ICMP_CONTROL_NEGOTIATE_ACK,
    ICMP_CONTROL_RESET_REQUIRED, ICMP_CONTROL_SESSION_ACTIVATED, ICMP_TUNNEL_CHALLENGE_BODY_LEN,
    ICMP_TUNNEL_CONTROL_HEADER_LEN, ICMP_TUNNEL_CONTROL_VERSION,
    ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN, ICMP_TUNNEL_NEGOTIATE_BODY_LEN,
    ICMP_TUNNEL_POOL_GENERATION_LEN, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
    ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN, ICMP_TUNNEL_SESSION_ID_LEN,
    ICMP_TUNNEL_SESSION_KEY_LEN, ICMP_TUNNEL_SESSION_ORDINAL_LEN, IcmpMalformedReason,
    IpMalformedReason, IpUnsupportedReason, IpVersion, NetworkParseOutcome, ParsedIcmpEcho,
    ParsedNetworkLayer, ParsedPacketHeaders, ParsedTransport, ReceiveParserKernel, SHIM_IS_CADENCE,
    SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER, WireIcmpIdentity, icmp_control_body_len,
};

use crate::cli::SupportedProtocol;
use pkthere_socket_policy::{ResolvedSocketPolicy, ip_version_for_domain};
#[cfg(test)]
pub(crate) use pkthere_wire::packet_headers::{ParsedNetworkHeader, ParsedUdpHeader};
use socket2::Domain;
use std::io;

pub(crate) fn select_packet_parser(
    proto: SupportedProtocol,
    family: Domain,
    policy: ResolvedSocketPolicy,
) -> io::Result<ReceiveParserKernel> {
    pkthere_wire::packet_headers::select_receive_parser(
        proto,
        ip_version_for_domain(family).map_err(io::Error::other)?,
        policy.receive_header,
        policy.ipv4_receive_length,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[cfg(test)]
mod tests;
