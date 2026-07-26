//! Shared capture and user-payload limits.
//!
//! IPv4 total length includes its fixed header, whereas the IPv6 payload
//! length excludes the fixed header. Keeping both calculations together
//! prevents parser capacity and CLI payload validation from drifting.

use crate::net::framing_shim::ICMP_TUNNEL_EXPLICIT_DATA_LEN;
pub(crate) use pkthere_wire::MAX_WIRE_PAYLOAD;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_ECHO_HEADER_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
pub(crate) const MAX_IPV4_PACKET_CAPTURE: usize = MAX_WIRE_PAYLOAD;
pub(crate) const MAX_IPV6_PACKET_CAPTURE: usize = IPV6_HEADER_LEN + MAX_WIRE_PAYLOAD;
pub(crate) const MAX_RECEIVE_CAPTURE: usize = if MAX_IPV4_PACKET_CAPTURE > MAX_IPV6_PACKET_CAPTURE {
    MAX_IPV4_PACKET_CAPTURE
} else {
    MAX_IPV6_PACKET_CAPTURE
};
pub(crate) const MAX_SAFE_UDP_IPV4_PAYLOAD: usize =
    MAX_WIRE_PAYLOAD - IPV4_HEADER_LEN - UDP_HEADER_LEN;
pub(crate) const MAX_SAFE_ICMP_IPV4_PAYLOAD: usize =
    MAX_WIRE_PAYLOAD - IPV4_HEADER_LEN - ICMP_ECHO_HEADER_LEN - ICMP_TUNNEL_EXPLICIT_DATA_LEN;
pub(crate) const MAX_SAFE_UDP_IPV6_PAYLOAD: usize = MAX_WIRE_PAYLOAD - UDP_HEADER_LEN;
pub(crate) const MAX_SAFE_ICMP_IPV6_PAYLOAD: usize =
    MAX_WIRE_PAYLOAD - ICMP_ECHO_HEADER_LEN - ICMP_TUNNEL_EXPLICIT_DATA_LEN;

const _: () = assert!(MAX_SAFE_ICMP_IPV4_PAYLOAD == 65_496);
const _: () = assert!(MAX_SAFE_ICMP_IPV6_PAYLOAD == 65_516);
const _: () = assert!(MAX_RECEIVE_CAPTURE == 65_575);
const _: () = assert!(MAX_RECEIVE_CAPTURE >= MAX_IPV4_PACKET_CAPTURE);
const _: () = assert!(MAX_RECEIVE_CAPTURE >= MAX_IPV6_PACKET_CAPTURE);

#[cfg(test)]
mod tests;
