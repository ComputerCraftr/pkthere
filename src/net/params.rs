// Shared protocol/packet limits
pub(crate) use pkthere_wire::MAX_WIRE_PAYLOAD;

// Maximum safe user payloads (IPv4 = 65535 - 20 IP - 8 L4 - 1 Shim)
pub(crate) const MAX_SAFE_UDP_IPV4_PAYLOAD: usize = 65507;
pub(crate) const MAX_SAFE_ICMP_IPV4_PAYLOAD: usize = 65506;

// Maximum safe user payloads (IPv6 = 65535 - 8 L4 - 1 Shim)
pub(crate) const MAX_SAFE_UDP_IPV6_PAYLOAD: usize = 65527;
pub(crate) const MAX_SAFE_ICMP_IPV6_PAYLOAD: usize = 65526;
