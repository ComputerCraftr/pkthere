// Shared protocol/packet limits
pub const MAX_WIRE_PAYLOAD: usize = 65535; // Used for receive buffer sizing

// Maximum safe user payloads (IPv4 = 65535 - 20 IP - 8 L4 - 1 Shim)
pub const MAX_SAFE_UDP_IPV4_PAYLOAD: usize = 65507;
pub const MAX_SAFE_ICMP_IPV4_PAYLOAD: usize = 65506;

// Maximum safe user payloads (IPv6 = 65535 - 8 L4 - 1 Shim)
pub const MAX_SAFE_UDP_IPV6_PAYLOAD: usize = 65527;
pub const MAX_SAFE_ICMP_IPV6_PAYLOAD: usize = 65526;
