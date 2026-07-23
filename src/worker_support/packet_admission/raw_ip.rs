use crate::endpoint::LogicalEndpoint;
use crate::net::packet_headers::{ParsedPacketHeaders, ParsedTransport};
use socket2::SockAddr;
use std::net::IpAddr;

#[inline]
pub(crate) fn raw_packet_destination_matches(
    parsed: &ParsedPacketHeaders,
    local: LogicalEndpoint,
    socket_is_ipv4: bool,
) -> bool {
    let local_ip = local.ip();
    if local_ip.is_unspecified() {
        return true;
    }
    if !socket_is_ipv4 && parsed.transport == ParsedTransport::HeaderlessIcmp {
        return true;
    }
    parsed.dst_ip == Some(local_ip)
}

#[inline]
pub(crate) fn parse_raw_ip_source(
    parsed: &ParsedPacketHeaders,
    socket_source: Option<&SockAddr>,
    socket_is_ipv4: bool,
    ident: u16,
) -> Option<LogicalEndpoint> {
    if let Some(src_ip) = parsed.src_ip {
        match src_ip {
            IpAddr::V4(ip) => Some(LogicalEndpoint::from_v4(ip, ident)),
            IpAddr::V6(ip) => {
                let meta = socket_source.and_then(|s| s.as_socket_ipv6())?;
                Some(LogicalEndpoint::from_v6(
                    ip,
                    ident,
                    meta.flowinfo(),
                    meta.scope_id(),
                ))
            }
        }
    } else if !socket_is_ipv4 && parsed.transport == ParsedTransport::HeaderlessIcmp {
        socket_source.and_then(|s| LogicalEndpoint::from_sock_addr_with_id(s, ident))
    } else {
        None
    }
}

#[inline]
pub(crate) fn icmp_remote_ip_matches(actual: LogicalEndpoint, expected: LogicalEndpoint) -> bool {
    expected.matches_ip_filter(actual)
}

#[inline]
pub(crate) fn parsed_transport_has_ip(parsed: &ParsedPacketHeaders) -> bool {
    matches!(
        parsed.transport,
        ParsedTransport::Ipv4Icmp
            | ParsedTransport::Ipv6Icmp
            | ParsedTransport::Ipv4Udp
            | ParsedTransport::Ipv6Udp
    )
}
