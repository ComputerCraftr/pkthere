use crate::net::packet_headers::{ParsedPacketHeaders, ParsedTransport};
use crate::net::params::CanonicalAddr;
use socket2::SockAddr;
use std::net::{IpAddr, SocketAddr};

#[inline]
pub(crate) fn raw_packet_destination_matches(
    parsed: &ParsedPacketHeaders,
    local: CanonicalAddr,
    socket_is_ipv4: bool,
) -> bool {
    let local_ip = local.addr.ip();
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
) -> Option<CanonicalAddr> {
    if let Some(src_ip) = parsed.src_ip {
        match src_ip {
            IpAddr::V4(ip) => Some(CanonicalAddr::from_v4(ip, ident)),
            IpAddr::V6(ip) => {
                let meta = socket_source.and_then(|s| s.as_socket_ipv6())?;
                Some(CanonicalAddr::from_v6(
                    ip,
                    ident,
                    meta.flowinfo(),
                    meta.scope_id(),
                ))
            }
        }
    } else if !socket_is_ipv4 && parsed.transport == ParsedTransport::HeaderlessIcmp {
        socket_source.and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, ident))
    } else {
        None
    }
}

#[inline]
pub(crate) fn icmp_remote_ip_matches(actual: CanonicalAddr, expected: CanonicalAddr) -> bool {
    match (actual.addr, expected.addr) {
        (SocketAddr::V4(actual), SocketAddr::V4(expected)) => actual.ip() == expected.ip(),
        (SocketAddr::V6(actual), SocketAddr::V6(expected)) => {
            actual.ip() == expected.ip()
                && (actual.scope_id() == 0
                    || expected.scope_id() == 0
                    || actual.scope_id() == expected.scope_id())
        }
        _ => false,
    }
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
