use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::icmp_echo_parse::parse_icmp_echo_header;
use crate::net::params::CanonicalAddr;
use crate::net::payload::IcmpAdmissionInfo;
use socket2::{SockAddr, Type};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketPeerRole {
    Client,
    Upstream,
}

#[inline]
pub(crate) fn log_rejected_packet(
    worker_id: usize,
    c2u: bool,
    cfg: &RuntimeConfig,
    role: SocketPeerRole,
    rejected: RejectedPacket,
    expected_remote: Option<CanonicalAddr>,
    expected_local_id: Option<u16>,
) {
    let role_name = match role {
        SocketPeerRole::Client => "client",
        SocketPeerRole::Upstream => "upstream",
    };
    let actual_source = rejected
        .normalized_source
        .map(|source| source.to_string())
        .unwrap_or_else(|| String::from("<unknown>"));
    match rejected.reason {
        RejectionReason::UnexpectedRemotePeer => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping packet from unexpected {role_name} peer {} (expected remote {:?}, local_id {:?})",
            actual_source,
            expected_remote,
            expected_local_id
        ),
        RejectionReason::UnexpectedLocalReceiveId => {
            let actual_id = rejected.normalized_source.map(|s| s.id);
            crate::log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                c2u,
                "dropping packet from {role_name} peer {} with unexpected local receive id {:?} (expected {:?})",
                actual_source,
                actual_id,
                expected_local_id
            )
        }
        RejectionReason::MalformedIcmpHeader => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping malformed ICMP packet from {role_name} peer {}",
            actual_source
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketAdmissionSpec {
    pub(crate) role: SocketPeerRole,
    pub(crate) proto: SupportedProtocol,
    pub(crate) sock_type: Type,
    pub(crate) expected_remote: Option<CanonicalAddr>,
    pub(crate) expected_local_icmp_id: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedPacket {
    pub(crate) normalized_source: Option<CanonicalAddr>,
    pub(crate) payload_bounds: (usize, usize),
    pub(crate) icmp_info: Option<IcmpAdmissionInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectionReason {
    UnexpectedRemotePeer,
    UnexpectedLocalReceiveId,
    MalformedIcmpHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectedPacket {
    pub(crate) normalized_source: Option<CanonicalAddr>,
    pub(crate) reason: RejectionReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketAdmission {
    Accepted(AdmittedPacket),
    Filtered(RejectedPacket),
    UnsupportedSource,
}

#[inline]
pub(crate) fn admit_packet(
    spec: PacketAdmissionSpec,
    payload: &[u8],
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    match spec.proto {
        SupportedProtocol::UDP => admit_udp_packet(spec, payload, socket_source),
        SupportedProtocol::ICMP => admit_icmp_packet(spec, payload, socket_source),
    }
}

#[inline]
fn admit_udp_packet(
    spec: PacketAdmissionSpec,
    payload: &[u8],
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    let Some(source_sa) = socket_source else {
        return PacketAdmission::Accepted(AdmittedPacket {
            normalized_source: None,
            payload_bounds: (0, payload.len()),
            icmp_info: None,
        });
    };
    let Some(canonical) = CanonicalAddr::from_sock_addr(source_sa) else {
        return PacketAdmission::UnsupportedSource;
    };
    if spec
        .expected_remote
        .is_some_and(|expected| canonical != expected)
    {
        PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        })
    } else {
        PacketAdmission::Accepted(AdmittedPacket {
            normalized_source: Some(canonical),
            payload_bounds: (0, payload.len()),
            icmp_info: None,
        })
    }
}

#[inline]
fn admit_icmp_packet(
    spec: PacketAdmissionSpec,
    payload: &[u8],
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    let (icmp_ok, ident, seq, is_req, ip_ver, p_bounds, src_ip, dst_ip) =
        parse_icmp_echo_header(payload);
    if !icmp_ok {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: socket_source.and_then(|s| CanonicalAddr::from_sock_addr(s)),
            reason: RejectionReason::MalformedIcmpHeader,
        });
    }

    if spec
        .expected_local_icmp_id
        .is_some_and(|expected| ident != expected)
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: socket_source
                .and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, ident)),
            reason: RejectionReason::UnexpectedLocalReceiveId,
        });
    }

    let canonical = if spec.sock_type == Type::RAW {
        parse_raw_ip_source(payload, ip_ver, src_ip, dst_ip, socket_source, ident)
            .or_else(|| socket_source.and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, ident)))
    } else {
        socket_source
            .and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, ident))
            .or_else(|| {
                spec.expected_remote
                    .map(|expected| CanonicalAddr::new(expected.addr, ident))
            })
    };

    let Some(canonical) = canonical else {
        return if spec.expected_remote.is_some() {
            PacketAdmission::UnsupportedSource
        } else {
            PacketAdmission::Accepted(AdmittedPacket {
                normalized_source: None,
                payload_bounds: p_bounds,
                icmp_info: Some(IcmpAdmissionInfo { ident, seq, is_req }),
            })
        };
    };

    if spec
        .expected_remote
        .is_some_and(|expected| !icmp_remote_ip_matches(canonical, expected))
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }

    let _ = spec.role;
    PacketAdmission::Accepted(AdmittedPacket {
        normalized_source: Some(canonical),
        payload_bounds: p_bounds,
        icmp_info: Some(IcmpAdmissionInfo { ident, seq, is_req }),
    })
}

#[inline]
fn icmp_remote_ip_matches(actual: CanonicalAddr, expected: CanonicalAddr) -> bool {
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
fn parse_raw_ip_source(
    payload: &[u8],
    ip_ver: u8,
    src_ip_bounds: (usize, usize),
    _dst_ip_bounds: (usize, usize),
    socket_source: Option<&SockAddr>,
    ident: u16,
) -> Option<CanonicalAddr> {
    let (start, end) = src_ip_bounds;
    if ip_ver == 4 && end - start == 4 {
        let octets: [u8; 4] = payload[start..end].try_into().unwrap();
        Some(CanonicalAddr::from_v4(Ipv4Addr::from(octets), ident))
    } else if ip_ver == 6 && end - start == 16 {
        let octets: [u8; 16] = payload[start..end].try_into().unwrap();
        let ip = Ipv6Addr::from(octets);
        Some(match socket_source.and_then(|s| s.as_socket_ipv6()) {
            Some(meta) => CanonicalAddr::from_v6(ip, ident, meta.flowinfo(), meta.scope_id()),
            _ => CanonicalAddr::from_v6(ip, ident, 0, 0),
        })
    } else {
        socket_source.and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, ident))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PacketAdmission, PacketAdmissionSpec, RejectionReason, SocketPeerRole, admit_packet,
    };
    use crate::cli::SupportedProtocol;
    use crate::net::params::CanonicalAddr;
    use socket2::Type;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    fn test_icmp_echo_packet(
        source_ip: Option<IpAddr>,
        dest_ip: Option<IpAddr>,
        ident: u16,
        is_request: bool,
    ) -> Vec<u8> {
        let icmp_type = match (source_ip, is_request) {
            (Some(IpAddr::V6(_)), true) => 128,
            (Some(IpAddr::V6(_)), false) => 129,
            (_, true) => 8,
            (_, false) => 0,
        };
        let mut icmp = vec![icmp_type, 0, 0, 0, 0, 0, 0, 1];
        let ident_bytes = ident.to_be_bytes();
        icmp[4] = ident_bytes[0];
        icmp[5] = ident_bytes[1];

        match (source_ip, dest_ip) {
            (Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))) => {
                let mut packet = vec![0u8; 20 + icmp.len()];
                packet[0] = 0x45;
                packet[9] = 1;
                packet[12..16].copy_from_slice(&src.octets());
                packet[16..20].copy_from_slice(&dst.octets());
                packet[20..].copy_from_slice(&icmp);
                packet
            }
            (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
                let mut packet = vec![0u8; 40 + icmp.len()];
                packet[0] = 0x60;
                packet[6] = 58;
                packet[8..24].copy_from_slice(&src.octets());
                packet[24..40].copy_from_slice(&dst.octets());
                packet[40..].copy_from_slice(&icmp);
                packet
            }
            _ => icmp,
        }
    }

    #[test]
    fn udp_admission_requires_exact_remote_ip_and_port() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::UDP,
            sock_type: Type::DGRAM,
            expected_remote: Some(CanonicalAddr::from_socket_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                4444,
            ))),
            expected_local_icmp_id: None,
        };
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444).into();
        assert!(matches!(
            admit_packet(spec, &[], Some(&source)),
            PacketAdmission::Accepted(_)
        ));
        let source_wrong = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4445).into();
        assert!(matches!(
            admit_packet(spec, &[], Some(&source_wrong)),
            PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
        ));
    }

    #[test]
    fn icmp_dgram_admission_requires_remote_ip_and_local_receive_id() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Client,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::DGRAM,
            expected_remote: Some(CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0),
                0x1234,
            )),
            expected_local_icmp_id: Some(0x1234),
        };
        let packet = test_icmp_echo_packet(None, None, 0x1234, true);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1).into();
        assert!(matches!(
            admit_packet(spec, &packet, Some(&source)),
            PacketAdmission::Accepted(_)
        ));
        let source_wrong = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 1).into();
        assert!(matches!(
            admit_packet(spec, &packet, Some(&source_wrong)),
            PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
        ));
        let wrong_id = test_icmp_echo_packet(None, None, 0x9999, true);
        assert!(matches!(
            admit_packet(spec, &wrong_id, Some(&source)),
            PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedLocalReceiveId
        ));
    }

    #[test]
    fn icmp_dgram_admission_falls_back_to_expected_remote_ip_when_metadata_is_missing() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::DGRAM,
            expected_remote: Some(CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 0),
                0x1234,
            )),
            expected_local_icmp_id: Some(0x1234),
        };
        let packet = test_icmp_echo_packet(None, None, 0x1234, false);
        assert!(matches!(
            admit_packet(spec, &packet, None),
            PacketAdmission::Accepted(admitted)
                if admitted.normalized_source
                    == Some(CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 0), 0x1234))
        ));
    }

    #[test]
    fn icmp_raw_admission_uses_packet_source_ip_not_socket_metadata() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::RAW,
            expected_remote: Some(CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
                65410,
            )),
            expected_local_icmp_id: Some(65410),
        };
        let packet = test_icmp_echo_packet(
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            65410,
            false,
        );
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
        assert!(matches!(
            admit_packet(spec, &packet, Some(&source)),
            PacketAdmission::Accepted(admitted)
                if admitted.normalized_source
                    == Some(CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0), 65410))
        ));
    }

    #[test]
    fn icmp_raw_reflected_self_loop_is_rejected_by_remote_ip_check() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::RAW,
            expected_remote: Some(CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0),
                65410,
            )),
            expected_local_icmp_id: Some(65410),
        };
        let packet = test_icmp_echo_packet(
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            65410,
            true,
        );
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0).into();
        assert!(matches!(
            admit_packet(spec, &packet, Some(&source)),
            PacketAdmission::Filtered(rej) if rej.reason == RejectionReason::UnexpectedRemotePeer
        ));
    }

    #[test]
    fn icmp_ipv6_raw_admission_preserves_metadata_scope_when_available() {
        let spec = PacketAdmissionSpec {
            role: SocketPeerRole::Upstream,
            proto: SupportedProtocol::ICMP,
            sock_type: Type::RAW,
            expected_remote: Some(CanonicalAddr::new(
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)),
                9999,
            )),
            expected_local_icmp_id: Some(9999),
        };
        let packet = test_icmp_echo_packet(
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            9999,
            false,
        );
        let source = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)).into();
        assert!(matches!(
            admit_packet(spec, &packet, Some(&source)),
            PacketAdmission::Accepted(admitted)
                if admitted.normalized_source
                    == Some(CanonicalAddr::new(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)), 9999))
        ));
    }
}
