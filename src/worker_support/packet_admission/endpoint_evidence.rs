use super::transport::{PeerSourceRequirement, ReceiveContext, RejectedPacket, RejectionReason};
use crate::cli::SupportedProtocol;
use crate::endpoint::LogicalEndpoint;
use crate::net::packet_headers::ParsedPacketHeaders;
use socket2::Type;
use std::net::{IpAddr, SocketAddr};

fn parse_raw_ip_source(
    parsed: &ParsedPacketHeaders,
    socket_source: Option<SocketAddr>,
    ident: u16,
) -> Option<LogicalEndpoint> {
    match parsed.network {
        crate::net::packet_headers::ParsedNetworkLayer::Valid(header)
        | crate::net::packet_headers::ParsedNetworkLayer::Unsupported { header, .. } => {
            match header.source {
                IpAddr::V4(ip) => Some(LogicalEndpoint::from_v4(ip, ident)),
                IpAddr::V6(ip) => {
                    let matching_meta = socket_source
                        .and_then(|source| match source {
                            SocketAddr::V6(source) => Some(source),
                            SocketAddr::V4(_) => None,
                        })
                        .filter(|metadata| *metadata.ip() == ip);
                    let scope_id = matching_meta.map_or(0, |metadata| metadata.scope_id());
                    if ip.is_unicast_link_local() && scope_id == 0 {
                        return None;
                    }
                    Some(LogicalEndpoint::from_v6(ip, ident, scope_id))
                }
            }
        }
        crate::net::packet_headers::ParsedNetworkLayer::NotPresent => {
            socket_source.map(|source| LogicalEndpoint::from_socket_addr_with_id(source, ident))
        }
        crate::net::packet_headers::ParsedNetworkLayer::Malformed(_)
        | crate::net::packet_headers::ParsedNetworkLayer::UnexpectedVersion { .. } => None,
    }
}

pub(super) fn resolve_transport_ids(
    spec: ReceiveContext<'_>,
    socket_source: Option<SocketAddr>,
    parsed: &ParsedPacketHeaders,
) -> Result<(u16, u16), RejectedPacket> {
    match spec.socket.proto {
        SupportedProtocol::UDP => {
            if spec.socket.sock_type == Type::DGRAM {
                let src_port = socket_source.map_or(0, |source| source.port());
                let Some(dst_port) = spec.local_filter().map(LogicalEndpoint::id) else {
                    return Err(RejectedPacket {
                        normalized_source: None,
                        actual_dst_id: None,
                        reason: RejectionReason::UnexpectedLocalReceiveId,
                    });
                };
                Ok((src_port, dst_port))
            } else {
                let Some(udp) = parsed.udp else {
                    return Err(RejectedPacket {
                        normalized_source: socket_source.map(LogicalEndpoint::from_socket_addr),
                        actual_dst_id: None,
                        reason: RejectionReason::MalformedIcmpHeader(None),
                    });
                };
                Ok((udp.src_port, udp.dst_port))
            }
        }
        SupportedProtocol::ICMP => {
            let Some(icmp) = parsed.icmp else {
                return Err(RejectedPacket {
                    normalized_source: socket_source.map(LogicalEndpoint::from_socket_addr),
                    actual_dst_id: None,
                    reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason),
                });
            };
            let Some(source_id) = icmp.identity.source_id else {
                return Err(RejectedPacket {
                    normalized_source: socket_source.map(LogicalEndpoint::from_socket_addr),
                    actual_dst_id: Some(icmp.identity.destination_id),
                    reason: RejectionReason::MalformedIcmpHeader(Some(
                        crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
                    )),
                });
            };
            let destination_id = icmp.identity.destination_id;
            if source_id == 0 {
                return Err(RejectedPacket {
                    normalized_source: socket_source.map(LogicalEndpoint::from_socket_addr),
                    actual_dst_id: Some(destination_id),
                    reason: RejectionReason::MalformedIcmpHeader(Some(
                        crate::net::packet_headers::IcmpMalformedReason::ZeroSourceId,
                    )),
                });
            }
            if destination_id == 0 {
                return Err(RejectedPacket {
                    normalized_source: socket_source.map(LogicalEndpoint::from_socket_addr),
                    actual_dst_id: Some(destination_id),
                    reason: RejectionReason::UnexpectedLocalReceiveId,
                });
            }
            Ok((source_id, destination_id))
        }
    }
}

pub(super) fn resolve_source_endpoint(
    spec: ReceiveContext<'_>,
    socket_source: Option<SocketAddr>,
    parsed: &ParsedPacketHeaders,
    logical_src_id: u16,
    logical_dst_id: u16,
) -> Result<Option<LogicalEndpoint>, RejectedPacket> {
    match spec.socket.evidence_policy().peer_source {
        PeerSourceRequirement::RawPacketHeader => {
            match parse_raw_ip_source(parsed, socket_source, logical_src_id) {
                Some(source) => Ok(Some(source)),
                None => Err(RejectedPacket {
                    normalized_source: None,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::MissingSourceEvidence,
                }),
            }
        }
        PeerSourceRequirement::SourceMetadata | PeerSourceRequirement::ConnectedKernel => {
            match socket_source
                .map(|source| LogicalEndpoint::from_socket_addr_with_id(source, logical_src_id))
            {
                Some(source) => Ok(Some(source)),
                None if spec.socket.evidence_policy().peer_source
                    == PeerSourceRequirement::ConnectedKernel =>
                {
                    if spec.socket.proto == SupportedProtocol::ICMP {
                        // A connected ICMP socket supplies peer-address but not
                        // source-ID authority; the shim supplies that ID.
                        Ok(spec
                            .expected_remote()
                            .map(|expected| expected.with_id(logical_src_id)))
                    } else {
                        // Connected UDP filtering is kernel-authoritative. No
                        // synthetic source-port evidence is needed or valid.
                        Ok(None)
                    }
                }
                None => Err(RejectedPacket {
                    normalized_source: None,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::MissingSourceEvidence,
                }),
            }
        }
    }
}
