pub(crate) use super::rejection::{RejectedPacket, RejectionReason};
use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::ClientFlowKey;
use crate::flow_state::PendingIcmpClientLock;
use crate::net::framing_shim::{
    IcmpTunnelControl, ReplyIdNegotiation, SessionId, parse_icmp_control,
};
use crate::net::packet_headers::{
    ParsedNetworkLayer, ParsedPacketHeaders, ParsedTransport, SHIM_IS_CADENCE, SHIM_IS_DATA,
};
use crate::net::payload::{AdmittedIcmpIdentity, PayloadEvent};
use pkthere_socket_policy::Ipv6DestinationScopeEvidence;
pub(crate) use pkthere_socket_policy::PeerSourceRequirement;
#[cfg(test)]
pub(crate) use pkthere_socket_policy::ProtocolIdRequirement;
#[cfg(test)]
pub(crate) use pkthere_socket_policy::ReceiveEvidencePolicy;
#[cfg(test)]
use socket2::SockAddr;
use socket2::Type;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketLeg {
    ClientFacing,
    UpstreamFacing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveNoiseReason {
    UnexpectedEchoDirection,
    UnrelatedIpProtocol,
    UnrelatedIcmpType,
    UnexpectedIpVersion,
}
#[cfg(test)]
pub(crate) use super::transport_context::{AdmissionStateContext, ReceiveSocketContext};
pub(crate) use super::transport_context::{
    ReceiveContext, client_receive_context, upstream_receive_context,
};

use super::admitted::ClientAdmissionCandidate;
pub(crate) use super::admitted::{AdmittedWirePacket, WirePacketAdmission, WirePacketRejection};
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TransportPacket<'a> {
    pub(crate) normalized_source: Option<LogicalEndpoint>,
    identity: AdmittedTransportIdentity,
    pub(crate) seq: u16,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) payload: &'a [u8],
    pub(crate) shim_flags: Option<u8>,
    pub(crate) control: Option<IcmpTunnelControl>,
    pub(crate) reply_id_negotiation: Option<ReplyIdNegotiation>,
    pub(crate) allows_control_identity_learning: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdmittedTransportIdentity {
    Udp { local_destination_id: u16 },
    Icmp(AdmittedIcmpIdentity),
}

impl TransportPacket<'_> {
    #[inline]
    const fn local_destination_id(&self) -> u16 {
        match self.identity {
            AdmittedTransportIdentity::Udp {
                local_destination_id,
            } => local_destination_id,
            AdmittedTransportIdentity::Icmp(identity) => identity.local_destination_id(),
        }
    }

    #[inline]
    pub(super) const fn icmp_identity(&self) -> Option<AdmittedIcmpIdentity> {
        match self.identity {
            AdmittedTransportIdentity::Udp { .. } => None,
            AdmittedTransportIdentity::Icmp(identity) => Some(identity),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TransportAdmission<'a> {
    Accepted(TransportPacket<'a>),
    Filtered(RejectedPacket),
    ReceiveNoise(ReceiveNoiseReason),
}

#[inline]
fn network_source(parsed: &ParsedPacketHeaders) -> Option<LogicalEndpoint> {
    parsed
        .source_ip()
        .map(|address| endpoint_from_ip(address, 0))
}

#[inline]
fn endpoint_from_ip(address: std::net::IpAddr, id: u16) -> LogicalEndpoint {
    match address {
        std::net::IpAddr::V4(address) => LogicalEndpoint::from_v4(address, id),
        std::net::IpAddr::V6(address) => LogicalEndpoint::from_v6(address, id, 0),
    }
}

#[inline]
pub(crate) fn admit_network_layer<'a>(
    spec: ReceiveContext<'_>,
    network: ParsedNetworkLayer,
) -> Option<TransportAdmission<'a>> {
    let header = match network {
        ParsedNetworkLayer::NotPresent => return None,
        ParsedNetworkLayer::Malformed(reason) => {
            return Some(TransportAdmission::Filtered(RejectedPacket {
                normalized_source: None,
                actual_dst_id: None,
                reason: RejectionReason::MalformedIpHeader(reason),
            }));
        }
        ParsedNetworkLayer::UnexpectedVersion { .. } => {
            return Some(TransportAdmission::ReceiveNoise(
                ReceiveNoiseReason::UnexpectedIpVersion,
            ));
        }
        ParsedNetworkLayer::Valid(header) | ParsedNetworkLayer::Unsupported { header, .. } => {
            header
        }
    };
    let normalized_source = Some(endpoint_from_ip(header.source, 0));
    if let Some(local) = spec.local_filter()
        && !local.ip().is_unspecified()
        && header.destination != local.ip()
    {
        return Some(TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: None,
            reason: RejectionReason::UnexpectedLocalReceiveAddress,
        }));
    }
    if let std::net::IpAddr::V6(address) = header.destination
        && address.is_unicast_link_local()
    {
        let exact_bound_scope = match (
            spec.socket.policy.ipv6_destination_scope,
            spec.local_filter(),
            spec.socket.local_kernel_addr,
        ) {
            (
                Ipv6DestinationScopeEvidence::ExactBoundEndpoint,
                Some(local),
                std::net::SocketAddr::V6(kernel),
            ) => {
                local.ip() == header.destination
                    && local.scope_id() != 0
                    && *kernel.ip() == address
                    && kernel.scope_id() == local.scope_id()
            }
            (Ipv6DestinationScopeEvidence::NotApplicable, _, _)
            | (Ipv6DestinationScopeEvidence::ExactBoundEndpoint, _, _) => false,
        };
        if !exact_bound_scope {
            return Some(TransportAdmission::Filtered(RejectedPacket {
                normalized_source,
                actual_dst_id: None,
                reason: RejectionReason::UnexpectedLocalReceiveAddress,
            }));
        }
    }
    if let Some(expected) = spec.expected_remote()
        && !matches!(
            header.source,
            std::net::IpAddr::V6(address) if address.is_unicast_link_local()
        )
        && !icmp_remote_ip_matches(endpoint_from_ip(header.source, expected.id()), expected)
    {
        return Some(TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: None,
            reason: RejectionReason::UnexpectedRemotePeer,
        }));
    }
    if let ParsedNetworkLayer::Unsupported { reason, .. } = network {
        return Some(TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: None,
            reason: RejectionReason::UnsupportedIpLayout(reason),
        }));
    }
    None
}

#[inline]
#[cfg(test)]
pub(crate) fn admit_packet<'a>(
    spec: super::test_support::SyntheticReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> TransportAdmission<'a> {
    let spec = spec.as_receive_context();
    let network = spec.socket.parser.parse_network(payload);
    let network_layer = match network {
        crate::net::packet_headers::NetworkParseOutcome::NotPresent => {
            ParsedNetworkLayer::NotPresent
        }
        crate::net::packet_headers::NetworkParseOutcome::Valid(validated) => {
            ParsedNetworkLayer::Valid(validated.header)
        }
        crate::net::packet_headers::NetworkParseOutcome::Rejected(layer) => layer,
    };
    if let Some(admission) = admit_network_layer(spec, network_layer) {
        return admission;
    }
    let parsed = spec.socket.parser.parse_transport(payload, network);
    admit_packet_with_parsed(
        spec,
        payload,
        socket_source.and_then(SockAddr::as_socket),
        &parsed,
    )
}

#[inline]
pub(crate) fn admit_packet_with_parsed<'a>(
    spec: ReceiveContext<'_>,
    payload: &'a [u8],
    socket_source: Option<std::net::SocketAddr>,
    parsed: &ParsedPacketHeaders,
) -> TransportAdmission<'a> {
    if let Some(admission) = admit_network_layer(spec, parsed.network) {
        return admission;
    }
    match parsed.transport {
        ParsedTransport::NotParsed => {
            return TransportAdmission::ReceiveNoise(ReceiveNoiseReason::UnrelatedIpProtocol);
        }
        ParsedTransport::UnrelatedProtocol => {
            return TransportAdmission::ReceiveNoise(ReceiveNoiseReason::UnrelatedIpProtocol);
        }
        ParsedTransport::UnrelatedIcmp => {
            return TransportAdmission::ReceiveNoise(ReceiveNoiseReason::UnrelatedIcmpType);
        }
        ParsedTransport::MalformedIcmp => {
            return TransportAdmission::Filtered(RejectedPacket {
                normalized_source: network_source(parsed),
                actual_dst_id: None,
                reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason),
            });
        }
        ParsedTransport::UdpDatagram | ParsedTransport::Icmp | ParsedTransport::Udp => {}
    }

    let (logical_src_id, logical_dst_id) = match resolve_transport_ids(spec, socket_source, parsed)
    {
        Ok(ids) => ids,
        Err(rejected) => return TransportAdmission::Filtered(rejected),
    };
    match spec.socket.proto {
        SupportedProtocol::UDP => admit_udp_packet(
            spec,
            payload,
            socket_source,
            parsed,
            logical_src_id,
            logical_dst_id,
        ),
        SupportedProtocol::ICMP => admit_icmp_packet(
            spec,
            payload,
            socket_source,
            parsed,
            logical_src_id,
            logical_dst_id,
        ),
    }
}

use super::endpoint_evidence::{resolve_source_endpoint, resolve_transport_ids};

fn admit_udp_packet<'a>(
    spec: ReceiveContext<'_>,
    payload: &'a [u8],
    socket_source: Option<std::net::SocketAddr>,
    parsed: &ParsedPacketHeaders,
    logical_src_id: u16,
    logical_dst_id: u16,
) -> TransportAdmission<'a> {
    let normalized_source = match resolve_source_endpoint(
        spec,
        socket_source,
        parsed,
        logical_src_id,
        logical_dst_id,
    ) {
        Ok(source) => source,
        Err(rejected) => return TransportAdmission::Filtered(rejected),
    };
    if parsed_transport_has_ip(parsed)
        && parsed
            .source_ip()
            .is_some_and(|source| normalized_source.is_some_and(|actual| source != actual.ip()))
    {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }
    if let (Some(expected), Some(source)) = (spec.expected_remote(), normalized_source)
        && !expected.matches_filter(source)
    {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source: Some(source),
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }
    let (payload_start, payload_end) = if spec.socket.sock_type == Type::DGRAM {
        (0, payload.len())
    } else {
        let Some(extent) = parsed.declared_extent(payload) else {
            return TransportAdmission::Filtered(RejectedPacket {
                normalized_source,
                actual_dst_id: Some(logical_dst_id),
                reason: RejectionReason::InvalidPayloadBounds,
            });
        };
        (extent.payload.start, extent.payload.end)
    };
    if payload_start > payload_end || payload_end > payload.len() {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::InvalidPayloadBounds,
        });
    }
    TransportAdmission::Accepted(TransportPacket {
        normalized_source,
        identity: AdmittedTransportIdentity::Udp {
            local_destination_id: logical_dst_id,
        },
        seq: 0,
        session_id: None,
        payload: &payload[payload_start..payload_end],
        shim_flags: None,
        control: None,
        reply_id_negotiation: None,
        allows_control_identity_learning: false,
    })
}

fn admit_icmp_packet<'a>(
    spec: ReceiveContext<'_>,
    payload: &'a [u8],
    socket_source: Option<std::net::SocketAddr>,
    parsed: &ParsedPacketHeaders,
    logical_src_id: u16,
    logical_dst_id: u16,
) -> TransportAdmission<'a> {
    let Some(icmp) = parsed.icmp else {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason),
        });
    };
    if icmp.is_req != (spec.socket.role == SocketLeg::ClientFacing) {
        return TransportAdmission::ReceiveNoise(ReceiveNoiseReason::UnexpectedEchoDirection);
    }
    let Some(extent) = spec.socket.parser.declared_extent(*parsed, payload) else {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::InvalidPayloadBounds,
        });
    };
    if extent.payload.end > payload.len() {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::InvalidPayloadBounds,
        });
    }
    let transport_payload = &payload[extent.payload];
    let Some(shim_flags) = icmp.shim_flags else {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source: None,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason.or(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
            ))),
        });
    };
    let control = match parse_icmp_control(shim_flags, transport_payload) {
        Ok(control) => control,
        Err(reason) => {
            return TransportAdmission::Filtered(RejectedPacket {
                normalized_source: None,
                actual_dst_id: Some(logical_dst_id),
                reason: RejectionReason::MalformedIcmpHeader(Some(reason)),
            });
        }
    };
    let reply_id_negotiation = match control {
        Some(IcmpTunnelControl::Negotiate(negotiation))
        | Some(IcmpTunnelControl::NegotiateAck(negotiation)) => Some(negotiation),
        Some(_) | None => None,
    };
    let normalized_source = match resolve_source_endpoint(
        spec,
        socket_source,
        parsed,
        logical_src_id,
        logical_dst_id,
    ) {
        Ok(source) => source,
        Err(rejected) => return TransportAdmission::Filtered(rejected),
    };
    let allows_control_identity_learning =
        allows_control_identity_learning(spec, parsed, normalized_source, reply_id_negotiation);
    if invalid_icmp_control_direction(spec, reply_id_negotiation, allows_control_identity_learning)
    {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection,
            )),
        });
    }
    if rejects_connected_reflection(
        spec,
        socket_source,
        reply_id_negotiation,
        allows_control_identity_learning,
    ) {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
        });
    }
    if spec
        .expected_local_id()
        .is_some_and(|expected| logical_dst_id != expected)
    {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::UnexpectedLocalReceiveId,
        });
    }
    if let Some(rejected) = reject_unexpected_icmp_peer(
        spec,
        normalized_source,
        logical_dst_id,
        allows_control_identity_learning,
    ) {
        return TransportAdmission::Filtered(rejected);
    }
    let Some(identity) = AdmittedIcmpIdentity::new(logical_src_id, logical_dst_id) else {
        return TransportAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(logical_dst_id),
            reason: RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::ZeroSourceId,
            )),
        });
    };
    TransportAdmission::Accepted(TransportPacket {
        normalized_source,
        identity: AdmittedTransportIdentity::Icmp(identity),
        seq: icmp.seq,
        session_id: SessionId::new(icmp.session_id),
        payload: transport_payload,
        shim_flags: icmp.shim_flags,
        control,
        reply_id_negotiation,
        allows_control_identity_learning,
    })
}

fn invalid_icmp_control_direction(
    spec: ReceiveContext<'_>,
    reply_id: Option<crate::net::framing_shim::ReplyIdNegotiation>,
    allows_identity_learning: bool,
) -> bool {
    reply_id.is_some_and(|control| {
        (spec.socket.role == SocketLeg::ClientFacing && control.is_ack())
            || (spec.socket.role == SocketLeg::UpstreamFacing
                && control.is_negotiate()
                && !allows_identity_learning)
    })
}

fn rejects_connected_reflection(
    spec: ReceiveContext<'_>,
    socket_source: Option<std::net::SocketAddr>,
    reply_id: Option<crate::net::framing_shim::ReplyIdNegotiation>,
    allows_identity_learning: bool,
) -> bool {
    let connected_reflection = spec.socket.role == SocketLeg::UpstreamFacing
        && spec.socket.evidence_policy().peer_source == PeerSourceRequirement::ConnectedKernel
        && socket_source.is_none()
        && spec.local_filter().is_some_and(|local| {
            spec.expected_remote()
                .is_some_and(|remote| remote.ip() == local.ip())
        });
    connected_reflection
        && reply_id.is_some_and(|control| control.is_negotiate() && !allows_identity_learning)
}

fn reject_unexpected_icmp_peer(
    spec: ReceiveContext<'_>,
    normalized_source: Option<LogicalEndpoint>,
    logical_dst_id: u16,
    allows_identity_learning: bool,
) -> Option<RejectedPacket> {
    let (expected, source) = (spec.expected_remote()?, normalized_source?);
    let matches_ip = icmp_remote_ip_matches(source, expected);
    let matches_id = source.id() == expected.id();
    if matches_ip && (matches_id || allows_identity_learning) {
        return None;
    }
    let reason = if matches_ip
        && spec
            .expected_local_id()
            .is_some_and(|id| logical_dst_id == id)
    {
        RejectionReason::IcmpSourceEndpointMismatch
    } else {
        RejectionReason::UnexpectedRemotePeer
    };
    Some(RejectedPacket {
        normalized_source: Some(source),
        actual_dst_id: Some(logical_dst_id),
        reason,
    })
}

#[inline]
#[cfg(test)]
pub(crate) fn admit_wire_packet<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: super::test_support::SyntheticReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> WirePacketAdmission<'a> {
    let spec = spec.as_receive_context();
    let network = spec.socket.parser.parse_network(payload);
    let parsed = spec.socket.parser.parse_transport(payload, network);
    admit_wire_packet_with_parsed(c2u, cfg, spec, payload, socket_source, &parsed)
}

#[inline]
#[cfg(test)]
pub(crate) fn admit_wire_packet_with_parsed<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: ReceiveContext<'_>,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
    parsed: &ParsedPacketHeaders,
) -> WirePacketAdmission<'a> {
    let socket_source = socket_source.and_then(SockAddr::as_socket);
    let admitted = match admit_packet_with_parsed(spec, payload, socket_source, parsed) {
        TransportAdmission::Accepted(admitted) => admitted,
        TransportAdmission::Filtered(rejected) => {
            return Err(
                crate::worker_support::packet_admission::WirePacketRejection::Filtered(rejected),
            );
        }
        TransportAdmission::ReceiveNoise(reason) => {
            return Err(
                crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(reason),
            );
        }
    };
    admit_transport_packet(c2u, cfg, spec, admitted)
}

/// Reports whether an endpoint-admitted frame spends authenticated-work budget.
/// Active/candidate data and cadence bypass it; controls and unknown sessions
/// are charged before the remaining admission state machine.
#[inline]
pub(crate) fn transport_requires_authenticated_work(
    spec: ReceiveContext<'_>,
    admitted: &TransportPacket<'_>,
) -> bool {
    if spec.socket.proto != SupportedProtocol::ICMP {
        return false;
    }
    if admitted.control.is_some() {
        return true;
    }
    let Some(flags) = admitted.shim_flags else {
        return false;
    };
    if flags & (SHIM_IS_DATA | SHIM_IS_CADENCE) == 0 {
        return false;
    }
    let Some(observed_session) = admitted.session_id else {
        return true;
    };
    let pending_matches = spec
        .admission
        .pending_icmp_client_lock
        .is_some_and(|pending| pending.session_id() == Some(observed_session));
    spec.admission.expected_session_id != Some(observed_session)
        && !spec
            .admission
            .additional_sessions
            .contains(observed_session)
        && !pending_matches
}

#[inline]
pub(crate) fn admit_transport_packet<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: ReceiveContext<'_>,
    admitted: TransportPacket<'a>,
) -> WirePacketAdmission<'a> {
    let dst_proto = if c2u {
        cfg.upstream_proto
    } else {
        cfg.listen_proto
    };
    let normalized_source = admitted.normalized_source;

    let event = match spec.socket.proto {
        SupportedProtocol::UDP => PayloadEvent::user_payload_plain(dst_proto, admitted.payload),
        SupportedProtocol::ICMP => match decode_icmp_payload_event(&admitted, dst_proto) {
            Ok(ev) => ev,
            Err(reason) => {
                return Err(
                    crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                        RejectedPacket {
                            normalized_source,
                            actual_dst_id: Some(admitted.local_destination_id()),
                            reason,
                        },
                    ),
                );
            }
        },
    };

    if event.payload_len() > cfg.max_payload {
        return Err(
            crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(admitted.local_destination_id()),
                    reason: RejectionReason::PayloadOversize,
                },
            ),
        );
    }

    if event_advertised_reply_id(&event)
        .is_some_and(|reply_id| reply_id != admitted.local_destination_id())
        && !spec.socket.can_honor_disjoint_icmp_ids()
        && !admitted.allows_control_identity_learning
    {
        return Err(
            crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(admitted.local_destination_id()),
                    reason: RejectionReason::UnsupportedDisjointReplyId,
                },
            ),
        );
    }

    let is_locked = spec.admission.locked_flow.is_some();

    let mut unknown_session_for_reset = false;
    if spec.socket.proto == SupportedProtocol::ICMP
        && matches!(
            event,
            PayloadEvent::UserPayload { .. } | PayloadEvent::CadencePacket { .. }
        )
    {
        let Some(observed_session) = event.icmp_meta().map(|icmp| icmp.session_id()) else {
            return Err(
                crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                    RejectedPacket {
                        normalized_source,
                        actual_dst_id: Some(admitted.local_destination_id()),
                        reason: RejectionReason::MalformedIcmpHeader(Some(
                            crate::net::packet_headers::IcmpMalformedReason::MissingSessionId,
                        )),
                    },
                ),
            );
        };
        let pending_matches = spec
            .admission
            .pending_icmp_client_lock
            .is_some_and(|pending| pending.session_id() == Some(observed_session));
        if spec.admission.expected_session_id != Some(observed_session)
            && !spec
                .admission
                .additional_sessions
                .contains(observed_session)
            && !pending_matches
        {
            if c2u && spec.socket.role == SocketLeg::ClientFacing && event.is_user_payload() {
                unknown_session_for_reset = true;
            } else {
                return Err(
                    crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                        RejectedPacket {
                            normalized_source,
                            actual_dst_id: Some(admitted.local_destination_id()),
                            reason: RejectionReason::IcmpSessionMismatch,
                        },
                    ),
                );
            }
        }
    }

    let mut lock_candidate = None;
    let mut pending_negotiation = None;
    let mut reset_candidate = None;
    if c2u && spec.socket.role == SocketLeg::ClientFacing {
        match &event {
            PayloadEvent::UserPayload { .. } => {
                if unknown_session_for_reset {
                    reset_candidate = normalized_source.and_then(|src| {
                        build_client_lock_candidate(
                            src,
                            spec.local_filter()?,
                            cfg.listener_source_id_request,
                            cfg.listen_proto,
                            &event,
                        )
                    });
                }
                lock_candidate = if spec.socket.proto == SupportedProtocol::ICMP {
                    spec.admission.pending_icmp_client_lock.filter(|pending| {
                        pending_client_candidate_matches(
                            *pending,
                            normalized_source,
                            event.icmp_meta().map(|icmp| icmp.session_id()),
                        )
                    })
                } else if is_locked {
                    // A stable UDP flow already carries its complete lock and
                    // routing authority in the immutable admission snapshot.
                    // Rebuilding and boxing that transition candidate here
                    // would allocate once per forwarded client packet.
                    None
                } else {
                    normalized_source.and_then(|src| {
                        build_client_lock_candidate(
                            src,
                            spec.local_filter()?,
                            cfg.listener_source_id_request,
                            cfg.listen_proto,
                            &event,
                        )
                    })
                };

                if !is_locked
                    && lock_candidate.is_none()
                    && spec.socket.proto == SupportedProtocol::ICMP
                    && !unknown_session_for_reset
                {
                    return Err(
                        crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                            RejectedPacket {
                                normalized_source,
                                actual_dst_id: Some(admitted.local_destination_id()),
                                reason: RejectionReason::IcmpReplyIdNegotiationRequired,
                            },
                        ),
                    );
                }
            }
            PayloadEvent::SessionControl { icmp, .. } => {
                if icmp.negotiates_reply_id() {
                    let candidate = normalized_source.and_then(|src| {
                        build_client_lock_candidate(
                            src,
                            spec.local_filter()?,
                            cfg.listener_source_id_request,
                            cfg.listen_proto,
                            &event,
                        )
                    });
                    pending_negotiation = if is_locked {
                        candidate.filter(|candidate| {
                            Some(candidate.flow_key) == spec.admission.locked_flow
                                && candidate.listener_flow.inbound
                                    == spec.admission.expected_inbound
                                && candidate.session_id() != spec.admission.expected_session_id
                        })
                    } else {
                        candidate
                    };
                    if is_locked && pending_negotiation.is_none() {
                        return Err(
                            crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                                RejectedPacket {
                                    normalized_source,
                                    actual_dst_id: Some(admitted.local_destination_id()),
                                    reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
                                },
                            ),
                        );
                    }
                }
            }
            PayloadEvent::CadencePacket { .. } => {}
        }
    }

    let candidate = if unknown_session_for_reset {
        if lock_candidate.is_some() || pending_negotiation.is_some() {
            return Err(
                crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                    RejectedPacket {
                        normalized_source,
                        actual_dst_id: event.icmp_meta().map(|icmp| icmp.inbound_header_ident()),
                        reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
                    },
                ),
            );
        }
        ClientAdmissionCandidate::reset(reset_candidate)
    } else {
        match (lock_candidate, pending_negotiation) {
            (Some(candidate), None) => ClientAdmissionCandidate::lock(candidate),
            (None, Some(candidate)) => ClientAdmissionCandidate::negotiation(candidate),
            (None, None) => ClientAdmissionCandidate::none(),
            (Some(_), Some(_)) => {
                return Err(
                    crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                        RejectedPacket {
                            normalized_source,
                            actual_dst_id: event
                                .icmp_meta()
                                .map(|icmp| icmp.inbound_header_ident()),
                            reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
                        },
                    ),
                );
            }
        }
    };
    Ok(AdmittedWirePacket {
        trace: None,
        normalized_source,
        event,
        candidate,
    })
}

#[inline]
fn pending_client_candidate_matches(
    pending: PendingIcmpClientLock,
    observed_source: Option<LogicalEndpoint>,
    observed_session: Option<SessionId>,
) -> bool {
    let ClientFlowKey::Icmp(expected_source) = pending.flow_key else {
        return false;
    };
    pending.session_id() == observed_session
        && observed_source.is_some_and(|source| expected_source.matches_filter(source))
}

#[inline]
fn decode_icmp_payload_event<'a>(
    admitted: &TransportPacket<'a>,
    dst_proto: SupportedProtocol,
) -> Result<PayloadEvent<'a>, RejectionReason> {
    let identity = admitted
        .icmp_identity()
        .ok_or(RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
        )))?;
    let Some(shim) = admitted.shim_flags else {
        return Err(RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
        )));
    };
    let session_id = admitted
        .session_id
        .ok_or(RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::ZeroSessionId,
        )))?;

    if (shim & SHIM_IS_CADENCE) != 0 {
        return Ok(PayloadEvent::cadence_packet_with_source(
            identity.remote_source_id(),
            identity.local_destination_id(),
            admitted.seq,
            session_id,
        ));
    }

    if (shim & SHIM_IS_DATA) != 0 {
        return Ok(PayloadEvent::icmp_user_payload(
            identity.remote_source_id(),
            identity.local_destination_id(),
            admitted.seq,
            session_id,
            dst_proto,
            admitted.payload,
        ));
    }

    let Some(control) = admitted.control else {
        return Err(RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::SessionControlReplyIdLength,
        )));
    };
    Ok(PayloadEvent::session_control_v3(
        identity.remote_source_id(),
        identity.local_destination_id(),
        admitted.seq,
        SupportedProtocol::ICMP,
        control,
    ))
}

#[inline]
fn allows_control_identity_learning(
    spec: ReceiveContext<'_>,
    parsed: &ParsedPacketHeaders,
    normalized_source: Option<LogicalEndpoint>,
    reply_id: Option<ReplyIdNegotiation>,
) -> bool {
    if spec.socket.proto != SupportedProtocol::ICMP {
        return false;
    }
    let Some(expected_local_id) = spec.expected_local_id() else {
        return false;
    };
    if parsed
        .icmp
        .is_some_and(|icmp| icmp.identity.destination_id == expected_local_id)
        && reply_id.is_some_and(ReplyIdNegotiation::is_ack)
    {
        return true;
    }

    if spec.socket.allow_debug_kernel_echo_self_handshake()
        && spec.socket.role == SocketLeg::UpstreamFacing
        && !spec.socket.can_honor_disjoint_icmp_ids()
    {
        let Some(local) = spec.local_filter() else {
            return false;
        };
        let src_ip = parsed
            .source_ip()
            .or_else(|| normalized_source.map(LogicalEndpoint::ip));
        let src_id = parsed.icmp.and_then(|icmp| icmp.identity.source_id);

        let local_ip = local.ip();
        let reflected_peer_ip = if local_ip.is_unspecified() {
            spec.expected_remote().map(LogicalEndpoint::ip)
        } else {
            Some(local_ip)
        };
        let source_matches_local = src_ip
            .zip(reflected_peer_ip)
            .is_some_and(|(source, expected)| source == expected)
            && src_id.is_some_and(|id| id == local.id());
        let connected_kernel_filtered_self = spec.socket.evidence_policy().peer_source
            == PeerSourceRequirement::ConnectedKernel
            && src_ip.is_none()
            && src_id.is_some_and(|id| id == local.id());

        if source_matches_local || connected_kernel_filtered_self {
            return reply_id.is_some_and(|reply_id| {
                reply_id.is_negotiate() && reply_id.reply_id() == expected_local_id
            });
        }
    }
    false
}

use super::transport_client_flow::{build_client_lock_candidate, event_advertised_reply_id};

#[inline]
fn icmp_remote_ip_matches(actual: LogicalEndpoint, expected: LogicalEndpoint) -> bool {
    expected.matches_ip_filter(actual)
}

#[inline]
fn parsed_transport_has_ip(parsed: &ParsedPacketHeaders) -> bool {
    matches!(
        parsed.network,
        ParsedNetworkLayer::Valid(_) | ParsedNetworkLayer::Unsupported { .. }
    )
}
