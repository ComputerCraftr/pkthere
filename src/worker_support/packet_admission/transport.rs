#[cfg(test)]
pub(crate) use super::rejection::record_rejection_stats;
pub(crate) use super::rejection::{RejectedPacket, RejectionReason};
use crate::cli::{IcmpReplyIdRequest, ListenMode, RuntimeConfig, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::PendingIcmpClientLock;
use crate::net::framing_shim::{ReplyIdNegotiation, parse_icmp_reply_negotiation};
#[cfg(test)]
use crate::net::packet_headers::parse_packet_headers;
use crate::net::packet_headers::{ParsedPacketHeaders, ReceiveParserKernel, SHIM_IS_DATA};
use crate::net::payload::{PayloadEvent, TunnelFlowIdentity};
use crate::net::sock_mgr::SocketHandles;
#[cfg(test)]
pub(crate) use pkthere_socket_policy::ProtocolIdRequirement;
use pkthere_socket_policy::ResolvedSocketPolicy;
pub(crate) use pkthere_socket_policy::{PeerSourceRequirement, ReceiveEvidencePolicy};
use socket2::{SockAddr, Type};
use std::net::SocketAddr;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketLeg {
    ClientFacing,
    UpstreamFacing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveNoiseReason {
    UnexpectedEchoDirection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveSocketContext {
    pub(crate) role: SocketLeg,
    pub(crate) proto: SupportedProtocol,
    pub(crate) sock_type: Type,
    pub(crate) parser: ReceiveParserKernel,
    pub(crate) policy: ResolvedSocketPolicy,
    pub(crate) connected: bool,
    pub(crate) local_filter: LogicalEndpoint,
    pub(crate) local_kernel_addr: SocketAddr,
    pub(crate) evidence_key: pkthere_socket_policy::SocketEvidenceKey,
}
impl ReceiveSocketContext {
    pub(crate) fn evidence_policy(self) -> ReceiveEvidencePolicy {
        self.policy.evidence_policy(self.connected)
    }

    pub(crate) const fn socket_is_ipv4(self) -> bool {
        matches!(
            self.parser.version(),
            crate::net::packet_headers::IpVersion::V4
        )
    }

    #[inline]
    pub(crate) fn can_honor_disjoint_icmp_ids(self) -> bool {
        self.policy
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    }

    #[inline]
    pub(crate) fn allow_debug_kernel_echo_self_handshake(self) -> bool {
        self.policy
            .icmp
            .is_some_and(|policy| policy.allow_debug_kernel_echo_self_handshake)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionStateContext {
    pub(crate) expected_inbound: Option<FlowTuple>,
    pub(crate) expected_local: Option<LogicalEndpoint>,
    pub(crate) locked_flow: Option<ClientFlowKey>,
    pub(crate) pending_icmp_client_lock: Option<PendingIcmpClientLock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveContext {
    pub(crate) socket: ReceiveSocketContext,
    pub(crate) admission: AdmissionStateContext,
}

impl ReceiveContext {
    #[inline]
    pub(crate) const fn local_filter(self) -> Option<LogicalEndpoint> {
        Some(self.socket.local_filter)
    }

    #[inline]
    pub(crate) fn expected_remote(self) -> Option<LogicalEndpoint> {
        self.admission.expected_inbound.map(|flow| flow.src)
    }

    #[inline]
    pub(crate) const fn expected_local_id(self) -> Option<u16> {
        match self.admission.expected_inbound {
            Some(flow) => Some(flow.dst.id()),
            None => match self.admission.expected_local {
                Some(endpoint) => Some(endpoint.id()),
                None => None,
            },
        }
    }
}

#[inline]
pub(crate) fn upstream_receive_context(
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
) -> ReceiveContext {
    debug_assert_eq!(handles.upstream.parser.protocol(), cfg.upstream_proto);
    debug_assert_eq!(
        handles.upstream.parser.mode(),
        handles.upstream.policy.receive_header
    );
    ReceiveContext {
        socket: ReceiveSocketContext {
            role: SocketLeg::UpstreamFacing,
            proto: cfg.upstream_proto,
            sock_type: handles.upstream.sock_type,
            parser: handles.upstream.parser,
            policy: handles.upstream.policy,
            connected: handles.upstream_connected(),
            local_filter: handles.upstream.upstream_local_filter,
            local_kernel_addr: handles.upstream.upstream_local_kernel_addr,
            evidence_key: handles.upstream.evidence_key,
        },
        admission: AdmissionStateContext {
            expected_inbound: handles.upstream.upstream_flow.inbound,
            expected_local: handles.upstream.upstream_flow.inbound.map(|flow| flow.dst),
            locked_flow: handles.listener.flow,
            pending_icmp_client_lock: None,
        },
    }
}

#[inline]
pub(crate) fn client_receive_context(
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
    expected_inbound: Option<FlowTuple>,
    pending_icmp_client_lock: Option<PendingIcmpClientLock>,
) -> ReceiveContext {
    let expected_local = if cfg.listen_proto == SupportedProtocol::ICMP {
        match (cfg.listen_mode, expected_inbound) {
            (ListenMode::Fixed, _) => Some(
                handles
                    .listener
                    .listen_local_filter
                    .with_id(cfg.listen.id()),
            ),
            (ListenMode::Dynamic, Some(flow)) => Some(flow.dst),
            (ListenMode::Dynamic, None) => None,
        }
    } else {
        None
    };

    debug_assert_eq!(handles.listener.parser.protocol(), cfg.listen_proto);
    debug_assert_eq!(
        handles.listener.parser.mode(),
        handles.listener.policy.receive_header
    );
    ReceiveContext {
        socket: ReceiveSocketContext {
            role: SocketLeg::ClientFacing,
            proto: cfg.listen_proto,
            sock_type: handles.listener.sock_type,
            parser: handles.listener.parser,
            policy: handles.listener.policy,
            connected: handles.listener_connected(),
            local_filter: handles.listener.listen_local_filter,
            local_kernel_addr: handles.listener.listen_local_kernel_addr,
            evidence_key: handles.listener.evidence_key,
        },
        admission: AdmissionStateContext {
            expected_inbound,
            expected_local,
            locked_flow: handles.listener.flow,
            pending_icmp_client_lock,
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmittedWirePacket<'a> {
    pub(crate) trace: Option<crate::packet_trace::PacketTraceId>,
    pub(crate) normalized_source: Option<LogicalEndpoint>,
    pub(crate) event: PayloadEvent<'a>,
    pub(crate) lock_candidate: Option<PendingIcmpClientLock>,
    pub(crate) pending_negotiation: Option<PendingIcmpClientLock>,
}

#[derive(Debug, PartialEq, Eq)]
// Boxing the accepted variant would allocate on every admitted packet.
#[allow(clippy::large_enum_variant)]
pub(crate) enum WirePacketAdmission<'a> {
    Accepted(AdmittedWirePacket<'a>),
    Filtered(RejectedPacket),
    ReceiveNoise(ReceiveNoiseReason),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TransportPacket<'a> {
    pub(crate) normalized_source: Option<LogicalEndpoint>,
    pub(crate) flow_identity: TunnelFlowIdentity,
    pub(crate) seq: u16,
    pub(crate) payload: &'a [u8],
    pub(crate) shim_flags: Option<u8>,
    pub(crate) reply_id_negotiation: Option<ReplyIdNegotiation>,
    pub(crate) is_handshake_or_debug: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TransportAdmission<'a> {
    Accepted(TransportPacket<'a>),
    Filtered(RejectedPacket),
    ReceiveNoise(ReceiveNoiseReason),
}

#[inline]
#[cfg(test)]
pub(crate) fn admit_packet<'a>(
    spec: ReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> TransportAdmission<'a> {
    let parsed = parse_packet_headers(payload);
    admit_packet_with_parsed(spec, payload, socket_source, &parsed)
}

#[inline]
pub(crate) fn admit_packet_with_parsed<'a>(
    spec: ReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
    parsed: &ParsedPacketHeaders,
) -> TransportAdmission<'a> {
    let (logical_src_id, logical_dst_id) = match spec.socket.proto {
        SupportedProtocol::UDP => {
            if spec.socket.sock_type == Type::DGRAM {
                let src_port = socket_source
                    .and_then(|s| s.as_socket())
                    .map_or(0, |s| s.port());
                let Some(dst_port) = spec.local_filter().map(LogicalEndpoint::id) else {
                    return TransportAdmission::Filtered(RejectedPacket {
                        normalized_source: None,
                        actual_dst_id: None,
                        reason: RejectionReason::UnexpectedLocalReceiveId,
                    });
                };
                (src_port, dst_port)
            } else {
                let Some(udp) = parsed.udp else {
                    return TransportAdmission::Filtered(RejectedPacket {
                        normalized_source: socket_source.and_then(LogicalEndpoint::from_sock_addr),
                        actual_dst_id: None,
                        reason: RejectionReason::MalformedIcmpHeader(None),
                    });
                };
                (udp.src_port, udp.dst_port)
            }
        }
        SupportedProtocol::ICMP => {
            let Some(icmp) = parsed.icmp else {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source: socket_source.and_then(LogicalEndpoint::from_sock_addr),
                    actual_dst_id: None,
                    reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason),
                });
            };
            let destination_id = icmp.identity.destination_id;
            let source_id = icmp
                .identity
                .source_id
                .or_else(|| spec.expected_remote().map(|remote| remote.id()))
                .or_else(|| {
                    socket_source
                        .and_then(SockAddr::as_socket)
                        .map(|addr| addr.port())
                        .filter(|id| *id != 0)
                })
                .unwrap_or(destination_id);
            (source_id, destination_id)
        }
    };

    let normalized_source = if spec.socket.proto == SupportedProtocol::UDP {
        match spec.socket.evidence_policy().peer_source {
            PeerSourceRequirement::RawPacketHeader => {
                match parse_raw_ip_source(
                    parsed,
                    socket_source,
                    spec.socket.socket_is_ipv4(),
                    logical_src_id,
                ) {
                    Some(src) => Some(src),
                    None => {
                        return TransportAdmission::Filtered(RejectedPacket {
                            normalized_source: None,
                            actual_dst_id: Some(logical_dst_id),
                            reason: RejectionReason::MissingSourceEvidence,
                        });
                    }
                }
            }
            PeerSourceRequirement::SourceMetadata | PeerSourceRequirement::ConnectedKernel => {
                match socket_source
                    .and_then(|s| LogicalEndpoint::from_sock_addr_with_id(s, logical_src_id))
                {
                    Some(src) => Some(src),
                    None if spec.socket.evidence_policy().peer_source
                        == PeerSourceRequirement::ConnectedKernel =>
                    {
                        None
                    }
                    None => {
                        return TransportAdmission::Filtered(RejectedPacket {
                            normalized_source: None,
                            actual_dst_id: Some(logical_dst_id),
                            reason: RejectionReason::MissingSourceEvidence,
                        });
                    }
                }
            }
        }
    } else {
        None
    };

    if spec.socket.proto == SupportedProtocol::UDP {
        if parsed_transport_has_ip(parsed)
            && parsed
                .src_ip
                .is_some_and(|src| normalized_source.is_some_and(|auth| src != auth.ip()))
        {
            return TransportAdmission::Filtered(RejectedPacket {
                normalized_source,
                actual_dst_id: Some(logical_dst_id),
                reason: RejectionReason::UnexpectedRemotePeer,
            });
        }
        if let (Some(expected), Some(src)) = (spec.expected_remote(), normalized_source)
            && !expected.matches_filter(src)
        {
            return TransportAdmission::Filtered(RejectedPacket {
                normalized_source: Some(src),
                actual_dst_id: Some(logical_dst_id),
                reason: RejectionReason::UnexpectedRemotePeer,
            });
        }
    }

    match spec.socket.proto {
        SupportedProtocol::UDP => {
            let (p_start, p_end) = if spec.socket.sock_type == Type::DGRAM {
                (0, payload.len())
            } else {
                parsed.payload_bounds
            };
            if p_start > p_end || p_end > payload.len() {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::InvalidPayloadBounds,
                });
            }
            TransportAdmission::Accepted(TransportPacket {
                normalized_source,
                flow_identity: TunnelFlowIdentity {
                    remote_source_id: logical_src_id,
                    local_destination_id: logical_dst_id,
                },
                seq: 0,
                payload: &payload[p_start..p_end],
                shim_flags: None,
                reply_id_negotiation: None,
                is_handshake_or_debug: false,
            })
        }
        SupportedProtocol::ICMP => {
            let Some(icmp) = parsed.icmp else {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::MalformedIcmpHeader(parsed.icmp_malformed_reason),
                });
            };
            if icmp.is_req != (spec.socket.role == SocketLeg::ClientFacing) {
                return TransportAdmission::ReceiveNoise(
                    ReceiveNoiseReason::UnexpectedEchoDirection,
                );
            }
            let (start, end) = parsed.payload_bounds;
            if start > end || end > payload.len() {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::InvalidPayloadBounds,
                });
            }
            let transport_payload = &payload[start..end];
            let reply_id_negotiation = match parse_icmp_reply_negotiation_for_admission(
                icmp.shim_flags,
                transport_payload,
            ) {
                Ok(reply_id) => reply_id,
                Err(reason) => {
                    return TransportAdmission::Filtered(RejectedPacket {
                        normalized_source,
                        actual_dst_id: Some(logical_dst_id),
                        reason,
                    });
                }
            };

            let normalized_source = match spec.socket.evidence_policy().peer_source {
                PeerSourceRequirement::RawPacketHeader => {
                    match parse_raw_ip_source(
                        parsed,
                        socket_source,
                        spec.socket.socket_is_ipv4(),
                        logical_src_id,
                    ) {
                        Some(src) => Some(src),
                        None => {
                            return TransportAdmission::Filtered(RejectedPacket {
                                normalized_source: None,
                                actual_dst_id: Some(logical_dst_id),
                                reason: RejectionReason::MissingSourceEvidence,
                            });
                        }
                    }
                }
                PeerSourceRequirement::SourceMetadata | PeerSourceRequirement::ConnectedKernel => {
                    match socket_source
                        .and_then(|s| LogicalEndpoint::from_sock_addr_with_id(s, logical_src_id))
                    {
                        Some(src) => Some(src),
                        None if spec.socket.evidence_policy().peer_source
                            == PeerSourceRequirement::ConnectedKernel =>
                        {
                            spec.expected_remote().map(|expected| {
                                let source_id =
                                    if icmp.shim_flags.is_none() && transport_payload.is_empty() {
                                        expected.id()
                                    } else {
                                        logical_src_id
                                    };
                                expected.with_id(source_id)
                            })
                        }
                        None => {
                            return TransportAdmission::Filtered(RejectedPacket {
                                normalized_source: None,
                                actual_dst_id: Some(logical_dst_id),
                                reason: RejectionReason::MissingSourceEvidence,
                            });
                        }
                    }
                }
            };

            let is_handshake_or_debug =
                is_valid_handshake_or_debug(spec, parsed, normalized_source, reply_id_negotiation);
            let connected_reflected_negotiation = spec.socket.role == SocketLeg::UpstreamFacing
                && spec.socket.evidence_policy().peer_source
                    == PeerSourceRequirement::ConnectedKernel
                && socket_source.is_none()
                && spec.local_filter().is_some_and(|local| {
                    spec.expected_remote()
                        .is_some_and(|remote| remote.ip() == local.ip())
                });
            if connected_reflected_negotiation
                && reply_id_negotiation.is_some_and(|reply_id| {
                    reply_id.negotiate && !reply_id.ack && !is_handshake_or_debug
                })
            {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
                });
            }

            if let Some(expected) = spec.expected_local_id()
                && logical_dst_id != expected
                && !is_handshake_or_debug
            {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::UnexpectedLocalReceiveId,
                });
            }

            if spec.socket.evidence_policy().peer_source == PeerSourceRequirement::RawPacketHeader
                && spec.local_filter().is_some_and(|local| {
                    !raw_packet_destination_matches(parsed, local, spec.socket.socket_is_ipv4())
                })
            {
                return TransportAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(logical_dst_id),
                    reason: RejectionReason::UnexpectedLocalReceiveAddress,
                });
            }

            if let (Some(expected), Some(src)) = (spec.expected_remote(), normalized_source) {
                let matches_ip = icmp_remote_ip_matches(src, expected);
                let matches_id = src.id() == expected.id();

                if !matches_ip || (!matches_id && !is_handshake_or_debug) {
                    let reason = if matches_ip
                        && spec
                            .expected_local_id()
                            .is_some_and(|id| logical_dst_id == id)
                    {
                        RejectionReason::IcmpSourceEndpointMismatch
                    } else {
                        RejectionReason::UnexpectedRemotePeer
                    };
                    return TransportAdmission::Filtered(RejectedPacket {
                        normalized_source: Some(src),
                        actual_dst_id: Some(logical_dst_id),
                        reason,
                    });
                }
            }

            TransportAdmission::Accepted(TransportPacket {
                normalized_source,
                flow_identity: TunnelFlowIdentity {
                    remote_source_id: logical_src_id,
                    local_destination_id: logical_dst_id,
                },
                seq: icmp.seq,
                payload: transport_payload,
                shim_flags: icmp.shim_flags,
                reply_id_negotiation,
                is_handshake_or_debug,
            })
        }
    }
}

#[inline]
#[cfg(test)]
pub(crate) fn admit_wire_packet<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: ReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> WirePacketAdmission<'a> {
    let parsed = parse_packet_headers(payload);
    admit_wire_packet_with_parsed(c2u, cfg, spec, payload, socket_source, &parsed)
}

#[inline]
pub(crate) fn admit_wire_packet_with_parsed<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: ReceiveContext,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
    parsed: &ParsedPacketHeaders,
) -> WirePacketAdmission<'a> {
    let dst_proto = if c2u {
        cfg.upstream_proto
    } else {
        cfg.listen_proto
    };

    let admitted = match admit_packet_with_parsed(spec, payload, socket_source, parsed) {
        TransportAdmission::Accepted(admitted) => admitted,
        TransportAdmission::Filtered(rejected) => {
            return WirePacketAdmission::Filtered(rejected);
        }
        TransportAdmission::ReceiveNoise(reason) => {
            return WirePacketAdmission::ReceiveNoise(reason);
        }
    };
    let normalized_source = admitted.normalized_source;

    let event = match spec.socket.proto {
        SupportedProtocol::UDP => PayloadEvent::user_payload_plain(dst_proto, admitted.payload),
        SupportedProtocol::ICMP => match decode_icmp_payload_event(
            admitted.flow_identity.remote_source_id,
            admitted.flow_identity.local_destination_id,
            admitted.seq,
            admitted.payload,
            admitted.shim_flags,
            admitted.reply_id_negotiation,
            dst_proto,
        ) {
            Ok(ev) => ev,
            Err(reason) => {
                return WirePacketAdmission::Filtered(RejectedPacket {
                    normalized_source,
                    actual_dst_id: Some(admitted.flow_identity.local_destination_id),
                    reason,
                });
            }
        },
    };

    if event.payload_len() > cfg.max_payload {
        return WirePacketAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(admitted.flow_identity.local_destination_id),
            reason: RejectionReason::PayloadOversize,
        });
    }

    if event_advertised_reply_id(&event)
        .is_some_and(|reply_id| reply_id != admitted.flow_identity.local_destination_id)
        && !spec.socket.can_honor_disjoint_icmp_ids()
        && !admitted.is_handshake_or_debug
    {
        return WirePacketAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(admitted.flow_identity.local_destination_id),
            reason: RejectionReason::UnsupportedDisjointReplyId,
        });
    }

    let is_locked = spec.admission.locked_flow.is_some();

    if is_locked
        && spec.socket.proto == SupportedProtocol::ICMP
        && event_negotiates_reply_id(&event)
        && !admitted.is_handshake_or_debug
    {
        return WirePacketAdmission::Filtered(RejectedPacket {
            normalized_source,
            actual_dst_id: Some(admitted.flow_identity.local_destination_id),
            reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
        });
    }

    let mut lock_candidate = None;
    let mut pending_negotiation = None;
    if c2u && spec.socket.role == SocketLeg::ClientFacing && !is_locked {
        match &event {
            PayloadEvent::UserPayload { .. } => {
                lock_candidate = if event_negotiates_reply_id(&event)
                    || spec.socket.proto != SupportedProtocol::ICMP
                {
                    normalized_source.and_then(|src| {
                        build_client_lock_candidate(
                            src,
                            spec.local_filter()?,
                            cfg.listener_source_id_request,
                            cfg.listen_proto,
                            &event,
                        )
                    })
                } else if let Some(pending) = spec.admission.pending_icmp_client_lock {
                    if normalized_source
                        .is_some_and(|src| pending_matches_user_event(pending, src, &event))
                    {
                        Some(pending)
                    } else {
                        return WirePacketAdmission::Filtered(RejectedPacket {
                            normalized_source,
                            actual_dst_id: Some(admitted.flow_identity.local_destination_id),
                            reason: RejectionReason::IcmpReplyIdRenegotiationMismatch,
                        });
                    }
                } else {
                    None
                };

                if lock_candidate.is_none() && spec.socket.proto == SupportedProtocol::ICMP {
                    return WirePacketAdmission::Filtered(RejectedPacket {
                        normalized_source,
                        actual_dst_id: Some(admitted.flow_identity.local_destination_id),
                        reason: RejectionReason::IcmpReplyIdNegotiationRequired,
                    });
                }
            }
            PayloadEvent::SessionControl { .. } => {
                pending_negotiation = normalized_source.and_then(|src| {
                    build_client_lock_candidate(
                        src,
                        spec.local_filter()?,
                        cfg.listener_source_id_request,
                        cfg.listen_proto,
                        &event,
                    )
                });
            }
            PayloadEvent::CadencePacket { .. } => {}
        }
    }

    WirePacketAdmission::Accepted(AdmittedWirePacket {
        trace: None,
        normalized_source,
        event,
        lock_candidate,
        pending_negotiation,
    })
}

#[inline]
fn decode_icmp_payload_event<'a>(
    logical_src_id: u16,
    logical_dst_id: u16,
    seq: u16,
    payload: &'a [u8],
    shim_flags: Option<u8>,
    reply_id_negotiation: Option<ReplyIdNegotiation>,
    dst_proto: SupportedProtocol,
) -> Result<PayloadEvent<'a>, RejectionReason> {
    let Some(shim) = shim_flags else {
        return if payload.is_empty() {
            Ok(PayloadEvent::cadence_packet(logical_dst_id, seq))
        } else {
            Err(RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
            )))
        };
    };

    if (shim & SHIM_IS_DATA) != 0 {
        return Ok(PayloadEvent::icmp_user_payload(
            logical_src_id,
            logical_dst_id,
            seq,
            dst_proto,
            payload,
        ));
    }

    let Some(reply_id) = reply_id_negotiation else {
        return Err(RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::SessionControlReplyIdLength,
        )));
    };
    Ok(PayloadEvent::session_control_negotiation(
        logical_src_id,
        logical_dst_id,
        seq,
        SupportedProtocol::ICMP,
        reply_id,
    ))
}

#[inline]
fn is_valid_handshake_or_debug(
    spec: ReceiveContext,
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
        && reply_id.is_some_and(|reply_id| reply_id.ack)
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
            .src_ip
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
                reply_id.negotiate && !reply_id.ack && reply_id.reply_id == expected_local_id
            });
        }
    }
    false
}

#[inline]
fn parse_icmp_reply_negotiation_for_admission(
    shim_flags: Option<u8>,
    payload: &[u8],
) -> Result<Option<ReplyIdNegotiation>, RejectionReason> {
    let Some(shim) = shim_flags else {
        return if payload.is_empty() {
            Ok(None)
        } else {
            Err(RejectionReason::MalformedIcmpHeader(Some(
                crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags,
            )))
        };
    };
    parse_icmp_reply_negotiation(shim, payload)
        .map_err(|reason| RejectionReason::MalformedIcmpHeader(Some(reason)))
}

#[inline]
fn event_negotiates_reply_id(event: &PayloadEvent<'_>) -> bool {
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        }
        | PayloadEvent::SessionControl { icmp, .. } => icmp.negotiates_reply_id(),
        _ => false,
    }
}

#[inline]
fn event_advertised_reply_id(event: &PayloadEvent<'_>) -> Option<u16> {
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        }
        | PayloadEvent::SessionControl { icmp, .. } => icmp.advertised_reply_id(),
        _ => None,
    }
}

#[inline]
fn pending_matches_user_event(
    pending: PendingIcmpClientLock,
    src: LogicalEndpoint,
    event: &PayloadEvent<'_>,
) -> bool {
    let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = event
    else {
        return false;
    };
    if pending.flow_key
        != ClientFlowKey::from_icmp_reply_id(src, icmp.flow_identity().remote_source_id)
    {
        return false;
    }
    pending.listener_flow.inbound.is_some_and(|flow| {
        icmp_remote_ip_matches(src, flow.src)
            && flow.src.id() == icmp.flow_identity().remote_source_id
            && flow.dst.id() == icmp.inbound_header_ident()
    })
}

#[inline]
fn build_client_lock_candidate(
    src: LogicalEndpoint,
    listen_local_recv: LogicalEndpoint,
    listener_source_id_request: IcmpReplyIdRequest,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<PendingIcmpClientLock> {
    let flow_key = client_flow_key_from_event(src, listen_proto, event)?;
    let remote = match listen_proto {
        SupportedProtocol::UDP => src,
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            }
            | PayloadEvent::SessionControl { icmp, .. } => {
                src.with_id(icmp.flow_identity().remote_source_id)
            }
            _ => return None,
        },
    };
    let inbound_local = match listen_proto {
        SupportedProtocol::UDP => listen_local_recv,
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            }
            | PayloadEvent::SessionControl { icmp, .. } => {
                listen_local_recv.with_id(icmp.inbound_header_ident())
            }
            _ => return None,
        },
    };
    let outbound_local = match listen_proto {
        SupportedProtocol::UDP => listen_local_recv,
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            }
            | PayloadEvent::SessionControl { icmp, .. } => listen_local_recv.with_id(
                match listener_source_id_request.resolved_reply_id(icmp.inbound_header_ident()) {
                    Some(id) => id,
                    None => icmp.inbound_header_ident(),
                },
            ),
            _ => return None,
        },
    };
    Some(PendingIcmpClientLock {
        flow_key,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(
                outbound_local,
                outbound_remote_for_event(remote, listen_proto, event),
            )),
        ),
    })
}

#[inline]
fn outbound_remote_for_event(
    remote: LogicalEndpoint,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> LogicalEndpoint {
    if listen_proto != SupportedProtocol::ICMP {
        return remote;
    }
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        }
        | PayloadEvent::SessionControl { icmp, .. } => {
            let reply_id = match icmp.reply_id_negotiation() {
                Some(negotiation) => negotiation.reply_id,
                None => icmp.flow_identity().remote_source_id,
            };
            remote.with_id(reply_id)
        }
        _ => remote,
    }
}

#[inline]
fn client_flow_key_from_event(
    src: LogicalEndpoint,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<ClientFlowKey> {
    match listen_proto {
        SupportedProtocol::UDP => Some(ClientFlowKey::Udp(src)),
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            }
            | PayloadEvent::SessionControl { icmp, .. } => Some(ClientFlowKey::from_icmp_reply_id(
                src,
                icmp.flow_identity().remote_source_id,
            )),
            _ => None,
        },
    }
}

#[cfg(test)]
#[path = "tests/general.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/debug.rs"]
mod debug_tests;

#[cfg(test)]
#[path = "tests/shim.rs"]
mod shim_tests;

#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod test_support;

use super::raw_ip::{
    icmp_remote_ip_matches, parse_raw_ip_source, parsed_transport_has_ip,
    raw_packet_destination_matches,
};
