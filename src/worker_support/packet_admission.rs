use crate::cli::{IcmpReplyIdRequest, ListenMode, RuntimeConfig, SupportedProtocol};
use crate::flow_key::{ClientFlowKey, FlowEndpoint, FlowTuple, SocketLegFlow};
use crate::net::packet_headers::{ParsedPacketHeaders, ParsedTransport, parse_packet_headers};
use crate::net::params::CanonicalAddr;
use crate::net::payload::{IcmpAdmissionInfo, PayloadEvent, PayloadOrigin, validate_payload};
use crate::net::sock_mgr::SocketHandles;
use crate::stats::StatsSink;
use socket2::{SockAddr, Type};

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

struct AdmissionStats;

impl StatsSink for AdmissionStats {
    fn send_add(&self, _c2u: bool, _bytes: u64, _start: Instant, _end: Instant) {}
    fn drop_err(&self, _c2u: bool) {}
    fn drop_oversize(&self, _c2u: bool) {}
}

static ADMISSION_STATS: AdmissionStats = AdmissionStats;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketPeerRole {
    Client,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceEvidenceMode {
    ConnectedKernelFiltered,
    SocketSourceRequired,
    RawPacketSourceRequired,
}

#[inline]
pub(crate) fn source_evidence_mode(
    proto: SupportedProtocol,
    sock_type: Type,
    connected: bool,
) -> SourceEvidenceMode {
    if proto == SupportedProtocol::ICMP && sock_type == Type::RAW {
        SourceEvidenceMode::RawPacketSourceRequired
    } else if connected {
        SourceEvidenceMode::ConnectedKernelFiltered
    } else {
        SourceEvidenceMode::SocketSourceRequired
    }
}

#[inline]
pub(crate) fn log_rejected_packet(
    worker_id: usize,
    c2u: bool,
    cfg: &RuntimeConfig,
    role: SocketPeerRole,
    rejected: RejectedPacket,
    spec: PacketAdmissionSpec,
) {
    let expected_remote = spec.expected_remote();
    let expected_local_id = spec.expected_local_icmp_id();
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
        RejectionReason::IcmpDirectionMismatch => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} with wrong Echo direction",
            actual_source
        ),
        RejectionReason::IcmpReplyIdNegotiationRequired => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} because reply-ID negotiation is required",
            actual_source
        ),
        RejectionReason::IcmpReplyIdRenegotiationMismatch => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} due to reply-ID renegotiation mismatch",
            actual_source
        ),
        RejectionReason::UnsupportedDisjointReplyId => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} due to unsupported disjoint reply-ID negotiation",
            actual_source
        ),
        RejectionReason::PayloadOversize => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping oversized packet from {role_name} peer {}",
            actual_source
        ),
        RejectionReason::MissingSourceEvidence => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping packet from {role_name} peer because source evidence is missing (expected remote {:?}, local_id {:?})",
            expected_remote,
            expected_local_id
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketAdmissionSpec {
    pub(crate) role: SocketPeerRole,
    pub(crate) proto: SupportedProtocol,
    pub(crate) sock_type: Type,
    pub(crate) source_evidence: SourceEvidenceMode,
    pub(crate) expected_inbound: Option<FlowTuple>,
    pub(crate) expected_local: Option<FlowEndpoint>,
    pub(crate) local_filter: Option<CanonicalAddr>,
    pub(crate) locked_flow: Option<ClientFlowKey>,
}

impl PacketAdmissionSpec {
    #[inline]
    pub(crate) fn expected_remote(self) -> Option<CanonicalAddr> {
        self.expected_inbound.map(|flow| flow.src.canonical())
    }

    #[inline]
    pub(crate) const fn expected_local_icmp_id(self) -> Option<u16> {
        match self.expected_inbound {
            Some(flow) => Some(flow.dst.id),
            None => match self.expected_local {
                Some(endpoint) => Some(endpoint.id),
                None => None,
            },
        }
    }
}

#[inline]
pub(crate) fn upstream_admission_spec(
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
) -> PacketAdmissionSpec {
    PacketAdmissionSpec {
        role: SocketPeerRole::Upstream,
        proto: cfg.upstream_proto,
        sock_type: handles.upstream_sock_type,
        source_evidence: source_evidence_mode(
            cfg.upstream_proto,
            handles.upstream_sock_type,
            handles.upstream_connected,
        ),
        expected_inbound: handles.upstream_flow.inbound,
        expected_local: handles.upstream_flow.inbound.map(|flow| flow.dst),
        local_filter: Some(handles.upstream_local_filter),
        locked_flow: handles.locked_flow,
    }
}

#[inline]
pub(crate) fn client_admission_spec(
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
    expected_inbound: Option<FlowTuple>,
) -> PacketAdmissionSpec {
    let expected_local = if cfg.listen_proto == SupportedProtocol::ICMP {
        match (cfg.listen_mode, expected_inbound) {
            (ListenMode::Fixed, _) => Some(
                FlowEndpoint::from_canonical(handles.listen_local_filter).with_id(cfg.listen.id),
            ),
            (ListenMode::Dynamic, Some(flow)) => Some(flow.dst),
            (ListenMode::Dynamic, None) => None,
        }
    } else {
        None
    };
    PacketAdmissionSpec {
        role: SocketPeerRole::Client,
        proto: cfg.listen_proto,
        sock_type: handles.listen_sock_type,
        source_evidence: source_evidence_mode(
            cfg.listen_proto,
            handles.listen_sock_type,
            handles.listener_connected,
        ),
        expected_inbound,
        expected_local,
        local_filter: Some(handles.listen_local_filter),
        locked_flow: handles.locked_flow,
    }
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
    MissingSourceEvidence,
    IcmpDirectionMismatch,
    IcmpReplyIdNegotiationRequired,
    IcmpReplyIdRenegotiationMismatch,
    UnsupportedDisjointReplyId,
    PayloadOversize,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientLockCandidate {
    pub(crate) flow_key: ClientFlowKey,
    pub(crate) listener_flow: SocketLegFlow,
}

#[derive(Debug)]
pub(crate) struct WireAdmittedPacket<'a> {
    pub(crate) normalized_source: Option<CanonicalAddr>,
    pub(crate) event: PayloadEvent<'a>,
    pub(crate) lock_candidate: Option<ClientLockCandidate>,
}

#[derive(Debug)]
pub(crate) enum WirePacketAdmission<'a> {
    Accepted(WireAdmittedPacket<'a>),
    Filtered(RejectedPacket),
    UnsupportedSource,
}

#[inline]
pub(crate) fn admit_wire_packet<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    spec: PacketAdmissionSpec,
    payload: &'a [u8],
    socket_source: Option<&SockAddr>,
) -> WirePacketAdmission<'a> {
    let admitted = match admit_packet(spec, payload, socket_source) {
        PacketAdmission::Accepted(admitted) => admitted,
        PacketAdmission::Filtered(rejected) => return WirePacketAdmission::Filtered(rejected),
        PacketAdmission::UnsupportedSource => return WirePacketAdmission::UnsupportedSource,
    };
    let is_locked = spec.locked_flow.is_some();
    let event = match validate_payload(
        c2u,
        cfg,
        &ADMISSION_STATS,
        payload,
        admitted.icmp_info,
        admitted.payload_bounds,
        None,
        spec.locked_flow.and_then(|flow| flow.icmp_ident()),
        PayloadOrigin::Wire,
        is_locked,
    ) {
        Ok(event) => event,
        Err(e) => {
            return WirePacketAdmission::Filtered(RejectedPacket {
                normalized_source: admitted.normalized_source,
                reason: rejection_from_payload_error(&e.to_string()),
            });
        }
    };
    if let Some(advertised_reply_id) = event_advertised_reply_id(&event)
        && spec.proto == SupportedProtocol::ICMP
        && spec.sock_type != Type::RAW
        && spec
            .local_filter
            .is_some_and(|local| local.id != advertised_reply_id)
    {
        return WirePacketAdmission::Filtered(RejectedPacket {
            normalized_source: admitted.normalized_source,
            reason: RejectionReason::UnsupportedDisjointReplyId,
        });
    }
    let lock_candidate = if c2u && spec.role == SocketPeerRole::Client && !is_locked {
        admitted.normalized_source.and_then(|src| {
            build_client_lock_candidate(
                src,
                spec.local_filter?,
                cfg.listener_reply_id_request,
                cfg.listen_proto,
                &event,
            )
        })
    } else {
        None
    };
    WirePacketAdmission::Accepted(WireAdmittedPacket {
        normalized_source: admitted.normalized_source,
        event,
        lock_candidate,
    })
}

#[inline]
fn event_advertised_reply_id(event: &PayloadEvent<'_>) -> Option<u16> {
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => icmp.advertised_reply_id,
        _ => None,
    }
}

#[inline]
pub(crate) fn admit_packet(
    spec: PacketAdmissionSpec,
    payload: &[u8],
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    let parsed = parse_packet_headers(payload);
    match spec.proto {
        SupportedProtocol::UDP => admit_udp_packet(spec, payload, &parsed, socket_source),
        SupportedProtocol::ICMP => admit_icmp_packet(spec, &parsed, socket_source),
    }
}

#[inline]
pub(crate) fn record_rejection_stats(stats: &dyn StatsSink, c2u: bool, rejected: RejectedPacket) {
    match rejected.reason {
        RejectionReason::PayloadOversize => stats.drop_oversize(c2u),
        RejectionReason::UnexpectedRemotePeer | RejectionReason::MissingSourceEvidence => {}
        _ => stats.drop_err(c2u),
    }
}

#[inline]
fn rejection_from_payload_error(msg: &str) -> RejectionReason {
    if msg.contains("payload length") && msg.contains("exceeds max") {
        RejectionReason::PayloadOversize
    } else if msg.contains("Echo direction mismatch") {
        RejectionReason::IcmpDirectionMismatch
    } else if msg.contains("requires reply-ID negotiation") {
        RejectionReason::IcmpReplyIdNegotiationRequired
    } else if msg.contains("reply-ID renegotiation mismatch") {
        RejectionReason::IcmpReplyIdRenegotiationMismatch
    } else if msg.contains("unsupported disjoint reply-ID") {
        RejectionReason::UnsupportedDisjointReplyId
    } else {
        RejectionReason::MalformedIcmpHeader
    }
}

#[inline]
fn build_client_lock_candidate(
    src: CanonicalAddr,
    listen_local_recv: CanonicalAddr,
    listener_reply_id_request: IcmpReplyIdRequest,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<ClientLockCandidate> {
    let flow_key = client_flow_key_from_event(src, listen_proto, event)?;
    let remote = match listen_proto {
        SupportedProtocol::UDP => FlowEndpoint::from_canonical(src),
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => FlowEndpoint::from_canonical(src).with_id(icmp.negotiated_remote_reply_id),
            _ => return None,
        },
    };
    let inbound_local = match listen_proto {
        SupportedProtocol::UDP => FlowEndpoint::from_canonical(listen_local_recv),
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => FlowEndpoint::from_canonical(listen_local_recv).with_id(icmp.inbound_header_ident),
            _ => return None,
        },
    };
    let outbound_local = match listen_proto {
        SupportedProtocol::UDP => FlowEndpoint::from_canonical(listen_local_recv),
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => FlowEndpoint::from_canonical(listen_local_recv).with_id(
                listener_reply_id_request
                    .resolved_reply_id(icmp.inbound_header_ident)
                    .unwrap_or(icmp.inbound_header_ident),
            ),
            _ => return None,
        },
    };
    Some(ClientLockCandidate {
        flow_key,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(outbound_local, remote)),
        ),
    })
}

#[inline]
fn client_flow_key_from_event(
    src: CanonicalAddr,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<ClientFlowKey> {
    match listen_proto {
        SupportedProtocol::UDP => Some(ClientFlowKey::Udp(src.addr)),
        SupportedProtocol::ICMP => match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => Some(ClientFlowKey::from_icmp_reply_id(
                src,
                icmp.negotiated_remote_reply_id,
            )),
            _ => None,
        },
    }
}

#[inline]
fn admit_udp_packet(
    spec: PacketAdmissionSpec,
    payload: &[u8],
    parsed: &ParsedPacketHeaders,
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    let Some(source_sa) = socket_source else {
        return if spec.source_evidence == SourceEvidenceMode::ConnectedKernelFiltered {
            PacketAdmission::Accepted(AdmittedPacket {
                normalized_source: None,
                payload_bounds: (0, payload.len()),
                icmp_info: None,
            })
        } else {
            PacketAdmission::Filtered(RejectedPacket {
                normalized_source: None,
                reason: RejectionReason::MissingSourceEvidence,
            })
        };
    };
    let Some(canonical) = CanonicalAddr::from_sock_addr(source_sa) else {
        return PacketAdmission::UnsupportedSource;
    };
    if let Some(udp) = parsed.udp
        && udp.src_port != canonical.addr.port()
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }
    if parsed_transport_has_ip(parsed)
        && parsed.src_ip.is_some_and(|src| src != canonical.addr.ip())
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }
    if spec
        .expected_remote()
        .is_some_and(|expected| canonical != expected)
    {
        PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        })
    } else {
        PacketAdmission::Accepted(AdmittedPacket {
            normalized_source: Some(canonical),
            payload_bounds: parsed
                .udp
                .map(|_| parsed.payload_bounds)
                .unwrap_or((0, payload.len())),
            icmp_info: None,
        })
    }
}

#[inline]
fn admit_icmp_packet(
    spec: PacketAdmissionSpec,
    parsed: &ParsedPacketHeaders,
    socket_source: Option<&SockAddr>,
) -> PacketAdmission {
    let Some(icmp) = parsed.icmp else {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: socket_source.and_then(CanonicalAddr::from_sock_addr),
            reason: RejectionReason::MalformedIcmpHeader,
        });
    };

    if spec
        .expected_local_icmp_id()
        .is_some_and(|expected| icmp.ident != expected)
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: socket_source
                .and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, icmp.ident)),
            reason: RejectionReason::UnexpectedLocalReceiveId,
        });
    }

    let canonical = match spec.source_evidence {
        SourceEvidenceMode::RawPacketSourceRequired => parse_raw_ip_source(parsed, socket_source),
        SourceEvidenceMode::SocketSourceRequired => {
            socket_source.and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, icmp.ident))
        }
        SourceEvidenceMode::ConnectedKernelFiltered => {
            socket_source.and_then(|s| CanonicalAddr::from_sock_addr_with_id(s, icmp.ident))
        }
    };

    let Some(canonical) = canonical else {
        return if spec.source_evidence == SourceEvidenceMode::ConnectedKernelFiltered {
            PacketAdmission::Accepted(AdmittedPacket {
                normalized_source: None,
                payload_bounds: parsed.payload_bounds,
                icmp_info: Some(IcmpAdmissionInfo {
                    ident: icmp.ident,
                    seq: icmp.seq,
                    is_req: icmp.is_req,
                }),
            })
        } else if socket_source.is_some()
            && spec.source_evidence == SourceEvidenceMode::SocketSourceRequired
        {
            PacketAdmission::UnsupportedSource
        } else {
            PacketAdmission::Filtered(RejectedPacket {
                normalized_source: None,
                reason: RejectionReason::MissingSourceEvidence,
            })
        };
    };

    if spec
        .expected_remote()
        .is_some_and(|expected| !icmp_remote_ip_matches(canonical, expected))
    {
        return PacketAdmission::Filtered(RejectedPacket {
            normalized_source: Some(canonical),
            reason: RejectionReason::UnexpectedRemotePeer,
        });
    }

    PacketAdmission::Accepted(AdmittedPacket {
        normalized_source: Some(canonical),
        payload_bounds: parsed.payload_bounds,
        icmp_info: Some(IcmpAdmissionInfo {
            ident: icmp.ident,
            seq: icmp.seq,
            is_req: icmp.is_req,
        }),
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
    parsed: &ParsedPacketHeaders,
    socket_source: Option<&SockAddr>,
) -> Option<CanonicalAddr> {
    let ident = parsed.icmp?.ident;
    match parsed.src_ip? {
        IpAddr::V4(ip) => Some(CanonicalAddr::from_v4(ip, ident)),
        IpAddr::V6(ip) => Some(match socket_source.and_then(|s| s.as_socket_ipv6()) {
            Some(meta) => CanonicalAddr::from_v6(ip, ident, meta.flowinfo(), meta.scope_id()),
            _ => CanonicalAddr::from_v6(ip, ident, 0, 0),
        }),
    }
}

#[inline]
fn parsed_transport_has_ip(parsed: &ParsedPacketHeaders) -> bool {
    matches!(
        parsed.transport,
        ParsedTransport::Ipv4Icmp
            | ParsedTransport::Ipv6Icmp
            | ParsedTransport::Ipv4Udp
            | ParsedTransport::Ipv6Udp
    )
}

#[cfg(test)]
#[path = "packet_admission_tests.rs"]
mod tests;
