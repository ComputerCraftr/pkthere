use crate::cli::RuntimeConfig;
use crate::endpoint::LogicalEndpoint;
use crate::net::packet_headers::{IcmpMalformedReason, IpMalformedReason, IpUnsupportedReason};
use crate::worker_support::packet_admission::{ReceiveContext, SocketLeg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectionLogContext {
    expected_remote: Option<LogicalEndpoint>,
    expected_local_id: Option<u16>,
    local_filter: Option<LogicalEndpoint>,
}

impl RejectionLogContext {
    #[inline]
    pub(crate) fn capture(spec: ReceiveContext<'_>) -> Self {
        Self {
            expected_remote: spec.expected_remote(),
            expected_local_id: spec.expected_local_id(),
            local_filter: spec.local_filter(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RejectionReason {
    UnexpectedRemotePeer,
    UnexpectedLocalReceiveId,
    UnexpectedLocalReceiveAddress,
    MalformedIpHeader(IpMalformedReason),
    UnsupportedIpLayout(IpUnsupportedReason),
    MalformedIcmpHeader(Option<IcmpMalformedReason>),
    MissingSourceEvidence,
    IcmpReplyIdNegotiationRequired,
    IcmpSourceEndpointMismatch,
    IcmpReplyIdRenegotiationMismatch,
    IcmpSessionMismatch,
    UnsupportedDisjointReplyId,
    PayloadOversize,
    InvalidPayloadBounds,
}

impl RejectionReason {
    pub(crate) const LOG_BUCKET_COUNT: usize = 14;

    pub(crate) const fn log_bucket_index(self) -> usize {
        match self {
            Self::UnexpectedRemotePeer => 0,
            Self::UnexpectedLocalReceiveId => 1,
            Self::UnexpectedLocalReceiveAddress => 2,
            Self::MalformedIpHeader(_) => 3,
            Self::UnsupportedIpLayout(_) => 4,
            Self::MalformedIcmpHeader(_) => 5,
            Self::MissingSourceEvidence => 6,
            Self::IcmpReplyIdNegotiationRequired => 7,
            Self::IcmpSourceEndpointMismatch => 8,
            Self::IcmpReplyIdRenegotiationMismatch => 9,
            Self::IcmpSessionMismatch => 10,
            Self::UnsupportedDisjointReplyId => 11,
            Self::PayloadOversize => 12,
            Self::InvalidPayloadBounds => 13,
        }
    }

    /// Whether basic packet shape and endpoint identity were established
    /// before this rejection. These frames consume the bounded authenticated
    /// work budget before session/replay/allocation work or diagnostics.
    pub(crate) const fn consumes_authenticated_work(self) -> bool {
        matches!(
            self,
            Self::IcmpReplyIdNegotiationRequired
                | Self::IcmpSourceEndpointMismatch
                | Self::IcmpReplyIdRenegotiationMismatch
                | Self::IcmpSessionMismatch
                | Self::UnsupportedDisjointReplyId
                | Self::PayloadOversize
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectedPacket {
    pub(crate) normalized_source: Option<LogicalEndpoint>,
    pub(crate) actual_dst_id: Option<u16>,
    pub(crate) reason: RejectionReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectedPacketExtent {
    length: usize,
    head: [u8; 4],
    head_len: u8,
}

impl RejectedPacketExtent {
    pub(crate) fn capture(packet: &[u8]) -> Self {
        let head_len = packet.len().min(4);
        let mut head = [0_u8; 4];
        if let Some(destination) = head.get_mut(..head_len)
            && let Some(source) = packet.get(..head_len)
        {
            destination.copy_from_slice(source);
        }
        Self {
            length: packet.len(),
            head,
            head_len: u8::try_from(head_len).unwrap_or(0),
        }
    }

    fn head(&self) -> &[u8] {
        self.head
            .get(..usize::from(self.head_len))
            .unwrap_or_default()
    }
}

#[inline]
pub(crate) fn log_rejected_packet(
    worker_id: usize,
    c2u: bool,
    cfg: &RuntimeConfig,
    role: SocketLeg,
    rejected: RejectedPacket,
    context: RejectionLogContext,
    packet: Option<RejectedPacketExtent>,
) {
    let expected_remote = context.expected_remote;
    let expected_local_id = context.expected_local_id;
    let role_name = match role {
        SocketLeg::ClientFacing => "client",
        SocketLeg::UpstreamFacing => "upstream",
    };
    let actual_source = rejected
        .normalized_source
        .map(|source| source.to_string())
        .unwrap_or_else(|| String::from("<unknown>"));

    let packet_details = || {
        if let Some(packet) = packet {
            format!(" (len: {}, head: {:x?})", packet.length, packet.head())
        } else {
            String::new()
        }
    };

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
            let actual_src_id = rejected.normalized_source.map(LogicalEndpoint::id);
            crate::log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                c2u,
                "dropping packet from {role_name} peer {} with unexpected local receive id {:?} (expected {:?}, packet source id was {:?})",
                actual_source,
                rejected.actual_dst_id,
                expected_local_id,
                actual_src_id
            )
        }
        RejectionReason::UnexpectedLocalReceiveAddress => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping packet from {role_name} peer {} with unexpected local receive address (expected {:?})",
            actual_source,
            context.local_filter
        ),
        RejectionReason::MalformedIcmpHeader(detail) => {
            crate::log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                c2u,
                "dropping malformed ICMP packet from {role_name} peer {} (reason: {:?}){}",
                actual_source,
                detail,
                packet_details()
            )
        }
        RejectionReason::MalformedIpHeader(detail) => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping malformed IP packet from {role_name} peer {} (reason: {:?}){}",
            actual_source,
            detail,
            packet_details()
        ),
        RejectionReason::UnsupportedIpLayout(detail) => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping unsupported IP packet from {role_name} peer {} (reason: {:?}){}",
            actual_source,
            detail,
            packet_details()
        ),
        RejectionReason::InvalidPayloadBounds => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping malformed ICMP packet from {role_name} peer {} (reason: invalid payload bounds){}",
            actual_source,
            packet_details()
        ),
        RejectionReason::IcmpReplyIdNegotiationRequired => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} because reply ID negotiation is required",
            actual_source
        ),
        RejectionReason::IcmpSourceEndpointMismatch => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} because source endpoint ID mismatches the locked flow",
            actual_source
        ),
        RejectionReason::IcmpReplyIdRenegotiationMismatch => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} because pending reply ID negotiation does not match",
            actual_source
        ),
        RejectionReason::IcmpSessionMismatch => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} because the v2 session ID is not active",
            actual_source
        ),
        RejectionReason::UnsupportedDisjointReplyId => crate::log_debug_dir!(
            cfg.debug_logs.drops,
            worker_id,
            c2u,
            "dropping ICMP packet from {role_name} peer {} due to unsupported disjoint reply ID negotiation",
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

#[inline]
pub(crate) fn record_rejection_stats(
    stats: &mut dyn crate::stats::StatsSink,
    c2u: bool,
    rejected: RejectedPacket,
) {
    use crate::net::packet_headers::{
        IpMalformedReason as Malformed, IpUnsupportedReason as Unsupported,
    };
    use crate::stats::PacketRejectionCategory as Category;
    let category = match rejected.reason {
        RejectionReason::MalformedIpHeader(Malformed::MissingHeader) => {
            Some(Category::IpMissingHeader)
        }
        RejectionReason::MalformedIpHeader(Malformed::InvalidVersion { .. }) => {
            Some(Category::IpInvalidVersion)
        }
        RejectionReason::MalformedIpHeader(Malformed::TruncatedHeader) => {
            Some(Category::IpTruncatedHeader)
        }
        RejectionReason::MalformedIpHeader(
            Malformed::InvalidHeaderLength | Malformed::InvalidPacketLength,
        ) => Some(Category::IpDeclaredLengthInvalid),
        RejectionReason::MalformedIpHeader(Malformed::CaptureTruncated) => {
            Some(Category::IpCaptureTruncated)
        }
        RejectionReason::MalformedIpHeader(Malformed::ReservedIpv4Flag) => {
            Some(Category::IpReservedFlag)
        }
        RejectionReason::MalformedIpHeader(Malformed::TruncatedExtension) => {
            Some(Category::IpExtensionChain)
        }
        RejectionReason::UnsupportedIpLayout(Unsupported::Fragmented) => {
            Some(Category::IpFragmented)
        }
        RejectionReason::UnsupportedIpLayout(Unsupported::RoutingHeaderWithSegments) => {
            Some(Category::IpRoutingUnsupported)
        }
        RejectionReason::UnsupportedIpLayout(Unsupported::Jumbogram) => {
            Some(Category::IpJumbogramUnsupported)
        }
        RejectionReason::UnsupportedIpLayout(
            Unsupported::ExtensionChain
            | Unsupported::AuthenticationHeader
            | Unsupported::EncryptedPayload,
        ) => Some(Category::IpExtensionChain),
        RejectionReason::UnexpectedRemotePeer => Some(Category::IpSourceMismatch),
        RejectionReason::UnexpectedLocalReceiveAddress => Some(Category::IpDestinationMismatch),
        RejectionReason::MalformedIcmpHeader(_) | RejectionReason::InvalidPayloadBounds => {
            Some(Category::IcmpMalformed)
        }
        _ => None,
    };
    if let Some(category) = category {
        stats.packet_rejection(c2u, category);
    }
    if matches!(
        rejected.reason,
        RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlFlags
                | crate::net::packet_headers::IcmpMalformedReason::InvalidSessionControlDirection
                | crate::net::packet_headers::IcmpMalformedReason::ZeroReplyId
                | crate::net::packet_headers::IcmpMalformedReason::ZeroSourceId
        ))
    ) {
        stats.handshake_invalid_control(c2u);
    }
    match rejected.reason {
        RejectionReason::PayloadOversize => stats.drop_oversize(c2u),
        RejectionReason::UnexpectedRemotePeer => stats.wrong_peer_drop(c2u),
        RejectionReason::UnexpectedLocalReceiveId
        | RejectionReason::UnexpectedLocalReceiveAddress
        | RejectionReason::MissingSourceEvidence
        | RejectionReason::IcmpSourceEndpointMismatch => stats.wrong_source_drop(c2u),
        RejectionReason::MalformedIpHeader(_)
        | RejectionReason::UnsupportedIpLayout(_)
        | RejectionReason::MalformedIcmpHeader(_)
        | RejectionReason::InvalidPayloadBounds => {
            stats.malformed_packet(c2u);
        }
        RejectionReason::IcmpReplyIdNegotiationRequired
        | RejectionReason::IcmpReplyIdRenegotiationMismatch => {
            stats.handshake_invalid_drop(c2u);
        }
        RejectionReason::IcmpSessionMismatch => stats.stale_session_drop(c2u),
        RejectionReason::UnsupportedDisjointReplyId => stats.admission_drop(c2u),
    }
}
