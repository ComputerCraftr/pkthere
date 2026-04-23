use crate::cli::RuntimeConfig;
use crate::net::packet_headers::IcmpMalformedReason;
use crate::net::params::CanonicalAddr;
use crate::worker_support::packet_admission::{ReceiveContext, SocketLeg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectionReason {
    UnexpectedRemotePeer,
    UnexpectedLocalReceiveId,
    UnexpectedLocalReceiveAddress,
    MalformedIcmpHeader(Option<IcmpMalformedReason>),
    MissingSourceEvidence,
    IcmpReplyIdNegotiationRequired,
    IcmpSourceEndpointMismatch,
    IcmpReplyIdRenegotiationMismatch,
    UnsupportedDisjointReplyId,
    PayloadOversize,
    InvalidPayloadBounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectedPacket {
    pub(crate) normalized_source: Option<CanonicalAddr>,
    pub(crate) actual_dst_id: Option<u16>,
    pub(crate) reason: RejectionReason,
}

#[inline]
pub(crate) fn log_rejected_packet(
    worker_id: usize,
    c2u: bool,
    cfg: &RuntimeConfig,
    role: SocketLeg,
    rejected: RejectedPacket,
    spec: ReceiveContext,
    packet: Option<&[u8]>,
) {
    let expected_remote = spec.expected_remote();
    let expected_local_id = spec.expected_local_id();
    let role_name = match role {
        SocketLeg::ClientFacing => "client",
        SocketLeg::UpstreamFacing => "upstream",
    };
    let actual_source = rejected
        .normalized_source
        .map(|source| source.to_string())
        .unwrap_or_else(|| String::from("<unknown>"));

    let packet_details = || {
        if let Some(buf) = packet {
            let snippet = &buf[..std::cmp::min(buf.len(), 4)];
            format!(" (len: {}, head: {:x?})", buf.len(), snippet)
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
            let actual_src_id = rejected.normalized_source.map(|s| s.id);
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
            spec.local_filter()
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
    stats: &dyn crate::stats::StatsSink,
    c2u: bool,
    rejected: RejectedPacket,
) {
    match rejected.reason {
        RejectionReason::PayloadOversize => stats.drop_oversize(c2u),
        RejectionReason::UnexpectedRemotePeer
        | RejectionReason::UnexpectedLocalReceiveId
        | RejectionReason::UnexpectedLocalReceiveAddress
        | RejectionReason::MissingSourceEvidence => {}
        _ => stats.drop_err(c2u),
    }
}
