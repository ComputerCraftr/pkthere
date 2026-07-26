use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::diagnostics::PacketTraceId;
use crate::net::framing_shim::{IcmpTunnelControl, ReplyIdNegotiation, ResetRequired, SessionId};
use crate::net::icmp_sequence::{
    IcmpSequenceCache, SharedIcmpSequenceState, admit_inbound_sequence, remember_request_seq,
};
use std::io;
use std::sync::Arc;
use std::time::Instant;

mod send;

#[cfg(all(test, not(miri)))]
pub(crate) use send::build_test_ipv4_icmp_packet;
pub(crate) use send::{
    OutboundPayloadEvent, outbound_control_payload_event, outbound_payload_event,
    prepare_outbound_payload_event, send_payload, send_payload_with_lease,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ICMP endpoint identity after wire admission has proved that source identity
/// is present and nonzero. The wire parser intentionally uses
/// `WireIcmpIdentity` because source identity is optional until shim
/// validation completes.
pub(crate) struct AdmittedIcmpIdentity {
    remote_source_id: u16,
    local_destination_id: u16,
}

impl AdmittedIcmpIdentity {
    pub(crate) const fn new(remote_source_id: u16, local_destination_id: u16) -> Option<Self> {
        if remote_source_id == 0 || local_destination_id == 0 {
            return None;
        }
        Some(Self {
            remote_source_id,
            local_destination_id,
        })
    }

    pub(crate) const fn remote_source_id(self) -> u16 {
        self.remote_source_id
    }

    pub(crate) const fn local_destination_id(self) -> u16 {
        self.local_destination_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum U2cDecision {
    ForwardPayload,
    ForwardSessionControl,
    ConsumeSessionControl,
    ConsumeCadence,
}

impl U2cDecision {
    #[inline]
    pub(crate) const fn should_send(self) -> bool {
        matches!(self, Self::ForwardPayload | Self::ForwardSessionControl)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum C2uSessionControlDecision {
    Forward,
    ReplyLocally,
    Consume,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PayloadEvent<'a> {
    UserPayload {
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        icmp: Option<IcmpPayloadMeta>,
    },
    SessionControl {
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        icmp: IcmpPayloadMeta,
    },
    CadencePacket {
        icmp: IcmpPayloadMeta,
    },
}

impl<'a> PayloadEvent<'a> {
    #[inline]
    pub(crate) fn icmp_meta(&self) -> Option<&IcmpPayloadMeta> {
        match self {
            Self::UserPayload { icmp, .. } => icmp.as_ref(),
            Self::SessionControl { icmp, .. } => Some(icmp),
            Self::CadencePacket { icmp } => Some(icmp),
        }
    }

    #[inline]
    pub(crate) const fn is_user_payload(&self) -> bool {
        matches!(self, Self::UserPayload { .. })
    }

    #[inline]
    pub(crate) const fn is_session_control(&self) -> bool {
        matches!(self, Self::SessionControl { .. })
    }

    #[inline]
    pub(crate) const fn is_cadence_packet(&self) -> bool {
        matches!(self, Self::CadencePacket { .. })
    }

    #[inline]
    pub(crate) const fn payload_len(&self) -> usize {
        match self {
            Self::UserPayload { bytes, .. } | Self::SessionControl { bytes, .. } => bytes.len(),
            Self::CadencePacket { .. } => 0,
        }
    }

    #[inline]
    pub(crate) const fn dst_proto(&self) -> SupportedProtocol {
        match self {
            Self::UserPayload { dst_proto, .. } | Self::SessionControl { dst_proto, .. } => {
                *dst_proto
            }
            Self::CadencePacket { .. } => SupportedProtocol::ICMP,
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn user_payload(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
    ) -> Self {
        Self::UserPayload {
            dst_proto,
            bytes,
            icmp: Some(IcmpPayloadMeta::new(
                remote_source_id,
                inbound_header_ident,
                seq,
                SessionId::for_tests(),
                None,
            )),
        }
    }

    #[inline]
    pub(crate) fn icmp_user_payload(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        session_id: SessionId,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
    ) -> Self {
        Self::UserPayload {
            dst_proto,
            bytes,
            icmp: Some(IcmpPayloadMeta::new(
                remote_source_id,
                inbound_header_ident,
                seq,
                session_id,
                None,
            )),
        }
    }

    #[inline]
    pub(crate) const fn user_payload_plain(dst_proto: SupportedProtocol, bytes: &'a [u8]) -> Self {
        Self::UserPayload {
            dst_proto,
            bytes,
            icmp: None,
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn session_control(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        advertised_reply_id: Option<u16>,
    ) -> Self {
        Self::SessionControl {
            dst_proto,
            bytes,
            icmp: IcmpPayloadMeta::new(
                remote_source_id,
                inbound_header_ident,
                seq,
                SessionId::for_tests(),
                match advertised_reply_id {
                    Some(reply_id) => ReplyIdNegotiation::negotiate(reply_id),
                    None => None,
                },
            ),
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn session_control_negotiation(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        session_id: SessionId,
        dst_proto: SupportedProtocol,
        reply_id: ReplyIdNegotiation,
    ) -> Self {
        Self::SessionControl {
            dst_proto,
            bytes: &[],
            icmp: IcmpPayloadMeta::new(
                remote_source_id,
                inbound_header_ident,
                seq,
                session_id,
                Some(reply_id),
            ),
        }
    }

    pub(crate) fn session_reset_required(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        reset_required: ResetRequired,
    ) -> Self {
        Self::SessionControl {
            dst_proto,
            bytes: &[],
            icmp: IcmpPayloadMeta::new_reset(
                remote_source_id,
                inbound_header_ident,
                seq,
                reset_required,
            ),
        }
    }

    pub(crate) fn session_control_v3(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        control: IcmpTunnelControl,
    ) -> Self {
        Self::SessionControl {
            dst_proto,
            bytes: &[],
            icmp: IcmpPayloadMeta::new_control(
                remote_source_id,
                inbound_header_ident,
                seq,
                control,
            ),
        }
    }

    #[inline]
    pub(crate) const fn cadence_packet(
        inbound_header_ident: u16,
        seq: u16,
        session_id: SessionId,
    ) -> Self {
        Self::cadence_packet_with_source(
            inbound_header_ident,
            inbound_header_ident,
            seq,
            session_id,
        )
    }

    #[inline]
    pub(crate) const fn cadence_packet_with_source(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        session_id: SessionId,
    ) -> Self {
        Self::CadencePacket {
            icmp: IcmpPayloadMeta::new(
                remote_source_id,
                inbound_header_ident,
                seq,
                session_id,
                None,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IcmpPayloadMeta {
    flow_identity: AdmittedIcmpIdentity,
    seq: u16,
    session_id: SessionId,
    control: IcmpControlMeta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IcmpControlMeta {
    None,
    Control(IcmpTunnelControl),
}

impl IcmpPayloadMeta {
    #[inline]
    pub(crate) const fn new(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        session_id: SessionId,
        reply_id_negotiation: Option<ReplyIdNegotiation>,
    ) -> Self {
        Self {
            flow_identity: AdmittedIcmpIdentity {
                remote_source_id,
                local_destination_id: inbound_header_ident,
            },
            seq,
            session_id,
            control: match reply_id_negotiation {
                Some(negotiation) if negotiation.is_negotiate() => {
                    IcmpControlMeta::Control(IcmpTunnelControl::Negotiate(negotiation))
                }
                Some(negotiation) => {
                    IcmpControlMeta::Control(IcmpTunnelControl::NegotiateAck(negotiation))
                }
                None => IcmpControlMeta::None,
            },
        }
    }

    pub(crate) const fn new_reset(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        reset_required: ResetRequired,
    ) -> Self {
        Self {
            flow_identity: AdmittedIcmpIdentity {
                remote_source_id,
                local_destination_id: inbound_header_ident,
            },
            seq,
            session_id: reset_required.rejected_session(),
            control: IcmpControlMeta::Control(IcmpTunnelControl::ResetRequired(reset_required)),
        }
    }

    pub(crate) const fn new_control(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        control: IcmpTunnelControl,
    ) -> Self {
        Self {
            flow_identity: AdmittedIcmpIdentity {
                remote_source_id,
                local_destination_id: inbound_header_ident,
            },
            seq,
            session_id: control.session_id(),
            control: IcmpControlMeta::Control(control),
        }
    }

    #[inline]
    pub(crate) const fn flow_identity(self) -> AdmittedIcmpIdentity {
        self.flow_identity
    }

    #[inline]
    pub(crate) const fn inbound_header_ident(self) -> u16 {
        self.flow_identity.local_destination_id()
    }

    #[inline]
    pub(crate) const fn seq(self) -> u16 {
        self.seq
    }

    #[inline]
    pub(crate) const fn session_id(self) -> SessionId {
        self.session_id
    }

    #[inline]
    pub(crate) const fn reply_id_negotiation(self) -> Option<ReplyIdNegotiation> {
        match self.control {
            IcmpControlMeta::Control(
                IcmpTunnelControl::Negotiate(negotiation)
                | IcmpTunnelControl::NegotiateAck(negotiation),
            ) => Some(negotiation),
            IcmpControlMeta::None | IcmpControlMeta::Control(_) => None,
        }
    }

    pub(crate) const fn reset_required(self) -> Option<ResetRequired> {
        match self.control {
            IcmpControlMeta::Control(IcmpTunnelControl::ResetRequired(reset)) => Some(reset),
            IcmpControlMeta::None | IcmpControlMeta::Control(_) => None,
        }
    }

    pub(crate) const fn control(self) -> Option<IcmpTunnelControl> {
        match self.control {
            IcmpControlMeta::Control(control) => Some(control),
            IcmpControlMeta::None => None,
        }
    }

    #[inline]
    pub(crate) const fn advertised_reply_id(self) -> Option<u16> {
        match self.control {
            IcmpControlMeta::Control(
                IcmpTunnelControl::Negotiate(negotiation)
                | IcmpTunnelControl::NegotiateAck(negotiation),
            ) => Some(negotiation.reply_id()),
            IcmpControlMeta::Control(IcmpTunnelControl::ChallengeNegotiate(challenge))
            | IcmpControlMeta::Control(IcmpTunnelControl::ChallengeAck(challenge)) => {
                Some(challenge.reply_id())
            }
            IcmpControlMeta::None | IcmpControlMeta::Control(_) => None,
        }
    }

    #[inline]
    pub(crate) const fn negotiates_reply_id(self) -> bool {
        matches!(
            self.control,
            IcmpControlMeta::Control(IcmpTunnelControl::Negotiate(
                ReplyIdNegotiation::Negotiate { .. }
            )) | IcmpControlMeta::Control(IcmpTunnelControl::ChallengeNegotiate(_))
        )
    }

    #[inline]
    pub(crate) const fn acknowledges_reply_id(self) -> bool {
        matches!(
            self.control,
            IcmpControlMeta::Control(IcmpTunnelControl::NegotiateAck(
                ReplyIdNegotiation::Acknowledge { .. }
            )) | IcmpControlMeta::Control(IcmpTunnelControl::ChallengeAck(_))
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BufferedPayload {
    received_at: Instant,
    event: BufferedEvent,
    trace: Option<PacketTraceId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BufferedEvent {
    UserPayload {
        dst_proto: SupportedProtocol,
        bytes: Arc<[u8]>,
        icmp: Option<IcmpPayloadMeta>,
    },
    Cadence {
        icmp: IcmpPayloadMeta,
    },
}

impl BufferedPayload {
    #[cfg(test)]
    #[inline]
    pub(crate) fn from_event(event: &PayloadEvent<'_>, trace: Option<PacketTraceId>) -> Self {
        Self::from_event_at(event, trace, Instant::now())
    }

    #[inline]
    pub(crate) fn from_event_at(
        event: &PayloadEvent<'_>,
        trace: Option<PacketTraceId>,
        received_at: Instant,
    ) -> Self {
        let event = match event {
            PayloadEvent::UserPayload {
                dst_proto,
                bytes,
                icmp,
            } => {
                #[cfg(any(test, feature = "authority-audit"))]
                crate::allocation_test_support::record_payload_copy();
                BufferedEvent::UserPayload {
                    dst_proto: *dst_proto,
                    bytes: Arc::from(*bytes),
                    icmp: *icmp,
                }
            }
            PayloadEvent::CadencePacket { icmp } => BufferedEvent::Cadence { icmp: *icmp },
            PayloadEvent::SessionControl { .. } => {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "session-control frame reached payload buffering"
                ))
            }
        };
        Self {
            received_at,
            event,
            trace,
        }
    }

    #[inline]
    pub(crate) fn as_event(&self) -> PayloadEvent<'_> {
        match &self.event {
            BufferedEvent::UserPayload {
                dst_proto,
                bytes,
                icmp,
            } => PayloadEvent::UserPayload {
                dst_proto: *dst_proto,
                bytes,
                icmp: *icmp,
            },
            BufferedEvent::Cadence { icmp } => PayloadEvent::CadencePacket { icmp: *icmp },
        }
    }

    #[inline]
    pub(crate) fn payload_len(&self) -> usize {
        match &self.event {
            BufferedEvent::UserPayload { bytes, .. } => bytes.len(),
            BufferedEvent::Cadence { .. } => 0,
        }
    }

    #[inline]
    pub(crate) const fn trace(&self) -> Option<PacketTraceId> {
        self.trace
    }

    #[inline]
    pub(crate) const fn received_at(&self) -> Instant {
        self.received_at
    }

    #[cfg(test)]
    pub(crate) fn shares_payload_storage(&self, other: &Self) -> bool {
        match (&self.event, &other.event) {
            (
                BufferedEvent::UserPayload { bytes: left, .. },
                BufferedEvent::UserPayload { bytes: right, .. },
            ) => Arc::ptr_eq(left, right),
            (BufferedEvent::Cadence { .. }, BufferedEvent::Cadence { .. }) => true,
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn payload_storage_strong_count(&self) -> usize {
        match &self.event {
            BufferedEvent::UserPayload { bytes, .. } => Arc::strong_count(bytes),
            BufferedEvent::Cadence { .. } => 0,
        }
    }
}

#[inline]
pub(crate) fn reply_id_negotiation_for_c2u(
    event: &PayloadEvent<'_>,
    reply_id_acked: bool,
    advertised_local_reply_id: u16,
) -> io::Result<Option<ReplyIdNegotiation>> {
    let dst_proto = match event {
        PayloadEvent::UserPayload { dst_proto, .. } => *dst_proto,
        _ => return Ok(None),
    };
    if dst_proto != SupportedProtocol::ICMP {
        return Ok(None);
    }
    if advertised_local_reply_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ICMP v2 session establishment requires a nonzero realized local reply ID",
        ));
    }

    if reply_id_acked {
        Ok(None)
    } else {
        ReplyIdNegotiation::fresh_negotiation(advertised_local_reply_id)
    }
}

#[inline]
pub(crate) fn reply_id_negotiation_for_u2c_listener_reply(
    event: &PayloadEvent<'_>,
    advertised_local_reply_id: Option<u16>,
) -> Option<ReplyIdNegotiation> {
    let icmp = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => return None,
    };

    if !icmp.negotiates_reply_id() {
        return None;
    }

    let reply_id = match advertised_local_reply_id {
        Some(id) => id,
        None => icmp.flow_identity().remote_source_id(),
    };
    if reply_id == 0 {
        return None;
    }

    icmp.reply_id_negotiation().and_then(|negotiation| {
        ReplyIdNegotiation::acknowledge_key_and_challenge(
            reply_id,
            negotiation.session_key(),
            negotiation.reset_challenge(),
        )
    })
}

pub(crate) fn classify_u2c_event(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    sequence_state: &SharedIcmpSequenceState,
) -> io::Result<U2cDecision> {
    if event.is_session_control() {
        return if cfg.listen_proto == SupportedProtocol::ICMP && cfg.is_icmp_sync_enabled() {
            Ok(U2cDecision::ForwardSessionControl)
        } else {
            Ok(U2cDecision::ConsumeSessionControl)
        };
    }

    let icmp = match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => icmp,
        PayloadEvent::UserPayload { icmp: None, .. } => return Ok(U2cDecision::ForwardPayload),
        PayloadEvent::SessionControl { .. } => {
            return Ok(U2cDecision::ConsumeSessionControl);
        }
        PayloadEvent::CadencePacket { icmp } => icmp,
    };

    // Tracks duplicates globally for the flow.
    let catchup_window = cfg
        .is_icmp_sync_enabled()
        .then(|| crate::net::sync_icmp::sync_catchup_window(cfg.icmp_sync_pps));
    admit_inbound_sequence(cfg.debug_logs.packets, sequence_state, icmp, catchup_window)?;

    if event.is_cadence_packet() {
        Ok(U2cDecision::ConsumeCadence)
    } else {
        Ok(U2cDecision::ForwardPayload)
    }
}

pub(crate) fn classify_c2u_session_control_event(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
) -> io::Result<C2uSessionControlDecision> {
    let (icmp, dst_proto) = match event {
        PayloadEvent::SessionControl {
            icmp, dst_proto, ..
        } => (icmp, *dst_proto),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session-control classification requires a session-control event",
            ));
        }
    };
    match icmp.control() {
        Some(
            IcmpTunnelControl::Negotiate(_)
            | IcmpTunnelControl::ChallengeNegotiate(_)
            | IcmpTunnelControl::GenerationAdvance(_),
        ) => return Ok(C2uSessionControlDecision::ReplyLocally),
        Some(
            IcmpTunnelControl::NegotiateAck(_)
            | IcmpTunnelControl::ResetRequired(_)
            | IcmpTunnelControl::ChallengeAck(_)
            | IcmpTunnelControl::GenerationAdvanceAck(_)
            | IcmpTunnelControl::SessionActivated(_),
        ) => return Ok(C2uSessionControlDecision::Consume),
        None => {}
    }
    if dst_proto == SupportedProtocol::ICMP && cfg.is_icmp_sync_enabled() {
        Ok(C2uSessionControlDecision::Forward)
    } else {
        Ok(C2uSessionControlDecision::Consume)
    }
}

pub(crate) fn classify_c2u_data_or_cadence_event(
    event: &PayloadEvent<'_>,
    sequence_state: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> io::Result<()> {
    let icmp = match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        }
        | PayloadEvent::CadencePacket { icmp } => icmp,
        PayloadEvent::UserPayload { icmp: None, .. } => return Ok(()),
        PayloadEvent::SessionControl { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data/cadence classification cannot admit session control",
            ));
        }
    };
    admit_inbound_sequence(false, sequence_state, icmp, None)?;
    remember_request_seq(sequence_state, cache, icmp);
    Ok(())
}

#[cfg(test)]
mod tests;
