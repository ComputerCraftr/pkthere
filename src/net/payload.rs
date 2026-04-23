use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::framing_shim::ReplyIdNegotiation;
use crate::net::icmp_sequence::{
    IcmpSequenceCache, SharedIcmpSequenceState, admit_inbound_sequence, current_reply_seq,
    remember_outbound_request_seq,
};
use crate::packet_trace::PacketTraceId;
use std::io;

#[path = "payload_send.rs"]
mod payload_send;

pub(crate) use payload_send::{outbound_payload_event, send_payload};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TunnelFlowIdentity {
    pub(crate) remote_source_id: u16,
    pub(crate) local_destination_id: u16,
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

    #[inline]
    pub(crate) const fn requires_sync_validation(self) -> bool {
        matches!(
            self,
            Self::ForwardPayload | Self::ForwardSessionControl | Self::ConsumeSessionControl
        )
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
            Self::SessionControl { icmp, .. } | Self::CadencePacket { icmp } => Some(icmp),
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
                None,
            )),
        }
    }

    #[inline]
    pub(crate) fn icmp_user_payload(
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
    pub(crate) const fn session_control(
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
                match advertised_reply_id {
                    Some(reply_id) => Some(ReplyIdNegotiation {
                        reply_id,
                        negotiate: true,
                        ack: false,
                    }),
                    None => None,
                },
            ),
        }
    }

    #[inline]
    pub(crate) fn session_control_negotiation(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        reply_id: ReplyIdNegotiation,
    ) -> Self {
        Self::SessionControl {
            dst_proto,
            bytes: &[],
            icmp: IcmpPayloadMeta::new(remote_source_id, inbound_header_ident, seq, Some(reply_id)),
        }
    }

    #[inline]
    pub(crate) const fn cadence_packet(inbound_header_ident: u16, seq: u16) -> Self {
        Self::CadencePacket {
            icmp: IcmpPayloadMeta::new(inbound_header_ident, inbound_header_ident, seq, None),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct IcmpPayloadMeta {
    flow_identity: TunnelFlowIdentity,
    seq: u16,
    reply_id_negotiation: Option<ReplyIdNegotiation>,
}

impl IcmpPayloadMeta {
    #[inline]
    pub(crate) const fn new(
        remote_source_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        reply_id_negotiation: Option<ReplyIdNegotiation>,
    ) -> Self {
        Self {
            flow_identity: TunnelFlowIdentity {
                remote_source_id,
                local_destination_id: inbound_header_ident,
            },
            seq,
            reply_id_negotiation,
        }
    }

    #[inline]
    pub(crate) const fn flow_identity(self) -> TunnelFlowIdentity {
        self.flow_identity
    }

    #[inline]
    pub(crate) const fn inbound_header_ident(self) -> u16 {
        self.flow_identity.local_destination_id
    }

    #[inline]
    pub(crate) const fn seq(self) -> u16 {
        self.seq
    }

    #[inline]
    pub(crate) const fn reply_id_negotiation(self) -> Option<ReplyIdNegotiation> {
        self.reply_id_negotiation
    }

    #[inline]
    pub(crate) const fn advertised_reply_id(self) -> Option<u16> {
        match self.reply_id_negotiation {
            Some(negotiation) => Some(negotiation.reply_id),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn negotiates_reply_id(self) -> bool {
        matches!(
            self.reply_id_negotiation,
            Some(ReplyIdNegotiation {
                negotiate: true,
                ..
            })
        )
    }

    #[inline]
    pub(crate) const fn acknowledges_reply_id(self) -> bool {
        matches!(
            self.reply_id_negotiation,
            Some(ReplyIdNegotiation { ack: true, .. })
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BufferedPayload {
    dst_proto: SupportedProtocol,
    bytes: Vec<u8>,
    icmp: Option<IcmpPayloadMeta>,
    trace: Option<PacketTraceId>,
}

impl BufferedPayload {
    #[inline]
    pub(crate) fn from_event(event: &PayloadEvent<'_>, trace: Option<PacketTraceId>) -> Self {
        let (dst_proto, bytes, icmp) = match event {
            PayloadEvent::UserPayload {
                dst_proto,
                bytes,
                icmp,
            } => (*dst_proto, *bytes, *icmp),
            _ => unreachable!("only user payloads are buffered"),
        };
        Self {
            dst_proto,
            bytes: bytes.to_vec(),
            icmp,
            trace,
        }
    }

    #[inline]
    pub(crate) fn as_event(&self) -> PayloadEvent<'_> {
        PayloadEvent::UserPayload {
            dst_proto: self.dst_proto,
            bytes: &self.bytes,
            icmp: self.icmp,
        }
    }

    #[inline]
    pub(crate) fn payload_len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub(crate) const fn trace(&self) -> Option<PacketTraceId> {
        self.trace
    }
}

#[inline]
pub(crate) fn reply_id_negotiation_for_c2u(
    event: &PayloadEvent<'_>,
    reply_id_acked: bool,
    advertised_local_reply_id: u16,
) -> Option<ReplyIdNegotiation> {
    let dst_proto = match event {
        PayloadEvent::UserPayload { dst_proto, .. } => *dst_proto,
        _ => return None,
    };
    if dst_proto != SupportedProtocol::ICMP || advertised_local_reply_id == 0 {
        return None;
    }

    if reply_id_acked {
        None
    } else {
        Some(ReplyIdNegotiation {
            reply_id: advertised_local_reply_id,
            negotiate: true,
            ack: false,
        })
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
        None => icmp.flow_identity().remote_source_id,
    };
    if reply_id == 0 {
        return None;
    }

    Some(ReplyIdNegotiation {
        reply_id,
        negotiate: false,
        ack: true,
    })
}

pub(crate) fn classify_u2c_event(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    sequence_state: &SharedIcmpSequenceState,
) -> io::Result<U2cDecision> {
    let icmp = match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => icmp,
        PayloadEvent::UserPayload { icmp: None, .. } => return Ok(U2cDecision::ForwardPayload),
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        PayloadEvent::CadencePacket { .. } => return Ok(U2cDecision::ConsumeCadence),
    };

    // Tracks duplicates globally for the flow.
    admit_inbound_sequence(cfg.debug_logs.packets, sequence_state, icmp)?;

    if event.is_session_control() {
        if cfg.listen_proto == SupportedProtocol::ICMP && cfg.is_icmp_sync_enabled() {
            Ok(U2cDecision::ForwardSessionControl)
        } else {
            Ok(U2cDecision::ConsumeSessionControl)
        }
    } else {
        Ok(U2cDecision::ForwardPayload)
    }
}

pub(crate) fn classify_c2u_session_control_event(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    sequence_state: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> io::Result<C2uSessionControlDecision> {
    let icmp = match event {
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session-control classification requires a session-control event",
            ));
        }
    };

    // Tracks duplicates globally for the flow.
    admit_inbound_sequence(false, sequence_state, icmp)?;
    // Track remote's sequence for sync-mode lag calculation (generic feature).
    crate::net::icmp_sequence::remember_request_seq(sequence_state, cache, icmp);

    let dst_proto = match event {
        PayloadEvent::SessionControl { dst_proto, .. } => *dst_proto,
        _ => unreachable!(),
    };
    if icmp.negotiates_reply_id() {
        return Ok(C2uSessionControlDecision::ReplyLocally);
    }
    if icmp.acknowledges_reply_id() {
        return Ok(C2uSessionControlDecision::Consume);
    }
    if dst_proto == SupportedProtocol::ICMP && cfg.is_icmp_sync_enabled() {
        Ok(C2uSessionControlDecision::Forward)
    } else {
        Ok(C2uSessionControlDecision::Consume)
    }
}

pub(crate) fn allocate_send_sequence(
    c2u: bool,
    event: &PayloadEvent<'_>,
    will_forward: bool,
    sequence_state: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> Option<u16> {
    let dst_proto = event.dst_proto();
    if !will_forward || dst_proto != SupportedProtocol::ICMP {
        return None;
    }
    if c2u {
        Some(remember_outbound_request_seq(sequence_state, cache))
    } else {
        Some(current_reply_seq(sequence_state, cache))
    }
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
