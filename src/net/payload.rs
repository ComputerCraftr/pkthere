use crate::cli::SupportedProtocol;
use crate::net::framing_shim::ReplyIdNegotiation;

#[path = "payload_send.rs"]
mod payload_send;

pub(crate) use payload_send::{outbound_payload_event, send_payload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadOrigin {
    Wire,
    SyntheticCadencePacket,
}

#[derive(Debug)]
pub(crate) enum PayloadEvent<'a> {
    UserPayload {
        data: PayloadData<'a>,
        icmp: Option<IcmpPayloadMeta>,
    },
    SessionControl {
        data: PayloadData<'a>,
        icmp: IcmpPayloadMeta,
    },
    CadencePacket {
        icmp: IcmpPayloadMeta,
    },
}

impl<'a> PayloadEvent<'a> {
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
            Self::UserPayload { data, .. } | Self::SessionControl { data, .. } => data.bytes.len(),
            Self::CadencePacket { .. } => 0,
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn user_payload(
        negotiated_remote_reply_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        advertised_reply_id: Option<u16>,
    ) -> Self {
        Self::UserPayload {
            data: PayloadData { dst_proto, bytes },
            icmp: Some(IcmpPayloadMeta {
                negotiated_remote_reply_id,
                inbound_header_ident,
                seq,
                advertised_reply_id,
                reply_id_negotiate: advertised_reply_id.is_some(),
                reply_id_ack: false,
            }),
        }
    }

    #[inline]
    pub(crate) fn user_payload_negotiation(
        negotiated_remote_reply_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        reply_id: Option<ReplyIdNegotiation>,
    ) -> Self {
        Self::UserPayload {
            data: PayloadData { dst_proto, bytes },
            icmp: Some(IcmpPayloadMeta {
                negotiated_remote_reply_id,
                inbound_header_ident,
                seq,
                advertised_reply_id: reply_id.map(|reply_id| reply_id.reply_id),
                reply_id_negotiate: reply_id.is_some_and(|reply_id| reply_id.negotiate),
                reply_id_ack: reply_id.is_some_and(|reply_id| reply_id.ack),
            }),
        }
    }

    #[inline]
    pub(crate) const fn user_payload_plain(dst_proto: SupportedProtocol, bytes: &'a [u8]) -> Self {
        Self::UserPayload {
            data: PayloadData { dst_proto, bytes },
            icmp: None,
        }
    }

    #[inline]
    pub(crate) const fn session_control(
        negotiated_remote_reply_id: u16,
        inbound_header_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        advertised_reply_id: Option<u16>,
    ) -> Self {
        Self::SessionControl {
            data: PayloadData { dst_proto, bytes },
            icmp: IcmpPayloadMeta {
                negotiated_remote_reply_id,
                inbound_header_ident,
                seq,
                advertised_reply_id,
                reply_id_negotiate: advertised_reply_id.is_some(),
                reply_id_ack: false,
            },
        }
    }

    #[inline]
    pub(crate) const fn cadence_packet(inbound_header_ident: u16, seq: u16) -> Self {
        Self::CadencePacket {
            icmp: IcmpPayloadMeta {
                negotiated_remote_reply_id: inbound_header_ident,
                inbound_header_ident,
                seq,
                advertised_reply_id: None,
                reply_id_negotiate: false,
                reply_id_ack: false,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct PayloadData<'a> {
    pub(crate) dst_proto: SupportedProtocol,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedPayloadData {
    pub(crate) dst_proto: SupportedProtocol,
    pub(crate) bytes: Vec<u8>,
}

impl OwnedPayloadData {
    #[inline]
    pub(crate) fn as_borrowed(&self) -> PayloadData<'_> {
        PayloadData {
            dst_proto: self.dst_proto,
            bytes: &self.bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IcmpPayloadMeta {
    pub(crate) negotiated_remote_reply_id: u16,
    pub(crate) inbound_header_ident: u16,
    pub(crate) seq: u16,
    pub(crate) advertised_reply_id: Option<u16>,
    pub(crate) reply_id_negotiate: bool,
    pub(crate) reply_id_ack: bool,
}

#[inline]
pub(crate) fn reply_id_negotiation_for_c2u(
    event: &PayloadEvent<'_>,
    reply_id_acked: bool,
    advertised_local_reply_id: u16,
) -> Option<ReplyIdNegotiation> {
    let dst_proto = match event {
        PayloadEvent::UserPayload { data, .. } => data.dst_proto,
        _ => return None,
    };
    if reply_id_acked || dst_proto != SupportedProtocol::ICMP || advertised_local_reply_id == 0 {
        return None;
    }

    Some(ReplyIdNegotiation {
        reply_id: advertised_local_reply_id,
        negotiate: true,
        ack: false,
    })
}

#[inline]
pub(crate) fn reply_id_negotiation_for_u2c_listener_reply(
    event: &PayloadEvent<'_>,
    advertised_local_reply_id: Option<u16>,
) -> Option<ReplyIdNegotiation> {
    if !event.is_user_payload() {
        return None;
    }
    advertised_local_reply_id
        .filter(|id| *id != 0)
        .map(|reply_id| ReplyIdNegotiation {
            reply_id,
            negotiate: true,
            ack: false,
        })
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
