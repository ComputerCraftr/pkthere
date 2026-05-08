use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::framing_shim::{IcmpTunnelFrame, ReplyIdNegotiation, parse_icmp_tunnel_frame};
use crate::stats::StatsSink;

use std::io;

#[path = "payload_send.rs"]
mod payload_send;

pub(crate) use payload_send::{outbound_payload_event, send_payload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadOrigin {
    Wire,
    SyntheticCadencePacket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IcmpAdmissionInfo {
    pub(crate) ident: u16,
    pub(crate) seq: u16,
    pub(crate) is_req: bool,
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
fn decode_icmp_tunnel_payload<'a>(
    ident: u16,
    seq: u16,
    payload: &'a [u8],
) -> io::Result<PayloadEvent<'a>> {
    match parse_icmp_tunnel_frame(payload)? {
        IcmpTunnelFrame::Cadence => Ok(PayloadEvent::cadence_packet(ident, seq)),
        IcmpTunnelFrame::UserPayload { bytes, reply_id } => {
            Ok(PayloadEvent::user_payload_negotiation(
                ident,
                ident,
                seq,
                SupportedProtocol::UDP,
                bytes,
                reply_id,
            ))
        }
        IcmpTunnelFrame::SessionControl => Ok(PayloadEvent::session_control(
            ident,
            ident,
            seq,
            SupportedProtocol::ICMP,
            &[],
            None,
        )),
    }
}

#[inline]
pub(crate) fn validate_payload<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    buf: &'a [u8],
    icmp_info: Option<IcmpAdmissionInfo>,
    payload_bounds: (usize, usize),
    synthetic_icmp_ident: Option<u16>,
    locked_icmp_negotiated_remote_reply_id: Option<u16>,
    origin: PayloadOrigin,
    is_locked: bool,
) -> io::Result<PayloadEvent<'a>> {
    let dst_proto = if c2u {
        cfg.upstream_proto
    } else {
        cfg.listen_proto
    };

    if origin == PayloadOrigin::SyntheticCadencePacket {
        if c2u && dst_proto == SupportedProtocol::ICMP && cfg.icmp_sync_pps > 0 {
            let Some(ident) = synthetic_icmp_ident else {
                stats.drop_err(c2u);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "synthetic cadence packet requires explicit ICMP ident",
                ));
            };
            return Ok(PayloadEvent::cadence_packet(ident, 0));
        } else {
            stats.drop_oversize(c2u);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic cadence packet is only valid for ICMP sync sends",
            ));
        }
    }

    let (start, end) = payload_bounds;
    if start > end || end > buf.len() {
        stats.drop_err(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid payload bounds ({start}, {end}) for buffer length {}",
                buf.len()
            ),
        ));
    }
    let payload = &buf[start..end];

    let decoded_event = if let Some(icmp_info) = icmp_info {
        if c2u != icmp_info.is_req {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ICMP Echo direction mismatch: got (req={}, id={}), expected req={}",
                    icmp_info.is_req, icmp_info.ident, c2u
                ),
            ));
        }
        let event = decode_icmp_tunnel_payload(icmp_info.ident, icmp_info.seq, payload)?;
        match event {
            PayloadEvent::CadencePacket { .. } => {
                PayloadEvent::cadence_packet(icmp_info.ident, icmp_info.seq)
            }
            PayloadEvent::UserPayload { data, icmp } => {
                let icmp = icmp.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "decoded ICMP user payload is missing ICMP metadata",
                    )
                })?;
                let advertised_reply_id = icmp.advertised_reply_id;
                let negotiated_remote_reply_id = if c2u && !is_locked {
                    advertised_reply_id.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "initial ICMP lock establishment requires reply-ID negotiation",
                        )
                    })?
                } else if c2u {
                    let locked_ident = locked_icmp_negotiated_remote_reply_id.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "locked ICMP C2U validation requires negotiated reply ID",
                        )
                    })?;
                    if let Some(shim_ident) = advertised_reply_id
                        && shim_ident != locked_ident
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "ICMP reply-ID renegotiation mismatch: got {shim_ident}, expected locked flow {locked_ident}"
                            ),
                        ));
                    }
                    locked_ident
                } else {
                    advertised_reply_id.unwrap_or(icmp_info.ident)
                };

                PayloadEvent::user_payload_negotiation(
                    negotiated_remote_reply_id,
                    icmp_info.ident,
                    icmp_info.seq,
                    dst_proto,
                    data.bytes,
                    advertised_reply_id.map(|reply_id| ReplyIdNegotiation {
                        reply_id,
                        negotiate: icmp.reply_id_negotiate,
                        ack: icmp.reply_id_ack,
                    }),
                )
            }
            PayloadEvent::SessionControl { data, icmp } => {
                if icmp.advertised_reply_id.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ICMP reply-ID negotiation attempted on session-control packet",
                    ));
                }

                PayloadEvent::session_control(
                    icmp_info.ident,
                    icmp_info.ident,
                    icmp_info.seq,
                    dst_proto,
                    data.bytes,
                    None,
                )
            }
        }
    } else {
        PayloadEvent::user_payload_plain(dst_proto, payload)
    };
    let len = decoded_event.payload_len();
    if len > cfg.max_payload {
        stats.drop_oversize(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload length {} exceeds max {}", len, cfg.max_payload),
        ));
    }
    Ok(decoded_event)
}

#[inline]
pub(crate) fn reply_id_negotiation_for_c2u(
    event: &PayloadEvent<'_>,
    reply_id_acked: bool,
    upstream_local_id: u16,
) -> Option<ReplyIdNegotiation> {
    let dst_proto = match event {
        PayloadEvent::UserPayload { data, .. } => data.dst_proto,
        _ => return None,
    };
    if reply_id_acked || dst_proto != SupportedProtocol::ICMP || upstream_local_id == 0 {
        return None;
    }

    Some(ReplyIdNegotiation {
        reply_id: upstream_local_id,
        negotiate: true,
        ack: false,
    })
}

#[inline]
pub(crate) fn reply_id_negotiation_for_u2c_listener_reply(
    event: &PayloadEvent<'_>,
    explicit_listen_reply_id: Option<u16>,
    listener_reply_id: Option<u16>,
) -> Option<ReplyIdNegotiation> {
    if !event.is_user_payload() || explicit_listen_reply_id.is_none() {
        return None;
    }
    listener_reply_id
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
