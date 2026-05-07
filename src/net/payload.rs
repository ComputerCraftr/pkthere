use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::framing_shim::{IcmpTunnelFrame, parse_icmp_tunnel_frame};
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
    pub(crate) const fn user_payload(
        logical_src_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        shim_src_ident: Option<u16>,
    ) -> Self {
        Self::UserPayload {
            data: PayloadData { dst_proto, bytes },
            icmp: Some(IcmpPayloadMeta {
                logical_src_ident,
                seq,
                shim_src_ident,
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
        logical_src_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        shim_src_ident: Option<u16>,
    ) -> Self {
        Self::SessionControl {
            data: PayloadData { dst_proto, bytes },
            icmp: IcmpPayloadMeta {
                logical_src_ident,
                seq,
                shim_src_ident,
            },
        }
    }

    #[inline]
    pub(crate) const fn cadence_packet(logical_src_ident: u16, seq: u16) -> Self {
        Self::CadencePacket {
            icmp: IcmpPayloadMeta {
                logical_src_ident,
                seq,
                shim_src_ident: None,
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
    pub(crate) logical_src_ident: u16,
    pub(crate) seq: u16,
    pub(crate) shim_src_ident: Option<u16>,
}

#[inline]
fn decode_icmp_tunnel_payload<'a>(
    ident: u16,
    seq: u16,
    payload: &'a [u8],
) -> io::Result<PayloadEvent<'a>> {
    match parse_icmp_tunnel_frame(payload)? {
        IcmpTunnelFrame::Cadence => Ok(PayloadEvent::cadence_packet(ident, seq)),
        IcmpTunnelFrame::UserPayload { bytes, source_id } => Ok(PayloadEvent::user_payload(
            ident,
            seq,
            SupportedProtocol::UDP,
            bytes,
            source_id,
        )),
        IcmpTunnelFrame::SessionControl => Ok(PayloadEvent::session_control(
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
                let shim_src_ident = icmp.and_then(|icmp| icmp.shim_src_ident);
                if shim_src_ident.is_some() && c2u && is_locked {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ICMP tunnel source ID shim is only valid for initial C2U lock establishment",
                    ));
                }
                if c2u && !is_locked && shim_src_ident.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "initial ICMP lock establishment requires source ID shim",
                    ));
                }

                let effective_src_ident = if c2u && !is_locked {
                    shim_src_ident.expect("validated initial ICMP lock source ID shim")
                } else {
                    icmp_info.ident
                };

                PayloadEvent::user_payload(
                    effective_src_ident,
                    icmp_info.seq,
                    dst_proto,
                    data.bytes,
                    shim_src_ident,
                )
            }
            PayloadEvent::SessionControl { data, icmp } => {
                if icmp.shim_src_ident.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ICMP tunnel handshake attempted on session-control packet",
                    ));
                }

                PayloadEvent::session_control(
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
pub(crate) fn source_id_shim_for_c2u(
    event: &PayloadEvent<'_>,
    had_prior_icmp_send: bool,
    upstream_local_id: u16,
) -> Option<u16> {
    let (dst_proto, source_id) = match event {
        PayloadEvent::UserPayload { data, icmp } => (
            data.dst_proto,
            icmp.map_or(upstream_local_id, |icmp| icmp.logical_src_ident),
        ),
        _ => return None,
    };
    if had_prior_icmp_send || dst_proto != SupportedProtocol::ICMP {
        return None;
    }

    (source_id != 0).then_some(source_id)
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
