use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::byte_order::be16_16;
use crate::net::icmp_echo_parse::parse_icmp_echo_header;
use crate::net::payload_support::{
    ICMP_SHIM_ALLOWED_BITS, ICMP_SHIM_HAS_PAYLOAD, ICMP_SHIM_HAS_SOURCE_ID, ICMP_SHIM_IS_DATA,
};
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
pub(crate) enum IcmpIdPolicy {
    Any,
    Exact(u16),
}

impl IcmpIdPolicy {
    #[inline]
    const fn accepts(self, ident: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => ident == expected,
        }
    }

    #[inline]
    const fn synthetic_ident(self) -> u16 {
        match self {
            Self::Any => 0,
            Self::Exact(ident) => ident,
        }
    }
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
        transport_src_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        shim_src_ident: Option<u16>,
    ) -> Self {
        Self::UserPayload {
            data: PayloadData { dst_proto, bytes },
            icmp: Some(IcmpPayloadMeta {
                logical_src_ident,
                transport_src_ident,
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
        transport_src_ident: u16,
        seq: u16,
        dst_proto: SupportedProtocol,
        bytes: &'a [u8],
        shim_src_ident: Option<u16>,
    ) -> Self {
        Self::SessionControl {
            data: PayloadData { dst_proto, bytes },
            icmp: IcmpPayloadMeta {
                logical_src_ident,
                transport_src_ident,
                seq,
                shim_src_ident,
            },
        }
    }

    #[inline]
    pub(crate) const fn cadence_packet(transport_src_ident: u16, seq: u16) -> Self {
        Self::CadencePacket {
            icmp: IcmpPayloadMeta {
                logical_src_ident: transport_src_ident,
                transport_src_ident,
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
    pub(crate) transport_src_ident: u16,
    pub(crate) seq: u16,
    pub(crate) shim_src_ident: Option<u16>,
}

#[inline]
fn decode_icmp_tunnel_payload<'a>(payload: &'a [u8]) -> io::Result<PayloadEvent<'a>> {
    if payload.is_empty() {
        return Ok(PayloadEvent::cadence_packet(0, 0));
    }

    let shim = payload[0];
    if (shim & !ICMP_SHIM_ALLOWED_BITS) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP tunnel shim header",
        ));
    }

    let has_source_id = (shim & ICMP_SHIM_HAS_SOURCE_ID) != 0;
    if has_source_id && payload.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP tunnel shim has source ID flag but payload is too short",
        ));
    }

    let (shim_src_ident, user_payload) = if has_source_id {
        let id = be16_16(payload[1], payload[2]);
        (Some(id), &payload[3..])
    } else {
        (None, &payload[1..])
    };

    let is_data = (shim & ICMP_SHIM_IS_DATA) != 0;
    let has_user_payload = (shim & ICMP_SHIM_HAS_PAYLOAD) != 0;

    // Normal tunnel packets MUST have a valid shim.
    // Zero-length user data has IS_DATA set but HAS_PAYLOAD unset.
    // Session-control packets have IS_DATA unset.
    match (is_data, has_user_payload, user_payload.is_empty()) {
        (true, true, false) => Ok(PayloadEvent::user_payload(
            0,
            0,
            0,
            SupportedProtocol::UDP,
            user_payload,
            shim_src_ident,
        )),
        (true, false, true) => Ok(PayloadEvent::user_payload(
            0,
            0,
            0,
            SupportedProtocol::UDP,
            &[],
            shim_src_ident,
        )),
        (false, false, true) => Ok(PayloadEvent::session_control(
            0,
            0,
            0,
            SupportedProtocol::ICMP,
            &[],
            shim_src_ident,
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP tunnel shim payload flags mismatch",
        )),
    }
}

#[inline]
pub(crate) fn validate_payload<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    buf: &'a [u8],
    icmp_id_policy: IcmpIdPolicy,
    origin: PayloadOrigin,
    is_locked: bool,
) -> io::Result<PayloadEvent<'a>> {
    let (src_proto, dst_proto) = if c2u {
        (cfg.listen_proto, cfg.upstream_proto)
    } else {
        (cfg.upstream_proto, cfg.listen_proto)
    };

    if origin == PayloadOrigin::SyntheticCadencePacket {
        if c2u && dst_proto == SupportedProtocol::ICMP && cfg.icmp_sync_pps > 0 {
            return Ok(PayloadEvent::cadence_packet(
                icmp_id_policy.synthetic_ident(),
                0,
            ));
        } else {
            stats.drop_oversize(c2u);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic cadence packet is only valid for ICMP sync sends",
            ));
        }
    }

    let (src_is_icmp, icmp_success, payload, src_ident_header, src_seq, src_is_req) =
        match src_proto {
            SupportedProtocol::ICMP => {
                let res = parse_icmp_echo_header(buf);
                (true, res.0, &res.1[res.2..res.3], res.4, res.5, res.6)
            }
            _ => (false, true, buf, 0u16, 0u16, c2u),
        };

    if !icmp_success {
        stats.drop_err(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP Echo header (missing or truncated)",
        ));
    }

    if c2u != src_is_req || (src_is_icmp && !icmp_id_policy.accepts(src_ident_header)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ICMP Echo direction or identity mismatch: got (req={}, id={}), expected (req={}, policy={:?})",
                src_is_req, src_ident_header, c2u, icmp_id_policy
            ),
        ));
    }

    let decoded_event = if src_is_icmp {
        let event = decode_icmp_tunnel_payload(payload)?;
        match event {
            PayloadEvent::CadencePacket { .. } => {
                PayloadEvent::cadence_packet(src_ident_header, src_seq)
            }
            PayloadEvent::UserPayload { data, icmp } => {
                let shim_src_ident = icmp.and_then(|icmp| icmp.shim_src_ident);
                if shim_src_ident.is_some() {
                    if c2u && !src_is_req {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ICMP tunnel handshake attempted on Echo Reply",
                        ));
                    }
                }

                let effective_src_ident = if c2u && !is_locked {
                    shim_src_ident.unwrap_or(src_ident_header)
                } else {
                    src_ident_header
                };

                PayloadEvent::user_payload(
                    effective_src_ident,
                    src_ident_header,
                    src_seq,
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
                    src_ident_header,
                    src_ident_header,
                    src_seq,
                    dst_proto,
                    data.bytes,
                    None,
                )
            }
        }
    } else {
        debug_assert!(!src_is_icmp);
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
