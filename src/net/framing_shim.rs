use crate::net::byte_order::be16_16;
use std::io;

const SHIM_IS_DATA: u8 = 0x80;
const SHIM_HAS_PAYLOAD: u8 = 0x40;
const SHIM_HAS_REPLY_ID: u8 = 0x20;
const SHIM_NEGOTIATE_REPLY_ID: u8 = 0x10;
const SHIM_ACK_REPLY_ID: u8 = 0x08;
const SHIM_ALLOWED_BITS: u8 = SHIM_IS_DATA
    | SHIM_HAS_PAYLOAD
    | SHIM_HAS_REPLY_ID
    | SHIM_NEGOTIATE_REPLY_ID
    | SHIM_ACK_REPLY_ID;

pub(crate) const ICMP_TUNNEL_SHIM_MAX_LEN: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplyIdNegotiation {
    pub(crate) reply_id: u16,
    pub(crate) negotiate: bool,
    pub(crate) ack: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpTunnelFrame<'a> {
    Cadence,
    UserPayload {
        bytes: &'a [u8],
        reply_id: Option<ReplyIdNegotiation>,
    },
    SessionControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpTunnelFrameKind {
    Cadence,
    UserPayload,
    SessionControl,
}

pub(crate) fn parse_icmp_tunnel_frame(payload: &[u8]) -> io::Result<IcmpTunnelFrame<'_>> {
    if payload.is_empty() {
        return Ok(IcmpTunnelFrame::Cadence);
    }

    let shim = payload[0];
    if (shim & !SHIM_ALLOWED_BITS) != 0 {
        return Err(invalid_data("invalid ICMP tunnel shim header"));
    }

    let is_data = (shim & SHIM_IS_DATA) != 0;
    let has_payload = (shim & SHIM_HAS_PAYLOAD) != 0;
    let has_reply_id = (shim & SHIM_HAS_REPLY_ID) != 0;
    let negotiate_reply_id = (shim & SHIM_NEGOTIATE_REPLY_ID) != 0;
    let ack_reply_id = (shim & SHIM_ACK_REPLY_ID) != 0;

    if (has_reply_id || negotiate_reply_id || ack_reply_id) && !is_data {
        return Err(invalid_data(
            "ICMP reply-ID negotiation flags require user-data shim",
        ));
    }
    if (negotiate_reply_id || ack_reply_id) && !has_reply_id {
        return Err(invalid_data(
            "ICMP reply-ID negotiation flag requires advertised reply ID",
        ));
    }
    if has_reply_id && payload.len() < ICMP_TUNNEL_SHIM_MAX_LEN {
        return Err(invalid_data(
            "ICMP tunnel shim has reply-ID flag but payload is too short",
        ));
    }

    let data_start = if has_reply_id {
        ICMP_TUNNEL_SHIM_MAX_LEN
    } else {
        1
    };
    let user_payload = &payload[data_start..];
    let reply_id = has_reply_id.then(|| ReplyIdNegotiation {
        reply_id: be16_16(payload[1], payload[2]),
        // Legacy reply-ID frames did not have explicit negotiation bits.
        // Treat them as negotiate-only so old peers still establish routes.
        negotiate: negotiate_reply_id || !ack_reply_id,
        ack: ack_reply_id,
    });

    match (is_data, has_payload, user_payload.is_empty()) {
        (true, true, false) | (true, false, true) => Ok(IcmpTunnelFrame::UserPayload {
            bytes: user_payload,
            reply_id,
        }),
        (false, false, true) => Ok(IcmpTunnelFrame::SessionControl),
        _ => Err(invalid_data("ICMP tunnel shim payload flags mismatch")),
    }
}

pub(crate) fn encode_icmp_tunnel_prefix(
    kind: IcmpTunnelFrameKind,
    reply_id: Option<ReplyIdNegotiation>,
    payload_len: usize,
    scratch: &mut [u8; ICMP_TUNNEL_SHIM_MAX_LEN],
) -> io::Result<&[u8]> {
    match kind {
        IcmpTunnelFrameKind::Cadence => {
            if reply_id.is_some() || payload_len != 0 {
                return Err(invalid_input("ICMP cadence frame cannot carry shim data"));
            }
            Ok(&[])
        }
        IcmpTunnelFrameKind::SessionControl => {
            if reply_id.is_some() || payload_len != 0 {
                return Err(invalid_input(
                    "ICMP session-control shim cannot carry reply-ID negotiation or payload",
                ));
            }
            scratch[0] = 0;
            Ok(&scratch[..1])
        }
        IcmpTunnelFrameKind::UserPayload => {
            let mut shim = SHIM_IS_DATA | (((payload_len != 0) as u8) * SHIM_HAS_PAYLOAD);
            if let Some(negotiation) = reply_id {
                if !negotiation.negotiate && !negotiation.ack {
                    return Err(invalid_input(
                        "ICMP reply-ID shim requires negotiate and/or ack flag",
                    ));
                }
                shim |= SHIM_HAS_REPLY_ID
                    | ((negotiation.negotiate as u8) * SHIM_NEGOTIATE_REPLY_ID)
                    | ((negotiation.ack as u8) * SHIM_ACK_REPLY_ID);
                let idb = negotiation.reply_id.to_be_bytes();
                scratch[0] = shim;
                scratch[1] = idb[0];
                scratch[2] = idb[1];
                Ok(&scratch[..ICMP_TUNNEL_SHIM_MAX_LEN])
            } else {
                scratch[0] = shim;
                Ok(&scratch[..1])
            }
        }
    }
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_shim_parses_cadence_from_empty_payload() {
        assert_eq!(
            parse_icmp_tunnel_frame(&[]).unwrap(),
            IcmpTunnelFrame::Cadence
        );
    }

    #[test]
    fn framing_shim_parses_session_control_only_from_single_zero_byte() {
        assert_eq!(
            parse_icmp_tunnel_frame(&[0x00]).unwrap(),
            IcmpTunnelFrame::SessionControl
        );
        assert!(parse_icmp_tunnel_frame(&[0x00, b'x']).is_err());
    }

    #[test]
    fn framing_shim_parses_user_payload_shapes() {
        assert_eq!(
            parse_icmp_tunnel_frame(&[0x80]).unwrap(),
            IcmpTunnelFrame::UserPayload {
                bytes: &[],
                reply_id: None
            }
        );
        assert_eq!(
            parse_icmp_tunnel_frame(&[0xC0, b'a', b'b', b'c']).unwrap(),
            IcmpTunnelFrame::UserPayload {
                bytes: b"abc",
                reply_id: None
            }
        );
    }

    #[test]
    fn framing_shim_parses_reply_id_negotiation_user_frames() {
        assert_eq!(
            parse_icmp_tunnel_frame(&[0xB0, 0x20, 0x02]).unwrap(),
            IcmpTunnelFrame::UserPayload {
                bytes: &[],
                reply_id: Some(ReplyIdNegotiation {
                    reply_id: 0x2002,
                    negotiate: true,
                    ack: false
                })
            }
        );
        assert_eq!(
            parse_icmp_tunnel_frame(&[0xE8, 0x20, 0x02, b'x']).unwrap(),
            IcmpTunnelFrame::UserPayload {
                bytes: b"x",
                reply_id: Some(ReplyIdNegotiation {
                    reply_id: 0x2002,
                    negotiate: false,
                    ack: true
                })
            }
        );
    }

    #[test]
    fn framing_shim_rejects_invalid_flags_and_truncated_reply_id() {
        assert!(parse_icmp_tunnel_frame(&[0x82]).is_err());
        assert!(parse_icmp_tunnel_frame(&[0xB0, 0x20]).is_err());
        assert!(parse_icmp_tunnel_frame(&[0x20, 0x20, 0x02]).is_err());
        assert!(parse_icmp_tunnel_frame(&[0x90]).is_err());
        assert!(parse_icmp_tunnel_frame(&[0x88]).is_err());
    }

    #[test]
    fn framing_shim_rejects_incompatible_payload_flags() {
        assert!(parse_icmp_tunnel_frame(&[0xC0]).is_err());
        assert!(parse_icmp_tunnel_frame(&[0x80, b'x']).is_err());
        assert!(parse_icmp_tunnel_frame(&[0x40]).is_err());
    }

    #[test]
    fn framing_shim_serializes_current_wire_standard() {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        assert_eq!(
            encode_icmp_tunnel_prefix(IcmpTunnelFrameKind::Cadence, None, 0, &mut scratch).unwrap(),
            &[] as &[u8]
        );
        assert_eq!(
            encode_icmp_tunnel_prefix(IcmpTunnelFrameKind::SessionControl, None, 0, &mut scratch)
                .unwrap(),
            &[0x00]
        );
        assert_eq!(
            encode_icmp_tunnel_prefix(IcmpTunnelFrameKind::UserPayload, None, 0, &mut scratch)
                .unwrap(),
            &[0x80]
        );
        assert_eq!(
            encode_icmp_tunnel_prefix(IcmpTunnelFrameKind::UserPayload, None, 1, &mut scratch)
                .unwrap(),
            &[0xC0]
        );
        assert_eq!(
            encode_icmp_tunnel_prefix(
                IcmpTunnelFrameKind::UserPayload,
                Some(ReplyIdNegotiation {
                    reply_id: 0x2002,
                    negotiate: true,
                    ack: false
                }),
                1,
                &mut scratch
            )
            .unwrap(),
            &[0xF0, 0x20, 0x02]
        );
        assert_eq!(
            encode_icmp_tunnel_prefix(
                IcmpTunnelFrameKind::UserPayload,
                Some(ReplyIdNegotiation {
                    reply_id: 0x2002,
                    negotiate: true,
                    ack: true
                }),
                0,
                &mut scratch
            )
            .unwrap(),
            &[0xB8, 0x20, 0x02]
        );
    }
}
