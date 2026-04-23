use crate::net::packet_headers::{
    IcmpMalformedReason, SHIM_ACK_REPLY_ID, SHIM_HAS_REPLY_ID, SHIM_IS_DATA,
    SHIM_NEGOTIATE_REPLY_ID, SHIM_SOURCE_ID_EQUALS_HEADER,
};
use pkthere_wire::be16_16;
use std::io;

pub(crate) const ICMP_TUNNEL_SHIM_MAX_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplyIdNegotiation {
    pub(crate) reply_id: u16,
    pub(crate) negotiate: bool,
    pub(crate) ack: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpTunnelFrameKind {
    Cadence,
    UserPayload,
    SessionControl,
}

pub(crate) fn parse_icmp_reply_negotiation(
    shim: u8,
    payload: &[u8],
) -> Result<Option<ReplyIdNegotiation>, IcmpMalformedReason> {
    if (shim & SHIM_IS_DATA) != 0 {
        if (shim & (SHIM_NEGOTIATE_REPLY_ID | SHIM_ACK_REPLY_ID | SHIM_HAS_REPLY_ID)) != 0 {
            return Err(IcmpMalformedReason::IllegalFrameFlags);
        }
        return Ok(None);
    }

    if (shim & SHIM_HAS_REPLY_ID) == 0 {
        return Err(IcmpMalformedReason::SessionControlMissingReplyId);
    }
    if payload.len() != 2 {
        return Err(IcmpMalformedReason::SessionControlReplyIdLength);
    }

    Ok(Some(ReplyIdNegotiation {
        reply_id: be16_16(payload[0], payload[1]),
        negotiate: (shim & SHIM_NEGOTIATE_REPLY_ID) != 0,
        ack: (shim & SHIM_ACK_REPLY_ID) != 0,
    }))
}

pub(crate) fn encode_icmp_tunnel_prefix_with_source(
    kind: IcmpTunnelFrameKind,
    echo_header_id: u16,
    source_id: u16,
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
        IcmpTunnelFrameKind::UserPayload => {
            if source_id == 0 {
                return Err(invalid_input("ICMP user-data shim requires source ID"));
            }
            if reply_id.is_some() {
                return Err(invalid_input(
                    "ICMP user-data shim cannot carry reply-ID negotiation",
                ));
            }
            if source_id == echo_header_id {
                scratch[0] = SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER;
                return Ok(&scratch[..1]);
            }
            scratch[0] = SHIM_IS_DATA;
            scratch[1] = (source_id >> 8) as u8;
            scratch[2] = source_id as u8;
            Ok(&scratch[..3])
        }
        IcmpTunnelFrameKind::SessionControl => {
            if source_id == 0 {
                return Err(invalid_input(
                    "ICMP session-control shim requires source ID",
                ));
            }
            if payload_len != 0 {
                return Err(invalid_input(
                    "ICMP session-control shim cannot carry payload",
                ));
            }
            let Some(negotiation) = reply_id else {
                return Err(invalid_input(
                    "ICMP session-control shim requires reply endpoint ID",
                ));
            };

            let flags = ((negotiation.negotiate as u8) * SHIM_NEGOTIATE_REPLY_ID)
                | ((negotiation.ack as u8) * SHIM_ACK_REPLY_ID)
                | SHIM_HAS_REPLY_ID;

            if source_id == echo_header_id {
                scratch[0] = flags | SHIM_SOURCE_ID_EQUALS_HEADER;
                scratch[1] = (negotiation.reply_id >> 8) as u8;
                scratch[2] = negotiation.reply_id as u8;
                return Ok(&scratch[..3]);
            }

            scratch[0] = flags;
            scratch[1] = (source_id >> 8) as u8;
            scratch[2] = source_id as u8;
            scratch[3] = (negotiation.reply_id >> 8) as u8;
            scratch[4] = negotiation.reply_id as u8;
            Ok(&scratch[..5])
        }
    }
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod tests {
    use super::{
        ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelFrameKind, ReplyIdNegotiation, SHIM_ACK_REPLY_ID,
        SHIM_HAS_REPLY_ID, SHIM_IS_DATA, SHIM_NEGOTIATE_REPLY_ID, SHIM_SOURCE_ID_EQUALS_HEADER,
        encode_icmp_tunnel_prefix_with_source, parse_icmp_reply_negotiation,
    };

    #[test]
    fn framing_shim_parses_user_payload_as_no_reply_negotiation() {
        assert_eq!(
            parse_icmp_reply_negotiation(SHIM_IS_DATA, b"hi").unwrap(),
            None
        );
    }

    #[test]
    fn framing_shim_parses_session_control_reply_id() {
        assert_eq!(
            parse_icmp_reply_negotiation(
                SHIM_NEGOTIATE_REPLY_ID | SHIM_HAS_REPLY_ID,
                &[0x30, 0x03]
            )
            .unwrap(),
            Some(ReplyIdNegotiation {
                reply_id: 0x3003,
                negotiate: true,
                ack: false,
            })
        );
    }

    #[test]
    fn framing_shim_parses_compact_session_control() {
        assert_eq!(
            parse_icmp_reply_negotiation(
                SHIM_SOURCE_ID_EQUALS_HEADER | SHIM_HAS_REPLY_ID | SHIM_ACK_REPLY_ID,
                &[0x44, 0x44],
            )
            .unwrap(),
            Some(ReplyIdNegotiation {
                reply_id: 0x4444,
                negotiate: false,
                ack: true,
            })
        );
    }

    #[test]
    fn framing_shim_rejects_non_data_without_reply_id_bit() {
        assert!(parse_icmp_reply_negotiation(SHIM_NEGOTIATE_REPLY_ID, &[0x30, 0x03]).is_err());
    }

    #[test]
    fn framing_shim_rejects_user_payload_reply_negotiation_bits() {
        assert!(parse_icmp_reply_negotiation(SHIM_IS_DATA | SHIM_HAS_REPLY_ID, b"").is_err());
    }

    #[test]
    fn framing_shim_encodes_explicit_user_payload_source_id() {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        assert_eq!(
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::UserPayload,
                0x1001,
                0x2002,
                None,
                2,
                &mut scratch,
            )
            .unwrap(),
            &[SHIM_IS_DATA, 0x20, 0x02]
        );
    }

    #[test]
    fn framing_shim_encodes_compact_user_payload_source_id() {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        assert_eq!(
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::UserPayload,
                0x2002,
                0x2002,
                None,
                2,
                &mut scratch,
            )
            .unwrap(),
            &[SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER]
        );
    }

    #[test]
    fn framing_shim_encodes_explicit_session_control() {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        assert_eq!(
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::SessionControl,
                0x9999,
                0x2002,
                Some(ReplyIdNegotiation {
                    reply_id: 0x3003,
                    negotiate: true,
                    ack: false,
                }),
                0,
                &mut scratch,
            )
            .unwrap(),
            &[
                SHIM_NEGOTIATE_REPLY_ID | SHIM_HAS_REPLY_ID,
                0x20,
                0x02,
                0x30,
                0x03,
            ]
        );
    }

    #[test]
    fn framing_shim_encodes_compact_session_control() {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        assert_eq!(
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::SessionControl,
                0x2002,
                0x2002,
                Some(ReplyIdNegotiation {
                    reply_id: 0x3003,
                    negotiate: true,
                    ack: false,
                }),
                0,
                &mut scratch,
            )
            .unwrap(),
            &[
                SHIM_NEGOTIATE_REPLY_ID | SHIM_HAS_REPLY_ID | SHIM_SOURCE_ID_EQUALS_HEADER,
                0x30,
                0x03,
            ]
        );
    }
}
