use super::{
    ChallengeControl, ICMP_CONTROL_CHALLENGE_ACK, ICMP_CONTROL_CHALLENGE_NEGOTIATE,
    ICMP_CONTROL_GENERATION_ADVANCE, ICMP_CONTROL_GENERATION_ADVANCE_ACK, ICMP_CONTROL_NEGOTIATE,
    ICMP_CONTROL_NEGOTIATE_ACK, ICMP_CONTROL_RESET_REQUIRED, ICMP_CONTROL_SESSION_ACTIVATED,
    ICMP_TUNNEL_CHALLENGE_BODY_LEN, ICMP_TUNNEL_CONTROL_VERSION, ICMP_TUNNEL_EXPLICIT_SOURCE_LEN,
    ICMP_TUNNEL_FLAGS_LEN, ICMP_TUNNEL_POOL_GENERATION_LEN, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
    ICMP_TUNNEL_SESSION_KEY_LEN, ICMP_TUNNEL_SESSION_ORDINAL_LEN, ICMP_TUNNEL_SHIM_MAX_LEN,
    IcmpTunnelControl, IcmpTunnelFrameKind, PoolGeneration, RejectedFrameEvidence,
    ReplyIdNegotiation, ResetRequired, SHIM_IS_CADENCE, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER,
    SessionId, SessionKey, icmp_control_body_len,
};
use std::io;

pub(crate) fn encode_icmp_tunnel_prefix_with_source(
    kind: IcmpTunnelFrameKind,
    echo_header_id: u16,
    source_id: u16,
    session_id: SessionId,
    reply_id: Option<ReplyIdNegotiation>,
    payload_len: usize,
    scratch: &mut [u8; ICMP_TUNNEL_SHIM_MAX_LEN],
) -> io::Result<&[u8]> {
    match kind {
        IcmpTunnelFrameKind::Cadence => {
            if source_id == 0 {
                return Err(invalid_input("ICMP cadence shim requires source ID"));
            }
            if reply_id.is_some() || payload_len != 0 {
                return Err(invalid_input("ICMP cadence frame cannot carry shim data"));
            }
            if source_id == echo_header_id {
                scratch[0] = SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER;
                scratch[1..9].copy_from_slice(&session_id.get().to_be_bytes());
                return Ok(&scratch[..9]);
            }
            scratch[0] = SHIM_IS_CADENCE;
            scratch[1] = (source_id >> 8) as u8;
            scratch[2] = source_id as u8;
            scratch[3..11].copy_from_slice(&session_id.get().to_be_bytes());
            Ok(&scratch[..11])
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
                scratch[1..9].copy_from_slice(&session_id.get().to_be_bytes());
                return Ok(&scratch[..9]);
            }
            scratch[0] = SHIM_IS_DATA;
            scratch[1] = (source_id >> 8) as u8;
            scratch[2] = source_id as u8;
            scratch[3..11].copy_from_slice(&session_id.get().to_be_bytes());
            Ok(&scratch[..11])
        }
        #[cfg(test)]
        IcmpTunnelFrameKind::SessionControl => {
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
            if negotiation.instance() != session_id {
                return Err(invalid_input(
                    "ICMP control session ID does not match negotiation",
                ));
            }
            let control = if negotiation.is_negotiate() {
                IcmpTunnelControl::Negotiate(negotiation)
            } else {
                IcmpTunnelControl::NegotiateAck(negotiation)
            };
            encode_icmp_control_prefix_with_source(control, echo_header_id, source_id, scratch)
        }
        #[cfg(test)]
        IcmpTunnelFrameKind::ResetRequired(reset) => {
            if payload_len != 0 || reply_id.is_some() {
                return Err(invalid_input(
                    "ICMP reset-required control requires source identity and no payload",
                ));
            }
            if reset.rejected_session() != session_id {
                return Err(invalid_input(
                    "ICMP reset-required session does not match rejected session",
                ));
            }
            encode_icmp_control_prefix_with_source(
                IcmpTunnelControl::ResetRequired(reset),
                echo_header_id,
                source_id,
                scratch,
            )
        }
    }
}

pub(crate) fn encode_icmp_control_prefix_with_source(
    control: IcmpTunnelControl,
    echo_header_id: u16,
    source_id: u16,
    scratch: &mut [u8; ICMP_TUNNEL_SHIM_MAX_LEN],
) -> io::Result<&[u8]> {
    if source_id == 0 {
        return Err(invalid_input("ICMP control requires a nonzero source ID"));
    }
    let opcode = control_opcode(control);
    let body_len = icmp_control_body_len(opcode);
    if body_len == 0 {
        return Err(invalid_input("ICMP control opcode has no encoded body"));
    }
    let source_len = if source_id == echo_header_id {
        scratch[0] = SHIM_SOURCE_ID_EQUALS_HEADER;
        ICMP_TUNNEL_FLAGS_LEN
    } else {
        scratch[0] = 0;
        scratch[1..3].copy_from_slice(&source_id.to_be_bytes());
        ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_EXPLICIT_SOURCE_LEN
    };
    write_control_body(control, &mut scratch[source_len..source_len + body_len])?;
    Ok(&scratch[..source_len + body_len])
}

pub(super) const fn control_opcode(control: IcmpTunnelControl) -> u8 {
    match control {
        IcmpTunnelControl::Negotiate(_) => ICMP_CONTROL_NEGOTIATE,
        IcmpTunnelControl::NegotiateAck(_) => ICMP_CONTROL_NEGOTIATE_ACK,
        IcmpTunnelControl::ResetRequired(_) => ICMP_CONTROL_RESET_REQUIRED,
        IcmpTunnelControl::ChallengeNegotiate(_) => ICMP_CONTROL_CHALLENGE_NEGOTIATE,
        IcmpTunnelControl::ChallengeAck(_) => ICMP_CONTROL_CHALLENGE_ACK,
        IcmpTunnelControl::GenerationAdvance(_) => ICMP_CONTROL_GENERATION_ADVANCE,
        IcmpTunnelControl::GenerationAdvanceAck(_) => ICMP_CONTROL_GENERATION_ADVANCE_ACK,
        IcmpTunnelControl::SessionActivated(_) => ICMP_CONTROL_SESSION_ACTIVATED,
    }
}

pub(super) fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(super) fn write_control_body(control: IcmpTunnelControl, body: &mut [u8]) -> io::Result<()> {
    let opcode = control_opcode(control);
    if body.len() != icmp_control_body_len(opcode) {
        return Err(invalid_input("ICMP control body length mismatch"));
    }
    body[0] = ICMP_TUNNEL_CONTROL_VERSION;
    body[1] = opcode;
    match control {
        IcmpTunnelControl::Negotiate(negotiation)
        | IcmpTunnelControl::NegotiateAck(negotiation) => {
            body[2..4].copy_from_slice(&negotiation.reply_id().to_be_bytes());
            write_session_key(negotiation.session_key(), &mut body[4..24])?;
        }
        IcmpTunnelControl::ResetRequired(reset) => write_reset_required_body(reset, body)?,
        IcmpTunnelControl::ChallengeNegotiate(challenge)
        | IcmpTunnelControl::ChallengeAck(challenge) => {
            write_challenge_body(challenge, body)?;
        }
        IcmpTunnelControl::GenerationAdvance(advance)
        | IcmpTunnelControl::GenerationAdvanceAck(advance) => {
            write_session_key(advance.current(), &mut body[2..22])?;
            body[22..30].copy_from_slice(&advance.proposed_generation().get().to_be_bytes());
        }
        IcmpTunnelControl::SessionActivated(activated) => {
            write_session_key(activated.session_key(), &mut body[2..22])?;
            body[22..24].copy_from_slice(&activated.accepted_sequence().to_be_bytes());
        }
    }
    Ok(())
}

fn write_session_key(session_key: SessionKey, body: &mut [u8]) -> io::Result<()> {
    if body.len() != ICMP_TUNNEL_SESSION_KEY_LEN {
        return Err(invalid_input("ICMP session-key body length mismatch"));
    }
    body[..ICMP_TUNNEL_POOL_GENERATION_LEN]
        .copy_from_slice(&session_key.pool_generation().to_be_bytes());
    body[ICMP_TUNNEL_POOL_GENERATION_LEN
        ..ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN]
        .copy_from_slice(&session_key.ordinal().to_be_bytes());
    body[ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN..]
        .copy_from_slice(&session_key.session_id().get().to_be_bytes());
    Ok(())
}

fn write_reset_required_body(reset: ResetRequired, body: &mut [u8]) -> io::Result<()> {
    if body.len() != ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN {
        return Err(invalid_input("ICMP reset-required body length mismatch"));
    }
    body[2] = reset.rejected_kind() as u8;
    body[3..11].copy_from_slice(&reset.rejected_session().get().to_be_bytes());
    body[11..13].copy_from_slice(&reset.rejected_sequence().to_be_bytes());
    body[13..21].copy_from_slice(
        &reset
            .receiver_generation()
            .map_or(0, PoolGeneration::get)
            .to_be_bytes(),
    );
    body[21..29].copy_from_slice(&reset.challenge().get().to_be_bytes());
    Ok(())
}

fn write_challenge_body(challenge: ChallengeControl, body: &mut [u8]) -> io::Result<()> {
    if body.len() != ICMP_TUNNEL_CHALLENGE_BODY_LEN {
        return Err(invalid_input("ICMP challenge body length mismatch"));
    }
    body[2..4].copy_from_slice(&challenge.reply_id().to_be_bytes());
    body[4..12].copy_from_slice(&challenge.challenge().get().to_be_bytes());
    body[12..20].copy_from_slice(
        &challenge
            .receiver_generation()
            .map_or(0, PoolGeneration::get)
            .to_be_bytes(),
    );
    body[20] = challenge.rejected().kind() as u8;
    write_rejected_key(challenge.rejected(), &mut body[21..41])?;
    body[41..43].copy_from_slice(&challenge.rejected().sequence().to_be_bytes());
    write_session_key(challenge.new_session(), &mut body[43..63])?;
    Ok(())
}

fn write_rejected_key(rejected: RejectedFrameEvidence, body: &mut [u8]) -> io::Result<()> {
    if body.len() != ICMP_TUNNEL_SESSION_KEY_LEN {
        return Err(invalid_input("ICMP rejected-key body length mismatch"));
    }
    match rejected {
        RejectedFrameEvidence::Data { session, .. } => {
            body.fill(0);
            body[ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN..]
                .copy_from_slice(&session.get().to_be_bytes());
        }
        RejectedFrameEvidence::Negotiate { candidate, .. } => {
            write_session_key(candidate, body)?;
        }
    }
    Ok(())
}
