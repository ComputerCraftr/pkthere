use super::{
    ICMP_CONTROL_CHALLENGE_ACK, ICMP_CONTROL_CHALLENGE_NEGOTIATE, ICMP_CONTROL_GENERATION_ADVANCE,
    ICMP_CONTROL_GENERATION_ADVANCE_ACK, ICMP_CONTROL_NEGOTIATE, ICMP_CONTROL_NEGOTIATE_ACK,
    ICMP_CONTROL_RESET_REQUIRED, ICMP_CONTROL_SESSION_ACTIVATED, ICMP_TUNNEL_CHALLENGE_BODY_LEN,
    ICMP_TUNNEL_CONTROL_HEADER_LEN, ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN,
    ICMP_TUNNEL_NEGOTIATE_BODY_LEN, ICMP_TUNNEL_POOL_GENERATION_LEN,
    ICMP_TUNNEL_RESET_CHALLENGE_LEN, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
    ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN, ICMP_TUNNEL_SESSION_KEY_LEN,
    ICMP_TUNNEL_SESSION_ORDINAL_LEN, has_len, read_be16,
};

pub const fn icmp_control_body_len(opcode: u8) -> usize {
    match opcode {
        ICMP_CONTROL_NEGOTIATE | ICMP_CONTROL_NEGOTIATE_ACK => ICMP_TUNNEL_NEGOTIATE_BODY_LEN,
        ICMP_CONTROL_RESET_REQUIRED => ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
        ICMP_CONTROL_CHALLENGE_NEGOTIATE | ICMP_CONTROL_CHALLENGE_ACK => {
            ICMP_TUNNEL_CHALLENGE_BODY_LEN
        }
        ICMP_CONTROL_GENERATION_ADVANCE | ICMP_CONTROL_GENERATION_ADVANCE_ACK => {
            ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN
        }
        ICMP_CONTROL_SESSION_ACTIVATED => ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN,
        _ => 0,
    }
}

#[inline]
pub(super) const fn control_session_id_offset(opcode: u8) -> usize {
    match opcode {
        ICMP_CONTROL_NEGOTIATE | ICMP_CONTROL_NEGOTIATE_ACK => {
            ICMP_TUNNEL_CONTROL_HEADER_LEN
                + size_of::<u16>()
                + ICMP_TUNNEL_POOL_GENERATION_LEN
                + ICMP_TUNNEL_SESSION_ORDINAL_LEN
        }
        ICMP_CONTROL_RESET_REQUIRED => ICMP_TUNNEL_CONTROL_HEADER_LEN + size_of::<u8>(),
        ICMP_CONTROL_CHALLENGE_NEGOTIATE | ICMP_CONTROL_CHALLENGE_ACK => {
            ICMP_TUNNEL_CONTROL_HEADER_LEN
                + size_of::<u16>()
                + ICMP_TUNNEL_RESET_CHALLENGE_LEN
                + ICMP_TUNNEL_POOL_GENERATION_LEN
                + size_of::<u8>()
                + ICMP_TUNNEL_SESSION_KEY_LEN
                + size_of::<u16>()
                + ICMP_TUNNEL_POOL_GENERATION_LEN
                + ICMP_TUNNEL_SESSION_ORDINAL_LEN
        }
        ICMP_CONTROL_GENERATION_ADVANCE | ICMP_CONTROL_GENERATION_ADVANCE_ACK => {
            ICMP_TUNNEL_CONTROL_HEADER_LEN
                + ICMP_TUNNEL_POOL_GENERATION_LEN
                + ICMP_TUNNEL_SESSION_ORDINAL_LEN
        }
        ICMP_CONTROL_SESSION_ACTIVATED => {
            ICMP_TUNNEL_CONTROL_HEADER_LEN
                + ICMP_TUNNEL_POOL_GENERATION_LEN
                + ICMP_TUNNEL_SESSION_ORDINAL_LEN
        }
        _ => 0,
    }
}

#[inline]
pub(super) const fn control_opcode_has_reply_id(opcode: u8) -> usize {
    matches!(
        opcode,
        ICMP_CONTROL_NEGOTIATE
            | ICMP_CONTROL_NEGOTIATE_ACK
            | ICMP_CONTROL_CHALLENGE_NEGOTIATE
            | ICMP_CONTROL_CHALLENGE_ACK
    ) as usize
}

#[inline]
pub(super) const fn read_control_reply_id(
    packet: &[u8],
    packet_len: usize,
    body_offset: usize,
    eligible_control: usize,
    opcode: u8,
) -> (u16, usize) {
    let has_reply_id = control_opcode_has_reply_id(opcode);
    let reply_id_present = has_len(
        packet_len,
        body_offset + ICMP_TUNNEL_CONTROL_HEADER_LEN + size_of::<u16>(),
    );
    let valid = eligible_control & has_reply_id & reply_id_present;
    (
        read_be16(packet, body_offset + ICMP_TUNNEL_CONTROL_HEADER_LEN, valid),
        valid,
    )
}
