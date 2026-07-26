use super::{
    ICMP_EXPLICIT_SOURCE_SHIM_LEN, ICMP_SHIM_FLAGS_LEN, ICMP_TUNNEL_CONTROL_HEADER_LEN,
    ICMP_TUNNEL_CONTROL_VERSION, ICMP_TUNNEL_SESSION_ID_LEN, IcmpMalformedReason,
    SHIM_ALLOWED_BITS, SHIM_IS_CADENCE, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER, bool01,
    byte_at, control_session_id_offset, has_len, icmp_control_body_len, not01, read_be16,
    read_be64, read_control_reply_id,
};

#[derive(Clone, Copy)]
pub(super) struct ParsedIcmpShim {
    pub(super) has_shim: usize,
    pub(super) explicit_source: usize,
    pub(super) malformed: usize,
    pub(super) flags: u8,
    pub(super) reason: Option<IcmpMalformedReason>,
    pub(super) session_id: u64,
    pub(super) payload_start: usize,
}

#[inline]
pub(super) const fn parse_icmp_shim(
    b: &[u8],
    n: usize,
    payload_off: usize,
    icmp_with_payload: usize,
) -> ParsedIcmpShim {
    let shim_flags = byte_at(b, payload_off, icmp_with_payload);

    let shim_has_only_known_flags = ((shim_flags & !SHIM_ALLOWED_BITS) == 0) as usize;
    let shim_uses_header_id = ((shim_flags & SHIM_SOURCE_ID_EQUALS_HEADER) != 0) as usize;
    let shim_is_data = ((shim_flags & SHIM_IS_DATA) != 0) as usize;
    let shim_is_cadence = ((shim_flags & SHIM_IS_CADENCE) != 0) as usize;
    let explicit_shim_has_src_bytes =
        icmp_with_payload & has_len(n, payload_off + ICMP_EXPLICIT_SOURCE_SHIM_LEN);
    let basic_flags_ok = shim_has_only_known_flags;
    let source_shape_ok = shim_uses_header_id | explicit_shim_has_src_bytes;
    let source_field_len =
        [ICMP_EXPLICIT_SOURCE_SHIM_LEN, ICMP_SHIM_FLAGS_LEN][shim_uses_header_id];
    let body_off = payload_off + source_field_len;
    let body_len = n.saturating_sub(body_off);
    let data_or_cadence = shim_is_data | shim_is_cadence;
    let control_frame = not01(data_or_cadence);

    let explicit_source_id = read_be16(
        b,
        payload_off + ICMP_SHIM_FLAGS_LEN,
        explicit_shim_has_src_bytes & not01(shim_uses_header_id),
    );
    let explicit_source_zero = basic_flags_ok
        & source_shape_ok
        & not01(shim_uses_header_id)
        & bool01(explicit_source_id == 0);

    let illegal_data_flags = basic_flags_ok & source_shape_ok & shim_is_data & shim_is_cadence;
    let illegal_cadence_shape = basic_flags_ok
        & source_shape_ok
        & shim_is_cadence
        & bool01(shim_is_data != 0 || body_len != ICMP_TUNNEL_SESSION_ID_LEN);
    let data_session_too_short = basic_flags_ok
        & source_shape_ok
        & data_or_cadence
        & bool01(body_len < ICMP_TUNNEL_SESSION_ID_LEN);

    let control_header_present = has_len(n, body_off + ICMP_TUNNEL_CONTROL_HEADER_LEN);
    let control_version = byte_at(b, body_off, control_header_present);
    let control_opcode = byte_at(b, body_off + 1, control_header_present);
    let expected_control_len = icmp_control_body_len(control_opcode);
    let known_control_opcode = bool01(expected_control_len != 0);
    let control_length_invalid =
        control_frame & bool01(body_len != expected_control_len || expected_control_len == 0);
    let control_flags_invalid = control_frame
        & bool01(control_version != ICMP_TUNNEL_CONTROL_VERSION || known_control_opcode == 0);
    let (reply_id, reply_id_valid) = read_control_reply_id(
        b,
        n,
        body_off,
        control_frame & control_header_present & known_control_opcode,
        control_opcode,
    );
    let reply_id_zero = reply_id_valid & bool01(reply_id == 0);

    let shim_is_valid = basic_flags_ok
        & source_shape_ok
        & not01(explicit_source_zero)
        & not01(data_session_too_short)
        & not01(illegal_data_flags)
        & not01(illegal_cadence_shape)
        & not01(control_length_invalid)
        & not01(control_flags_invalid)
        & not01(reply_id_zero);

    let has_shim = icmp_with_payload & shim_is_valid;
    let explicit_icmp_src = has_shim & not01(shim_uses_header_id);
    let malformed_shim = icmp_with_payload & not01(shim_is_valid);
    let invalid_flags = icmp_with_payload & not01(basic_flags_ok);
    let truncated_source = icmp_with_payload
        & basic_flags_ok
        & not01(shim_uses_header_id)
        & not01(explicit_shim_has_src_bytes);
    let illegal_frame = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & (illegal_data_flags | illegal_cadence_shape);
    let invalid_control_flags = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & control_flags_invalid;
    let invalid_reply_length = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & not01(invalid_control_flags)
        & control_length_invalid;
    let zero_source = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & not01(invalid_control_flags)
        & not01(invalid_reply_length)
        & explicit_source_zero;
    let zero_reply = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(illegal_frame)
        & not01(invalid_control_flags)
        & not01(invalid_reply_length)
        & not01(zero_source)
        & reply_id_zero;
    let control_session_offset = control_session_id_offset(control_opcode);
    let session_id_off = body_off + (control_frame * control_session_offset);
    let session_id = read_be64(
        b,
        session_id_off,
        icmp_with_payload
            & basic_flags_ok
            & source_shape_ok
            & not01(data_session_too_short)
            & not01(control_length_invalid)
            & not01(control_flags_invalid),
    );
    let zero_session = icmp_with_payload
        & basic_flags_ok
        & source_shape_ok
        & not01(data_session_too_short)
        & not01(control_length_invalid)
        & not01(control_flags_invalid)
        & bool01(session_id == 0);
    let previous_reason = invalid_flags
        | truncated_source
        | illegal_frame
        | invalid_control_flags
        | invalid_reply_length
        | zero_source
        | zero_reply;
    let missing_session_reason = data_session_too_short & not01(previous_reason);
    let zero_session_reason = zero_session & not01(previous_reason | missing_session_reason);
    let reason_code = invalid_flags
        | (truncated_source * 2)
        | (illegal_frame * 3)
        | (invalid_control_flags * 4)
        | (invalid_reply_length * 5)
        | (zero_source * 6)
        | (zero_reply * 7)
        | (missing_session_reason * 8)
        | (zero_session_reason * 9);
    let reason = [
        None,
        Some(IcmpMalformedReason::InvalidShimFlags),
        Some(IcmpMalformedReason::TruncatedSourceId),
        Some(IcmpMalformedReason::IllegalFrameFlags),
        Some(IcmpMalformedReason::InvalidSessionControlFlags),
        Some(IcmpMalformedReason::SessionControlReplyIdLength),
        Some(IcmpMalformedReason::ZeroSourceId),
        Some(IcmpMalformedReason::ZeroReplyId),
        Some(IcmpMalformedReason::MissingSessionId),
        Some(IcmpMalformedReason::ZeroSessionId),
    ][reason_code];

    ParsedIcmpShim {
        has_shim,
        explicit_source: explicit_icmp_src,
        malformed: malformed_shim,
        flags: shim_flags,
        reason,
        session_id,
        payload_start: body_off + (ICMP_TUNNEL_SESSION_ID_LEN * data_or_cadence),
    }
}
