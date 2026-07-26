use super::{
    FlowRuntimeState, HandshakeAckMatched, ObserveAckResult, PacketTraceId, PayloadEvent,
    ReplyIdHandshakeAck, ReplyIdHandshakeAckIgnored, RuntimeConfig, SocketHandles,
    debug_kernel_echo_self_handshake_ack, explicit_reply_id_ack,
};
use std::time::Instant;

#[inline]
pub(crate) fn observe_reply_id_ack(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    flow_state: &FlowRuntimeState,
    observed_at: Instant,
    ack_trace: PacketTraceId,
) -> ObserveAckResult {
    let c2u = ack_trace.c2u;
    if c2u {
        return ObserveAckResult::NotAck;
    }
    let icmp = match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => icmp,
        PayloadEvent::SessionControl { icmp, .. } => icmp,
        _ => return ObserveAckResult::NotAck,
    };
    if explicit_reply_id_ack(icmp)
        && icmp.inbound_header_ident() == handles.upstream.upstream_local_filter.id()
    {
        let Some((control, peer_reply_id)) = (match icmp.control() {
            Some(
                control @ crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(negotiation),
            ) => Some((control, negotiation.reply_id())),
            Some(
                control @ crate::net::framing_shim::IcmpTunnelControl::ChallengeAck(challenge),
            ) => Some((control, challenge.reply_id())),
            _ => None,
        }) else {
            return ObserveAckResult::NotAck;
        };
        let peer_source_id = icmp.flow_identity().remote_source_id();
        let acknowledged = flow_state.ack_upstream_icmp_control(
            icmp.inbound_header_ident(),
            control,
            icmp.seq(),
            observed_at,
            Some(ack_trace),
        );
        let result = match acknowledged {
            ReplyIdHandshakeAck::Matched {
                token,
                instance,
                expected_ack_destination_id,
                buffered_len,
                buffered_trace,
                ..
            } => {
                let handshake_trace = HandshakeAckMatched {
                    session_id: instance,
                    sequence: icmp.seq(),
                    expected_ack_destination_id,
                    observed_ack_destination_id: icmp.inbound_header_ident(),
                    peer_source_id,
                    peer_reply_id,
                    buffered_len,
                    buffered_trace,
                    trigger_trace: Some(ack_trace),
                };
                ObserveAckResult::Matched {
                    token,
                    peer_source_id,
                    peer_reply_id,
                    trigger_trace: ack_trace,
                    handshake_trace,
                }
            }
            ReplyIdHandshakeAck::ReserveReady { .. } => ObserveAckResult::ReserveReady {
                trigger_trace: ack_trace,
            },
            ReplyIdHandshakeAck::Ignored(reason) => {
                ignored_observation(reason, icmp.inbound_header_ident(), ack_trace)
            }
        };
        return result;
    }

    if debug_kernel_echo_self_handshake_ack(cfg, c2u, event, handles)
        && let Some(negotiation) = icmp.reply_id_negotiation()
    {
        let revealed_id = negotiation.reply_id();
        let observed_ack_destination_id = icmp.inbound_header_ident();
        let result = match flow_state.ack_upstream_reply_id_handshake_key(
            observed_ack_destination_id,
            negotiation.session_key(),
            icmp.seq(),
            negotiation.reset_challenge(),
            observed_at,
            Some(ack_trace),
        ) {
            ReplyIdHandshakeAck::Matched {
                token,
                instance,
                expected_ack_destination_id,
                buffered_len,
                buffered_trace,
                ..
            } => {
                let handshake_trace = HandshakeAckMatched {
                    session_id: instance,
                    sequence: icmp.seq(),
                    expected_ack_destination_id,
                    observed_ack_destination_id,
                    peer_source_id: revealed_id,
                    peer_reply_id: revealed_id,
                    buffered_len,
                    buffered_trace,
                    trigger_trace: Some(ack_trace),
                };
                ObserveAckResult::Matched {
                    token,
                    peer_source_id: revealed_id,
                    peer_reply_id: revealed_id,
                    trigger_trace: ack_trace,
                    handshake_trace,
                }
            }
            ReplyIdHandshakeAck::ReserveReady { .. } => ObserveAckResult::ReserveReady {
                trigger_trace: ack_trace,
            },
            ReplyIdHandshakeAck::Ignored(reason) => {
                ignored_observation(reason, observed_ack_destination_id, ack_trace)
            }
        };
        return result;
    }

    ObserveAckResult::NotAck
}

pub(crate) fn reply_id_ack_is_reserve_local(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
    flow_state: &FlowRuntimeState,
) -> bool {
    let PayloadEvent::SessionControl { icmp, .. } = event else {
        return false;
    };
    let key = if explicit_reply_id_ack(icmp)
        && icmp.inbound_header_ident() == handles.upstream.upstream_local_filter.id()
    {
        match icmp.control() {
            Some(crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(negotiation)) => {
                negotiation.session_key()
            }
            Some(crate::net::framing_shim::IcmpTunnelControl::ChallengeAck(challenge)) => {
                challenge.new_session()
            }
            _ => return false,
        }
    } else if debug_kernel_echo_self_handshake_ack(cfg, false, event, handles) {
        let Some(negotiation) = icmp.reply_id_negotiation() else {
            return false;
        };
        negotiation.session_key()
    } else {
        return false;
    };
    flow_state.upstream_ack_key_is_reserve_local(key)
}

pub(super) fn ignored_observation(
    reason: ReplyIdHandshakeAckIgnored,
    observed_ack_destination_id: u16,
    trigger_trace: PacketTraceId,
) -> ObserveAckResult {
    ObserveAckResult::Ignored {
        reason,
        observed_ack_destination_id,
        trigger_trace,
    }
}
