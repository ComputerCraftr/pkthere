use super::SessionAuthority;
use crate::flow_state::session_lifecycles::ControlSendCore;
use crate::flow_state::{
    ControlObservationLanes, ControlTransactionKey, DroppedReplyIdHandshake,
    ExpiredReplyIdHandshake, ReplyIdHandshake,
};
use std::time::Instant;

pub(in crate::flow_state) fn expire_handshake(
    state: &SessionAuthority,
    control_observations: &ControlObservationLanes,
    flow_epoch: u64,
    now: Instant,
) -> Option<ExpiredReplyIdHandshake> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let pending_key = sessions.control.upstream_pending_key;
    let pending_challenge = sessions.control.upstream_pending_challenge;
    let peer_flow = sessions.authority.client_flow;
    let blocks = |expected_ack_destination_id, deadline, control: &ControlSendCore| {
        let Some(session_key) = pending_key else {
            return false;
        };
        control_observations.blocks_matching(deadline, |observed| {
            let sequence = observed.sequence();
            if !control.acknowledges(sequence) {
                return false;
            }
            let control = match pending_challenge {
                Some(challenge) => {
                    crate::net::framing_shim::IcmpTunnelControl::ChallengeAck(challenge)
                }
                None => {
                    let Some(ack) =
                        crate::net::framing_shim::ReplyIdNegotiation::acknowledge_key_and_challenge(
                            expected_ack_destination_id,
                            session_key,
                            0,
                        )
                    else {
                        return false;
                    };
                    crate::net::framing_shim::IcmpTunnelControl::NegotiateAck(ack)
                }
            };
            let expected = ControlTransactionKey::new(
                flow_epoch,
                false,
                peer_flow,
                crate::net::payload::IcmpPayloadMeta::new_control(
                    expected_ack_destination_id,
                    expected_ack_destination_id,
                    sequence,
                    control,
                ),
            );
            if observed.matches_key(expected) {
                return true;
            }
            // The explicitly configured kernel-echo compatibility path sees
            // the reflected request rather than a protocol-v3 ACK. It still
            // has to match the complete request transaction.
            let reflected = pending_challenge.is_none().then(|| {
                let request = crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key(
                    expected_ack_destination_id,
                    session_key,
                )?;
                Some(ControlTransactionKey::new(
                    flow_epoch,
                    false,
                    peer_flow,
                    crate::net::payload::IcmpPayloadMeta::new_control(
                        expected_ack_destination_id,
                        expected_ack_destination_id,
                        sequence,
                        crate::net::framing_shim::IcmpTunnelControl::Negotiate(request),
                    ),
                ))
            });
            reflected
                .flatten()
                .is_some_and(|key| observed.matches_key(key))
        })
    };
    let expired = match &mut sessions.control.upstream_reply_id_handshake {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            payload,
            control,
            ..
        } if !blocks(*expected_ack_destination_id, *absolute_deadline, control)
            && now >= *absolute_deadline =>
        {
            Some(ExpiredReplyIdHandshake {
                expected_ack_destination_id: *expected_ack_destination_id,
                instance: *instance,
                started_s: *started_s,
                buffered_len: payload.payload_len(),
                buffered_trace: payload.trace(),
            })
        }
        ReplyIdHandshake::AckedRetryable {
            commit,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            ..
        } if now >= *absolute_deadline => commit.payload().map(|payload| ExpiredReplyIdHandshake {
            expected_ack_destination_id: *expected_ack_destination_id,
            instance: *instance,
            started_s: *started_s,
            buffered_len: payload.payload_len(),
            buffered_trace: payload.trace(),
        }),
        ReplyIdHandshake::Sending {
            started_s,
            absolute_deadline,
            commit,
            ..
        } if now >= *absolute_deadline => {
            commit.request_timeout();
            None
        }
        ReplyIdHandshake::Committing {
            started_s,
            absolute_deadline,
            commit,
            ..
        } if now >= *absolute_deadline => {
            commit.request_timeout();
            None
        }
        ReplyIdHandshake::Pending { .. }
        | ReplyIdHandshake::Committing { .. }
        | ReplyIdHandshake::Sending { .. }
        | ReplyIdHandshake::AckedRetryable { .. }
        | ReplyIdHandshake::NotRequired
        | ReplyIdHandshake::Acked { .. } => None,
    };
    if expired.is_some() {
        sessions.authority.upstream_leg.transmit = None;
        sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::NotRequired;
    }
    expired
}

pub(in crate::flow_state) fn take_pending_handshake_locked(
    handshake: &mut ReplyIdHandshake,
) -> Option<DroppedReplyIdHandshake> {
    let previous = std::mem::replace(handshake, ReplyIdHandshake::NotRequired);
    match previous {
        ReplyIdHandshake::Pending {
            expected_ack_destination_id,
            instance,
            payload,
            ..
        } => Some(DroppedReplyIdHandshake {
            expected_ack_destination_id,
            instance,
            buffered_len: payload.payload_len(),
            buffered_trace: payload.trace(),
        }),
        ReplyIdHandshake::Committing {
            commit,
            expected_ack_destination_id,
            instance,
            ..
        }
        | ReplyIdHandshake::AckedRetryable {
            commit,
            expected_ack_destination_id,
            instance,
            ..
        } => commit.payload().map(|payload| DroppedReplyIdHandshake {
            expected_ack_destination_id,
            instance,
            buffered_len: payload.payload_len(),
            buffered_trace: payload.trace(),
        }),
        ReplyIdHandshake::Sending { .. }
        | ReplyIdHandshake::NotRequired
        | ReplyIdHandshake::Acked { .. } => None,
    }
}
