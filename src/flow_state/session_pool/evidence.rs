use super::ReplyIdHandshake;
use crate::flow_state::{
    ControlObservationLanes, FlowSessionState, MAX_RECEIVE_SESSION_CANDIDATES,
};
use crate::net::framing_shim::SessionKey;
use std::time::Instant;

pub(super) fn rollover_challenge_matches(
    sessions: &FlowSessionState,
    reset: crate::net::framing_shim::ResetRequired,
    expected_ack_destination_id: u16,
    now: Instant,
) -> bool {
    let receiver_generation_matches = reset.receiver_generation().is_none()
        || reset.receiver_generation()
            == sessions
                .upstream_pool
                .upstream_active_key
                .map(SessionKey::generation);
    receiver_generation_matches
        && (sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter()
            .any(|candidate| {
                now < candidate.control.deadline()
                    && candidate.expected_ack_destination_id == expected_ack_destination_id
                    && candidate.session_key.session_id() == reset.rejected_session()
                    && candidate.control.acknowledges(reset.rejected_sequence())
            })
            || (sessions
                .control
                .upstream_pending_key
                .is_some_and(|key| key.session_id() == reset.rejected_session())
                && matches!(
                    &sessions.control.upstream_reply_id_handshake,
                    ReplyIdHandshake::Pending {
                        expected_ack_destination_id: pending_destination,
                        control,
                        ..
                    } if *pending_destination == expected_ack_destination_id
                        && control.acknowledges(reset.rejected_sequence())
                )))
}

pub(super) fn rollover_challenge_is_in_flight(
    sessions: &FlowSessionState,
    reset: crate::net::framing_shim::ResetRequired,
    expected_ack_destination_id: u16,
    now: Instant,
) -> bool {
    sessions
        .upstream_pool
        .upstream_reserve_handshakes
        .iter()
        .any(|candidate| {
            now < candidate.control.deadline()
                && candidate.expected_ack_destination_id == expected_ack_destination_id
                && candidate.session_key.session_id() == reset.rejected_session()
                && candidate
                    .control
                    .sequence_in_flight(reset.rejected_sequence())
        })
        || (sessions
            .control
            .upstream_pending_key
            .is_some_and(|key| key.session_id() == reset.rejected_session())
            && matches!(
                &sessions.control.upstream_reply_id_handshake,
                ReplyIdHandshake::Pending {
                    expected_ack_destination_id: pending_destination,
                    control,
                    ..
                } if *pending_destination == expected_ack_destination_id
                    && control.sequence_in_flight(reset.rejected_sequence())
            ))
}

pub(in crate::flow_state) fn expire_receive_candidates(
    sessions: &mut FlowSessionState,
    _flow_epoch: u64,
    now: Instant,
    observations: &ControlObservationLanes,
) {
    let mut expired = [None; MAX_RECEIVE_SESSION_CANDIDATES];
    let mut expired_len = 0;
    sessions
        .client_pool
        .client_ready_sessions
        .retain(|candidate| {
            if !candidate.is_expired_negotiating(now)
                || observations
                    .blocks_exact_key(candidate.transaction_key, candidate.absolute_deadline())
            {
                true
            } else {
                expired[expired_len] = Some(candidate.session_key.ordinal());
                expired_len += 1;
                false
            }
        });
    for ordinal in expired.into_iter().take(expired_len).flatten() {
        if sessions
            .client_pool
            .client_retired_ordinals
            .retire_exact(ordinal)
            .is_err()
        {
            sessions.metrics.sparse_retirement_exhaustions = sessions
                .metrics
                .sparse_retirement_exhaustions
                .saturating_add(1);
        }
    }
    sessions.metrics.candidate_expirations = sessions
        .metrics
        .candidate_expirations
        .saturating_add(expired_len as u64);
}
