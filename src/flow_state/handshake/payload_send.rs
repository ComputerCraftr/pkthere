use super::{SessionAuthority, commit_core, retry_backoff};
use crate::flow_state::{
    ReplyIdHandshake, ReplyIdHandshakeInvariantError, ReplyIdPayloadSendLease,
};
use std::time::Instant;

pub(in crate::flow_state) fn complete_handshake_send(
    state: &SessionAuthority,
    lease: ReplyIdPayloadSendLease,
) -> Result<bool, ReplyIdHandshakeInvariantError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let previous = std::mem::replace(
        &mut sessions.control.upstream_reply_id_handshake,
        ReplyIdHandshake::NotRequired,
    );
    match previous {
        ReplyIdHandshake::Sending {
            mut commit,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            attempts,
        } => {
            let decision = match commit.complete_success(lease) {
                Ok(decision) => decision,
                Err(error) => {
                    drop(error.payload);
                    sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Sending {
                        commit,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                        attempts,
                    };
                    return Err(ReplyIdHandshakeInvariantError);
                }
            };
            let cancelled = matches!(decision, commit_core::HandshakeSendDecision::Cancelled);
            if cancelled {
                sessions.authority.upstream_leg.transmit = None;
                sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::NotRequired;
            } else if matches!(decision, commit_core::HandshakeSendDecision::Acked) {
                sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Acked { instance };
            } else {
                return Err(ReplyIdHandshakeInvariantError);
            }
            Ok(cancelled)
        }
        other => {
            sessions.control.upstream_reply_id_handshake = other;
            Err(ReplyIdHandshakeInvariantError)
        }
    }
}

pub(in crate::flow_state) fn release_handshake_send(
    state: &SessionAuthority,
    lease: ReplyIdPayloadSendLease,
) -> Result<bool, ReplyIdHandshakeInvariantError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let previous = std::mem::replace(
        &mut sessions.control.upstream_reply_id_handshake,
        ReplyIdHandshake::NotRequired,
    );
    match previous {
        ReplyIdHandshake::Sending {
            mut commit,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            attempts,
        } => {
            let decision = match commit.complete_failure(lease) {
                Ok(decision) => decision,
                Err(error) => {
                    drop(error.payload);
                    sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::Sending {
                        commit,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                        attempts,
                    };
                    return Err(ReplyIdHandshakeInvariantError);
                }
            };
            let cancelled = matches!(decision, commit_core::HandshakeSendDecision::Cancelled);
            if cancelled {
                sessions.authority.upstream_leg.transmit = None;
            } else if matches!(decision, commit_core::HandshakeSendDecision::Retryable) {
                sessions.control.upstream_reply_id_handshake = ReplyIdHandshake::AckedRetryable {
                    commit,
                    expected_ack_destination_id,
                    instance,
                    started_s,
                    absolute_deadline,
                    next_attempt: Instant::now() + retry_backoff(attempts),
                    attempts,
                };
            } else {
                return Err(ReplyIdHandshakeInvariantError);
            }
            Ok(cancelled)
        }
        other => {
            sessions.control.upstream_reply_id_handshake = other;
            Err(ReplyIdHandshakeInvariantError)
        }
    }
}

pub(in crate::flow_state) fn lease_due_handshake_payload(
    state: &SessionAuthority,
    now: Instant,
) -> Option<ReplyIdPayloadSendLease> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    let guard = &mut sessions.control.upstream_reply_id_handshake;
    let previous = std::mem::replace(guard, ReplyIdHandshake::NotRequired);
    match previous {
        ReplyIdHandshake::AckedRetryable {
            mut commit,
            expected_ack_destination_id,
            instance,
            started_s,
            absolute_deadline,
            next_attempt,
            attempts,
        } if now >= next_attempt => {
            let lease = match commit.begin_retry(commit.token()) {
                Ok(lease) => lease,
                Err(_) => {
                    *guard = ReplyIdHandshake::AckedRetryable {
                        commit,
                        expected_ack_destination_id,
                        instance,
                        started_s,
                        absolute_deadline,
                        next_attempt,
                        attempts,
                    };
                    return None;
                }
            };
            *guard = ReplyIdHandshake::Sending {
                commit,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
                attempts: attempts.saturating_add(1),
            };
            Some(lease)
        }
        other => {
            *guard = other;
            None
        }
    }
}
