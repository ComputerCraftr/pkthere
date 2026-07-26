use super::SessionAuthority;
use crate::flow_state::{
    ReplyIdControlSendLease, ReplyIdControlSequenceRecord, ReplyIdHandshake,
    ReplyIdHandshakeInvariantError,
};

pub(in crate::flow_state) fn record_handshake_control_sequence(
    state: &SessionAuthority,
    lease: &ReplyIdControlSendLease,
    sequence: u16,
) -> Result<ReplyIdControlSequenceRecord, ReplyIdHandshakeInvariantError> {
    let mut sessions = crate::runtime_support::lock_authority_or_shutdown(state, "flow session");
    if sessions.control.control_lease_epoch_exhausted
        || lease.control_lease_epoch != sessions.control.control_lease_epoch
    {
        return Ok(ReplyIdControlSequenceRecord::ResetWon);
    }
    if lease.generation_advance {
        let Some(advance) = sessions.upstream_pool.upstream_generation_advance.as_mut() else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        if advance.current != lease.session_key {
            return Err(ReplyIdHandshakeInvariantError);
        }
        advance.control.record_sequence(&lease.attempt, sequence)?;
        return Ok(ReplyIdControlSequenceRecord::Recorded);
    }
    if lease.reserve {
        let Some(candidate) = sessions
            .upstream_pool
            .upstream_reserve_handshakes
            .iter_mut()
            .find(|candidate| candidate.session_key == lease.session_key)
        else {
            return if sessions
                .upstream_pool
                .upstream_ready_sessions
                .iter()
                .any(|session| session.session_key == lease.session_key)
            {
                Ok(ReplyIdControlSequenceRecord::HandshakeAdvanced)
            } else {
                Err(ReplyIdHandshakeInvariantError)
            };
        };
        if candidate.expected_ack_destination_id != lease.expected_ack_destination_id {
            return Err(ReplyIdHandshakeInvariantError);
        }
        candidate
            .control
            .record_sequence(&lease.attempt, sequence)?;
        return Ok(ReplyIdControlSequenceRecord::Recorded);
    }
    let ReplyIdHandshake::Pending {
        expected_ack_destination_id,
        instance,
        control,
        ..
    } = &mut sessions.control.upstream_reply_id_handshake
    else {
        return if matches!(
            sessions.control.upstream_reply_id_handshake,
            ReplyIdHandshake::Committing { instance, .. }
                | ReplyIdHandshake::Sending { instance, .. }
                | ReplyIdHandshake::AckedRetryable { instance, .. }
                | ReplyIdHandshake::Acked { instance }
                if instance == lease.session_id.get()
        ) {
            Ok(ReplyIdControlSequenceRecord::HandshakeAdvanced)
        } else {
            Err(ReplyIdHandshakeInvariantError)
        };
    };
    if *instance != lease.session_id.get()
        || *expected_ack_destination_id != lease.expected_ack_destination_id
    {
        return Err(ReplyIdHandshakeInvariantError);
    }
    control.record_sequence(&lease.attempt, sequence)?;
    Ok(ReplyIdControlSequenceRecord::Recorded)
}
