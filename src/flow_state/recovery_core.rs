use super::{RecoveryPayloadSendToken, ReplyIdHandshakeInvariantError};
use crate::net::framing_shim::ResetRequired;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverySendPhase {
    AwaitingRecognition,
    RetryAt {
        attempt: u32,
        when: Instant,
    },
    Sending {
        session: crate::net::framing_shim::SessionId,
        attempt: u32,
        sequence: Option<u16>,
        pending_reset: Option<ResetRequired>,
        timeout_requested: bool,
    },
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryRecognitionDecision {
    Retain,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryTimeoutDecision {
    AwaitCompletion,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoverySendDecision {
    pub(super) pending_reset: Option<ResetRequired>,
    pub(super) timeout_requested: bool,
    pub(super) remove: bool,
}

/// A non-cloneable payload lease issued and consumed by [`RecoverySendCore`].
pub(crate) struct RecoverySendLease<Payload> {
    pub(crate) token: RecoveryPayloadSendToken,
    pub(crate) payload: Payload,
}

/// Owns the complete retry lifecycle and payload custody for one recovery send.
#[derive(Debug)]
pub(super) struct RecoverySendCore<Payload> {
    phase: RecoverySendPhase,
    recognized: bool,
    payload: Option<Payload>,
}

impl<Payload> RecoverySendCore<Payload> {
    pub(super) const fn new(payload: Payload) -> Self {
        Self {
            phase: RecoverySendPhase::AwaitingRecognition,
            recognized: false,
            payload: Some(payload),
        }
    }

    pub(super) fn retry_deadline(&self) -> Option<Instant> {
        match self.phase {
            RecoverySendPhase::RetryAt { when, .. } => Some(when),
            RecoverySendPhase::AwaitingRecognition
            | RecoverySendPhase::Sending { .. }
            | RecoverySendPhase::Terminal => None,
        }
    }

    pub(super) fn record_initial_send_result(
        &mut self,
        sent: bool,
        retry_at: Instant,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        if !matches!(self.phase, RecoverySendPhase::AwaitingRecognition) {
            return Err(ReplyIdHandshakeInvariantError);
        }
        if !sent {
            self.phase = RecoverySendPhase::RetryAt {
                attempt: 1,
                when: retry_at,
            };
        }
        Ok(())
    }

    pub(super) fn lease_due(
        &mut self,
        session: crate::net::framing_shim::SessionId,
        now: Instant,
    ) -> Result<Option<RecoverySendLease<Payload>>, ReplyIdHandshakeInvariantError> {
        let RecoverySendPhase::RetryAt { attempt, when } = self.phase else {
            return Ok(None);
        };
        if now < when {
            return Ok(None);
        }
        let token = RecoveryPayloadSendToken { session, attempt };
        let payload = self.payload.take().ok_or(ReplyIdHandshakeInvariantError)?;
        self.phase = RecoverySendPhase::Sending {
            session,
            attempt,
            sequence: None,
            pending_reset: None,
            timeout_requested: false,
        };
        Ok(Some(RecoverySendLease { token, payload }))
    }

    pub(super) fn prepare_sequence(
        &mut self,
        token: &RecoveryPayloadSendToken,
        sequence: u16,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        let RecoverySendPhase::Sending {
            session,
            attempt,
            sequence: current_sequence,
            ..
        } = &mut self.phase
        else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        if *session != token.session || *attempt != token.attempt || current_sequence.is_some() {
            return Err(ReplyIdHandshakeInvariantError);
        }
        *current_sequence = Some(sequence);
        Ok(())
    }

    pub(super) fn complete_send(
        &mut self,
        lease: RecoverySendLease<Payload>,
        sent: bool,
        retry_at: Option<(u32, Instant)>,
    ) -> Result<RecoverySendDecision, ReplyIdHandshakeInvariantError> {
        let RecoverySendPhase::Sending {
            session,
            attempt,
            sequence,
            pending_reset,
            timeout_requested,
        } = self.phase
        else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        if session != lease.token.session
            || attempt != lease.token.attempt
            || sequence.is_none()
            || self.payload.is_some()
        {
            return Err(ReplyIdHandshakeInvariantError);
        }
        self.payload = Some(lease.payload);
        let remove = timeout_requested || (self.recognized && sent);
        self.phase = if remove {
            RecoverySendPhase::Terminal
        } else if pending_reset.is_some() || sent {
            RecoverySendPhase::AwaitingRecognition
        } else {
            let Some((attempt, when)) = retry_at else {
                return Err(ReplyIdHandshakeInvariantError);
            };
            RecoverySendPhase::RetryAt { attempt, when }
        };
        Ok(RecoverySendDecision {
            pending_reset: (!timeout_requested).then_some(pending_reset).flatten(),
            timeout_requested,
            remove,
        })
    }

    pub(super) fn observe_recognition(
        &mut self,
    ) -> Result<RecoveryRecognitionDecision, ReplyIdHandshakeInvariantError> {
        match self.phase {
            RecoverySendPhase::AwaitingRecognition => {
                self.phase = RecoverySendPhase::Terminal;
                Ok(RecoveryRecognitionDecision::Remove)
            }
            RecoverySendPhase::RetryAt { .. } | RecoverySendPhase::Sending { .. } => {
                self.recognized = true;
                Ok(RecoveryRecognitionDecision::Retain)
            }
            RecoverySendPhase::Terminal => Err(ReplyIdHandshakeInvariantError),
        }
    }

    pub(super) fn request_timeout(&mut self) -> RecoveryTimeoutDecision {
        match &mut self.phase {
            RecoverySendPhase::Sending {
                timeout_requested, ..
            } => {
                *timeout_requested = true;
                RecoveryTimeoutDecision::AwaitCompletion
            }
            RecoverySendPhase::AwaitingRecognition | RecoverySendPhase::RetryAt { .. } => {
                self.phase = RecoverySendPhase::Terminal;
                RecoveryTimeoutDecision::Remove
            }
            RecoverySendPhase::Terminal => RecoveryTimeoutDecision::Remove,
        }
    }

    pub(super) fn defer_reset(&mut self, reset: ResetRequired) -> bool {
        let RecoverySendPhase::Sending { pending_reset, .. } = &mut self.phase else {
            return false;
        };
        if pending_reset.is_some() {
            return false;
        }
        *pending_reset = Some(reset);
        true
    }

    pub(super) fn take_available_payload(&mut self) -> Option<Payload> {
        self.payload.take()
    }

    pub(super) fn restart_retry(&mut self, payload: Payload, when: Instant) {
        self.payload = Some(payload);
        self.recognized = false;
        self.phase = RecoverySendPhase::RetryAt { attempt: 1, when };
    }

    #[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
    pub(super) fn is_terminal(&self) -> bool {
        matches!(self.phase, RecoverySendPhase::Terminal)
    }
}
