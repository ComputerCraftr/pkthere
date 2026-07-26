use super::{PendingIcmpClientLockMismatch, ReplyIdHandshakeInvariantError, SentControlSequences};
use std::time::Instant;

pub(super) struct ControlSendCore {
    deadline: Instant,
    next_control_attempt: Instant,
    control_attempts: u32,
    control_in_flight: bool,
    in_flight_control_sequences: SentControlSequences,
    sent_control_sequences: SentControlSequences,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ControlSendAttempt {
    attempt: u32,
}

impl ControlSendAttempt {
    pub(super) const fn number(&self) -> u32 {
        self.attempt
    }
}

impl ControlSendCore {
    pub(super) fn new(now: Instant, deadline: Instant) -> Self {
        Self {
            deadline,
            next_control_attempt: now,
            control_attempts: 0,
            control_in_flight: false,
            in_flight_control_sequences: SentControlSequences::default(),
            sent_control_sequences: SentControlSequences::default(),
        }
    }

    pub(super) fn lease_due(
        &mut self,
        now: Instant,
        maximum_attempts: u32,
    ) -> Result<Option<ControlSendAttempt>, ReplyIdHandshakeInvariantError> {
        if self.control_in_flight
            || now >= self.deadline
            || now < self.next_control_attempt
            || self.control_attempts >= maximum_attempts
        {
            return Ok(None);
        }
        self.control_attempts = self
            .control_attempts
            .checked_add(1)
            .ok_or(ReplyIdHandshakeInvariantError)?;
        self.control_in_flight = true;
        Ok(Some(ControlSendAttempt {
            attempt: self.control_attempts,
        }))
    }

    pub(super) fn is_due(&self, now: Instant, maximum_attempts: u32) -> bool {
        !self.control_in_flight
            && now < self.deadline
            && now >= self.next_control_attempt
            && self.control_attempts < maximum_attempts
    }

    pub(super) fn record_sequence(
        &mut self,
        attempt: &ControlSendAttempt,
        sequence: u16,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        if !self.matches_in_flight(attempt.number())
            || self.sent_control_sequences.contains(sequence)
        {
            return Err(ReplyIdHandshakeInvariantError);
        }
        self.in_flight_control_sequences.insert(sequence)
    }

    pub(super) fn complete_sequence(
        &mut self,
        attempt: ControlSendAttempt,
        sequence: u16,
        sent: bool,
        retry_at: Instant,
    ) -> Result<bool, ReplyIdHandshakeInvariantError> {
        if !self.matches_in_flight(attempt.number())
            || !self.in_flight_control_sequences.remove(sequence)
        {
            return Ok(false);
        }
        if sent {
            self.sent_control_sequences.insert(sequence)?;
        }
        self.control_in_flight = false;
        self.next_control_attempt = retry_at;
        Ok(true)
    }

    pub(super) fn release_unsequenced(
        &mut self,
        attempt: ControlSendAttempt,
        retry_at: Instant,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        if !self.matches_in_flight(attempt.number()) || !self.in_flight_control_sequences.is_empty()
        {
            return Err(ReplyIdHandshakeInvariantError);
        }
        self.control_in_flight = false;
        self.next_control_attempt = retry_at;
        Ok(())
    }

    pub(super) fn acknowledges(&self, sequence: u16) -> bool {
        self.sent_control_sequences.contains(sequence)
            || self.in_flight_control_sequences.contains(sequence)
    }

    pub(super) fn sequence_in_flight(&self, sequence: u16) -> bool {
        self.in_flight_control_sequences.contains(sequence)
    }

    pub(super) fn was_sent(&self, sequence: u16) -> bool {
        self.sent_control_sequences.contains(sequence)
    }

    pub(super) fn restart(&mut self, now: Instant) -> Result<(), ReplyIdHandshakeInvariantError> {
        if self.control_in_flight || !self.in_flight_control_sequences.is_empty() {
            return Err(ReplyIdHandshakeInvariantError);
        }
        self.next_control_attempt = now;
        self.control_attempts = 0;
        Ok(())
    }

    pub(super) fn reset_for_new_transaction(&mut self, now: Instant, deadline: Instant) {
        self.deadline = deadline;
        self.next_control_attempt = now;
        self.control_attempts = 0;
        self.control_in_flight = false;
        self.in_flight_control_sequences.clear();
        self.sent_control_sequences.clear();
    }

    pub(super) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) const fn next_attempt(&self) -> Instant {
        self.next_control_attempt
    }

    pub(super) const fn in_flight(&self) -> bool {
        self.control_in_flight
    }

    fn matches_in_flight(&self, attempt: u32) -> bool {
        self.control_in_flight && self.control_attempts == attempt
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiveCandidateState {
    Negotiating,
    AckSending {
        installation_order: u64,
        in_flight: u16,
    },
    NegotiatedReady {
        installation_order: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReceiveCandidateAckCore {
    absolute_deadline: Instant,
    state: ReceiveCandidateState,
}

pub(super) struct ReceiveCandidateAckTransaction<'a> {
    candidate: &'a mut ReceiveCandidateAckCore,
    next_installation_order: &'a mut u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReceiveCandidateAckPermit {
    installation_order: u64,
}

impl ReceiveCandidateAckPermit {
    #[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
    pub(super) const fn installation_order(&self) -> u64 {
        self.installation_order
    }
}

impl<'a> ReceiveCandidateAckTransaction<'a> {
    pub(super) const fn new(
        candidate: &'a mut ReceiveCandidateAckCore,
        next_installation_order: &'a mut u64,
    ) -> Self {
        Self {
            candidate,
            next_installation_order,
        }
    }

    pub(super) fn begin_send(
        self,
        observed_at: Instant,
    ) -> Result<Option<ReceiveCandidateAckPermit>, PendingIcmpClientLockMismatch> {
        self.candidate
            .begin_send_owned(observed_at, self.next_installation_order)
    }
}

impl ReceiveCandidateAckCore {
    pub(super) const fn new(absolute_deadline: Instant) -> Self {
        Self {
            absolute_deadline,
            state: ReceiveCandidateState::Negotiating,
        }
    }

    pub(super) fn is_expired(self, now: Instant) -> bool {
        now >= self.absolute_deadline
            && matches!(
                self.state,
                ReceiveCandidateState::Negotiating | ReceiveCandidateState::AckSending { .. }
            )
    }

    pub(super) fn is_live_at(self, observed_at: Instant) -> bool {
        match self.state {
            ReceiveCandidateState::Negotiating | ReceiveCandidateState::AckSending { .. } => {
                observed_at < self.absolute_deadline
            }
            ReceiveCandidateState::NegotiatedReady { .. } => true,
        }
    }

    pub(super) fn is_negotiating(self) -> bool {
        matches!(self.state, ReceiveCandidateState::Negotiating)
    }

    pub(super) fn is_promotable(self) -> bool {
        matches!(
            self.state,
            ReceiveCandidateState::AckSending { .. }
                | ReceiveCandidateState::NegotiatedReady { .. }
        )
    }

    fn begin_send_owned(
        &mut self,
        observed_at: Instant,
        next_installation_order: &mut u64,
    ) -> Result<Option<ReceiveCandidateAckPermit>, PendingIcmpClientLockMismatch> {
        match self.state {
            ReceiveCandidateState::NegotiatedReady { .. } => Ok(None),
            ReceiveCandidateState::Negotiating | ReceiveCandidateState::AckSending { .. }
                if observed_at >= self.absolute_deadline =>
            {
                Err(PendingIcmpClientLockMismatch)
            }
            ReceiveCandidateState::AckSending {
                installation_order,
                in_flight,
            } => {
                let next_in_flight = in_flight
                    .checked_add(1)
                    .ok_or(PendingIcmpClientLockMismatch)?;
                self.state = ReceiveCandidateState::AckSending {
                    installation_order,
                    in_flight: next_in_flight,
                };
                Ok(Some(ReceiveCandidateAckPermit { installation_order }))
            }
            ReceiveCandidateState::Negotiating => {
                let installation_order = *next_installation_order;
                *next_installation_order = installation_order
                    .checked_add(1)
                    .ok_or(PendingIcmpClientLockMismatch)?;
                self.state = ReceiveCandidateState::AckSending {
                    installation_order,
                    in_flight: 1,
                };
                Ok(Some(ReceiveCandidateAckPermit { installation_order }))
            }
        }
    }

    pub(super) fn complete_send(
        &mut self,
        permit: ReceiveCandidateAckPermit,
        sent: bool,
    ) -> Result<(), PendingIcmpClientLockMismatch> {
        let installation_order = permit.installation_order;
        match self.state {
            ReceiveCandidateState::NegotiatedReady {
                installation_order: current,
            } if current == installation_order => Ok(()),
            ReceiveCandidateState::AckSending {
                installation_order: current,
                in_flight,
            } if current == installation_order => {
                self.state = if sent {
                    ReceiveCandidateState::NegotiatedReady { installation_order }
                } else if in_flight == 1 {
                    ReceiveCandidateState::Negotiating
                } else {
                    ReceiveCandidateState::AckSending {
                        installation_order,
                        in_flight: in_flight - 1,
                    }
                };
                Ok(())
            }
            ReceiveCandidateState::Negotiating
            | ReceiveCandidateState::NegotiatedReady { .. }
            | ReceiveCandidateState::AckSending { .. } => Err(PendingIcmpClientLockMismatch),
        }
    }

    pub(super) fn ready_installation_order(self) -> Option<u64> {
        match self.state {
            ReceiveCandidateState::NegotiatedReady { installation_order } => {
                Some(installation_order)
            }
            ReceiveCandidateState::Negotiating | ReceiveCandidateState::AckSending { .. } => None,
        }
    }

    pub(super) const fn deadline(self) -> Instant {
        self.absolute_deadline
    }
}
