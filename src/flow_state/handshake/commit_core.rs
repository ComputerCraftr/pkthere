#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::flow_state) enum HandshakeCommitPhase {
    Committing,
    ManagerPublished,
    SessionCommitted,
    Sending,
    Retryable,
    Terminal,
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::flow_state) enum HandshakeRollbackDecision<Payload> {
    Retryable(Payload),
    TimedOut(Payload),
    ResetApplied(Payload),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::flow_state) enum HandshakeSendDecision {
    Acked,
    Retryable,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::flow_state) enum HandshakeCommitCoreError {
    InvalidPhase,
    StaleToken,
}

#[derive(Debug)]
pub(crate) struct HandshakeManagerReceipt {
    token: u64,
}

#[derive(Debug)]
pub(crate) struct HandshakeActivationLease {
    token: u64,
}

pub(in crate::flow_state) trait HandshakeSessionPublication {
    type Output;

    fn publish_session(&mut self, instance: u64);
    fn finish(self) -> Self::Output;
}

#[derive(Debug)]
pub(in crate::flow_state) struct HandshakePayloadError<Payload> {
    pub(in crate::flow_state) payload: Payload,
}

#[derive(Debug)]
pub(crate) struct HandshakePayloadLease<Payload> {
    token: u64,
    payload: Payload,
}

impl<Payload> HandshakePayloadLease<Payload> {
    pub(crate) const fn payload(&self) -> &Payload {
        &self.payload
    }
}

impl<Payload> std::ops::Deref for HandshakePayloadLease<Payload> {
    type Target = Payload;

    fn deref(&self) -> &Self::Target {
        self.payload()
    }
}

/// Complete ownership state for one matched ACK from observation through the
/// buffered payload's terminal send, retry, timeout, or reset disposition.
///
/// `payload == None` is valid only while `phase == Sending`: the unique send
/// lease then owns the payload and must return it through `complete_failure`
/// or consume it through `complete_success`.
pub(in crate::flow_state) struct HandshakeCommitCore<Payload> {
    token: u64,
    phase: HandshakeCommitPhase,
    timeout_requested: bool,
    reset_requested: bool,
    payload: Option<Payload>,
}

impl<Payload> HandshakeCommitCore<Payload> {
    pub(in crate::flow_state) const fn new(token: u64, payload: Payload) -> Self {
        Self {
            token,
            phase: HandshakeCommitPhase::Committing,
            timeout_requested: false,
            reset_requested: false,
            payload: Some(payload),
        }
    }

    pub(in crate::flow_state) const fn token(&self) -> u64 {
        self.token
    }

    #[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
    pub(in crate::flow_state) const fn phase(&self) -> HandshakeCommitPhase {
        self.phase
    }

    pub(in crate::flow_state) const fn cancel_requested(&self) -> bool {
        self.timeout_requested || self.reset_requested
    }

    pub(in crate::flow_state) const fn payload(&self) -> Option<&Payload> {
        self.payload.as_ref()
    }

    pub(in crate::flow_state) fn request_timeout(&mut self) {
        if !matches!(
            self.phase,
            HandshakeCommitPhase::Terminal | HandshakeCommitPhase::Poisoned
        ) {
            self.timeout_requested = true;
        }
    }

    pub(in crate::flow_state) fn request_reset(&mut self) {
        if !matches!(
            self.phase,
            HandshakeCommitPhase::Terminal | HandshakeCommitPhase::Poisoned
        ) {
            self.reset_requested = true;
        }
    }

    pub(in crate::flow_state) fn manager_published(
        &mut self,
        token: u64,
    ) -> Result<HandshakeManagerReceipt, HandshakeCommitCoreError> {
        self.require(token, HandshakeCommitPhase::Committing)?;
        self.phase = HandshakeCommitPhase::ManagerPublished;
        Ok(HandshakeManagerReceipt { token })
    }

    pub(in crate::flow_state) fn commit_session<Publication>(
        &mut self,
        receipt: HandshakeManagerReceipt,
        mut publication: Publication,
    ) -> Result<(HandshakeActivationLease, Publication::Output), HandshakeCommitCoreError>
    where
        Publication: HandshakeSessionPublication,
    {
        self.require(receipt.token, HandshakeCommitPhase::ManagerPublished)?;
        publication.publish_session(receipt.token);
        self.phase = HandshakeCommitPhase::SessionCommitted;
        Ok((
            HandshakeActivationLease {
                token: receipt.token,
            },
            publication.finish(),
        ))
    }

    pub(in crate::flow_state) fn begin_send(
        &mut self,
        activation: HandshakeActivationLease,
    ) -> Result<HandshakePayloadLease<Payload>, HandshakeCommitCoreError> {
        self.require(activation.token, HandshakeCommitPhase::SessionCommitted)?;
        let payload = self
            .payload
            .take()
            .ok_or(HandshakeCommitCoreError::InvalidPhase)?;
        self.phase = HandshakeCommitPhase::Sending;
        Ok(HandshakePayloadLease {
            token: activation.token,
            payload,
        })
    }

    pub(in crate::flow_state) fn poison_after_session_commit(
        &mut self,
        activation: HandshakeActivationLease,
    ) -> Result<(), HandshakeCommitCoreError> {
        self.require(activation.token, HandshakeCommitPhase::SessionCommitted)?;
        self.phase = HandshakeCommitPhase::Poisoned;
        Ok(())
    }

    pub(in crate::flow_state) fn rollback(
        &mut self,
        token: u64,
        deadline_expired: bool,
    ) -> Result<HandshakeRollbackDecision<Payload>, HandshakeCommitCoreError> {
        self.require(token, HandshakeCommitPhase::Committing)?;
        let decision = if self.reset_requested {
            HandshakeRollbackDecision::ResetApplied(
                self.payload
                    .take()
                    .ok_or(HandshakeCommitCoreError::InvalidPhase)?,
            )
        } else if self.timeout_requested || deadline_expired {
            HandshakeRollbackDecision::TimedOut(
                self.payload
                    .take()
                    .ok_or(HandshakeCommitCoreError::InvalidPhase)?,
            )
        } else {
            HandshakeRollbackDecision::Retryable(
                self.payload
                    .take()
                    .ok_or(HandshakeCommitCoreError::InvalidPhase)?,
            )
        };
        self.phase = HandshakeCommitPhase::Terminal;
        Ok(decision)
    }

    pub(in crate::flow_state) fn complete_success(
        &mut self,
        lease: HandshakePayloadLease<Payload>,
    ) -> Result<HandshakeSendDecision, HandshakePayloadError<Payload>> {
        match self.require(lease.token, HandshakeCommitPhase::Sending) {
            Ok(()) => {}
            Err(HandshakeCommitCoreError::InvalidPhase | HandshakeCommitCoreError::StaleToken) => {
                return Err(HandshakePayloadError {
                    payload: lease.payload,
                });
            }
        }
        if self.payload.is_some() {
            return Err(HandshakePayloadError {
                payload: lease.payload,
            });
        }
        let decision = if self.cancel_requested() {
            HandshakeSendDecision::Cancelled
        } else {
            HandshakeSendDecision::Acked
        };
        drop(lease.payload);
        self.phase = HandshakeCommitPhase::Terminal;
        Ok(decision)
    }

    pub(in crate::flow_state) fn complete_failure(
        &mut self,
        lease: HandshakePayloadLease<Payload>,
    ) -> Result<HandshakeSendDecision, HandshakePayloadError<Payload>> {
        match self.require(lease.token, HandshakeCommitPhase::Sending) {
            Ok(()) => {}
            Err(HandshakeCommitCoreError::InvalidPhase | HandshakeCommitCoreError::StaleToken) => {
                return Err(HandshakePayloadError {
                    payload: lease.payload,
                });
            }
        }
        if self.payload.is_some() {
            return Err(HandshakePayloadError {
                payload: lease.payload,
            });
        }
        if self.cancel_requested() {
            self.phase = HandshakeCommitPhase::Terminal;
            drop(lease.payload);
            Ok(HandshakeSendDecision::Cancelled)
        } else {
            self.payload = Some(lease.payload);
            self.phase = HandshakeCommitPhase::Retryable;
            Ok(HandshakeSendDecision::Retryable)
        }
    }

    pub(in crate::flow_state) fn begin_retry(
        &mut self,
        token: u64,
    ) -> Result<HandshakePayloadLease<Payload>, HandshakeCommitCoreError> {
        self.require(token, HandshakeCommitPhase::Retryable)?;
        let payload = self
            .payload
            .take()
            .ok_or(HandshakeCommitCoreError::InvalidPhase)?;
        self.phase = HandshakeCommitPhase::Sending;
        Ok(HandshakePayloadLease { token, payload })
    }

    fn require(
        &self,
        token: u64,
        phase: HandshakeCommitPhase,
    ) -> Result<(), HandshakeCommitCoreError> {
        if self.token != token {
            return Err(HandshakeCommitCoreError::StaleToken);
        }
        if self.phase != phase {
            return Err(HandshakeCommitCoreError::InvalidPhase);
        }
        Ok(())
    }
}
