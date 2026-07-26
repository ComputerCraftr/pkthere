#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StaleRetryError {
    AssociationChanged,
    FlowChanged,
    RetryRepeated,
}

/// Observed stale-association evidence bound to the exact payload that proved
/// the original syscall sent no bytes.
pub(super) struct ObservedStaleRetry<Identity, Payload> {
    expected_association_epoch: u64,
    identity: Identity,
    payload: Payload,
}

pub(super) struct TransitionAuthorizedStaleRetry<Identity, Payload> {
    expected_association_epoch: u64,
    identity: Identity,
    payload: Payload,
}

pub(super) struct ReconciledStaleRetry<Identity, Payload> {
    identity: Identity,
    payload: Payload,
}

/// The only capability that permits the one managed retry.
pub(super) struct AuthorizedStaleRetry<Payload> {
    payload: Payload,
}

impl<Identity: Copy + Eq, Payload> ObservedStaleRetry<Identity, Payload> {
    pub(super) const fn new(
        expected_association_epoch: u64,
        identity: Identity,
        payload: Payload,
    ) -> Self {
        Self {
            expected_association_epoch,
            identity,
            payload,
        }
    }

    pub(super) fn authorize_transition(
        self,
        current: Identity,
    ) -> Result<TransitionAuthorizedStaleRetry<Identity, Payload>, StaleRetryError> {
        if current != self.identity {
            return Err(StaleRetryError::FlowChanged);
        }
        Ok(TransitionAuthorizedStaleRetry {
            expected_association_epoch: self.expected_association_epoch,
            identity: self.identity,
            payload: self.payload,
        })
    }
}

impl<Identity, Payload> TransitionAuthorizedStaleRetry<Identity, Payload> {
    pub(super) fn reconciled(
        self,
        observed_association_epoch: u64,
    ) -> Result<ReconciledStaleRetry<Identity, Payload>, StaleRetryError> {
        if observed_association_epoch != self.expected_association_epoch {
            return Err(StaleRetryError::AssociationChanged);
        }
        Ok(ReconciledStaleRetry {
            identity: self.identity,
            payload: self.payload,
        })
    }
}

impl<Identity: Eq, Payload> ReconciledStaleRetry<Identity, Payload> {
    pub(super) fn authorize(
        self,
        current: Identity,
    ) -> Result<AuthorizedStaleRetry<Payload>, StaleRetryError> {
        if current != self.identity {
            return Err(StaleRetryError::FlowChanged);
        }
        Ok(AuthorizedStaleRetry {
            payload: self.payload,
        })
    }
}

impl<Payload> AuthorizedStaleRetry<Payload> {
    pub(super) const fn payload(&self) -> &Payload {
        &self.payload
    }

    pub(super) fn complete(self, stale_again: bool) -> Result<(), StaleRetryError> {
        if stale_again {
            Err(StaleRetryError::RetryRepeated)
        } else {
            Ok(())
        }
    }
}
