#[derive(Debug)]
pub(crate) struct SyncSendLease<Payload = BufferedPayload> {
    pub(super) token: u64,
    pub(crate) payload: Option<Payload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncSendCompletion {
    Completed,
    Restored,
    Superseded,
    ResetWon,
}

#[derive(Debug)]
struct SyncSendInFlight {
    token: u64,
    reset_requested: bool,
}

#[derive(Debug)]
pub(super) struct SyncPayloadSlot<Payload = BufferedPayload> {
    pending: Option<Payload>,
    sending: Option<SyncSendInFlight>,
    next_token: u64,
}

impl<Payload> Default for SyncPayloadSlot<Payload> {
    fn default() -> Self {
        Self {
            pending: None,
            sending: None,
            next_token: 0,
        }
    }
}

impl<Payload> SyncPayloadSlot<Payload> {
    pub(super) fn replace(&mut self, payload: Payload) -> Option<Payload> {
        self.pending.replace(payload)
    }

    pub(super) fn lease(
        &mut self,
    ) -> Result<Option<SyncSendLease<Payload>>, ReplyIdHandshakeInvariantError> {
        if self.sending.is_some() {
            return Ok(None);
        }
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(ReplyIdHandshakeInvariantError)?;
        let token = self.next_token;
        self.sending = Some(SyncSendInFlight {
            token,
            reset_requested: false,
        });
        Ok(Some(SyncSendLease {
            token,
            payload: self.pending.take(),
        }))
    }

    pub(super) fn complete(
        &mut self,
        lease: SyncSendLease<Payload>,
        committed: bool,
    ) -> Result<SyncSendCompletion, ReplyIdHandshakeInvariantError> {
        let Some(sending) = self.sending.take() else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        if sending.token != lease.token {
            self.sending = Some(sending);
            return Err(ReplyIdHandshakeInvariantError);
        }
        if sending.reset_requested {
            return Ok(SyncSendCompletion::ResetWon);
        }
        if committed {
            if lease.payload.is_some() {
                return Err(ReplyIdHandshakeInvariantError);
            }
            return Ok(SyncSendCompletion::Completed);
        }
        let Some(payload) = lease.payload else {
            return Ok(SyncSendCompletion::Completed);
        };
        if self.pending.is_none() {
            self.pending = Some(payload);
            Ok(SyncSendCompletion::Restored)
        } else {
            Ok(SyncSendCompletion::Superseded)
        }
    }

    pub(super) fn reset(&mut self) {
        self.pending = None;
        if let Some(sending) = self.sending.as_mut() {
            sending.reset_requested = true;
        }
    }
}

impl FlowRuntimeState {
    pub(crate) fn replace_sync_payload(&self, payload: BufferedPayload) -> Option<BufferedPayload> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .sync_payload
            .replace(payload)
    }

    pub(crate) fn lease_sync_send(
        &self,
    ) -> Result<Option<SyncSendLease>, ReplyIdHandshakeInvariantError> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .sync_payload
            .lease()
    }

    pub(crate) fn complete_sync_send(
        &self,
        lease: SyncSendLease,
        committed: bool,
    ) -> Result<SyncSendCompletion, ReplyIdHandshakeInvariantError> {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .sync_payload
            .complete(lease, committed)
    }
}

#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod sync_slot_loom;
#[cfg(test)]
mod sync_slot_tests;
use super::{BufferedPayload, FlowRuntimeState, ReplyIdHandshakeInvariantError};
