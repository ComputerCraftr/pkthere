#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReceiverTransferError {
    AlreadyOwned,
    GenerationExhausted,
    GenerationMovedBackwards,
    OwnerExited,
    OwnershipLost,
    ReceiverUnavailable,
}

#[cfg(all(test, not(miri)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReceiverTransferSnapshot {
    pub(super) generation: u64,
    pub(super) owner: Option<usize>,
    pub(super) receiver_available: bool,
    pub(super) owner_exited: bool,
}

/// Production ownership state machine for one managed receiver slot.
///
/// The caller serializes these transitions with the receiver-slot authority
/// mutex and stages the descriptor-backed resource before publishing the
/// returned generation with Release ordering. Loom uses these same methods
/// under its modeled mutex.
pub(super) struct ReceiverGenerationView<Published, Shared> {
    published: Shared,
    _published: std::marker::PhantomData<fn() -> Published>,
}

pub(super) struct ReceiverTransferCore<Receiver, Published, Shared> {
    generation: u64,
    owner: Option<usize>,
    receiver: Option<Receiver>,
    owner_exited: bool,
    published: Shared,
    _published: std::marker::PhantomData<fn() -> Published>,
}

impl<Published, Shared> ReceiverGenerationView<Published, Shared>
where
    Published: AtomicU64Value,
    Shared: Deref<Target = Published>,
{
    pub(super) fn generation(&self) -> u64 {
        self.published.load_acquire()
    }

    pub(super) fn changed(&self, claimed_generation: u64) -> Option<u64> {
        let published = self.generation();
        (published != claimed_generation).then_some(published)
    }
}

impl<Published, Shared> Clone for ReceiverGenerationView<Published, Shared>
where
    Shared: Clone,
{
    fn clone(&self) -> Self {
        Self {
            published: self.published.clone(),
            _published: std::marker::PhantomData,
        }
    }
}

impl<Receiver, Published, Shared> ReceiverTransferCore<Receiver, Published, Shared>
where
    Published: AtomicU64Value,
    Shared: Clone + Deref<Target = Published>,
{
    pub(super) fn new(
        receiver: Receiver,
        published: Shared,
    ) -> (Self, ReceiverGenerationView<Published, Shared>) {
        published.store_release(1);
        let view = ReceiverGenerationView {
            published: published.clone(),
            _published: std::marker::PhantomData,
        };
        (
            Self {
                generation: 1,
                owner: None,
                receiver: Some(receiver),
                owner_exited: false,
                published,
                _published: std::marker::PhantomData,
            },
            view,
        )
    }

    pub(super) fn claim(&mut self, owner: usize) -> Result<(u64, Receiver), ReceiverTransferError> {
        if self.owner_exited {
            return Err(ReceiverTransferError::OwnerExited);
        }
        if self.owner.is_some() {
            return Err(ReceiverTransferError::AlreadyOwned);
        }
        let receiver = self
            .receiver
            .take()
            .ok_or(ReceiverTransferError::ReceiverUnavailable)?;
        self.owner = Some(owner);
        Ok((self.generation, receiver))
    }

    pub(super) fn publish_replacement(
        &mut self,
        receiver: Receiver,
    ) -> Result<u64, ReceiverTransferError> {
        if self.owner_exited {
            return Err(ReceiverTransferError::OwnerExited);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ReceiverTransferError::GenerationExhausted)?;
        self.receiver = Some(receiver);
        self.published.store_release(self.generation);
        Ok(self.generation)
    }

    pub(super) fn transfer_replacement_to_owner(
        &mut self,
        owner: usize,
        claimed_generation: u64,
    ) -> Result<Option<(u64, Receiver)>, ReceiverTransferError> {
        if self.owner != Some(owner) || self.owner_exited {
            return Err(ReceiverTransferError::OwnershipLost);
        }
        if self.generation == claimed_generation {
            return Ok(None);
        }
        if self.generation < claimed_generation {
            return Err(ReceiverTransferError::GenerationMovedBackwards);
        }
        let receiver = self
            .receiver
            .take()
            .ok_or(ReceiverTransferError::ReceiverUnavailable)?;
        Ok(Some((self.generation, receiver)))
    }

    pub(super) fn owner_exit(&mut self, owner: usize) -> Result<(), ReceiverTransferError> {
        if self.owner != Some(owner) || self.owner_exited {
            return Err(ReceiverTransferError::OwnershipLost);
        }
        self.owner = None;
        self.receiver = None;
        self.owner_exited = true;
        Ok(())
    }

    pub(super) fn precheck_publication(&self) -> Result<(), ReceiverTransferError> {
        if self.owner_exited {
            return Err(ReceiverTransferError::OwnerExited);
        }
        if self.generation == u64::MAX {
            return Err(ReceiverTransferError::GenerationExhausted);
        }
        Ok(())
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(all(test, not(miri)))]
    pub(super) const fn snapshot(&self) -> ReceiverTransferSnapshot {
        ReceiverTransferSnapshot {
            generation: self.generation,
            owner: self.owner,
            receiver_available: self.receiver.is_some(),
            owner_exited: self.owner_exited,
        }
    }
}
use crate::atomic_core::AtomicU64Value;
use std::ops::Deref;
