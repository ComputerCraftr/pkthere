use super::send_completion::{
    DeferredControl, DeferredInstall, DeferredSlotId, DeferredUpdate, SendCompletionControl,
    SendCompletionError, SendCompletionStore,
};
use crate::flow_state::DeferredPeerControl;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};

const VACANT_OWNER: u32 = 0;

pub(super) trait DeferredOwnerAtomic {
    fn new(value: u32) -> Self;
    fn load_acquire(&self) -> u32;
    fn claim(&self, current: u32, next: u32) -> Result<u32, u32>;
    fn release(&self, current: u32, next: u32) -> Result<u32, u32>;
}

pub(super) trait DeferredControlCell<Control> {
    fn with_mut<Result>(
        &self,
        operation: impl FnOnce(&mut Option<DeferredControl<Control>>) -> Result,
    ) -> Result;
}

struct SequenceOwnedDeferredSlot<Owner, Cell> {
    owner: Owner,
    control: Cell,
}

pub(super) struct SequenceOwnedDeferredStore<Owner, Cell, Control> {
    slots: Box<[SequenceOwnedDeferredSlot<Owner, Cell>]>,
    _control: PhantomData<fn(Control)>,
}

impl<Owner, Cell, Control> SequenceOwnedDeferredStore<Owner, Cell, Control>
where
    Owner: DeferredOwnerAtomic,
{
    pub(super) fn new(capacity: usize, mut create_cell: impl FnMut(usize) -> Cell) -> Self {
        let slots = (0..capacity)
            .map(|index| SequenceOwnedDeferredSlot {
                owner: Owner::new(VACANT_OWNER),
                control: create_cell(index),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            _control: PhantomData,
        }
    }

    fn owner(sequence: u16) -> u32 {
        u32::from(sequence) + 1
    }

    fn slot(
        &self,
        slot: DeferredSlotId,
        sequence: u16,
    ) -> Result<&SequenceOwnedDeferredSlot<Owner, Cell>, SendCompletionError> {
        let slot = self
            .slots
            .get(slot.index())
            .ok_or(SendCompletionError::DeferredSlotMissing)?;
        if slot.owner.load_acquire() != Self::owner(sequence) {
            return Err(SendCompletionError::DeferredSlotMissing);
        }
        Ok(slot)
    }

    fn release(
        slot: &SequenceOwnedDeferredSlot<Owner, Cell>,
        sequence: u16,
    ) -> Result<(), SendCompletionError> {
        slot.owner
            .release(Self::owner(sequence), VACANT_OWNER)
            .map(|_| ())
            .map_err(|_| SendCompletionError::OwnershipLost)
    }
}

impl<Owner, Cell, Control> SendCompletionStore<Control>
    for SequenceOwnedDeferredStore<Owner, Cell, Control>
where
    Owner: DeferredOwnerAtomic,
    Cell: DeferredControlCell<Control>,
    Control: SendCompletionControl,
{
    fn install(
        &self,
        deferred: DeferredControl<Control>,
        publish: impl FnOnce(DeferredSlotId) -> Result<bool, SendCompletionError>,
    ) -> Result<DeferredInstall, SendCompletionError> {
        let owner = Self::owner(deferred.sequence);
        let mut publish = Some(publish);
        for (index, slot) in self.slots.iter().enumerate() {
            let slot_id = DeferredSlotId::from_index(index)?;
            let attempt = slot.control.with_mut(|control| {
                let observed = slot.owner.load_acquire();
                if observed == owner {
                    return Ok(Some(DeferredInstall::Raced));
                }
                if observed != VACANT_OWNER {
                    return Ok(None);
                }
                match slot.owner.claim(VACANT_OWNER, owner) {
                    Ok(_) => {}
                    Err(observed) if observed == owner => {
                        return Ok(Some(DeferredInstall::Raced));
                    }
                    Err(_) => return Ok(None),
                }
                if control.is_some() {
                    Self::release(slot, deferred.sequence)?;
                    return Err(SendCompletionError::OwnershipLost);
                }
                *control = Some(deferred);
                let published = publish.take().ok_or(SendCompletionError::OwnershipLost)?(slot_id)?;
                if !published {
                    *control = None;
                    Self::release(slot, deferred.sequence)?;
                }
                Ok(Some(if published {
                    DeferredInstall::Published(slot_id)
                } else {
                    DeferredInstall::Raced
                }))
            });
            match attempt {
                Ok(Some(disposition)) => return Ok(disposition),
                Ok(None) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(SendCompletionError::DeferredStoreFull)
    }

    fn update(
        &self,
        slot: DeferredSlotId,
        deferred: DeferredControl<Control>,
    ) -> Result<DeferredUpdate, SendCompletionError> {
        let slot = self.slot(slot, deferred.sequence)?;
        slot.control.with_mut(|control| {
            let existing = control
                .as_mut()
                .filter(|existing| existing.sequence == deferred.sequence)
                .ok_or(SendCompletionError::DeferredSlotMissing)?;
            if !SendCompletionControl::same_control(existing.control, deferred.control) {
                return Ok(DeferredUpdate::Conflict);
            }
            SendCompletionControl::retain_earliest(&mut existing.control, deferred.control);
            Ok(DeferredUpdate::Retained)
        })
    }

    fn take(&self, slot: DeferredSlotId, sequence: u16) -> Result<Control, SendCompletionError> {
        let slot = self.slot(slot, sequence)?;
        slot.control.with_mut(|stored| {
            let control = stored
                .take()
                .filter(|deferred| deferred.sequence == sequence)
                .map(|deferred| deferred.control)
                .ok_or(SendCompletionError::DeferredSlotMissing)?;
            Self::release(slot, sequence)?;
            Ok(control)
        })
    }
}

pub(super) struct ProductionOwnerAtomic(
    crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU32>,
);

impl DeferredOwnerAtomic for ProductionOwnerAtomic {
    fn new(value: u32) -> Self {
        Self(crate::authority::AuthorityAtomic::new_u32(
            value,
            crate::authority::AtomicProtocolId::TransmitCompletion,
        ))
    }

    fn load_acquire(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    fn claim(&self, current: u32, next: u32) -> Result<u32, u32> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn release(&self, current: u32, next: u32) -> Result<u32, u32> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }
}

pub(super) struct ProductionControlCell(
    crate::authority::AuthorityMutex<
        crate::authority::tags::SessionControl,
        Option<DeferredControl<DeferredPeerControl>>,
    >,
);

impl DeferredControlCell<DeferredPeerControl> for ProductionControlCell {
    fn with_mut<Result>(
        &self,
        operation: impl FnOnce(&mut Option<DeferredControl<DeferredPeerControl>>) -> Result,
    ) -> Result {
        let mut control = crate::runtime_support::lock_authority_or_shutdown(
            &self.0,
            "ICMP send-completion deferred slot",
        );
        operation(&mut control)
    }
}

pub(super) type ProductionDeferredStore =
    SequenceOwnedDeferredStore<ProductionOwnerAtomic, ProductionControlCell, DeferredPeerControl>;

pub(super) fn production_deferred_store(
    capacity: usize,
    authority_flow: u64,
) -> ProductionDeferredStore {
    SequenceOwnedDeferredStore::new(capacity, |index| {
        ProductionControlCell(crate::authority::AuthorityMutex::new(
            None,
            crate::authority::AuthorityInstance {
                id: crate::authority::AuthorityId::SessionControl,
                flow: authority_flow,
                direction: 0,
                kind: 1,
                session: u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .unwrap_or_else(|| {
                        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                            "ICMP deferred-slot authority identity overflowed"
                        ))
                    }),
            },
        ))
    })
}
