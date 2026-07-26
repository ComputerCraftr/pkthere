use std::marker::PhantomData;

const RETIREMENT_OPEN: u8 = 0;
const RETIREMENT_REQUESTED: u8 = 1;
const RETIREMENT_COMPLETE: u8 = 2;
const COMPLETION_PHASE_MASK: u32 = u8::MAX as u32;
const DEFERRED_SLOT_SHIFT: u32 = u8::BITS;
const TRANSMIT_NEXT_BITS: u32 = 17;
const TRANSMIT_NEXT_MASK: u64 = (1_u64 << TRANSMIT_NEXT_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SendCompletionState {
    Vacant = 0,
    Reserved = 1,
    InFlight = 2,
    InFlightDeferred = 3,
    Sent = 4,
    Failed = 5,
    ApplyingSuccessByCompletion = 6,
    RejectingFailureByCompletion = 7,
    ApplyingByControl = 8,
    RejectingByControl = 9,
    RetirementPending = 10,
    RetirementPendingDeferred = 11,
    Retired = 12,
    ConsumedSent = 13,
    ConsumedFailed = 14,
}

impl SendCompletionState {
    fn decode(value: u32) -> Result<Self, SendCompletionError> {
        match value & COMPLETION_PHASE_MASK {
            0 => Ok(Self::Vacant),
            1 => Ok(Self::Reserved),
            2 => Ok(Self::InFlight),
            3 => Ok(Self::InFlightDeferred),
            4 => Ok(Self::Sent),
            5 => Ok(Self::Failed),
            6 => Ok(Self::ApplyingSuccessByCompletion),
            7 => Ok(Self::RejectingFailureByCompletion),
            8 => Ok(Self::ApplyingByControl),
            9 => Ok(Self::RejectingByControl),
            10 => Ok(Self::RetirementPending),
            11 => Ok(Self::RetirementPendingDeferred),
            12 => Ok(Self::Retired),
            13 => Ok(Self::ConsumedSent),
            14 => Ok(Self::ConsumedFailed),
            _ => Err(SendCompletionError::InvalidState(value)),
        }
    }

    const fn encode(self) -> u32 {
        self as u32
    }

    fn encode_deferred(self, slot: DeferredSlotId) -> Result<u32, SendCompletionError> {
        let encoded_slot = u32::try_from(slot.index())
            .ok()
            .and_then(|index| index.checked_add(1))
            .and_then(|index| index.checked_shl(DEFERRED_SLOT_SHIFT))
            .ok_or(SendCompletionError::DeferredStoreFull)?;
        Ok(encoded_slot | self.encode())
    }

    fn deferred_slot(value: u32) -> Result<DeferredSlotId, SendCompletionError> {
        let encoded = value >> DEFERRED_SLOT_SHIFT;
        let index = encoded
            .checked_sub(1)
            .ok_or(SendCompletionError::DeferredSlotMissing)?;
        let index = usize::try_from(index).map_err(|_| SendCompletionError::DeferredSlotMissing)?;
        DeferredSlotId::from_index(index)
    }
}

pub(super) trait SendCompletionAtomic: Sized {
    fn new(value: u32) -> Self;
    fn load(&self) -> u32;
    fn compare_exchange(&self, current: u32, next: u32) -> Result<u32, u32>;
    fn store(&self, value: u32);
}

pub(super) trait SendAllocationAtomic: Sized {
    fn new(value: u64) -> Self;
    fn load(&self) -> u64;
    fn compare_exchange(&self, current: u64, next: u64) -> Result<u64, u64>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(super) enum TransmitSessionStatus {
    Active = 0,
    Exhausted = 1,
    Superseded = 2,
    Retired = 3,
}

impl TransmitSessionStatus {
    fn decode(value: u64) -> Result<Self, SendCompletionError> {
        match value {
            0 => Ok(Self::Active),
            1 => Ok(Self::Exhausted),
            2 => Ok(Self::Superseded),
            3 => Ok(Self::Retired),
            _ => Err(SendCompletionError::InvalidAllocationState(value)),
        }
    }
}

pub(super) trait SendCompletionStore<Control> {
    fn install(
        &self,
        deferred: DeferredControl<Control>,
        publish: impl FnOnce(DeferredSlotId) -> Result<bool, SendCompletionError>,
    ) -> Result<DeferredInstall, SendCompletionError>;

    fn update(
        &self,
        slot: DeferredSlotId,
        deferred: DeferredControl<Control>,
    ) -> Result<DeferredUpdate, SendCompletionError>;

    fn take(&self, slot: DeferredSlotId, sequence: u16) -> Result<Control, SendCompletionError>;
}

pub(super) trait SendCompletionControl: Copy {
    fn same_control(self, other: Self) -> bool;
    fn retain_earliest(&mut self, other: Self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeferredControl<Control> {
    pub(super) sequence: u16,
    pub(super) control: Control,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeferredSlotId(u16);

impl DeferredSlotId {
    pub(super) fn from_index(index: usize) -> Result<Self, SendCompletionError> {
        u16::try_from(index)
            .map(Self)
            .map_err(|_| SendCompletionError::DeferredStoreFull)
    }

    pub(super) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeferredUpdate {
    Retained,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeferredInstall {
    Published(DeferredSlotId),
    Raced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ControlObservation<Control> {
    Deferred,
    Apply(Control),
    Reject(Control),
    Stale,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompletionDisposition<Control> {
    None,
    Apply(Control),
    Reject(Control),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArmSendDisposition<Control> {
    Armed,
    Retired(CompletionDisposition<Control>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetirementProgress {
    Draining,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SendCompletionEvidence {
    Unknown,
    InFlight,
    Sent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SendCompletionError {
    InvalidSequence,
    InvalidState(u32),
    InvalidAllocationState(u64),
    SequenceExhausted,
    OwnershipLost,
    DeferredSlotMissing,
    DeferredStoreFull,
    Retired,
}

pub(super) struct SendCompletionCore<Atomic, AllocationAtomic, Store, Control> {
    states: Box<[Atomic]>,
    allocation: AllocationAtomic,
    retirement: Atomic,
    deferred: Store,
    _control: PhantomData<fn(Control)>,
}

impl<Atomic, AllocationAtomic, Store, Control>
    SendCompletionCore<Atomic, AllocationAtomic, Store, Control>
where
    Atomic: SendCompletionAtomic,
    AllocationAtomic: SendAllocationAtomic,
    Store: SendCompletionStore<Control>,
    Control: SendCompletionControl,
{
    pub(super) fn new(
        sequence_count: usize,
        deferred_capacity: usize,
        create_deferred: impl FnOnce(usize) -> Store,
    ) -> Self {
        let states = (0..sequence_count)
            .map(|_| Atomic::new(SendCompletionState::Vacant.encode()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            states,
            allocation: AllocationAtomic::new(
                (TransmitSessionStatus::Active as u64) << TRANSMIT_NEXT_BITS,
            ),
            retirement: Atomic::new(u32::from(RETIREMENT_OPEN)),
            deferred: create_deferred(deferred_capacity),
            _control: PhantomData,
        }
    }

    pub(super) fn reserve_next(&self) -> Result<u16, SendCompletionError> {
        loop {
            let observed = self.allocation.load();
            let status = TransmitSessionStatus::decode(observed >> TRANSMIT_NEXT_BITS)?;
            match status {
                TransmitSessionStatus::Active => {}
                TransmitSessionStatus::Exhausted => {
                    return Err(SendCompletionError::SequenceExhausted);
                }
                TransmitSessionStatus::Superseded | TransmitSessionStatus::Retired => {
                    return Err(SendCompletionError::Retired);
                }
            }
            let next = observed & TRANSMIT_NEXT_MASK;
            if next > u64::from(u16::MAX) {
                return Err(SendCompletionError::SequenceExhausted);
            }
            let sequence = u16::try_from(next)
                .map_err(|_| SendCompletionError::InvalidAllocationState(observed))?;
            let following = next
                .checked_add(1)
                .ok_or(SendCompletionError::InvalidAllocationState(observed))?;
            let next_status = if sequence == u16::MAX {
                TransmitSessionStatus::Exhausted
            } else {
                TransmitSessionStatus::Active
            };
            let updated = (next_status as u64) << TRANSMIT_NEXT_BITS | following;
            if self.allocation.compare_exchange(observed, updated).is_err() {
                continue;
            }
            let state = self.state(sequence)?;
            if state
                .compare_exchange(
                    SendCompletionState::Vacant.encode(),
                    SendCompletionState::Reserved.encode(),
                )
                .is_err()
            {
                return if SendCompletionState::decode(state.load())? == SendCompletionState::Retired
                    && matches!(
                        self.status()?,
                        TransmitSessionStatus::Superseded | TransmitSessionStatus::Retired
                    ) {
                    Err(SendCompletionError::Retired)
                } else {
                    Err(SendCompletionError::OwnershipLost)
                };
            }
            let current_status = self.status()?;
            if matches!(
                current_status,
                TransmitSessionStatus::Active | TransmitSessionStatus::Exhausted
            ) {
                return Ok(sequence);
            }
            self.cancel_unexposed_reservation(sequence)?;
            return Err(SendCompletionError::Retired);
        }
    }

    pub(super) fn arm_send(
        &self,
        sequence: u16,
    ) -> Result<ArmSendDisposition<Control>, SendCompletionError> {
        if self.retirement.load() != u32::from(RETIREMENT_OPEN) {
            return Ok(ArmSendDisposition::Retired(
                self.cancel_unexposed_reservation(sequence)?,
            ));
        }
        let state = self.state(sequence)?;
        if state
            .compare_exchange(
                SendCompletionState::Reserved.encode(),
                SendCompletionState::InFlight.encode(),
            )
            .is_err()
        {
            return match SendCompletionState::decode(state.load())? {
                SendCompletionState::Retired => Err(SendCompletionError::Retired),
                _ => Err(SendCompletionError::OwnershipLost),
            };
        }
        if self.retirement.load() == u32::from(RETIREMENT_OPEN) {
            Ok(ArmSendDisposition::Armed)
        } else {
            Ok(ArmSendDisposition::Retired(
                self.cancel_unexposed_reservation(sequence)?,
            ))
        }
    }

    pub(super) fn allocated(&self) -> Result<u32, SendCompletionError> {
        u32::try_from(self.allocation.load() & TRANSMIT_NEXT_MASK)
            .map_err(|_| SendCompletionError::InvalidAllocationState(self.allocation.load()))
    }

    pub(super) fn status(&self) -> Result<TransmitSessionStatus, SendCompletionError> {
        TransmitSessionStatus::decode(self.allocation.load() >> TRANSMIT_NEXT_BITS)
    }

    pub(super) fn request_retirement(
        &self,
        status: TransmitSessionStatus,
    ) -> Result<RetirementProgress, SendCompletionError> {
        if !matches!(
            status,
            TransmitSessionStatus::Superseded | TransmitSessionStatus::Retired
        ) {
            return Err(SendCompletionError::InvalidAllocationState(status as u64));
        }
        loop {
            let observed = self.allocation.load();
            let current = TransmitSessionStatus::decode(observed >> TRANSMIT_NEXT_BITS)?;
            if matches!(
                current,
                TransmitSessionStatus::Superseded | TransmitSessionStatus::Retired
            ) {
                break;
            }
            let updated = (status as u64) << TRANSMIT_NEXT_BITS | (observed & TRANSMIT_NEXT_MASK);
            if self.allocation.compare_exchange(observed, updated).is_ok() {
                break;
            }
        }
        self.retire_allocated()?;
        self.complete_retirement()
    }

    pub(super) fn complete_retirement(&self) -> Result<RetirementProgress, SendCompletionError> {
        if self.retirement.load() == u32::from(RETIREMENT_COMPLETE) {
            return Ok(RetirementProgress::Complete);
        }
        let limit = usize::try_from(self.allocated()?)
            .map_err(|_| SendCompletionError::InvalidSequence)?
            .min(self.states.len());
        if self.states.iter().take(limit).any(|state| {
            matches!(
                SendCompletionState::decode(state.load()),
                Ok(SendCompletionState::InFlight
                    | SendCompletionState::InFlightDeferred
                    | SendCompletionState::RetirementPending
                    | SendCompletionState::RetirementPendingDeferred
                    | SendCompletionState::ApplyingSuccessByCompletion
                    | SendCompletionState::RejectingFailureByCompletion
                    | SendCompletionState::ApplyingByControl
                    | SendCompletionState::RejectingByControl)
            )
        }) {
            return Ok(RetirementProgress::Draining);
        }
        self.retirement
            .compare_exchange(
                u32::from(RETIREMENT_REQUESTED),
                u32::from(RETIREMENT_COMPLETE),
            )
            .or_else(|observed| {
                (observed == u32::from(RETIREMENT_COMPLETE))
                    .then_some(observed)
                    .ok_or(observed)
            })
            .map_err(SendCompletionError::InvalidState)?;
        Ok(RetirementProgress::Complete)
    }

    pub(super) fn observe_peer_control(
        &self,
        sequence: u16,
        control: Control,
    ) -> Result<ControlObservation<Control>, SendCompletionError> {
        let state = self.state(sequence)?;
        loop {
            let observed = state.load();
            match SendCompletionState::decode(observed)? {
                SendCompletionState::InFlight => {
                    let installed =
                        self.deferred
                            .install(DeferredControl { sequence, control }, |slot| {
                                let deferred =
                                    SendCompletionState::InFlightDeferred.encode_deferred(slot)?;
                                Ok(state.compare_exchange(observed, deferred).is_ok())
                            })?;
                    if matches!(installed, DeferredInstall::Published(_)) {
                        return Ok(ControlObservation::Deferred);
                    }
                }
                SendCompletionState::InFlightDeferred
                | SendCompletionState::RetirementPendingDeferred => {
                    let slot = SendCompletionState::deferred_slot(observed)?;
                    return Ok(
                        match self
                            .deferred
                            .update(slot, DeferredControl { sequence, control })?
                        {
                            DeferredUpdate::Retained => ControlObservation::Deferred,
                            DeferredUpdate::Conflict => ControlObservation::Conflict,
                        },
                    );
                }
                SendCompletionState::Sent => {
                    if state
                        .compare_exchange(observed, SendCompletionState::ApplyingByControl.encode())
                        .is_ok()
                    {
                        self.store_disposition_terminal(state, true);
                        return Ok(ControlObservation::Apply(control));
                    }
                }
                SendCompletionState::Failed => {
                    if state
                        .compare_exchange(
                            observed,
                            SendCompletionState::RejectingByControl.encode(),
                        )
                        .is_ok()
                    {
                        self.store_disposition_terminal(state, false);
                        return Ok(ControlObservation::Reject(control));
                    }
                }
                SendCompletionState::RetirementPending | SendCompletionState::Retired => {
                    return Ok(ControlObservation::Reject(control));
                }
                SendCompletionState::Vacant
                | SendCompletionState::Reserved
                | SendCompletionState::ConsumedSent
                | SendCompletionState::ConsumedFailed
                | SendCompletionState::ApplyingSuccessByCompletion
                | SendCompletionState::RejectingFailureByCompletion
                | SendCompletionState::ApplyingByControl
                | SendCompletionState::RejectingByControl => {
                    return Ok(ControlObservation::Stale);
                }
            }
        }
    }

    pub(super) fn complete_send_success(
        &self,
        sequence: u16,
    ) -> Result<CompletionDisposition<Control>, SendCompletionError> {
        self.complete_send(sequence, true)
    }

    pub(super) fn complete_send_failure(
        &self,
        sequence: u16,
    ) -> Result<CompletionDisposition<Control>, SendCompletionError> {
        self.complete_send(sequence, false)
    }

    fn complete_send(
        &self,
        sequence: u16,
        sent: bool,
    ) -> Result<CompletionDisposition<Control>, SendCompletionError> {
        let state = self.state(sequence)?;
        loop {
            let observed = state.load();
            match SendCompletionState::decode(observed)? {
                SendCompletionState::InFlight => {
                    let terminal = if sent {
                        SendCompletionState::Sent
                    } else {
                        SendCompletionState::Failed
                    };
                    if state.compare_exchange(observed, terminal.encode()).is_ok() {
                        return Ok(CompletionDisposition::None);
                    }
                }
                SendCompletionState::InFlightDeferred => {
                    let slot = SendCompletionState::deferred_slot(observed)?;
                    let owned = if sent {
                        SendCompletionState::ApplyingSuccessByCompletion
                    } else {
                        SendCompletionState::RejectingFailureByCompletion
                    };
                    let owned = owned.encode_deferred(slot)?;
                    if state.compare_exchange(observed, owned).is_ok() {
                        let control = self.deferred.take(slot, sequence)?;
                        self.store_disposition_terminal(state, sent);
                        return Ok(if sent {
                            CompletionDisposition::Apply(control)
                        } else {
                            CompletionDisposition::Reject(control)
                        });
                    }
                }
                SendCompletionState::RetirementPending => {
                    if state
                        .compare_exchange(observed, SendCompletionState::Retired.encode())
                        .is_ok()
                    {
                        return Ok(CompletionDisposition::None);
                    }
                }
                SendCompletionState::RetirementPendingDeferred => {
                    let slot = SendCompletionState::deferred_slot(observed)?;
                    let rejecting =
                        SendCompletionState::RejectingFailureByCompletion.encode_deferred(slot)?;
                    if state.compare_exchange(observed, rejecting).is_ok() {
                        let control = self.deferred.take(slot, sequence)?;
                        state.store(SendCompletionState::Retired.encode());
                        return Ok(CompletionDisposition::Reject(control));
                    }
                }
                _ => return Err(SendCompletionError::OwnershipLost),
            }
        }
    }

    fn retire_allocated(&self) -> Result<(), SendCompletionError> {
        match self
            .retirement
            .compare_exchange(u32::from(RETIREMENT_OPEN), u32::from(RETIREMENT_REQUESTED))
        {
            Ok(_) => {}
            Err(value)
                if value == u32::from(RETIREMENT_REQUESTED)
                    || value == u32::from(RETIREMENT_COMPLETE) => {}
            Err(state) => return Err(SendCompletionError::InvalidState(state)),
        }
        let limit = usize::try_from(self.allocated()?)
            .map_err(|_| SendCompletionError::InvalidSequence)?
            .min(self.states.len());
        for sequence in 0..limit {
            let sequence =
                u16::try_from(sequence).map_err(|_| SendCompletionError::InvalidSequence)?;
            self.request_sequence_retirement(sequence)?;
        }
        Ok(())
    }

    fn request_sequence_retirement(&self, sequence: u16) -> Result<(), SendCompletionError> {
        let state = self.state(sequence)?;
        loop {
            let observed = state.load();
            let next = match SendCompletionState::decode(observed)? {
                SendCompletionState::InFlight => SendCompletionState::RetirementPending,
                SendCompletionState::InFlightDeferred => {
                    let slot = SendCompletionState::deferred_slot(observed)?;
                    if state
                        .compare_exchange(
                            observed,
                            SendCompletionState::RetirementPendingDeferred.encode_deferred(slot)?,
                        )
                        .is_ok()
                    {
                        return Ok(());
                    }
                    continue;
                }
                SendCompletionState::Vacant
                | SendCompletionState::Reserved
                | SendCompletionState::Sent
                | SendCompletionState::Failed
                | SendCompletionState::ConsumedSent
                | SendCompletionState::ConsumedFailed => SendCompletionState::Retired,
                SendCompletionState::RetirementPending
                | SendCompletionState::RetirementPendingDeferred
                | SendCompletionState::Retired => return Ok(()),
                SendCompletionState::ApplyingSuccessByCompletion
                | SendCompletionState::RejectingFailureByCompletion
                | SendCompletionState::ApplyingByControl
                | SendCompletionState::RejectingByControl => return Ok(()),
            };
            if state.compare_exchange(observed, next.encode()).is_ok() {
                return Ok(());
            }
        }
    }

    pub(super) fn evidence(
        &self,
        sequence: u16,
    ) -> Result<SendCompletionEvidence, SendCompletionError> {
        let state = SendCompletionState::decode(self.state(sequence)?.load())?;
        Ok(match state {
            SendCompletionState::InFlight | SendCompletionState::InFlightDeferred => {
                SendCompletionEvidence::InFlight
            }
            SendCompletionState::Sent | SendCompletionState::ConsumedSent => {
                SendCompletionEvidence::Sent
            }
            _ => SendCompletionEvidence::Unknown,
        })
    }

    #[cfg(test)]
    pub(super) fn state_for_test(
        &self,
        sequence: u16,
    ) -> Result<SendCompletionState, SendCompletionError> {
        SendCompletionState::decode(self.state(sequence)?.load())
    }

    #[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
    pub(super) fn deferred_slot_for_test(
        &self,
        sequence: u16,
    ) -> Result<Option<usize>, SendCompletionError> {
        let state = self.state(sequence)?.load();
        Ok(matches!(
            SendCompletionState::decode(state)?,
            SendCompletionState::InFlightDeferred
                | SendCompletionState::RetirementPendingDeferred
                | SendCompletionState::ApplyingSuccessByCompletion
                | SendCompletionState::RejectingFailureByCompletion
        )
        .then(|| SendCompletionState::deferred_slot(state).map(DeferredSlotId::index))
        .transpose()?)
    }

    pub(super) fn cancel_unexposed_reservation(
        &self,
        sequence: u16,
    ) -> Result<CompletionDisposition<Control>, SendCompletionError> {
        let state = self.state(sequence)?;
        loop {
            let observed = state.load();
            match SendCompletionState::decode(observed)? {
                SendCompletionState::Reserved
                | SendCompletionState::InFlight
                | SendCompletionState::RetirementPending => {
                    if state
                        .compare_exchange(observed, SendCompletionState::Retired.encode())
                        .is_ok()
                    {
                        return Ok(CompletionDisposition::None);
                    }
                }
                SendCompletionState::InFlightDeferred
                | SendCompletionState::RetirementPendingDeferred => {
                    let slot = SendCompletionState::deferred_slot(observed)?;
                    let rejecting =
                        SendCompletionState::RejectingFailureByCompletion.encode_deferred(slot)?;
                    if state.compare_exchange(observed, rejecting).is_ok() {
                        let rejected = self.deferred.take(slot, sequence)?;
                        state.store(SendCompletionState::Retired.encode());
                        return Ok(CompletionDisposition::Reject(rejected));
                    }
                }
                SendCompletionState::Retired => return Ok(CompletionDisposition::None),
                _ => return Err(SendCompletionError::OwnershipLost),
            }
        }
    }

    fn store_disposition_terminal(&self, state: &Atomic, sent: bool) {
        let terminal = if self.retirement.load() == u32::from(RETIREMENT_REQUESTED) {
            SendCompletionState::Retired
        } else if sent {
            SendCompletionState::ConsumedSent
        } else {
            SendCompletionState::ConsumedFailed
        };
        state.store(terminal.encode());
    }

    fn state(&self, sequence: u16) -> Result<&Atomic, SendCompletionError> {
        self.states
            .get(usize::from(sequence))
            .ok_or(SendCompletionError::InvalidSequence)
    }
}
