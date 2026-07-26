use crate::atomic_core::{
    AllocationStepError, AtomicBoolAuthority, AtomicU64Authority, FifoTicketError,
    allocate_bounded_u64, mark_fifo_ticket_cancelled, release_fifo_ticket,
    skip_cancelled_fifo_ticket, stabilize_fifo_cancellation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FifoReservationCoreError {
    QueueFull,
    Shutdown,
    Exhausted,
    OwnershipLost,
    CancellationCorrupted,
    Corrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FifoReservationPoll {
    Ready,
    Shutdown,
    Wait { wake_generation: u64 },
}

pub(super) struct FifoTicketCore<Atomic, const CAPACITY: usize> {
    next: Atomic,
    serving: Atomic,
    cancelled: [Atomic; CAPACITY],
}

/// Complete atomic ownership core for one FIFO reservation authority.
///
/// Ticket allocation, cancellation, release, emergency release, corruption,
/// and the wake generation used by the sleep recheck are one publication
/// protocol. The condition variable remains a sleep mechanism only.
pub(super) struct FifoReservationCore<Atomic, Flag, const CAPACITY: usize> {
    tickets: FifoTicketCore<Atomic, CAPACITY>,
    corrupted: Flag,
    wake_generation: Atomic,
}

pub(super) trait FifoReservationLeaseOwner {
    type Error;

    fn validate_ticket(&self, ticket: u64) -> Result<(), Self::Error>;
    fn complete_ticket(&self, ticket: u64) -> Result<(), Self::Error>;
    fn emergency_release_ticket(&self, ticket: u64);
}

impl<Owner: FifoReservationLeaseOwner + ?Sized> FifoReservationLeaseOwner for &Owner {
    type Error = Owner::Error;

    fn validate_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        (**self).validate_ticket(ticket)
    }

    fn complete_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        (**self).complete_ticket(ticket)
    }

    fn emergency_release_ticket(&self, ticket: u64) {
        (**self).emergency_release_ticket(ticket);
    }
}

/// Consuming ownership for one FIFO ticket, including emergency `Drop`.
///
/// Production and Loom use this same typestate so explicit completion and
/// unwind cleanup cannot drift into separate release protocols.
pub(super) struct FifoReservationLease<Owner: FifoReservationLeaseOwner> {
    owner: Owner,
    ticket: u64,
    armed: bool,
}

impl<Owner: FifoReservationLeaseOwner> FifoReservationLease<Owner> {
    pub(super) const fn new(owner: Owner, ticket: u64) -> Self {
        Self {
            owner,
            ticket,
            armed: true,
        }
    }

    pub(super) const fn ticket(&self) -> u64 {
        self.ticket
    }

    pub(super) fn validate(&self) -> Result<(), Owner::Error> {
        self.owner.validate_ticket(self.ticket)
    }

    pub(super) fn commit(mut self) -> Result<u64, Owner::Error> {
        let result = self.owner.complete_ticket(self.ticket);
        self.armed = false;
        result.map(|()| self.ticket)
    }

    pub(super) fn rollback(self) -> Result<(), Owner::Error> {
        self.commit().map(|_| ())
    }
}

impl<Owner: FifoReservationLeaseOwner> Drop for FifoReservationLease<Owner> {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            self.owner.emergency_release_ticket(self.ticket);
        }
    }
}

impl<Atomic: AtomicU64Authority, const CAPACITY: usize> FifoTicketCore<Atomic, CAPACITY> {
    pub(super) const fn new(next: Atomic, serving: Atomic, cancelled: [Atomic; CAPACITY]) -> Self {
        Self {
            next,
            serving,
            cancelled,
        }
    }

    pub(super) fn allocate(&self) -> Result<u64, AllocationStepError> {
        allocate_bounded_u64(&self.next, || self.serving.load_acquire(), CAPACITY as u64)
    }

    pub(super) fn is_serving(&self, ticket: u64) -> bool {
        self.serving.load_acquire() == ticket
    }

    pub(super) fn cancel(&self, ticket: u64) -> Result<(), FifoTicketError> {
        let index = ticket as usize % CAPACITY;
        mark_fifo_ticket_cancelled(&self.cancelled[index], ticket)?;
        stabilize_fifo_cancellation(&self.serving, &self.cancelled[index], ticket)?;
        self.skip_cancelled()
    }

    pub(super) fn release(&self, ticket: u64) -> Result<(), FifoTicketError> {
        release_fifo_ticket(&self.serving, ticket)?;
        self.skip_cancelled()
    }

    fn skip_cancelled(&self) -> Result<(), FifoTicketError> {
        loop {
            let serving = self.serving.load_acquire();
            let index = serving as usize % CAPACITY;
            if !skip_cancelled_fifo_ticket(&self.serving, &self.cancelled[index])? {
                return Ok(());
            }
        }
    }
}

impl<Atomic, Flag, const CAPACITY: usize> FifoReservationCore<Atomic, Flag, CAPACITY>
where
    Atomic: AtomicU64Authority,
    Flag: AtomicBoolAuthority,
{
    pub(super) const fn new(
        next: Atomic,
        serving: Atomic,
        cancelled: [Atomic; CAPACITY],
        corrupted: Flag,
        wake_generation: Atomic,
    ) -> Self {
        Self {
            tickets: FifoTicketCore::new(next, serving, cancelled),
            corrupted,
            wake_generation,
        }
    }

    pub(super) fn allocate(&self, shutdown: bool) -> Result<u64, FifoReservationCoreError> {
        self.ensure_not_corrupted()?;
        if shutdown {
            return Err(FifoReservationCoreError::Shutdown);
        }
        self.tickets.allocate().map_err(|error| match error {
            AllocationStepError::QueueFull => FifoReservationCoreError::QueueFull,
            AllocationStepError::Exhausted => self.corrupt(FifoReservationCoreError::Exhausted),
        })
    }

    pub(super) fn poll(
        &self,
        ticket: u64,
        shutdown: bool,
    ) -> Result<FifoReservationPoll, FifoReservationCoreError> {
        self.ensure_not_corrupted()?;
        if shutdown {
            return Ok(FifoReservationPoll::Shutdown);
        }
        if self.tickets.is_serving(ticket) {
            return Ok(FifoReservationPoll::Ready);
        }
        Ok(FifoReservationPoll::Wait {
            wake_generation: self.wake_generation.load_acquire(),
        })
    }

    pub(super) fn wait_required(
        &self,
        ticket: u64,
        observed_wake_generation: u64,
        shutdown: bool,
    ) -> Result<bool, FifoReservationCoreError> {
        match self.poll(ticket, shutdown)? {
            FifoReservationPoll::Ready | FifoReservationPoll::Shutdown => Ok(false),
            FifoReservationPoll::Wait { wake_generation } => {
                Ok(wake_generation == observed_wake_generation)
            }
        }
    }

    pub(super) fn cancel(&self, ticket: u64) -> Result<(), FifoReservationCoreError> {
        self.ensure_not_corrupted()?;
        self.tickets
            .cancel(ticket)
            .map_err(|error| self.corrupt(map_ticket_error(error)))?;
        self.publish_wake()
    }

    pub(super) fn release(&self, ticket: u64) -> Result<(), FifoReservationCoreError> {
        self.ensure_not_corrupted()?;
        self.tickets
            .release(ticket)
            .map_err(|error| self.corrupt(map_ticket_error(error)))?;
        self.publish_wake()
    }

    pub(super) fn validate(&self, ticket: u64) -> Result<(), FifoReservationCoreError> {
        self.ensure_not_corrupted()?;
        if self.tickets.is_serving(ticket) {
            Ok(())
        } else {
            Err(self.corrupt(FifoReservationCoreError::OwnershipLost))
        }
    }

    pub(super) fn is_corrupted(&self) -> bool {
        self.corrupted.load_acquire()
    }

    pub(super) fn force_corrupted(&self) {
        self.corrupted.store_release(true);
    }

    #[cfg(test)]
    pub(super) fn tickets(&self) -> &FifoTicketCore<Atomic, CAPACITY> {
        &self.tickets
    }

    fn ensure_not_corrupted(&self) -> Result<(), FifoReservationCoreError> {
        if self.is_corrupted() {
            Err(FifoReservationCoreError::Corrupted)
        } else {
            Ok(())
        }
    }

    fn publish_wake(&self) -> Result<(), FifoReservationCoreError> {
        loop {
            let current = self.wake_generation.load_acquire();
            let Some(next) = current.checked_add(1) else {
                return Err(self.corrupt(FifoReservationCoreError::Exhausted));
            };
            if self.wake_generation.compare_release(current, next).is_ok() {
                return Ok(());
            }
        }
    }

    fn corrupt(&self, error: FifoReservationCoreError) -> FifoReservationCoreError {
        self.corrupted.store_release(true);
        error
    }
}

const fn map_ticket_error(error: FifoTicketError) -> FifoReservationCoreError {
    match error {
        FifoTicketError::Exhausted => FifoReservationCoreError::Exhausted,
        FifoTicketError::OwnershipLost => FifoReservationCoreError::OwnershipLost,
        FifoTicketError::CancellationCorrupted => FifoReservationCoreError::CancellationCorrupted,
    }
}
