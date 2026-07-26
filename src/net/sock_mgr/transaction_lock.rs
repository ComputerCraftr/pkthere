use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::{Duration, Instant};

pub(super) const MAX_CANCELLED_TICKETS: usize = 256;
pub(crate) const MANAGER_RESERVATION_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationError {
    TimedOut,
    Shutdown,
    QueueFull,
    TicketExhausted,
    OwnershipLost,
    CancellationCorrupted,
}

impl fmt::Display for ReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::runtime_support::format_debug(self, formatter)
    }
}

impl std::error::Error for ReservationError {}

impl ReservationError {
    pub(crate) const fn class(self) -> crate::runtime_support::FailureClass {
        use crate::runtime_support::FailureClass;
        match self {
            Self::TimedOut => FailureClass::RetryableContention,
            Self::Shutdown => FailureClass::Shutdown,
            Self::QueueFull => FailureClass::OperationFailed,
            Self::TicketExhausted | Self::OwnershipLost | Self::CancellationCorrupted => {
                FailureClass::FatalInvariant
            }
        }
    }
}

/// FIFO manager reservation whose guard never retains a `MutexGuard`.
///
/// The serving ticket is both queue position and ownership authority. Keeping
/// those facts in one atomic prevents a release from exposing a split
/// `unowned/current-ticket` state. The mutex coordinates sleeping and
/// cancellation scanning only.
pub(crate) struct ManagerTransaction<
    Tag: crate::authority::AuthoritySpec = crate::authority::tags::ManagerTransaction,
> {
    instance_key: u64,
    pub(super) core: super::fifo_core::FifoReservationCore<
        crate::authority::AuthorityAtomic<Tag, AtomicU64>,
        crate::authority::AuthorityAtomic<Tag, AtomicBool>,
        MAX_CANCELLED_TICKETS,
    >,
    wake: Arc<crate::runtime_support::WaitAuthorityWake>,
    _tag: PhantomData<Tag>,
}

pub(crate) struct ManagerTransactionGuard<
    'a,
    Tag: crate::authority::AuthoritySpec = crate::authority::tags::ManagerTransaction,
> {
    lease: super::fifo_core::FifoReservationLease<&'a ManagerTransaction<Tag>>,
    _authority: crate::authority::AuthorityScope<Tag>,
}

pub(crate) struct CommittedReservation {
    _ticket: NonZeroU64,
}

pub(crate) struct ManagerTransactionGuardSet<'a> {
    guards: Vec<ManagerTransactionGuard<'a>>,
}

impl<'a> ManagerTransactionGuardSet<'a> {
    pub(crate) fn try_collect<E>(
        guards: impl IntoIterator<Item = Result<ManagerTransactionGuard<'a>, E>>,
    ) -> Result<Self, E> {
        let iterator = guards.into_iter();
        let mut collected = Vec::with_capacity(iterator.size_hint().0);
        for guard in iterator {
            match guard {
                Ok(guard) => collected.push(guard),
                Err(error) => {
                    while collected.pop().is_some() {}
                    return Err(error);
                }
            }
        }
        Ok(Self { guards: collected })
    }

    pub(crate) fn try_collect_into<E>(
        mut collected: Vec<ManagerTransactionGuard<'a>>,
        guards: impl IntoIterator<Item = Result<ManagerTransactionGuard<'a>, E>>,
    ) -> Result<Self, E> {
        for guard in guards {
            match guard {
                Ok(guard) => collected.push(guard),
                Err(error) => {
                    while collected.pop().is_some() {}
                    return Err(error);
                }
            }
        }
        Ok(Self { guards: collected })
    }

    pub(crate) fn commit_all(mut self) -> Result<(), ReservationError> {
        while let Some(guard) = self.guards.pop() {
            guard.commit()?;
        }
        Ok(())
    }
}

impl<'a> Deref for ManagerTransactionGuardSet<'a> {
    type Target = [ManagerTransactionGuard<'a>];

    fn deref(&self) -> &Self::Target {
        &self.guards
    }
}

impl<'set, 'guard> IntoIterator for &'set ManagerTransactionGuardSet<'guard> {
    type Item = &'set ManagerTransactionGuard<'guard>;
    type IntoIter = std::slice::Iter<'set, ManagerTransactionGuard<'guard>>;

    fn into_iter(self) -> Self::IntoIter {
        self.guards.iter()
    }
}

impl Drop for ManagerTransactionGuardSet<'_> {
    fn drop(&mut self) {
        while self.guards.pop().is_some() {}
    }
}

impl CommittedReservation {
    #[cfg(test)]
    pub(super) fn ticket(&self) -> NonZeroU64 {
        self._ticket
    }
}

impl ManagerTransaction<crate::authority::tags::ManagerTransaction> {
    pub(crate) fn new(instance_key: u64) -> Self {
        Self::new_tagged(instance_key)
    }
}

impl<Tag: crate::authority::AuthoritySpec> ManagerTransaction<Tag> {
    pub(crate) fn new_tagged(instance_key: u64) -> Self {
        Self {
            instance_key,
            core: super::fifo_core::FifoReservationCore::new(
                crate::authority::AuthorityAtomic::new_u64(
                    1,
                    crate::authority::AtomicProtocolId::ReservationOwnership,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    1,
                    crate::authority::AtomicProtocolId::ReservationOwnership,
                ),
                [const {
                    crate::authority::AuthorityAtomic::new_u64(
                        0,
                        crate::authority::AtomicProtocolId::ReservationOwnership,
                    )
                }; MAX_CANCELLED_TICKETS],
                crate::authority::AuthorityAtomic::new_bool(
                    false,
                    crate::authority::AtomicProtocolId::ReservationOwnership,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::ReservationOwnership,
                ),
            ),
            wake: crate::runtime_support::WaitAuthorityWake::new(
                crate::authority::WaitId::FifoReservation,
            ),
            _tag: PhantomData,
        }
    }

    #[track_caller]
    pub(crate) fn reserve_until(
        &self,
        deadline: Instant,
    ) -> Result<ManagerTransactionGuard<'_, Tag>, ReservationError> {
        if self.core.is_corrupted() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "FIFO reservation authority was already corrupted"
            ));
            return Err(ReservationError::CancellationCorrupted);
        }
        let ticket = self.allocate_ticket()?;
        loop {
            match self
                .core
                .poll(
                    ticket.get(),
                    crate::runtime_support::process_shutdown_requested(),
                )
                .map_err(|error| self.map_core_error(error))?
            {
                super::fifo_core::FifoReservationPoll::Ready => {
                    return Ok(ManagerTransactionGuard {
                        lease: super::fifo_core::FifoReservationLease::new(self, ticket.get()),
                        _authority: crate::authority::AuthorityScope::enter_at(
                            crate::authority::AuthorityInstance {
                                id: Tag::RECORD.id,
                                flow: self.instance_key,
                                direction: 0,
                                kind: 0,
                                session: ticket.get(),
                            },
                            std::panic::Location::caller(),
                        )
                        .unwrap_or_else(|error| {
                            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                                "manager transaction authority order was violated: {error}"
                            ))
                        }),
                    });
                }
                super::fifo_core::FifoReservationPoll::Shutdown => {
                    self.cancel(ticket)?;
                    return Err(ReservationError::Shutdown);
                }
                super::fifo_core::FifoReservationPoll::Wait { wake_generation } => {
                    if Instant::now() >= deadline {
                        self.cancel(ticket)?;
                        return Err(ReservationError::TimedOut);
                    }
                    self.wait_once(ticket, wake_generation, deadline)?;
                }
            }
        }
    }

    fn allocate_ticket(&self) -> Result<NonZeroU64, ReservationError> {
        let ticket = self
            .core
            .allocate(crate::runtime_support::process_shutdown_requested())
            .map_err(|error| self.map_core_error(error))?;
        NonZeroU64::new(ticket).ok_or_else(|| self.corrupt(ReservationError::TicketExhausted))
    }

    fn cancel(&self, ticket: NonZeroU64) -> Result<(), ReservationError> {
        let guard = self.wake.coordination_guard();
        self.core
            .cancel(ticket.get())
            .map_err(|error| self.map_core_error(error))?;
        self.wake.notify_all();
        drop(guard);
        Ok(())
    }

    fn release(&self, ticket: NonZeroU64) -> Result<(), ReservationError> {
        let guard = self.wake.coordination_guard();
        self.core
            .release(ticket.get())
            .map_err(|error| self.map_core_error(error))?;
        self.wake.notify_all();
        drop(guard);
        Ok(())
    }

    fn corrupt(&self, error: ReservationError) -> ReservationError {
        self.core.force_corrupted();
        self.wake.notify_all();
        crate::runtime_support::publish_process_fatal(format_args!(
            "FIFO reservation authority corrupted: {error}"
        ));
        error
    }

    fn map_core_error(
        &self,
        error: super::fifo_core::FifoReservationCoreError,
    ) -> ReservationError {
        use super::fifo_core::FifoReservationCoreError;
        let mapped = match error {
            FifoReservationCoreError::QueueFull => return ReservationError::QueueFull,
            FifoReservationCoreError::Shutdown => return ReservationError::Shutdown,
            FifoReservationCoreError::Exhausted => ReservationError::TicketExhausted,
            FifoReservationCoreError::OwnershipLost => ReservationError::OwnershipLost,
            FifoReservationCoreError::CancellationCorrupted
            | FifoReservationCoreError::Corrupted => ReservationError::CancellationCorrupted,
        };
        self.corrupt(mapped)
    }

    fn wait_once(
        &self,
        ticket: NonZeroU64,
        wake_generation: u64,
        deadline: Instant,
    ) -> Result<(), ReservationError> {
        let guard = self.wake.coordination_guard();
        let should_wait = self
            .core
            .wait_required(
                ticket.get(),
                wake_generation,
                crate::runtime_support::process_shutdown_requested(),
            )
            .map_err(|error| self.map_core_error(error))?;
        if should_wait {
            self.wake
                .wait_guard_until(guard, deadline, Duration::from_millis(50));
        } else {
            drop(guard);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn coordination_mutex_is_available_for_test(&self) -> bool {
        self.wake.coordination_mutex_is_available()
    }
}

impl<Tag: crate::authority::AuthoritySpec> super::fifo_core::FifoReservationLeaseOwner
    for ManagerTransaction<Tag>
{
    type Error = ReservationError;

    fn validate_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        self.core
            .validate(ticket)
            .map_err(|error| self.map_core_error(error))
    }

    fn complete_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        let ticket = NonZeroU64::new(ticket)
            .ok_or_else(|| self.corrupt(ReservationError::TicketExhausted))?;
        self.release(ticket)
    }

    fn emergency_release_ticket(&self, ticket: u64) {
        let Some(ticket) = NonZeroU64::new(ticket) else {
            self.corrupt(ReservationError::TicketExhausted);
            return;
        };
        if self.release(ticket).is_err() {
            self.core.force_corrupted();
            self.wake.notify_all();
            crate::runtime_support::publish_process_fatal(format_args!(
                "FIFO reservation ticket {ticket} lost ownership during emergency release"
            ));
        }
    }
}

impl<Tag: crate::authority::AuthoritySpec> ManagerTransactionGuard<'_, Tag> {
    pub(crate) fn ticket(&self) -> NonZeroU64 {
        NonZeroU64::new(self.lease.ticket()).unwrap_or_else(|| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "manager transaction lease exposed a zero ticket"
            ))
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ReservationError> {
        self.lease.validate()
    }

    pub(crate) fn commit(self) -> Result<CommittedReservation, ReservationError> {
        let ticket = self.lease.commit()?;
        let ticket = NonZeroU64::new(ticket).ok_or(ReservationError::TicketExhausted)?;
        Ok(CommittedReservation { _ticket: ticket })
    }

    pub(crate) fn rollback(self) -> Result<(), ReservationError> {
        self.lease.rollback()
    }
}
