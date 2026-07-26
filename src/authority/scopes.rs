use super::{AuthorityError, AuthorityInstance, AuthoritySpec, OperationId, audit};
use std::fmt;
use std::marker::PhantomData;
use std::time::Duration;

pub(crate) struct AuthorityScope<Tag: AuthoritySpec> {
    instance: AuthorityInstance,
    active: bool,
    _tag: PhantomData<Tag>,
}

impl<Tag: AuthoritySpec> fmt::Debug for AuthorityScope<Tag> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityScope")
            .field("instance", &self.instance)
            .field("active", &self.active)
            .finish()
    }
}

pub(crate) struct AuditedOperationScope {
    id: OperationId,
    active: bool,
}

impl AuditedOperationScope {
    pub(crate) fn enter(id: OperationId) -> Result<Self, AuthorityError> {
        audit::enter_operation(id)?;
        Ok(Self { id, active: true })
    }

    pub(crate) fn enter_fatal_publication() -> Self {
        let id = OperationId::FatalPublication;
        let active = audit::enter_operation(id).is_ok();
        Self { id, active }
    }
}

impl Drop for AuditedOperationScope {
    fn drop(&mut self) {
        if self.active {
            audit::leave_operation(self.id);
            self.active = false;
        }
    }
}

impl<Tag: AuthoritySpec> AuthorityScope<Tag> {
    #[track_caller]
    pub(crate) fn enter(instance: AuthorityInstance) -> Result<Self, AuthorityError> {
        Self::enter_at(instance, std::panic::Location::caller())
    }

    pub(crate) fn enter_at(
        instance: AuthorityInstance,
        location: &'static std::panic::Location<'static>,
    ) -> Result<Self, AuthorityError> {
        audit::acquire(instance, location)?;
        Ok(Self {
            instance,
            active: true,
            _tag: PhantomData,
        })
    }

    pub(crate) fn release(&mut self) {
        if self.active {
            audit::release(self.instance);
            self.active = false;
        }
    }
}

impl<Tag: AuthoritySpec> Drop for AuthorityScope<Tag> {
    fn drop(&mut self) {
        self.release();
    }
}

pub(crate) struct AuthorityQueue<Tag: AuthoritySpec, T> {
    inner: crossbeam_queue::ArrayQueue<T>,
    instance: AuthorityInstance,
    _tag: PhantomData<Tag>,
}

impl<Tag: AuthoritySpec, T> AuthorityQueue<Tag, T> {
    pub(crate) fn new(capacity: usize, instance: AuthorityInstance) -> Self {
        Self {
            inner: crossbeam_queue::ArrayQueue::new(capacity),
            instance,
            _tag: PhantomData,
        }
    }

    pub(crate) fn push(&self, value: T) -> Result<(), T> {
        let operation = match AuditedOperationScope::enter(OperationId::FixedQueue) {
            Ok(scope) => scope,
            Err(error) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "queue authority audit rejected publication: {error}"
                ));
                return Err(value);
            }
        };
        audit::record_access(self.instance.id);
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        let result = self.inner.push(value);
        drop(operation);
        result
    }

    pub(crate) fn pop(&self) -> Option<T> {
        let operation =
            AuditedOperationScope::enter(OperationId::FixedQueue).unwrap_or_else(|error| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "queue authority audit rejected consumption: {error}"
                ))
            });
        audit::record_access(self.instance.id);
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        let value = self.inner.pop();
        drop(operation);
        value
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

pub(crate) struct AuthorityChannelSender<Tag: AuthoritySpec, T> {
    inner: crossbeam_channel::Sender<T>,
    instance: AuthorityInstance,
    operation: OperationId,
    _tag: PhantomData<Tag>,
}

pub(crate) struct AuthorityChannelReceiver<Tag: AuthoritySpec, T> {
    inner: crossbeam_channel::Receiver<T>,
    instance: AuthorityInstance,
    operation: OperationId,
    _tag: PhantomData<Tag>,
}

/// Consuming bootstrap ownership for a value with exactly one runtime consumer.
///
/// The wrapped value cannot be cloned or claimed through shared state. Startup
/// must move this token directly into the component that owns consumption.
#[must_use]
pub(crate) struct SingleConsumerBootstrap<T> {
    value: T,
}

impl<T> SingleConsumerBootstrap<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self { value }
    }

    pub(crate) fn transfer(self) -> T {
        self.value
    }
}

pub(crate) fn bounded_authority_channel<Tag: AuthoritySpec, T>(
    capacity: usize,
    instance: AuthorityInstance,
    send_operation: OperationId,
    receive_operation: OperationId,
) -> (
    AuthorityChannelSender<Tag, T>,
    AuthorityChannelReceiver<Tag, T>,
) {
    let (sender, receiver) = crossbeam_channel::bounded(capacity);
    (
        AuthorityChannelSender {
            inner: sender,
            instance,
            operation: send_operation,
            _tag: PhantomData,
        },
        AuthorityChannelReceiver {
            inner: receiver,
            instance,
            operation: receive_operation,
            _tag: PhantomData,
        },
    )
}

impl<Tag: AuthoritySpec, T> AuthorityChannelSender<Tag, T> {
    pub(crate) fn try_send(&self, value: T) -> Result<(), crossbeam_channel::TrySendError<T>> {
        let _operation = AuditedOperationScope::enter(self.operation).unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "channel send authority audit rejected publication: {error}"
            ))
        });
        audit::record_access(self.instance.id);
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        self.inner.try_send(value)
    }
}

impl<Tag: AuthoritySpec, T> AuthorityChannelReceiver<Tag, T> {
    pub(crate) fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<T, crossbeam_channel::RecvTimeoutError> {
        let _operation = AuditedOperationScope::enter(self.operation).unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "channel receive authority audit rejected consumption: {error}"
            ))
        });
        audit::record_access(self.instance.id);
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        self.inner.recv_timeout(timeout)
    }
}
