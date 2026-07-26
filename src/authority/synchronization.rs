use super::wait_core::{WaitReacquireBackend, wait_reacquire};
use super::{
    AuditedOperationScope, AuthorityError, AuthorityInstance, AuthoritySpec, AuthorityTryLockError,
    OperationId, WaitId, audit, publish_poison, tags,
};
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{
    AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Condvar, LockResult, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

pub(crate) struct AuthorityMutex<Tag: AuthoritySpec, T> {
    inner: Mutex<T>,
    instance: AuthorityInstance,
    _tag: PhantomData<Tag>,
}

impl<Tag: AuthoritySpec, T> AuthorityMutex<Tag, T> {
    pub(crate) const fn new(value: T, instance: AuthorityInstance) -> Self {
        Self {
            inner: Mutex::new(value),
            instance,
            _tag: PhantomData,
        }
    }

    pub(crate) fn lock(&self) -> Result<AuthorityMutexGuard<'_, Tag, T>, AuthorityError> {
        audit::validate_acquisition(self.instance)?;
        let guard = self.inner.lock().map_err(|poisoned| {
            drop(poisoned.into_inner());
            publish_poison(Tag::RECORD.id);
            AuthorityError::Poisoned(Tag::RECORD.id)
        })?;
        if let Err(error) = audit::acquire(self.instance, std::panic::Location::caller()) {
            drop(guard);
            return Err(error);
        }
        Ok(AuthorityMutexGuard {
            guard: Some(guard),
            instance: self.instance,
            _tag: PhantomData,
        })
    }

    pub(crate) fn try_lock(
        &self,
    ) -> Result<AuthorityMutexGuard<'_, Tag, T>, AuthorityTryLockError> {
        audit::validate_acquisition(self.instance).map_err(AuthorityTryLockError::Authority)?;
        let guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(AuthorityTryLockError::WouldBlock);
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                drop(poisoned.into_inner());
                publish_poison(Tag::RECORD.id);
                return Err(AuthorityTryLockError::Authority(AuthorityError::Poisoned(
                    Tag::RECORD.id,
                )));
            }
        };
        audit::acquire(self.instance, std::panic::Location::caller())
            .map_err(AuthorityTryLockError::Authority)?;
        Ok(AuthorityMutexGuard {
            guard: Some(guard),
            instance: self.instance,
            _tag: PhantomData,
        })
    }

    pub(crate) fn prewarm(&self) -> Result<(), AuthorityError> {
        drop(self.lock()?);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn is_available_for_test(&self) -> bool {
        self.inner.try_lock().is_ok()
    }
}

impl<T> AuthorityMutex<tags::Diagnostic, T> {
    pub(crate) fn try_lock_reinitializing(
        &self,
        replacement: impl FnOnce() -> T,
    ) -> Result<(AuthorityMutexGuard<'_, tags::Diagnostic, T>, bool), AuthorityTryLockError> {
        audit::validate_acquisition(self.instance).map_err(AuthorityTryLockError::Authority)?;
        let (guard, reinitialized) = match self.inner.try_lock() {
            Ok(guard) => (guard, false),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(AuthorityTryLockError::WouldBlock);
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let mut guard = poisoned.into_inner();
                *guard = replacement();
                self.inner.clear_poison();
                (guard, true)
            }
        };
        audit::acquire(self.instance, std::panic::Location::caller())
            .map_err(AuthorityTryLockError::Authority)?;
        Ok((
            AuthorityMutexGuard {
                guard: Some(guard),
                instance: self.instance,
                _tag: PhantomData,
            },
            reinitialized,
        ))
    }
}

pub(crate) struct AuthorityMutexGuard<'a, Tag: AuthoritySpec, T> {
    guard: Option<MutexGuard<'a, T>>,
    instance: AuthorityInstance,
    _tag: PhantomData<Tag>,
}

pub(crate) struct AuthorityMutexGuardSet<'a, Tag: AuthoritySpec, T> {
    guards: Vec<AuthorityMutexGuard<'a, Tag, T>>,
}

impl<'a, Tag: AuthoritySpec, T> AuthorityMutexGuardSet<'a, Tag, T> {
    pub(crate) fn collect_ordered<E>(
        guards: impl IntoIterator<Item = Result<AuthorityMutexGuard<'a, Tag, T>, E>>,
    ) -> Result<Self, E> {
        let iterator = guards.into_iter();
        let (minimum, maximum) = iterator.size_hint();
        if maximum != Some(minimum) {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ordered authority collection requires an exact preallocation bound"
            ));
        }
        let mut collected = Self {
            guards: Vec::with_capacity(minimum),
        };
        for guard in iterator {
            match guard {
                Ok(guard) => collected.guards.push(guard),
                Err(error) => {
                    while collected.guards.pop().is_some() {}
                    return Err(error);
                }
            }
        }
        Ok(collected)
    }

    pub(crate) fn collect_ordered_into<E>(
        mut guards: Vec<AuthorityMutexGuard<'a, Tag, T>>,
        incoming: impl IntoIterator<Item = Result<AuthorityMutexGuard<'a, Tag, T>, E>>,
    ) -> Result<Self, E> {
        let iterator = incoming.into_iter();
        let (minimum, maximum) = iterator.size_hint();
        if maximum != Some(minimum) || guards.capacity().saturating_sub(guards.len()) < minimum {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ordered authority collection lost its preallocated guard capacity"
            ));
        }
        for guard in iterator {
            match guard {
                Ok(guard) => guards.push(guard),
                Err(error) => {
                    while guards.pop().is_some() {}
                    return Err(error);
                }
            }
        }
        Ok(Self { guards })
    }
}

impl<'a, Tag: AuthoritySpec, T> Deref for AuthorityMutexGuardSet<'a, Tag, T> {
    type Target = [AuthorityMutexGuard<'a, Tag, T>];

    fn deref(&self) -> &Self::Target {
        &self.guards
    }
}

impl<'a, Tag: AuthoritySpec, T> DerefMut for AuthorityMutexGuardSet<'a, Tag, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guards
    }
}

impl<'set, 'guard, Tag: AuthoritySpec, T> IntoIterator
    for &'set AuthorityMutexGuardSet<'guard, Tag, T>
{
    type Item = &'set AuthorityMutexGuard<'guard, Tag, T>;
    type IntoIter = std::slice::Iter<'set, AuthorityMutexGuard<'guard, Tag, T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.guards.iter()
    }
}

impl<'set, 'guard, Tag: AuthoritySpec, T> IntoIterator
    for &'set mut AuthorityMutexGuardSet<'guard, Tag, T>
{
    type Item = &'set mut AuthorityMutexGuard<'guard, Tag, T>;
    type IntoIter = std::slice::IterMut<'set, AuthorityMutexGuard<'guard, Tag, T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.guards.iter_mut()
    }
}

impl<Tag: AuthoritySpec, T> Drop for AuthorityMutexGuardSet<'_, Tag, T> {
    fn drop(&mut self) {
        while self.guards.pop().is_some() {}
    }
}

impl<Tag: AuthoritySpec, T> Deref for AuthorityMutexGuard<'_, Tag, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self.guard.as_deref() {
            Some(value) => value,
            None => crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "authority guard was accessed while released for a wait"
            )),
        }
    }
}

impl<Tag: AuthoritySpec, T> DerefMut for AuthorityMutexGuard<'_, Tag, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.guard.as_deref_mut() {
            Some(value) => value,
            None => crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "authority guard was mutably accessed while released for a wait"
            )),
        }
    }
}

impl<Tag: AuthoritySpec, T> Drop for AuthorityMutexGuard<'_, Tag, T> {
    fn drop(&mut self) {
        if self.guard.take().is_some() {
            audit::release(self.instance);
        }
    }
}

pub(crate) struct AuthorityCondvar<Tag: AuthoritySpec> {
    inner: Condvar,
    wait: WaitId,
    _tag: PhantomData<Tag>,
}

struct AuthorityWaitBackend<'condition, Tag: AuthoritySpec> {
    condition: &'condition Condvar,
    instance: AuthorityInstance,
    wait: WaitId,
    operation: Option<AuditedOperationScope>,
    _tag: PhantomData<Tag>,
}

impl<'condition, 'guard, Tag: AuthoritySpec, T> WaitReacquireBackend<MutexGuard<'guard, T>>
    for AuthorityWaitBackend<'condition, Tag>
{
    type Error = AuthorityError;

    fn release_for_wait(&mut self) -> Result<(), Self::Error> {
        audit::release_for_wait(self.instance);
        self.operation = Some(AuditedOperationScope::enter(OperationId::CondvarWait)?);
        audit::record_wait(self.wait);
        Ok(())
    }

    fn wait_timeout(
        &mut self,
        guard: MutexGuard<'guard, T>,
        timeout: Duration,
    ) -> Result<(MutexGuard<'guard, T>, bool), Self::Error> {
        let waited: LockResult<(MutexGuard<'guard, T>, std::sync::WaitTimeoutResult)> =
            self.condition.wait_timeout(guard, timeout);
        drop(self.operation.take());
        let (guard, timeout) = waited.map_err(|poisoned| {
            let (recovered, _) = poisoned.into_inner();
            drop(recovered);
            publish_poison(Tag::RECORD.id);
            AuthorityError::Poisoned(Tag::RECORD.id)
        })?;
        Ok((guard, timeout.timed_out()))
    }

    fn reacquire_after_wait(&mut self) -> Result<(), Self::Error> {
        audit::reacquire_after_wait(self.instance, std::panic::Location::caller())
    }
}

impl<Tag: AuthoritySpec> AuthorityCondvar<Tag> {
    pub(crate) const fn new(wait: WaitId) -> Self {
        Self {
            inner: Condvar::new(),
            wait,
            _tag: PhantomData,
        }
    }

    pub(crate) fn notify_all(&self) {
        self.inner.notify_all();
    }

    pub(crate) fn prewarm(&self) {
        self.inner.notify_all();
    }

    pub(crate) fn wait_until<'a, T>(
        &self,
        guard: AuthorityMutexGuard<'a, Tag, T>,
        deadline: Instant,
    ) -> Result<(AuthorityMutexGuard<'a, Tag, T>, bool), AuthorityError> {
        self.wait_until_as(guard, deadline, self.wait)
    }

    pub(crate) fn wait_until_as<'a, T>(
        &self,
        mut guard: AuthorityMutexGuard<'a, Tag, T>,
        deadline: Instant,
        wait: WaitId,
    ) -> Result<(AuthorityMutexGuard<'a, Tag, T>, bool), AuthorityError> {
        audit::validate_wait(wait)?;
        let Some(raw_guard) = guard.guard.take() else {
            return Err(AuthorityError::WaitGuardOwnershipLost { wait });
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        let backend = AuthorityWaitBackend::<Tag> {
            condition: &self.inner,
            instance: guard.instance,
            wait,
            operation: None,
            _tag: PhantomData,
        };
        let (_backend, raw_guard, timeout) = wait_reacquire(backend, raw_guard, remaining)?;
        guard.guard = Some(raw_guard);
        Ok((guard, timeout))
    }
}

pub(crate) fn audited_operation(operation: OperationId) -> AuditedOperationScope {
    AuditedOperationScope::enter(operation).unwrap_or_else(|error| {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "{operation:?} operation scope rejected its held authorities: {error}"
        ))
    })
}

pub(crate) fn audited_thread_sleep(duration: Duration) {
    let _operation = audited_operation(OperationId::ThreadSleep);
    std::thread::sleep(duration);
}

pub(crate) struct AuthorityAtomic<Tag: AuthoritySpec, Atomic> {
    pub(super) inner: Atomic,
    pub(super) protocol: super::AtomicProtocolId,
    pub(super) _tag: PhantomData<Tag>,
}

pub(crate) trait AtomicCompareExchange {
    type Value;

    fn compare_exchange_raw(
        &self,
        current: Self::Value,
        new: Self::Value,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Self::Value, Self::Value>;
}

pub(crate) trait AtomicTryUpdate {
    type Value;

    fn try_update_raw(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        function: impl FnMut(Self::Value) -> Option<Self::Value>,
    ) -> Result<Self::Value, Self::Value>;
}

macro_rules! impl_atomic_compare_exchange {
    ($atomic:ty, $value:ty) => {
        impl AtomicCompareExchange for $atomic {
            type Value = $value;

            fn compare_exchange_raw(
                &self,
                current: Self::Value,
                new: Self::Value,
                success: Ordering,
                failure: Ordering,
            ) -> Result<Self::Value, Self::Value> {
                self.compare_exchange(current, new, success, failure)
            }
        }
    };
}

macro_rules! impl_atomic_try_update {
    ($atomic:ty, $value:ty) => {
        impl AtomicTryUpdate for $atomic {
            type Value = $value;

            fn try_update_raw(
                &self,
                set_order: Ordering,
                fetch_order: Ordering,
                function: impl FnMut(Self::Value) -> Option<Self::Value>,
            ) -> Result<Self::Value, Self::Value> {
                self.try_update(set_order, fetch_order, function)
            }
        }
    };
}

impl_atomic_compare_exchange!(AtomicU64, u64);
impl_atomic_compare_exchange!(AtomicBool, bool);
impl_atomic_compare_exchange!(AtomicU8, u8);
impl_atomic_compare_exchange!(AtomicU32, u32);
impl_atomic_try_update!(AtomicU64, u64);
impl_atomic_try_update!(AtomicU16, u16);
impl_atomic_try_update!(AtomicUsize, usize);

impl<Tag, Atomic> AuthorityAtomic<Tag, Atomic>
where
    Tag: AuthoritySpec,
    Atomic: AtomicCompareExchange,
{
    pub(crate) fn compare_exchange(
        &self,
        current: Atomic::Value,
        new: Atomic::Value,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Atomic::Value, Atomic::Value> {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, success);
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, failure);
        audit::record_rmw(Tag::RECORD.id, self.protocol);
        self.inner
            .compare_exchange_raw(current, new, success, failure)
    }
}

impl<Tag, Atomic> AuthorityAtomic<Tag, Atomic>
where
    Tag: AuthoritySpec,
    Atomic: AtomicTryUpdate,
{
    pub(crate) fn try_update(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        function: impl FnMut(Atomic::Value) -> Option<Atomic::Value>,
    ) -> Result<Atomic::Value, Atomic::Value> {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, set_order);
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, fetch_order);
        audit::record_rmw(Tag::RECORD.id, self.protocol);
        self.inner.try_update_raw(set_order, fetch_order, function)
    }
}

impl<Tag: AuthoritySpec, Atomic: fmt::Debug> fmt::Debug for AuthorityAtomic<Tag, Atomic> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityAtomic")
            .field("authority", &Tag::RECORD.id)
            .field("atomic_protocol", &self.protocol)
            .field("inner", &self.inner)
            .finish()
    }
}

pub(crate) struct AuthorityOnceLock<Tag: AuthoritySpec, T> {
    inner: OnceLock<T>,
    _tag: PhantomData<Tag>,
}

impl<Tag: AuthoritySpec, T> AuthorityOnceLock<Tag, T> {
    pub(crate) const fn new() -> Self {
        Self {
            inner: OnceLock::new(),
            _tag: PhantomData,
        }
    }

    pub(crate) fn get(&self) -> Option<&T> {
        self.inner.get()
    }

    pub(crate) fn set(&self, value: T) -> Result<(), T> {
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        self.inner.set(value)
    }

    pub(crate) fn get_or_init(&self, initialize: impl FnOnce() -> T) -> &T {
        if let Some(value) = self.inner.get() {
            return value;
        }
        audit::record_rmw(Tag::RECORD.id, Tag::ATOMIC_PROTOCOL);
        self.inner.get_or_init(initialize)
    }
}
