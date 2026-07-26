use super::{AuthorityAtomic, AuthoritySpec, audit};
use std::marker::PhantomData;
use std::sync::atomic::{
    AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

pub(crate) struct ThreadOwned<Tag: AuthoritySpec, T> {
    value: T,
    _tag: PhantomData<Tag>,
    _not_send_or_sync: PhantomData<std::rc::Rc<()>>,
}

impl<Tag: AuthoritySpec, T> ThreadOwned<Tag, T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            value,
            _tag: PhantomData,
            _not_send_or_sync: PhantomData,
        }
    }

    pub(crate) fn into_inner(self) -> T {
        self.value
    }
}

macro_rules! impl_atomic_value {
    ($atomic:ty, $value:ty, $constructor:ident, $new_atomic:expr) => {
        impl<Tag: AuthoritySpec> AuthorityAtomic<Tag, $atomic> {
            pub(crate) const fn $constructor(
                value: $value,
                protocol: super::AtomicProtocolId,
            ) -> Self {
                Self {
                    inner: $new_atomic(value),
                    protocol,
                    _tag: PhantomData,
                }
            }

            pub(crate) fn load(&self, ordering: Ordering) -> $value {
                audit::validate_atomic_access(Tag::RECORD.id, self.protocol, ordering);
                self.inner.load(ordering)
            }

            pub(crate) fn store(&self, value: $value, ordering: Ordering) {
                audit::validate_atomic_access(Tag::RECORD.id, self.protocol, ordering);
                self.inner.store(value, ordering);
            }
        }
    };
}

impl_atomic_value!(AtomicU64, u64, new_u64, AtomicU64::new);
impl_atomic_value!(AtomicBool, bool, new_bool, AtomicBool::new);
impl_atomic_value!(AtomicU8, u8, new_u8, AtomicU8::new);
impl_atomic_value!(AtomicU32, u32, new_u32, AtomicU32::new);

impl<Tag: AuthoritySpec> AuthorityAtomic<Tag, AtomicU64> {
    pub(crate) fn compare_exchange_weak(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, success);
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, failure);
        audit::record_rmw(Tag::RECORD.id, self.protocol);
        self.inner
            .compare_exchange_weak(current, new, success, failure)
    }

    #[cfg(any(test, feature = "authority-audit"))]
    pub(crate) fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, ordering);
        audit::record_rmw(Tag::RECORD.id, self.protocol);
        self.inner.fetch_add(value, ordering)
    }

    pub(crate) fn fetch_min(&self, value: u64, ordering: Ordering) -> u64 {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, ordering);
        audit::record_rmw(Tag::RECORD.id, self.protocol);
        self.inner.fetch_min(value, ordering)
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::AtomicObservationWord
    for AuthorityAtomic<Tag, AtomicU64>
{
    fn load_acquire(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn load_relaxed(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }

    fn store_relaxed(&self, value: u64) {
        self.store(value, Ordering::Relaxed);
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::AtomicU64Authority
    for AuthorityAtomic<Tag, AtomicU64>
{
    fn load_acquire(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        AuthorityAtomic::compare_exchange(self, current, next, Ordering::Release, Ordering::Acquire)
    }

    fn cross_atomic_fence(&self) {
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::AtomicU64Value for AuthorityAtomic<Tag, AtomicU64> {
    fn load_acquire(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.store(value, Ordering::Release);
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::PacingAtomic for AuthorityAtomic<Tag, AtomicU64> {
    fn load_relaxed(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }

    fn compare_relaxed_weak(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::AtomicBoolAuthority
    for AuthorityAtomic<Tag, AtomicBool>
{
    fn load_acquire(&self) -> bool {
        self.load(Ordering::Acquire)
    }

    fn claim_acqrel(&self) -> bool {
        self.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn store_release(&self, value: bool) {
        self.store(value, Ordering::Release);
    }
}

impl<Tag: AuthoritySpec> crate::atomic_core::AtomicU8Authority for AuthorityAtomic<Tag, AtomicU8> {
    fn load_acquire(&self) -> u8 {
        self.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u8) {
        self.store(value, Ordering::Release);
    }

    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8> {
        match AuthorityAtomic::compare_exchange(
            self,
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(previous) => Ok(previous),
            Err(observed) => Err(observed),
        }
    }

    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8> {
        match AuthorityAtomic::compare_exchange(
            self,
            current,
            next,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(previous) => Ok(previous),
            Err(observed) => Err(observed),
        }
    }
}

impl<Tag: AuthoritySpec> AuthorityAtomic<Tag, AtomicU16> {
    pub(crate) const fn new_u16(value: u16, protocol: super::AtomicProtocolId) -> Self {
        Self {
            inner: AtomicU16::new(value),
            protocol,
            _tag: PhantomData,
        }
    }
}

impl<Tag: AuthoritySpec> AuthorityAtomic<Tag, AtomicUsize> {
    pub(crate) const fn new_usize(value: usize, protocol: super::AtomicProtocolId) -> Self {
        Self {
            inner: AtomicUsize::new(value),
            protocol,
            _tag: PhantomData,
        }
    }

    pub(crate) fn load(&self, ordering: Ordering) -> usize {
        audit::validate_atomic_access(Tag::RECORD.id, self.protocol, ordering);
        self.inner.load(ordering)
    }
}
