use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::ManagerError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
/// Monotonic version of manager-owned topology and socket identity.
///
/// This clock deliberately excludes association changes within an existing
/// `ManagedSocket`; those are ordered by that socket's `association_epoch`.
pub(crate) struct StateVersion(pub(super) u64);

impl StateVersion {
    pub(crate) const INITIAL: Self = Self(0);

    #[cfg(all(test, not(miri)))]
    pub(crate) const MAX: Self = Self(u64::MAX);

    #[cfg(all(test, not(miri)))]
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StateVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub(super) struct VersionCapacityGuard {
    current: StateVersion,
}

pub(super) struct VersionClock {
    value: crate::authority::AuthorityAtomic<crate::authority::tags::ManagerState, AtomicU64>,
}

impl VersionClock {
    pub(super) const fn new() -> Self {
        Self::with_initial(StateVersion::INITIAL)
    }

    pub(super) const fn with_initial(initial: StateVersion) -> Self {
        Self {
            value: crate::authority::AuthorityAtomic::new_u64(
                initial.0,
                crate::authority::AtomicProtocolId::ManagerPublication,
            ),
        }
    }

    #[inline]
    pub(super) fn current(&self) -> StateVersion {
        StateVersion(self.value.load(Ordering::Acquire))
    }

    #[inline]
    pub(super) fn precheck_capacity(&self) -> Result<VersionCapacityGuard, ManagerError> {
        let current = self.current();
        if current.0 == u64::MAX {
            Err(ManagerError::VersionExhausted { current })
        } else {
            Ok(VersionCapacityGuard { current })
        }
    }

    #[inline]
    pub(super) fn publish_prechecked(
        &self,
        capacity: VersionCapacityGuard,
    ) -> Result<StateVersion, ManagerError> {
        // Release publishes manager topology written while the transaction
        // mutex is held. Relaxed failure ordering observes no usable state.
        match crate::atomic_core::publish_expected_u64(&self.value, capacity.current.0) {
            Ok(next) => Ok(StateVersion(next)),
            Err(crate::atomic_core::ExpectedPublicationError::Exhausted) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "prechecked manager version wrapped during publication"
                ));
                Err(ManagerError::VersionPublicationFailed {
                    expected: capacity.current,
                    actual: None,
                })
            }
            Err(crate::atomic_core::ExpectedPublicationError::Changed(actual)) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "manager version changed during reserved publication: expected {}, observed {actual}",
                    capacity.current
                ));
                Err(ManagerError::VersionPublicationFailed {
                    expected: capacity.current,
                    actual: Some(StateVersion(actual)),
                })
            }
        }
    }
}
