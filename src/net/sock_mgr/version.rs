use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::ManagerError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
/// Monotonic version of manager-owned topology and socket identity.
///
/// This clock deliberately excludes association changes within an existing
/// `ManagedSocket`; those are ordered by that socket's `association_epoch`.
pub(crate) struct StateVersion(u64);

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
    value: AtomicU64,
}

impl VersionClock {
    pub(super) const fn new() -> Self {
        Self {
            value: AtomicU64::new(StateVersion::INITIAL.0),
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
    pub(super) fn publish_prechecked(&self, capacity: VersionCapacityGuard) -> StateVersion {
        let previous = self
            .value
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("prechecked manager version capacity must remain available");
        assert_eq!(
            previous, capacity.current.0,
            "manager version changed while its transaction lock was held"
        );
        StateVersion(
            previous
                .checked_add(1)
                .expect("prechecked manager version cannot wrap"),
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn set_for_test(&self, version: StateVersion) {
        self.value.store(version.0, Ordering::Release);
    }
}

// Loom uses stackful generators whose Unix stack allocator calls `getrlimit`.
// Miri intentionally does not implement that foreign function, so the Loom
// model belongs to the normal test runner while Miri continues exercising the
// remaining production unit suite.
#[cfg(all(test, not(miri)))]
mod tests {
    use loom::sync::atomic::{AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    #[test]
    fn version_publication_loom_keeps_multi_leg_snapshots_coherent() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(|| {
            let transaction = Arc::new(Mutex::new(()));
            let listener = Arc::new(Mutex::new(0u64));
            let upstream = Arc::new(Mutex::new(0u64));
            let version = Arc::new(AtomicU64::new(0));
            let allocations = Arc::new(Mutex::new(Vec::new()));

            let mut writers = Vec::new();
            for topology in [1u64, 2u64] {
                let transaction = Arc::clone(&transaction);
                let listener = Arc::clone(&listener);
                let upstream = Arc::clone(&upstream);
                let version = Arc::clone(&version);
                let allocations = Arc::clone(&allocations);
                writers.push(thread::spawn(move || {
                    let _transaction = transaction.lock().unwrap();
                    *listener.lock().unwrap() = topology;
                    *upstream.lock().unwrap() = topology;
                    let previous = version
                        .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                            value.checked_add(1)
                        })
                        .unwrap();
                    allocations.lock().unwrap().push(previous + 1);
                }));
            }

            let reader = {
                let transaction = Arc::clone(&transaction);
                let listener = Arc::clone(&listener);
                let upstream = Arc::clone(&upstream);
                let version = Arc::clone(&version);
                thread::spawn(move || {
                    let observed = version.load(Ordering::Acquire);
                    if observed == 0 {
                        return;
                    }
                    let _transaction = transaction.lock().unwrap();
                    let listener = *listener.lock().unwrap();
                    let upstream = *upstream.lock().unwrap();
                    let captured_version = version.load(Ordering::Acquire);
                    assert_eq!(listener, upstream);
                    assert!(captured_version >= observed);
                })
            };

            for writer in writers {
                writer.join().unwrap();
            }
            reader.join().unwrap();
            let mut allocations = allocations.lock().unwrap().clone();
            allocations.sort_unstable();
            assert_eq!(allocations, [1, 2]);
        });
    }
}
