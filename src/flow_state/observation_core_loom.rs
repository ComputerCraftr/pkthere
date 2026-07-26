#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::observation_core::{ObservationLifecycleCore, ObservationLifecycleError};
use crate::atomic_core::AtomicObservationWord;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

const MAX_GENERATION: u64 = u64::MAX >> 2;
const PHASE_MASK: u64 = 0b11;
const POLLING: u64 = 1;
const OBSERVED: u64 = 2;

struct LoomObservationAtomic(AtomicU64);

impl LoomObservationAtomic {
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }
}

impl AtomicObservationWord for LoomObservationAtomic {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn load_relaxed(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }

    fn store_relaxed(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

#[test]
fn production_observation_lifecycle_never_exposes_partial_or_stale_ownership() {
    loom::model(|| {
        let core = Arc::new(ObservationLifecycleCore::<LoomObservationAtomic, 2>::new(
            || LoomObservationAtomic::new(0),
        ));
        let generation = core.begin(MAX_GENERATION, 2, POLLING).unwrap();
        let publisher_core = Arc::clone(&core);
        let publisher = thread::spawn(move || {
            publisher_core.finish_receive(generation, 2, POLLING, OBSERVED, Some((&[41, 73], 97)))
        });
        let reader_core = Arc::clone(&core);
        let reader = thread::spawn(move || reader_core.observed(PHASE_MASK, OBSERVED));
        assert_eq!(publisher.join().unwrap(), Ok(true));
        if let Some((binding, tick)) = reader.join().unwrap() {
            assert_eq!((binding, tick), ([41, 73], 97));
        }
        core.clear(generation, 2).unwrap();
        assert_eq!(
            core.clear(generation, 2),
            Err(ObservationLifecycleError::OwnershipLost)
        );
    });
}

#[test]
fn production_observation_lifecycle_rejects_publish_after_clear() {
    loom::model(|| {
        let core = ObservationLifecycleCore::<LoomObservationAtomic, 1>::new(|| {
            LoomObservationAtomic::new(0)
        });
        let generation = core.begin(MAX_GENERATION, 2, POLLING).unwrap();
        core.clear(generation, 2).unwrap();
        assert_eq!(
            core.finish_receive(generation, 2, POLLING, OBSERVED, Some((&[11], 13))),
            Err(ObservationLifecycleError::OwnershipLost)
        );
    });
}

#[test]
fn production_observation_lifecycle_rejects_overlapping_lane_writers() {
    loom::model(|| {
        let core = Arc::new(ObservationLifecycleCore::<LoomObservationAtomic, 1>::new(
            || LoomObservationAtomic::new(0),
        ));
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || first_core.begin(MAX_GENERATION, 2, POLLING));
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || second_core.begin(MAX_GENERATION, 2, POLLING));

        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let generation = first.or(second).expect("one exact lane owner");
        core.clear(generation, 2).expect("release exact lane owner");
    });
}

#[test]
fn production_observation_lifecycle_clears_polling_when_receive_has_no_control() {
    loom::model(|| {
        let core = ObservationLifecycleCore::<LoomObservationAtomic, 1>::new(|| {
            LoomObservationAtomic::new(0)
        });
        let generation = core.begin(MAX_GENERATION, 2, POLLING).unwrap();
        assert_eq!(
            core.finish_receive(generation, 2, POLLING, OBSERVED, None),
            Ok(false)
        );
        assert!(core.begin(MAX_GENERATION, 2, POLLING).is_ok());
    });
}

#[test]
fn production_observation_expiry_requires_the_exact_binding_and_predeadline_receive() {
    loom::model(|| {
        let core = Arc::new(ObservationLifecycleCore::<LoomObservationAtomic, 2>::new(
            || LoomObservationAtomic::new(0),
        ));
        let generation = core.begin(MAX_GENERATION, 2, POLLING).unwrap();
        let publisher_core = Arc::clone(&core);
        let publisher = thread::spawn(move || {
            publisher_core.finish_receive(generation, 2, POLLING, OBSERVED, Some((&[41, 73], 97)))
        });
        let expiry_core = Arc::clone(&core);
        let expiry = thread::spawn(move || {
            (
                expiry_core.blocks_exact(PHASE_MASK, OBSERVED, &[41, 73], 100),
                expiry_core.blocks_exact(PHASE_MASK, OBSERVED, &[41, 74], 100),
                expiry_core.blocks_exact(PHASE_MASK, OBSERVED, &[41, 73], 97),
            )
        });
        assert_eq!(publisher.join().unwrap(), Ok(true));
        let (exact, wrong_binding, at_deadline) = expiry.join().unwrap();
        assert!(!wrong_binding);
        assert!(!at_deadline);
        if exact {
            assert!(core.blocks_exact(PHASE_MASK, OBSERVED, &[41, 73], 100));
        }
        assert!(core.blocks_exact(PHASE_MASK, OBSERVED, &[41, 73], 100));
    });
}
