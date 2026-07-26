#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::fifo_core::{
    FifoReservationCore, FifoReservationCoreError, FifoReservationLease, FifoReservationLeaseOwner,
    FifoReservationPoll,
};
use loom::sync::atomic::{AtomicBool, AtomicU64};
use loom::sync::{Arc, Mutex};
use loom::thread;

fn core<const CAPACITY: usize>() -> FifoReservationCore<AtomicU64, AtomicBool, CAPACITY> {
    FifoReservationCore::new(
        AtomicU64::new(1),
        AtomicU64::new(1),
        std::array::from_fn(|_| AtomicU64::new(0)),
        AtomicBool::new(false),
        AtomicU64::new(0),
    )
}

struct LoomLeaseOwner<const CAPACITY: usize> {
    core: FifoReservationCore<AtomicU64, AtomicBool, CAPACITY>,
    emergency_releases: AtomicU64,
}

impl<const CAPACITY: usize> FifoReservationLeaseOwner for LoomLeaseOwner<CAPACITY> {
    type Error = FifoReservationCoreError;

    fn validate_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        self.core.validate(ticket)
    }

    fn complete_ticket(&self, ticket: u64) -> Result<(), Self::Error> {
        self.core.release(ticket)
    }

    fn emergency_release_ticket(&self, ticket: u64) {
        self.emergency_releases
            .fetch_add(1, loom::sync::atomic::Ordering::AcqRel);
        if self.core.release(ticket).is_err() {
            self.core.force_corrupted();
        }
    }
}

#[test]
fn production_fifo_lease_explicit_completion_cannot_double_release() {
    loom::model(|| {
        let owner = LoomLeaseOwner::<3> {
            core: core(),
            emergency_releases: AtomicU64::new(0),
        };
        let first = owner.core.allocate(false).expect("first ticket");
        let second = owner.core.allocate(false).expect("second ticket");
        let lease = FifoReservationLease::new(&owner, first);
        assert_eq!(lease.commit(), Ok(first));
        assert_eq!(
            owner.core.poll(second, false),
            Ok(FifoReservationPoll::Ready)
        );
        assert_eq!(
            owner
                .emergency_releases
                .load(loom::sync::atomic::Ordering::Acquire),
            0
        );
    });
}

#[test]
fn production_fifo_lease_drop_releases_exact_ticket() {
    loom::model(|| {
        let owner = LoomLeaseOwner::<3> {
            core: core(),
            emergency_releases: AtomicU64::new(0),
        };
        let first = owner.core.allocate(false).expect("first ticket");
        let second = owner.core.allocate(false).expect("second ticket");
        let lease = FifoReservationLease::new(&owner, first);
        lease.validate().expect("owned ticket");
        drop(lease);
        assert_eq!(
            owner.core.poll(second, false),
            Ok(FifoReservationPoll::Ready)
        );
        assert_eq!(
            owner
                .emergency_releases
                .load(loom::sync::atomic::Ordering::Acquire),
            1
        );
    });
}

#[test]
fn production_fifo_core_allocates_unique_bounded_tickets() {
    loom::model(|| {
        let core = Arc::new(core::<2>());
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || first_core.allocate(false));
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || second_core.allocate(false));
        let first = first
            .join()
            .expect("first allocator")
            .expect("first ticket");
        let second = second
            .join()
            .expect("second allocator")
            .expect("second ticket");
        assert_ne!(first, second);
        assert_eq!(first.min(second), 1);
        assert_eq!(first.max(second), 2);
        assert_eq!(
            core.allocate(false),
            Err(FifoReservationCoreError::QueueFull)
        );
    });
}

#[test]
fn production_fifo_core_cancellation_and_release_cannot_strand_successor() {
    loom::model(|| {
        let core = Arc::new(core::<3>());
        let coordination = Arc::new(Mutex::new(()));
        let first = core.allocate(false).expect("first ticket");
        let cancelled = core.allocate(false).expect("cancelled ticket");
        assert_eq!((first, cancelled), (1, 2));

        let cancel_core = Arc::clone(&core);
        let cancel_coordination = Arc::clone(&coordination);
        let cancel = thread::spawn(move || {
            let _guard = cancel_coordination.lock().expect("cancel coordination");
            cancel_core.cancel(cancelled)
        });
        let release_core = Arc::clone(&core);
        let release = thread::spawn(move || {
            let _guard = coordination.lock().expect("release coordination");
            release_core.release(first)
        });
        cancel.join().expect("cancel actor").expect("cancel ticket");
        release
            .join()
            .expect("release actor")
            .expect("release ticket");
        assert!(core.tickets().is_serving(3));
    });
}

#[test]
fn production_fifo_allocation_cannot_observe_a_false_exhaustion_during_progress() {
    loom::model(|| {
        let core = Arc::new(core::<3>());
        let first = core.allocate(false).expect("first ticket");

        let progress_core = Arc::clone(&core);
        let progress = thread::spawn(move || {
            let ticket = progress_core.allocate(false)?;
            progress_core.release(first)?;
            progress_core.cancel(ticket)?;
            Ok::<_, FifoReservationCoreError>(ticket)
        });
        let allocate_core = Arc::clone(&core);
        let allocate = thread::spawn(move || allocate_core.allocate(false));

        let progressed = progress
            .join()
            .expect("progress actor")
            .expect("progress ticket");
        let allocated = allocate
            .join()
            .expect("allocation actor")
            .expect("concurrent ticket");
        assert_eq!(progressed.min(allocated), 2);
        assert_eq!(progressed.max(allocated), 3);
        assert!(!core.is_corrupted());
    });
}

#[test]
fn production_fifo_core_wrong_owner_cannot_release_current_ticket() {
    loom::model(|| {
        let core = core::<2>();
        let ticket = core.allocate(false).expect("ticket");
        assert_eq!(
            core.release(ticket + 1),
            Err(FifoReservationCoreError::OwnershipLost)
        );
        assert!(core.tickets().is_serving(ticket));
        assert!(core.is_corrupted());
    });
}

#[test]
fn production_fifo_core_current_cancellation_drains_cancelled_successor() {
    loom::model(|| {
        let core = core::<4>();
        let first = core.allocate(false).expect("first ticket");
        let second = core.allocate(false).expect("second ticket");
        let third = core.allocate(false).expect("third ticket");

        core.release(first).expect("release first");
        core.cancel(third).expect("cancel successor");
        core.cancel(second).expect("cancel current");

        assert!(core.tickets().is_serving(4));
    });
}

#[test]
fn production_fifo_reservation_wake_generation_closes_last_owner_race() {
    loom::model(|| {
        let core = Arc::new(core::<3>());
        let first = core.allocate(false).expect("first ticket");
        let second = core.allocate(false).expect("second ticket");
        let FifoReservationPoll::Wait { wake_generation } =
            core.poll(second, false).expect("poll second")
        else {
            panic!("second reservation must initially wait");
        };

        let release_core = Arc::clone(&core);
        let release = thread::spawn(move || release_core.release(first));
        let wait_core = Arc::clone(&core);
        let recheck =
            thread::spawn(move || wait_core.wait_required(second, wake_generation, false));

        release
            .join()
            .expect("release actor")
            .expect("release first");
        let should_wait = recheck
            .join()
            .expect("recheck actor")
            .expect("recheck reservation");
        if should_wait {
            assert_eq!(
                core.poll(second, false),
                Ok(FifoReservationPoll::Ready),
                "a waiter may sleep only before the releasing publication; its condition is then already ready"
            );
        }
        assert_eq!(core.poll(second, false), Ok(FifoReservationPoll::Ready));
    });
}

#[test]
fn production_fifo_reservation_shutdown_prevents_new_ownership() {
    loom::model(|| {
        let core = core::<2>();
        assert_eq!(core.allocate(true), Err(FifoReservationCoreError::Shutdown));
        let ticket = core.allocate(false).expect("ticket before shutdown");
        assert_eq!(core.poll(ticket, true), Ok(FifoReservationPoll::Shutdown));
        core.cancel(ticket).expect("shutdown cancellation");
        assert!(core.tickets().is_serving(2));
    });
}
