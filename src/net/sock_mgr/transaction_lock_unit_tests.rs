use super::transaction_lock::{
    MANAGER_RESERVATION_TIMEOUT, MAX_CANCELLED_TICKETS, ManagerTransaction, ReservationError,
};
use crate::authority::{AuthorityAtomic, tags};
use crate::runtime_support::FailureClass;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn reservation_error_classification_is_exhaustive() {
    assert_eq!(
        ReservationError::TimedOut.class(),
        FailureClass::RetryableContention
    );
    assert_eq!(
        ReservationError::QueueFull.class(),
        FailureClass::OperationFailed
    );
    assert_eq!(ReservationError::Shutdown.class(), FailureClass::Shutdown);
    for error in [
        ReservationError::TicketExhausted,
        ReservationError::OwnershipLost,
        ReservationError::CancellationCorrupted,
    ] {
        assert_eq!(error.class(), FailureClass::FatalInvariant);
    }
}

#[test]
fn reservation_is_fifo_and_consuming_completion_does_not_double_release() {
    let transaction = Arc::new(ManagerTransaction::new(1));
    let first = transaction
        .reserve_until(Instant::now() + MANAGER_RESERVATION_TIMEOUT)
        .expect("first reservation");
    let barrier = Arc::new(Barrier::new(2));
    let contender_transaction = Arc::clone(&transaction);
    let contender_barrier = Arc::clone(&barrier);
    let contender = thread::spawn(move || {
        contender_barrier.wait();
        contender_transaction
            .reserve_until(Instant::now() + MANAGER_RESERVATION_TIMEOUT)
            .expect("second reservation")
            .commit()
            .expect("commit second")
            .ticket()
    });
    barrier.wait();
    let first_ticket = first.commit().expect("commit first").ticket();
    let second_ticket = contender.join().expect("join contender");
    assert!(first_ticket < second_ticket);
}

#[test]
fn timed_out_ticket_is_cancelled_without_blocking_its_successor() {
    let transaction = ManagerTransaction::new(1);
    let first = transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("first");
    assert!(matches!(
        transaction.reserve_until(Instant::now()),
        Err(ReservationError::TimedOut)
    ));
    first.rollback().expect("release first");
    transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("successor")
        .rollback()
        .expect("release successor");
}

#[test]
fn queue_capacity_and_core_ticket_exhaustion_fail_before_reuse() {
    let queue_full = ManagerTransaction::new(1);
    for expected in 1..=MAX_CANCELLED_TICKETS as u64 {
        assert_eq!(queue_full.core.allocate(false), Ok(expected));
    }
    assert!(matches!(
        queue_full.reserve_until(Instant::now() + Duration::from_millis(1)),
        Err(ReservationError::QueueFull)
    ));

    let exhausted = super::fifo_core::FifoReservationCore::<
        AuthorityAtomic<tags::ManagerTransaction, AtomicU64>,
        AuthorityAtomic<tags::ManagerTransaction, AtomicBool>,
        MAX_CANCELLED_TICKETS,
    >::new(
        AuthorityAtomic::new_u64(
            u64::MAX,
            crate::authority::AtomicProtocolId::ReservationOwnership,
        ),
        AuthorityAtomic::new_u64(
            u64::MAX,
            crate::authority::AtomicProtocolId::ReservationOwnership,
        ),
        std::array::from_fn(|_| {
            AuthorityAtomic::new_u64(0, crate::authority::AtomicProtocolId::ReservationOwnership)
        }),
        AuthorityAtomic::new_bool(
            false,
            crate::authority::AtomicProtocolId::ReservationOwnership,
        ),
        AuthorityAtomic::new_u64(0, crate::authority::AtomicProtocolId::ReservationOwnership),
    );
    assert_eq!(
        exhausted.allocate(false),
        Err(super::fifo_core::FifoReservationCoreError::Exhausted)
    );
}

#[test]
fn contention_timeout_uses_the_original_deadline() {
    let transaction = ManagerTransaction::new(1);
    let held = transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("held reservation");
    let started = Instant::now();
    let deadline = started + Duration::from_millis(20);
    assert!(matches!(
        transaction.reserve_until(deadline),
        Err(ReservationError::TimedOut)
    ));
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "reservation retries must not restart the outer deadline"
    );
    held.rollback().expect("release held reservation");
}

#[test]
fn emergency_release_never_clears_a_foreign_owner() {
    let transaction = ManagerTransaction::new(1);
    let reservation = transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("reservation");
    transaction
        .core
        .release(reservation.ticket().get())
        .expect("advance the production FIFO before stale guard cleanup");
    drop(reservation);
    assert!(
        transaction.core.tickets().is_serving(2),
        "ownership mismatch must not clear another reservation"
    );
    assert!(transaction.core.is_corrupted());
}

#[test]
fn concurrent_short_reservations_and_cancellations_preserve_ownership() {
    const WORKERS: usize = 4;
    const ITERATIONS: usize = 500;

    let transaction = Arc::new(ManagerTransaction::new(1));
    let start = Arc::new(Barrier::new(WORKERS + 1));
    let workers = (0..WORKERS)
        .map(|worker| {
            let transaction = Arc::clone(&transaction);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                for iteration in 0..ITERATIONS {
                    let deadline = if (worker + iteration) % 17 == 0 {
                        Instant::now()
                    } else {
                        Instant::now() + Duration::from_millis(100)
                    };
                    match transaction.reserve_until(deadline) {
                        Ok(reservation) => {
                            reservation.validate().expect("reservation ownership");
                            drop(reservation);
                        }
                        Err(ReservationError::TimedOut | ReservationError::QueueFull) => {}
                        Err(error) => panic!("unexpected reservation failure: {error}"),
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    for worker in workers {
        worker.join().expect("join reservation worker");
    }
    assert!(
        !transaction.core.is_corrupted(),
        "valid contention must not corrupt reservation ownership"
    );
    transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("bounded rejections leave no stranded FIFO ticket")
        .rollback()
        .expect("final reservation releases cleanly");
}

#[test]
fn cancelling_the_current_ticket_drains_an_already_cancelled_successor() {
    let transaction = ManagerTransaction::new(1);
    let first = transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("first reservation");
    let second = transaction.core.allocate(false).expect("second ticket");
    let third = transaction.core.allocate(false).expect("third ticket");

    first.rollback().expect("release first");
    transaction.core.cancel(third).expect("cancel successor");
    transaction.core.cancel(second).expect("cancel current");

    transaction
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("contiguous cancellation prefix is drained")
        .rollback()
        .expect("release final reservation");
}
