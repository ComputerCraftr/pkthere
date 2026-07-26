use super::{
    DEFAULT_FLOW_READER_LANES, FlowReaderLane, FlowTopologyCoordinator, FlowTopologyError,
    ReleasedFlowOperationError, TransitionPhase,
};
use crate::runtime_support::FailureClass;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[test]
fn worker_lane_mapping_preserves_direction_for_every_flow_mode() {
    assert_eq!(
        FlowReaderLane::for_worker(8, crate::cli::WorkerFlowMode::SharedFlow).index(),
        8
    );
    assert_eq!(
        FlowReaderLane::for_worker(8, crate::cli::WorkerFlowMode::SingleFlow).index(),
        0
    );
    assert_eq!(
        FlowReaderLane::for_worker(9, crate::cli::WorkerFlowMode::SingleFlow).index(),
        1
    );
}

#[test]
fn topology_error_classification_is_exhaustive() {
    for error in [FlowTopologyError::Busy, FlowTopologyError::TimedOut] {
        assert_eq!(error.class(), FailureClass::RetryableContention);
    }
    assert_eq!(
        FlowTopologyError::QueueFull.class(),
        FailureClass::OperationFailed
    );
    assert_eq!(FlowTopologyError::Shutdown.class(), FailureClass::Shutdown);
    for error in [
        FlowTopologyError::ReaderCountExhausted,
        FlowTopologyError::EpochExhausted,
        FlowTopologyError::TokenExhausted,
        FlowTopologyError::OwnershipLost,
        FlowTopologyError::ForeignReceipt,
        FlowTopologyError::AlreadyCommitted,
        FlowTopologyError::Poisoned,
    ] {
        assert_eq!(error.class(), FailureClass::FatalInvariant);
    }
}

#[test]
fn rollback_advances_epoch_and_invalidates_old_reader() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let reader = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("initial reader");
    let epoch = reader.transaction_epoch();
    drop(reader);
    coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer")
        .rollback()
        .expect("rollback");
    let next = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("reader after rollback");
    assert_eq!(next.transaction_epoch(), epoch + 1);
}

#[test]
fn released_operation_reacquires_only_the_epoch_it_released() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let read = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("initial read");
    let epoch = read.transaction_epoch();
    let (reacquired, ()) = read
        .run_released(|| Ok::<(), ()>(()))
        .expect("unchanged epoch reacquires");
    assert_eq!(reacquired.transaction_epoch(), epoch);
}

#[test]
fn released_operation_rejects_an_intervening_publication_epoch() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let read = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("initial read");
    let result = read.run_released(|| {
        coordinator
            .reserve_until(Instant::now() + Duration::from_secs(1))
            .expect("writer")
            .rollback()
            .expect("fresh rollback epoch");
        Ok::<(), ()>(())
    });
    assert!(matches!(
        result,
        Err(ReleasedFlowOperationError::Reacquire(
            FlowTopologyError::Busy
        ))
    ));
    assert!(
        coordinator.try_read_lane(FlowReaderLane::new(0)).is_ok(),
        "stale refresh rejection must release the newly admitted lane"
    );
}

#[test]
fn committed_session_requires_matching_receipt() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let writer = coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer");
    writer
        .prepare_for_session_commit()
        .expect("prepare")
        .commit_session(1, 2)
        .expect("commit session")
        .publish()
        .expect("publish");
}

#[test]
fn active_reader_prevents_writer_from_draining_past_deadline() {
    let coordinator = Arc::new(FlowTopologyCoordinator::with_reader_lanes(
        DEFAULT_FLOW_READER_LANES,
    ));
    let reader = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("reader");
    let writer = Arc::clone(&coordinator);
    let result = std::thread::spawn(move || {
        writer
            .reserve_until(Instant::now() + Duration::from_millis(10))
            .map(|reservation| reservation.phase())
    })
    .join()
    .expect("join writer");
    assert!(matches!(result, Err(FlowTopologyError::TimedOut)));
    assert!(
        !reader.is_current(),
        "rollback advances the epoch so a pre-transition lease cannot regain authority"
    );
}

#[test]
fn unwinding_reader_releases_its_production_lane() {
    let coordinator = Arc::new(FlowTopologyCoordinator::with_reader_lanes(
        DEFAULT_FLOW_READER_LANES,
    ));
    let panicking_coordinator = Arc::clone(&coordinator);
    let panicked = std::thread::spawn(move || {
        let _reader = panicking_coordinator
            .try_read_lane(FlowReaderLane::new(0))
            .expect("reader before unwind");
        panic!("exercise production read-lease unwind cleanup");
    })
    .join();
    assert!(panicked.is_err());

    coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer must drain after reader unwind")
        .rollback()
        .expect("reopen after unwind regression");
}

#[test]
fn admitted_reader_remains_authoritative_while_writer_drains() {
    let coordinator = Arc::new(FlowTopologyCoordinator::with_reader_lanes(
        DEFAULT_FLOW_READER_LANES,
    ));
    let reader = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("reader");
    let writer = Arc::clone(&coordinator);
    let writer_thread = std::thread::spawn(move || {
        let reservation = writer
            .reserve_until(Instant::now() + Duration::from_secs(1))
            .expect("writer drains after reader completes");
        reservation.rollback().expect("rollback")
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !coordinator.admission_closed_for_test() {
        assert!(Instant::now() < deadline, "writer did not close admission");
        std::thread::yield_now();
    }
    assert!(
        reader.is_current(),
        "a reader admitted before closure remains valid until it releases its lane"
    );
    drop(reader);
    writer_thread.join().expect("join writer");
}

#[test]
fn pending_writer_blocks_later_reader_without_serializing_existing_readers() {
    let coordinator = Arc::new(FlowTopologyCoordinator::with_reader_lanes(3));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(2);
    let (first_release_tx, first_release_rx) = std::sync::mpsc::sync_channel(1);
    let (second_release_tx, second_release_rx) = std::sync::mpsc::sync_channel(1);
    let (released_tx, released_rx) = std::sync::mpsc::sync_channel(2);
    let first_coordinator = Arc::clone(&coordinator);
    let first_entered = entered_tx.clone();
    let first_released = released_tx.clone();
    let first_reader = std::thread::spawn(move || {
        let reader = first_coordinator
            .try_read_lane(FlowReaderLane::new(0))
            .expect("first reader");
        first_entered
            .send(reader.transaction_epoch())
            .expect("publish first reader");
        first_release_rx.recv().expect("release first reader");
        assert!(reader.is_current());
        drop(reader);
        first_released.send(()).expect("first reader released");
    });
    let second_coordinator = Arc::clone(&coordinator);
    let second_reader = std::thread::spawn(move || {
        let reader = second_coordinator
            .try_read_lane(FlowReaderLane::new(1))
            .expect("second reader");
        entered_tx
            .send(reader.transaction_epoch())
            .expect("publish second reader");
        second_release_rx.recv().expect("release second reader");
        assert!(reader.is_current());
        drop(reader);
        released_tx.send(()).expect("second reader released");
    });
    let first_epoch = entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first reader entered");
    let second_epoch = entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("second reader entered");
    assert_eq!(first_epoch, second_epoch);

    let writer_coordinator = Arc::clone(&coordinator);
    let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(1);
    let writer = std::thread::spawn(move || {
        let reservation = writer_coordinator
            .reserve_until(Instant::now() + Duration::from_secs(1))
            .expect("writer drains admitted readers");
        reservation.rollback().expect("writer rollback");
        completed_tx.send(()).expect("publish writer completion");
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while !coordinator.admission_closed_for_test() {
        assert!(Instant::now() < deadline, "writer did not close admission");
        std::thread::yield_now();
    }
    assert!(matches!(
        coordinator.try_read_lane(FlowReaderLane::new(2)),
        Err(FlowTopologyError::Busy)
    ));
    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(20))
            .is_err(),
        "writer must wait for every admitted lane"
    );

    first_release_tx.send(()).expect("release first reader");
    released_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first reader exits");
    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(20))
            .is_err(),
        "one reader cannot release another reader's authority"
    );
    second_release_tx.send(()).expect("release second reader");
    released_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("second reader exits");
    completed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("writer completes after all readers drain");
    first_reader.join().expect("join first reader");
    second_reader.join().expect("join second reader");
    writer.join().expect("join writer");

    let later = coordinator
        .try_read_lane(FlowReaderLane::new(2))
        .expect("later reader enters under fresh epoch");
    assert!(later.transaction_epoch() > 0);
}

#[test]
fn competing_flow_writers_are_served_fifo_without_reader_barging() {
    let coordinator = Arc::new(FlowTopologyCoordinator::with_reader_lanes(2));
    let reader = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("initial reader");
    let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(2);
    let (release_first_tx, release_first_rx) = std::sync::mpsc::sync_channel(1);

    let first_coordinator = Arc::clone(&coordinator);
    let first_acquired = acquired_tx.clone();
    let first = std::thread::spawn(move || {
        let reservation = first_coordinator
            .reserve_until(Instant::now() + Duration::from_secs(1))
            .expect("first FIFO writer");
        first_acquired.send(1).expect("publish first writer");
        release_first_rx.recv().expect("release first writer");
        reservation.rollback().expect("first writer rollback");
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while coordinator.pending_writers.load(Ordering::Acquire) != 1 {
        assert!(Instant::now() < deadline, "first writer did not queue");
        std::thread::yield_now();
    }

    let second_coordinator = Arc::clone(&coordinator);
    let second = std::thread::spawn(move || {
        let reservation = second_coordinator
            .reserve_until(Instant::now() + Duration::from_secs(1))
            .expect("second FIFO writer");
        acquired_tx.send(2).expect("publish second writer");
        reservation.rollback().expect("second writer rollback");
    });
    while coordinator.pending_writers.load(Ordering::Acquire) != 2 {
        assert!(Instant::now() < deadline, "second writer did not queue");
        std::thread::yield_now();
    }
    assert!(matches!(
        coordinator.try_read_lane(FlowReaderLane::new(1)),
        Err(FlowTopologyError::Busy)
    ));

    drop(reader);
    assert_eq!(
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first writer acquires"),
        1
    );
    assert!(
        acquired_rx.recv_timeout(Duration::from_millis(20)).is_err(),
        "second writer cannot pass the first FIFO owner"
    );
    release_first_tx.send(()).expect("release first writer");
    assert_eq!(
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second writer acquires"),
        2
    );
    first.join().expect("join first writer");
    second.join().expect("join second writer");
}

#[test]
fn abandoning_irreversible_session_commit_poison_closes_barrier() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let writer = coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer");
    let committed = writer
        .prepare_for_session_commit()
        .expect("prepare")
        .commit_session(8, 9)
        .expect("commit session");
    drop(committed);
    assert!(matches!(
        coordinator.try_read_lane(FlowReaderLane::new(0)),
        Err(FlowTopologyError::Poisoned)
    ));
}

#[test]
fn readers_observe_complete_old_or_complete_new_topology() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let manager = AtomicU64::new(10);
    let session = AtomicU64::new(10);
    {
        let lease = coordinator
            .try_read_lane(FlowReaderLane::new(0))
            .expect("old reader");
        assert_eq!(
            (
                manager.load(Ordering::Acquire),
                session.load(Ordering::Acquire)
            ),
            (10, 10)
        );
        assert!(lease.is_current());
    }

    let writer = coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer");
    manager.store(11, Ordering::Release);
    assert!(matches!(
        coordinator.try_read_lane(FlowReaderLane::new(0)),
        Err(FlowTopologyError::Busy)
    ));
    let prepared = writer
        .prepare_for_session_commit()
        .expect("prepare topology");
    session.store(11, Ordering::Release);
    prepared
        .commit_session(10, 11)
        .expect("session commit")
        .publish()
        .expect("publication");

    let lease = coordinator
        .try_read_lane(FlowReaderLane::new(0))
        .expect("new reader");
    assert_eq!(
        (
            manager.load(Ordering::Acquire),
            session.load(Ordering::Acquire)
        ),
        (11, 11)
    );
    assert!(lease.is_current());
}

#[test]
fn skipped_transition_phase_poison_closes_barrier() {
    let coordinator = FlowTopologyCoordinator::with_reader_lanes(DEFAULT_FLOW_READER_LANES);
    let mut writer = coordinator
        .reserve_until(Instant::now() + Duration::from_secs(1))
        .expect("writer");
    assert!(matches!(
        writer.advance_to(TransitionPhase::ManagerStatePrepared),
        Err(FlowTopologyError::OwnershipLost)
    ));
    drop(writer);
    assert!(matches!(
        coordinator.try_read_lane(FlowReaderLane::new(0)),
        Err(FlowTopologyError::Poisoned)
    ));
}
