use super::{
    BoundedFailureMessage, RuntimeFailure, ShutdownController, ThreadOutcome, ThreadRole,
    ThreadSupervisor, WaitAuthorityWake, lock_authority,
};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn fatal_shutdown_overrides_graceful_shutdown() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    shutdown.request_graceful(0);
    shutdown.request_fatal(RuntimeFailure::fatal(format_args!("fatal")));
    assert_eq!(shutdown.exit_status(), Some(1));
}

#[test]
fn fatal_requests_publish_into_the_control_outcome_slot() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    shutdown.request_fatal(RuntimeFailure::fatal(format_args!("control failure")));
    assert_eq!(shutdown.exit_status(), Some(1));
    assert!(matches!(
        shutdown.outcome(0),
        Some(ThreadOutcome::Failed(failure))
            if failure.message.as_str() == "control failure"
    ));
}

#[test]
fn graceful_shutdown_never_overrides_fatal_shutdown() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    shutdown.request_fatal(RuntimeFailure::fatal(format_args!("fatal")));
    shutdown.request_graceful(0);
    assert_eq!(shutdown.exit_status(), Some(1));
    assert!(matches!(
        shutdown.primary_fatal_outcome(),
        Some(ThreadOutcome::Failed(failure)) if failure.message.as_str() == "fatal"
    ));
}

#[test]
fn unexpected_normal_thread_completion_publishes_a_fatal_cause() {
    let (shutdown, events) = ShutdownController::bootstrap(2).expect("shutdown controller");
    let mut supervisor = ThreadSupervisor::new(shutdown.clone(), events);
    supervisor
        .spawn(ThreadRole::Watchdog, "early-exit".to_string(), || Ok(()))
        .expect("spawn");
    while shutdown.exit_status().is_none() {
        shutdown.wait_for_change(Instant::now() + Duration::from_millis(50));
    }
    assert!(matches!(
        shutdown.outcome(1),
        Some(ThreadOutcome::Failed(_))
    ));
    assert!(matches!(
        shutdown.primary_fatal_outcome(),
        Some(ThreadOutcome::Failed(_))
    ));
    shutdown.request_graceful(0);
    assert!(supervisor.finish(Instant::now() + Duration::from_secs(1)));
}

#[test]
fn unknown_panic_payload_is_reported_before_terminal_notification() {
    let (shutdown, events) = ShutdownController::bootstrap(2).expect("shutdown controller");
    let mut supervisor = ThreadSupervisor::new(shutdown.clone(), events);
    supervisor
        .spawn(ThreadRole::Watchdog, "panic".to_string(), || {
            std::panic::panic_any(7_u8)
        })
        .expect("spawn");
    while shutdown.exit_status().is_none() {
        shutdown.wait_for_change(Instant::now() + Duration::from_millis(50));
    }
    assert_eq!(
        shutdown.outcome(1),
        Some(ThreadOutcome::Panicked(BoundedFailureMessage::from_static(
            "thread panicked with a non-string payload"
        )))
    );
    assert!(supervisor.finish(Instant::now() + Duration::from_secs(1)));
}

#[test]
fn full_supervisor_event_channel_never_blocks_terminal_publication() {
    let (shutdown, _events) = ShutdownController::bootstrap_with_event_capacity_for_test(2, 1)
        .expect("shutdown controller");
    shutdown.request_graceful(0);
    let terminal =
        shutdown.begin_worker_termination(1, ThreadRole::Watchdog, ThreadOutcome::Completed);
    terminal.complete(&mut (), |_| {});
    assert_eq!(shutdown.terminal_outcome(1), Some(ThreadOutcome::Completed));
}

#[test]
fn disconnected_supervisor_event_channel_never_blocks_fatal_publication() {
    let (shutdown, events) = ShutdownController::bootstrap(2).expect("shutdown controller");
    drop(events);
    let terminal = shutdown.begin_worker_termination(
        1,
        ThreadRole::Watchdog,
        ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!("disconnected"))),
    );
    terminal.complete(&mut (), |_| {});
    assert_eq!(shutdown.exit_status(), Some(1));
    assert!(matches!(
        shutdown.terminal_outcome(1),
        Some(ThreadOutcome::Failed(failure))
            if failure.message.as_str() == "disconnected"
    ));
}

#[test]
fn secondary_failure_queue_is_bounded_and_preserves_primary_cause() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    shutdown.request_fatal(RuntimeFailure::fatal(format_args!("primary")));
    for secondary in ["secondary one", "secondary two", "secondary three"] {
        shutdown.request_fatal(RuntimeFailure::fatal(format_args!("{secondary}")));
    }
    assert!(matches!(
        shutdown.outcome(0),
        Some(ThreadOutcome::Failed(failure)) if failure.message.as_str() == "primary"
    ));
    assert_eq!(shutdown.secondary_failure_count(), 2);
    assert_eq!(shutdown.secondary_failure_overflow(), 1);
}

#[test]
fn fatal_cause_is_visible_before_thread_becomes_joinable() {
    let shutdown = ShutdownController::new(2).expect("shutdown controller");
    let terminal = shutdown.begin_worker_termination(
        1,
        ThreadRole::Watchdog,
        ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!("fatal"))),
    );
    assert!(shutdown.outcome(1).is_some());
    assert!(shutdown.terminal_outcome(1).is_none());
    terminal.complete(&mut (), |_| {});
    assert!(shutdown.terminal_outcome(1).is_some());
}

#[test]
fn fatal_publication_wins_a_concurrent_graceful_request() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    let barrier = Arc::new(Barrier::new(3));
    let graceful_shutdown = Arc::clone(&shutdown);
    let graceful_barrier = Arc::clone(&barrier);
    let graceful = thread::spawn(move || {
        graceful_barrier.wait();
        graceful_shutdown.request_graceful(0);
    });
    let fatal_shutdown = Arc::clone(&shutdown);
    let fatal_barrier = Arc::clone(&barrier);
    let fatal = thread::spawn(move || {
        fatal_barrier.wait();
        fatal_shutdown.request_fatal(RuntimeFailure::fatal(format_args!("fatal race")));
    });
    barrier.wait();
    graceful.join().expect("join graceful publisher");
    fatal.join().expect("join fatal publisher");
    assert_eq!(shutdown.exit_status(), Some(1));
    assert!(matches!(
        shutdown.outcome(0),
        Some(ThreadOutcome::Failed(_))
    ));
}

#[test]
fn every_partial_startup_capacity_failure_index_shuts_down_started_threads() {
    for started_count in 1..=4 {
        let (shutdown, events) =
            ShutdownController::bootstrap(started_count + 1).expect("shutdown controller");
        let mut supervisor = ThreadSupervisor::new(Arc::clone(&shutdown), events);
        for worker_index in 0..started_count {
            let worker_shutdown = Arc::clone(&shutdown);
            supervisor
                .spawn(
                    ThreadRole::Watchdog,
                    format!("started-{worker_index}"),
                    move || {
                        while !worker_shutdown.is_requested() {
                            worker_shutdown
                                .wait_for_change(Instant::now() + Duration::from_millis(10));
                        }
                        Ok(())
                    },
                )
                .expect("spawn thread before injected capacity failure");
        }
        assert!(
            supervisor
                .spawn(
                    ThreadRole::StatsPrinter,
                    format!("over-capacity-{started_count}"),
                    || Ok(()),
                )
                .is_err()
        );
        assert_eq!(shutdown.exit_status(), Some(1));
        assert!(supervisor.finish(Instant::now() + Duration::from_secs(1)));
    }
}

#[test]
fn shutdown_publication_wakes_registered_authority_waiters() {
    let shutdown = ShutdownController::new(1).expect("shutdown controller");
    let wake = WaitAuthorityWake::new(crate::authority::WaitId::SupervisorTerminal);
    let waiter_wake = Arc::clone(&wake);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let started_at = Instant::now();
    let waiter = thread::spawn(move || {
        let guard = waiter_wake.coordination_guard();
        ready_tx.send(()).expect("waiter ready");
        waiter_wake.wait_timeout(guard, Duration::from_secs(1));
    });
    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("waiter reached authority wait");
    let coordination_guard = loop {
        match wake.coordination.try_lock() {
            Ok(guard) => break guard,
            Err(crate::authority::AuthorityTryLockError::WouldBlock) => thread::yield_now(),
            Err(crate::authority::AuthorityTryLockError::Authority(error)) => {
                panic!("coordination authority failed while waiting for wake: {error:?}")
            }
        }
    };

    shutdown.request_graceful(0);
    drop(coordination_guard);
    waiter.join().expect("join woken authority waiter");

    assert!(
        started_at.elapsed() < Duration::from_millis(250),
        "shutdown wake must not wait for the one-second authority fallback"
    );
}

#[test]
fn poisoned_authority_returns_typed_error_without_recovered_mutation() {
    let authority = Arc::new(crate::authority::AuthorityMutex::<
        crate::authority::tags::Diagnostic,
        _,
    >::new(
        7_u64,
        crate::authority::AuthorityInstance::singleton(crate::authority::AuthorityId::Diagnostic),
    ));
    let poisoned = Arc::clone(&authority);
    assert!(
        thread::spawn(move || {
            let _guard = poisoned.lock().expect("hold authority before poisoning");
            std::panic::panic_any("poison authority");
        })
        .join()
        .is_err()
    );
    assert!(lock_authority(&authority, "test authority").is_err());
}
