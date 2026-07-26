use super::{
    ControlOutcomeRole, EmergencyFailureSource, OutcomeStore, SHUTDOWN_FATAL_PUBLISHED,
    SHUTDOWN_GRACEFUL, SHUTDOWN_KIND_MASK, SHUTDOWN_RUNNING, SHUTDOWN_VALUE_SHIFT,
    ShutdownPublicationCore, ThreadOutcomeCore, WorkerOutcomeRole, WorkerTerminationDecision,
};
use crate::atomic_core::{AtomicU8Authority, AtomicU64Authority, AtomicU64Value};
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

struct LoomU8(AtomicU8);

impl AtomicU8Authority for LoomU8 {
    fn load_acquire(&self) -> u8 {
        self.0.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u8) {
        self.0.store(value, Ordering::Release);
    }

    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }
}

struct LoomU64(AtomicU64);

impl AtomicU64Authority for LoomU64 {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }

    fn cross_atomic_fence(&self) {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
}

struct LoomEmergency(AtomicU64);

impl EmergencyFailureSource for LoomEmergency {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

impl AtomicU64Value for LoomU64 {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.0.store(value, Ordering::Release);
    }
}

struct LoomOutcomeStore(Mutex<Option<u8>>);

impl OutcomeStore<u8> for LoomOutcomeStore {
    fn install(&self, outcome: u8) -> Result<(), u8> {
        let mut stored = self.0.lock().map_err(|_| outcome)?;
        if stored.is_some() {
            return Err(outcome);
        }
        *stored = Some(outcome);
        Ok(())
    }

    fn load(&self) -> Option<u8> {
        self.0.lock().ok().and_then(|stored| *stored)
    }
}

type LoomControlOutcome = ThreadOutcomeCore<LoomU8, LoomOutcomeStore, u8, ControlOutcomeRole>;
type LoomWorkerOutcome = ThreadOutcomeCore<LoomU8, LoomOutcomeStore, u8, WorkerOutcomeRole>;

fn control_outcome() -> LoomControlOutcome {
    ThreadOutcomeCore::new_control(LoomU8(AtomicU8::new(0)), LoomOutcomeStore(Mutex::new(None)))
}

fn worker_outcome() -> LoomWorkerOutcome {
    ThreadOutcomeCore::new_worker(LoomU8(AtomicU8::new(0)), LoomOutcomeStore(Mutex::new(None)))
}

#[test]
fn production_shutdown_core_never_exposes_fatal_without_its_cause() {
    loom::model(|| {
        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let outcome = Arc::new(control_outcome());
        let writer_shutdown = Arc::clone(&shutdown);
        let writer_outcome = Arc::clone(&outcome);
        let writer = thread::spawn(move || {
            writer_shutdown.publish_fatal(&writer_outcome, 41, 1_u64 << SHUTDOWN_VALUE_SHIFT)
        });
        let reader_shutdown = Arc::clone(&shutdown);
        let reader_outcome = Arc::clone(&outcome);
        let reader = thread::spawn(move || {
            if reader_shutdown.fatal_owner_value().is_some() {
                assert_eq!(reader_outcome.load(), Some(41));
            }
        });
        let publication = writer.join().expect("writer");
        reader.join().expect("reader");
        assert!(publication.cause_installed);
        assert!(publication.primary_won);
    });
}

#[test]
fn production_shutdown_core_gives_one_primary_owner_and_retains_secondary_cause() {
    loom::model(|| {
        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let first = Arc::new(control_outcome());
        let second = Arc::new(control_outcome());
        let left_shutdown = Arc::clone(&shutdown);
        let left_outcome = Arc::clone(&first);
        let left = thread::spawn(move || {
            left_shutdown.publish_fatal(&left_outcome, 11, 1_u64 << SHUTDOWN_VALUE_SHIFT)
        });
        let right_shutdown = Arc::clone(&shutdown);
        let right_outcome = Arc::clone(&second);
        let right = thread::spawn(move || {
            right_shutdown.publish_fatal(&right_outcome, 22, 2_u64 << SHUTDOWN_VALUE_SHIFT)
        });
        let left = left.join().expect("left");
        let right = right.join().expect("right");
        assert_ne!(left.primary_won, right.primary_won);
        assert_eq!(first.load(), Some(11));
        assert_eq!(second.load(), Some(22));
    });
}

#[test]
fn production_shutdown_core_requires_cleanup_before_terminal_publication() {
    loom::model(|| {
        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let outcome = Arc::new(worker_outcome());
        let cleanup_complete = Arc::new(AtomicBool::new(false));
        let writer_shutdown = Arc::clone(&shutdown);
        let writer_outcome = Arc::clone(&outcome);
        let writer_cleanup = Arc::clone(&cleanup_complete);
        let writer = thread::spawn(move || {
            let transaction = writer_shutdown
                .begin_worker_termination(
                    &writer_outcome,
                    &LoomEmergency(AtomicU64::new(0)),
                    WorkerTerminationDecision::new(
                        Some(41),
                        0,
                        42,
                        |_| 43,
                        1_u64 << SHUTDOWN_VALUE_SHIFT,
                    ),
                )
                .expect("worker termination transaction");
            let (_, terminal_published) = transaction.complete(|| {
                writer_cleanup.store(true, Ordering::Release);
            });
            assert!(terminal_published);
        });
        let reader_outcome = Arc::clone(&outcome);
        let reader_cleanup = Arc::clone(&cleanup_complete);
        let reader = thread::spawn(move || {
            if reader_outcome.load_terminal().is_some() {
                assert!(reader_cleanup.load(Ordering::Acquire));
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
        assert_eq!(outcome.load_terminal(), Some(41));
        assert!(cleanup_complete.load(Ordering::Acquire));
    });
}

#[test]
fn production_shutdown_core_has_one_cleanup_owner() {
    loom::model(|| {
        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let outcome = Arc::new(worker_outcome());
        let cleanup_owners = Arc::new(AtomicUsize::new(0));
        let first_shutdown = Arc::clone(&shutdown);
        let first_outcome = Arc::clone(&outcome);
        let first_owners = Arc::clone(&cleanup_owners);
        let first = thread::spawn(move || {
            match first_shutdown.begin_worker_termination(
                &first_outcome,
                &LoomEmergency(AtomicU64::new(0)),
                WorkerTerminationDecision::new(
                    Some(17),
                    0,
                    18,
                    |_| 19,
                    1_u64 << SHUTDOWN_VALUE_SHIFT,
                ),
            ) {
                Ok(transaction) => {
                    first_owners.fetch_add(1, Ordering::AcqRel);
                    assert!(transaction.complete(|| {}).1);
                    true
                }
                Err(_) => false,
            }
        });
        let second_shutdown = Arc::clone(&shutdown);
        let second_outcome = Arc::clone(&outcome);
        let second_owners = Arc::clone(&cleanup_owners);
        let second = thread::spawn(move || {
            match second_shutdown.begin_worker_termination(
                &second_outcome,
                &LoomEmergency(AtomicU64::new(0)),
                WorkerTerminationDecision::new(
                    Some(27),
                    0,
                    28,
                    |_| 29,
                    1_u64 << SHUTDOWN_VALUE_SHIFT,
                ),
            ) {
                Ok(transaction) => {
                    second_owners.fetch_add(1, Ordering::AcqRel);
                    assert!(transaction.complete(|| {}).1);
                    true
                }
                Err(_) => false,
            }
        });
        let first = first.join().expect("first cleanup claimant");
        let second = second.join().expect("second cleanup claimant");
        assert_eq!(cleanup_owners.load(Ordering::Acquire), 1);
        assert_ne!(first, second);
        assert!(matches!(outcome.load_terminal(), Some(17 | 27)));
    });
}

#[test]
fn production_shutdown_core_reloads_fatal_after_supervisor_completion() {
    loom::model(|| {
        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let outcome = Arc::new(control_outcome());
        let graceful = SHUTDOWN_GRACEFUL;
        assert!(shutdown.request_graceful(graceful));
        let completion_transaction = shutdown
            .begin_supervision()
            .expect("graceful shutdown completion transaction");

        let writer_shutdown = Arc::clone(&shutdown);
        let writer_outcome = Arc::clone(&outcome);
        let (publication, final_state) = completion_transaction.complete(|| {
            thread::spawn(move || {
                writer_shutdown.publish_fatal(&writer_outcome, 61, 1_u64 << SHUTDOWN_VALUE_SHIFT)
            })
            .join()
            .expect("supervisor completion fatal publisher")
        });

        assert!(publication.cause_installed);
        assert!(publication.primary_won);
        assert_eq!(final_state & SHUTDOWN_KIND_MASK, SHUTDOWN_FATAL_PUBLISHED);
        assert_eq!(outcome.load(), Some(61));
    });
}

#[test]
fn production_worker_termination_preserves_pre_return_emergency_cause() {
    loom::model(|| {
        const EMERGENCY_CODE: u64 = 0x51;
        const EMERGENCY_OUTCOME: u8 = 51;
        const UNEXPECTED_OUTCOME: u8 = 52;

        let shutdown = Arc::new(ShutdownPublicationCore::new(LoomU64(AtomicU64::new(
            SHUTDOWN_RUNNING,
        ))));
        let outcome = Arc::new(worker_outcome());
        let emergency = Arc::new(LoomEmergency(AtomicU64::new(0)));
        let returned = Arc::new(AtomicBool::new(false));

        let writer_emergency = Arc::clone(&emergency);
        let writer_returned = Arc::clone(&returned);
        let writer = thread::spawn(move || {
            writer_emergency.0.store(EMERGENCY_CODE, Ordering::Release);
            writer_returned.store(true, Ordering::Release);
        });

        let reader_shutdown = Arc::clone(&shutdown);
        let reader_outcome = Arc::clone(&outcome);
        let reader_emergency = Arc::clone(&emergency);
        let reader_returned = Arc::clone(&returned);
        let reader = thread::spawn(move || {
            while !reader_returned.load(Ordering::Acquire) {
                thread::yield_now();
            }
            let publication = reader_shutdown
                .begin_worker_termination(
                    &reader_outcome,
                    reader_emergency.as_ref(),
                    WorkerTerminationDecision::new(
                        None,
                        0,
                        UNEXPECTED_OUTCOME,
                        |_| EMERGENCY_OUTCOME,
                        1_u64 << SHUTDOWN_VALUE_SHIFT,
                    ),
                )
                .expect("worker terminal publication");
            assert_eq!(publication.outcome(), EMERGENCY_OUTCOME);
            assert!(publication.fatal().is_some_and(|fatal| fatal.primary_won));
            assert!(publication.complete(|| {}).1);
        });

        writer.join().expect("emergency publisher");
        reader.join().expect("worker return classifier");
        assert_eq!(outcome.load_terminal(), Some(EMERGENCY_OUTCOME));
    });
}
