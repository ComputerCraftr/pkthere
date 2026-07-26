#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::send_completion::{
    ArmSendDisposition, CompletionDisposition, ControlObservation, DeferredControl,
    RetirementProgress, SendAllocationAtomic, SendCompletionAtomic, SendCompletionControl,
    SendCompletionCore, SendCompletionError, SendCompletionState, TransmitSessionStatus,
};
use super::send_completion_store::{
    DeferredControlCell, DeferredOwnerAtomic, SequenceOwnedDeferredStore,
};
use loom::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::time::Duration;

const FOCUSED_MAX_BRANCHES: usize = 200_000;
const FOCUSED_PREEMPTIONS: usize = 2;
const COMPOSED_PREEMPTIONS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestControl {
    identity: u8,
    observed: u8,
}

impl SendCompletionControl for TestControl {
    fn same_control(self, other: Self) -> bool {
        self.identity == other.identity
    }

    fn retain_earliest(&mut self, other: Self) {
        self.observed = self.observed.min(other.observed);
    }
}

impl SendCompletionAtomic for AtomicU32 {
    fn new(value: u32) -> Self {
        AtomicU32::new(value)
    }

    fn load(&self) -> u32 {
        self.load(Ordering::Acquire)
    }

    fn compare_exchange(&self, current: u32, next: u32) -> Result<u32, u32> {
        self.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn store(&self, value: u32) {
        self.store(value, Ordering::Release);
    }
}

impl SendAllocationAtomic for AtomicU64 {
    fn new(value: u64) -> Self {
        AtomicU64::new(value)
    }

    fn load(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn compare_exchange(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }
}

struct LoomOwnerAtomic(AtomicU32);

impl DeferredOwnerAtomic for LoomOwnerAtomic {
    fn new(value: u32) -> Self {
        Self(AtomicU32::new(value))
    }

    fn load_acquire(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    fn claim(&self, current: u32, next: u32) -> Result<u32, u32> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn release(&self, current: u32, next: u32) -> Result<u32, u32> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }
}

struct LoomControlCell(Mutex<Option<DeferredControl<TestControl>>>);

impl DeferredControlCell<TestControl> for LoomControlCell {
    fn with_mut<Result>(
        &self,
        operation: impl FnOnce(&mut Option<DeferredControl<TestControl>>) -> Result,
    ) -> Result {
        operation(&mut self.0.lock().unwrap())
    }
}

type LoomStore = SequenceOwnedDeferredStore<LoomOwnerAtomic, LoomControlCell, TestControl>;

type LoomCompletionCore = SendCompletionCore<AtomicU32, AtomicU64, LoomStore, TestControl>;

fn loom_store(capacity: usize) -> LoomStore {
    SequenceOwnedDeferredStore::new(capacity, |_| LoomControlCell(Mutex::new(None)))
}

fn reserve_send(core: &LoomCompletionCore, expected: u16) -> Result<(), SendCompletionError> {
    let sequence = core.reserve_next()?;
    assert_eq!(sequence, expected);
    match core.arm_send(sequence)? {
        ArmSendDisposition::Armed => Ok(()),
        ArmSendDisposition::Retired(disposition) => {
            assert!(matches!(
                disposition,
                CompletionDisposition::None | CompletionDisposition::Reject(_)
            ));
            Err(SendCompletionError::Retired)
        }
    }
}

fn count_completion(
    disposition: CompletionDisposition<TestControl>,
    applied: &AtomicUsize,
    rejected: &AtomicUsize,
) {
    match disposition {
        CompletionDisposition::None => {}
        CompletionDisposition::Apply(_) => {
            applied.fetch_add(1, Ordering::Relaxed);
        }
        CompletionDisposition::Reject(_) => {
            rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn count_observation(
    observation: ControlObservation<TestControl>,
    applied: &AtomicUsize,
    rejected: &AtomicUsize,
) {
    match observation {
        ControlObservation::Apply(_) => {
            applied.fetch_add(1, Ordering::Relaxed);
        }
        ControlObservation::Reject(_) => {
            rejected.fetch_add(1, Ordering::Relaxed);
        }
        ControlObservation::Deferred | ControlObservation::Stale | ControlObservation::Conflict => {
        }
    }
}

fn focused_builder(actors: usize, preemptions: usize) -> loom::model::Builder {
    let mut model = loom::model::Builder::new();
    model.max_threads = actors + 1;
    model.preemption_bound = Some(preemptions);
    model.max_branches = FOCUSED_MAX_BRANCHES;
    eprintln!(
        "loom-model actors={actors} preemption_bound={preemptions} \
         permutation_limit=exhaustive-within-bound duration=unbounded \
         max_branches={FOCUSED_MAX_BRANCHES}"
    );
    model
}

fn bounded_deep_builder() -> loom::model::Builder {
    let mut model = focused_builder(3, COMPOSED_PREEMPTIONS);
    if let Ok(seconds) = std::env::var("PKTHERE_LOOM_DEEP_DURATION_SECS") {
        let seconds = seconds
            .parse::<u64>()
            .expect("PKTHERE_LOOM_DEEP_DURATION_SECS must be an integer");
        model.max_duration = Some(Duration::from_secs(seconds));
        eprintln!(
            "loom-model bounded duration_seconds={seconds}; completion is partial evidence \
             if the duration is reached"
        );
    }
    model
}

fn model_completion(sent: bool, retire: bool) {
    let model = if retire {
        bounded_deep_builder()
    } else {
        focused_builder(2, FOCUSED_PREEMPTIONS)
    };
    model.check(move || {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        reserve_send(&core, 0).unwrap();
        let applied = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));

        let control_core = Arc::clone(&core);
        let control_applied = Arc::clone(&applied);
        let control_rejected = Arc::clone(&rejected);
        let control = thread::spawn(move || {
            let observation = control_core
                .observe_peer_control(
                    0,
                    TestControl {
                        identity: 7,
                        observed: 2,
                    },
                )
                .unwrap();
            count_observation(observation, &control_applied, &control_rejected);
            observation
        });

        let completion_core = Arc::clone(&core);
        let completion_applied = Arc::clone(&applied);
        let completion_rejected = Arc::clone(&rejected);
        let completion = thread::spawn(move || {
            let disposition = if sent {
                completion_core.complete_send_success(0)
            } else {
                completion_core.complete_send_failure(0)
            }
            .unwrap();
            count_completion(disposition, &completion_applied, &completion_rejected);
        });

        let retirement = retire.then(|| {
            let retirement_core = Arc::clone(&core);
            thread::spawn(move || {
                retirement_core.request_retirement(TransmitSessionStatus::Retired)
            })
        });

        let observation = control.join().unwrap();
        completion.join().unwrap();
        if let Some(retirement) = retirement {
            let result = retirement.join().unwrap();
            assert!(matches!(
                result,
                Ok(RetirementProgress::Complete | RetirementProgress::Draining)
            ));
            assert_eq!(
                core.complete_retirement().unwrap(),
                RetirementProgress::Complete
            );
        }
        let applied = applied.load(Ordering::Relaxed);
        let rejected = rejected.load(Ordering::Relaxed);
        assert!(applied <= 1);
        assert!(rejected <= 1);
        assert!(applied + rejected <= 1);
        if observation == ControlObservation::Deferred {
            assert_eq!(applied + rejected, 1);
        }
        assert!(!matches!(
            core.state_for_test(0).unwrap(),
            SendCompletionState::InFlightDeferred
                | SendCompletionState::RetirementPendingDeferred
                | SendCompletionState::ApplyingSuccessByCompletion
                | SendCompletionState::RejectingFailureByCompletion
                | SendCompletionState::ApplyingByControl
                | SendCompletionState::RejectingByControl
        ));
    });
}

#[test]
fn production_core_success_disposes_every_accepted_control_once() {
    model_completion(true, false);
}

#[test]
fn production_core_failure_rejects_every_deferred_control_once() {
    model_completion(false, false);
}

#[test]
fn production_core_retirement_cannot_strand_or_double_apply_control() {
    model_completion(true, true);
}

#[test]
fn production_core_failed_send_retirement_rejects_control_once() {
    model_completion(false, true);
}

#[test]
fn production_core_duplicate_control_retains_one_disposition_owner() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        reserve_send(&core, 0).unwrap();
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || {
            first_core.observe_peer_control(
                0,
                TestControl {
                    identity: 7,
                    observed: 2,
                },
            )
        });
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || {
            second_core.observe_peer_control(
                0,
                TestControl {
                    identity: 7,
                    observed: 1,
                },
            )
        });
        assert_eq!(first.join().unwrap().unwrap(), ControlObservation::Deferred);
        assert_eq!(
            second.join().unwrap().unwrap(),
            ControlObservation::Deferred
        );
        assert_eq!(
            core.complete_send_success(0).unwrap(),
            CompletionDisposition::Apply(TestControl {
                identity: 7,
                observed: 1,
            })
        );
        assert_eq!(
            core.state_for_test(0).unwrap(),
            SendCompletionState::ConsumedSent
        );
    });
}

#[test]
fn production_core_reservation_cannot_cross_retirement() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        let reserve_core = Arc::clone(&core);
        let reserve = thread::spawn(move || reserve_send(&reserve_core, 0));
        let retire_core = Arc::clone(&core);
        let retire =
            thread::spawn(move || retire_core.request_retirement(TransmitSessionStatus::Retired));
        let reserved = reserve.join().unwrap();
        let retired = retire.join().unwrap();
        if reserved.is_ok() {
            assert_eq!(
                core.complete_send_success(0).unwrap(),
                CompletionDisposition::None
            );
        }
        assert!(matches!(
            retired,
            Ok(RetirementProgress::Complete | RetirementProgress::Draining)
        ));
        assert_eq!(
            core.complete_retirement().unwrap(),
            RetirementProgress::Complete
        );
        assert!(matches!(
            reserved,
            Err(SendCompletionError::Retired) | Ok(())
        ));
        let terminal = core.state_for_test(0).unwrap();
        if reserved.is_ok() {
            assert_eq!(terminal, SendCompletionState::Retired);
        } else {
            assert!(matches!(
                terminal,
                SendCompletionState::Vacant | SendCompletionState::Retired
            ));
        }
    });
}

#[test]
fn production_core_arm_control_and_retirement_dispose_every_accepted_control() {
    bounded_deep_builder().check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        assert_eq!(core.reserve_next().unwrap(), 0);
        let applied = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));

        let arm_core = Arc::clone(&core);
        let arm = thread::spawn(move || arm_core.arm_send(0));
        let control_core = Arc::clone(&core);
        let control_applied = Arc::clone(&applied);
        let control_rejected = Arc::clone(&rejected);
        let control = thread::spawn(move || {
            let observation = control_core
                .observe_peer_control(
                    0,
                    TestControl {
                        identity: 9,
                        observed: 1,
                    },
                )
                .unwrap();
            count_observation(observation, &control_applied, &control_rejected);
            observation
        });
        let retirement_core = Arc::clone(&core);
        let retirement = thread::spawn(move || {
            retirement_core.request_retirement(TransmitSessionStatus::Retired)
        });

        let arm = arm.join().unwrap();
        match arm {
            Ok(ArmSendDisposition::Armed) => {
                let disposition = core.complete_send_failure(0).unwrap();
                count_completion(disposition, &applied, &rejected);
            }
            Ok(ArmSendDisposition::Retired(disposition)) => {
                count_completion(disposition, &applied, &rejected);
            }
            Err(SendCompletionError::Retired) => {}
            Err(error) => panic!("unexpected arm failure: {error:?}"),
        }
        let observation = control.join().unwrap();
        assert!(matches!(
            retirement.join().unwrap(),
            Ok(RetirementProgress::Complete | RetirementProgress::Draining)
        ));
        assert_eq!(
            core.complete_retirement().unwrap(),
            RetirementProgress::Complete
        );
        let applied = applied.load(Ordering::Relaxed);
        let rejected = rejected.load(Ordering::Relaxed);
        assert!(applied <= 1);
        assert!(rejected <= 1);
        assert!(applied + rejected <= 1);
        if observation == ControlObservation::Deferred {
            assert_eq!(applied + rejected, 1);
        }
    });
}

#[test]
fn production_core_abandoned_reservation_and_retirement_have_one_terminal_owner() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        let sequence = core.reserve_next().unwrap();
        assert_eq!(sequence, 0);
        let cancel_core = Arc::clone(&core);
        let cancel = thread::spawn(move || cancel_core.cancel_unexposed_reservation(0));
        let retirement_core = Arc::clone(&core);
        let retirement = thread::spawn(move || {
            retirement_core.request_retirement(TransmitSessionStatus::Retired)
        });
        assert_eq!(cancel.join().unwrap().unwrap(), CompletionDisposition::None);
        let retired = retirement.join().unwrap();
        assert!(matches!(
            retired,
            Ok(RetirementProgress::Complete | RetirementProgress::Draining)
        ));
        assert_eq!(
            core.complete_retirement().unwrap(),
            RetirementProgress::Complete
        );
        assert_eq!(
            core.state_for_test(0).unwrap(),
            SendCompletionState::Retired
        );
    });
}

#[test]
fn production_core_completion_and_retirement_have_one_terminal_owner() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        reserve_send(&core, 0).unwrap();
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || completion_core.complete_send_success(0).unwrap());
        let retirement_core = Arc::clone(&core);
        let retirement = thread::spawn(move || {
            retirement_core.request_retirement(TransmitSessionStatus::Retired)
        });
        assert_eq!(completion.join().unwrap(), CompletionDisposition::None);
        let retired = retirement.join().unwrap();
        assert!(matches!(
            retired,
            Ok(RetirementProgress::Complete | RetirementProgress::Draining)
        ));
        assert_eq!(
            core.complete_retirement().unwrap(),
            RetirementProgress::Complete
        );
        assert_eq!(
            core.state_for_test(0).unwrap(),
            SendCompletionState::Retired
        );
    });
}

#[test]
fn production_core_conflicting_controls_have_one_deferred_owner() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(1, 1, |capacity| loom_store(capacity)));
        reserve_send(&core, 0).unwrap();
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || {
            first_core.observe_peer_control(
                0,
                TestControl {
                    identity: 7,
                    observed: 2,
                },
            )
        });
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || {
            second_core.observe_peer_control(
                0,
                TestControl {
                    identity: 8,
                    observed: 1,
                },
            )
        });
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        let deferred = usize::from(first == ControlObservation::Deferred)
            + usize::from(second == ControlObservation::Deferred);
        assert_eq!(deferred, 1);
        assert!(matches!(
            core.complete_send_success(0).unwrap(),
            CompletionDisposition::Apply(_)
        ));
    });
}

#[test]
fn production_core_two_sequences_have_independent_deferred_slots() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let core = Arc::new(SendCompletionCore::<
            AtomicU32,
            AtomicU64,
            LoomStore,
            TestControl,
        >::new(2, 2, |capacity| loom_store(capacity)));
        reserve_send(&core, 0).unwrap();
        reserve_send(&core, 1).unwrap();
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || {
            first_core
                .observe_peer_control(
                    0,
                    TestControl {
                        identity: 7,
                        observed: 2,
                    },
                )
                .unwrap()
        });
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || {
            second_core
                .observe_peer_control(
                    1,
                    TestControl {
                        identity: 8,
                        observed: 1,
                    },
                )
                .unwrap()
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!(first, ControlObservation::Deferred);
        assert_eq!(second, ControlObservation::Deferred);
        assert_ne!(
            core.deferred_slot_for_test(0).unwrap(),
            core.deferred_slot_for_test(1).unwrap(),
            "distinct sequences must never share deferred-control ownership"
        );
        let first_completion = core.complete_send_success(0).unwrap();
        let second_completion = core.complete_send_success(1).unwrap();
        assert_eq!(
            usize::from(matches!(first_completion, CompletionDisposition::Apply(_)))
                + usize::from(matches!(second_completion, CompletionDisposition::Apply(_))),
            2
        );
    });
}

#[test]
#[should_panic(expected = "weakened split ownership stranded a control")]
fn weakened_split_pending_check_recreates_the_stranded_control() {
    focused_builder(2, FOCUSED_PREEMPTIONS).check(|| {
        let in_flight = Arc::new(AtomicU32::new(1));
        let pending = Arc::new(AtomicU32::new(0));
        let slot = Arc::new(Mutex::new(false));
        let completion_pending = Arc::clone(&pending);
        let completion_slot = Arc::clone(&slot);
        let completion = thread::spawn(move || {
            if completion_pending.load(Ordering::Acquire) != 0 {
                *completion_slot.lock().unwrap() = false;
            }
        });
        let control_in_flight = Arc::clone(&in_flight);
        let control_pending = Arc::clone(&pending);
        let control_slot = Arc::clone(&slot);
        let control = thread::spawn(move || {
            if control_in_flight.load(Ordering::Acquire) == 1 {
                *control_slot.lock().unwrap() = true;
                control_pending.store(1, Ordering::Release);
            }
        });
        completion.join().unwrap();
        control.join().unwrap();
        assert!(
            !*slot.lock().unwrap(),
            "weakened split ownership stranded a control"
        );
    });
}
