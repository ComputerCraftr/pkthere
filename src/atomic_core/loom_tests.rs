use super::{
    ActivityPublicationError, AllocationStepError, AtomicBoolAuthority, AtomicObservationWord,
    AtomicU8Authority, AtomicU64Authority, AtomicU64Value, DescriptorCacheCore,
    DescriptorCacheRegistration, EpochLaneGuard, EpochLaneReleaseOwner, ExpectedPublicationError,
    FlowSnapshotPublicationBackend, FlowSnapshotPublicationCore, IdleTransitionAttempt,
    IdleTransitionBackend, MaintenanceRepairCore, acquire_epoch_lane, allocate_bounded_u64,
    announce_writer, attempt_idle_transition, clear_wake_pending, close_expected_epoch_gate,
    descriptor_cache_revocation_pending, lane_drain_wait_required, publish_activity_lane,
    publish_expected_u64, publish_observation_words, publish_wake_generation, read_activity_lane,
    read_observation_binding, release_epoch_lane, release_writer_epoch_lane,
    request_descriptor_cache_revocation, reserve_epoch_lane_for_writer, wake_drain_is_stable,
    withdraw_writer,
};
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, Condvar, Mutex, mpsc};
use loom::thread;

struct LoomIdleReservation {
    gate: Arc<AtomicU64>,
    lane: Arc<AtomicU64>,
    closed_state: u64,
    reopened_state: u64,
}

struct LoomActivityPublication {
    sequence: Arc<AtomicU64>,
    generation: Arc<AtomicU64>,
    tick: Arc<AtomicU64>,
}

struct LoomIdleTransition {
    gate: Arc<AtomicU64>,
    lane: Arc<AtomicU64>,
    current: LoomActivityPublication,
    retired: Option<LoomActivityPublication>,
    drain: Arc<(Mutex<()>, Condvar)>,
    gate_closed: Option<Arc<AtomicBool>>,
    revalidated_tick: Option<Arc<AtomicU64>>,
    expected_generation: u64,
    timeout_cutoff: u64,
    closed_state: u64,
    reopened_state: u64,
}

struct LoomFlowSnapshotPublication {
    snapshot_epoch: Arc<AtomicU64>,
    visible_epoch: Arc<AtomicU64>,
    next_epoch: u64,
}

struct LoomCachedDescriptor(Arc<AtomicBool>);

impl Drop for LoomCachedDescriptor {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl FlowSnapshotPublicationBackend for LoomFlowSnapshotPublication {
    type Error = ();

    fn install_snapshot(&mut self) -> Result<(), Self::Error> {
        self.snapshot_epoch
            .store(self.next_epoch, Ordering::Relaxed);
        Ok(())
    }

    fn publish_visibility(&mut self) -> Result<(), Self::Error> {
        self.visible_epoch.store(self.next_epoch, Ordering::Release);
        Ok(())
    }
}

impl IdleTransitionBackend for LoomIdleTransition {
    type Reservation = LoomIdleReservation;
    type Error = ();

    fn tentative_timeout(&mut self) -> bool {
        self.current_tick()
            .is_some_and(|tick| tick <= self.timeout_cutoff)
    }

    fn reserve_and_drain(&mut self) -> Result<Self::Reservation, Self::Error> {
        self.gate
            .compare_exchange(0, self.closed_state, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        if let Some(gate_closed) = &self.gate_closed {
            gate_closed.store(true, Ordering::Release);
        }
        let (coordination, wake) = &*self.drain;
        let mut guard = coordination.lock().map_err(|_| ())?;
        while !reserve_epoch_lane_for_writer(&*self.lane).map_err(|_| ())? {
            guard = wake.wait(guard).map_err(|_| ())?;
        }
        drop(guard);
        Ok(LoomIdleReservation {
            gate: Arc::clone(&self.gate),
            lane: Arc::clone(&self.lane),
            closed_state: self.closed_state,
            reopened_state: self.reopened_state,
        })
    }

    fn revalidate_after_drain(
        &mut self,
        _reservation: &Self::Reservation,
    ) -> Result<bool, Self::Error> {
        let current = self.current_tick();
        if let Some(revalidated_tick) = &self.revalidated_tick {
            revalidated_tick.store(current.unwrap_or(u64::MAX), Ordering::Release);
        }
        if let Some(retired) = &self.retired {
            assert_eq!(
                read_activity_lane(
                    &*retired.sequence,
                    &*retired.generation,
                    &*retired.tick,
                    self.expected_generation,
                ),
                None,
                "retired-flow activity must be excluded",
            );
        }
        Ok(current.is_some_and(|tick| tick <= self.timeout_cutoff))
    }
}

impl LoomIdleTransition {
    fn current_tick(&self) -> Option<u64> {
        read_activity_lane(
            &*self.current.sequence,
            &*self.current.generation,
            &*self.current.tick,
            self.expected_generation,
        )
    }
}

#[test]
fn primitive_writer_count_cannot_lose_a_concurrent_announcement() {
    loom::model(|| {
        let count = Arc::new(AtomicU64::new(1));
        let announcing_count = Arc::clone(&count);
        let announcing = thread::spawn(move || announce_writer(&*announcing_count));
        let withdrawing_count = Arc::clone(&count);
        let withdrawing = thread::spawn(move || withdraw_writer(&*withdrawing_count));

        announcing
            .join()
            .expect("announcing actor")
            .expect("writer announcement");
        withdrawing
            .join()
            .expect("withdrawing actor")
            .expect("writer withdrawal");
        assert_eq!(count.load(Ordering::Acquire), 1);
    });
}

struct LoomEpochLaneOwner {
    lane: AtomicU64,
}

impl EpochLaneReleaseOwner for LoomEpochLaneOwner {
    fn release_owned_epoch_lane(&self, lane_index: usize, epoch: u64) {
        assert_eq!(lane_index, 0);
        assert_eq!(release_epoch_lane(&self.lane, epoch), Ok(()));
    }
}

impl Drop for LoomIdleReservation {
    fn drop(&mut self) {
        assert_eq!(
            self.gate.compare_exchange(
                self.closed_state,
                self.reopened_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(self.closed_state)
        );
        assert_eq!(release_writer_epoch_lane(&*self.lane), Ok(()));
    }
}

impl AtomicU64Authority for AtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        AtomicU64::compare_exchange(self, current, next, Ordering::Release, Ordering::Acquire)
    }

    fn cross_atomic_fence(&self) {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
}

impl AtomicBoolAuthority for AtomicBool {
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

impl AtomicU64Value for AtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.store(value, Ordering::Release);
    }
}

impl AtomicU8Authority for AtomicU8 {
    fn load_acquire(&self) -> u8 {
        self.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u8) {
        self.store(value, Ordering::Release);
    }

    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8> {
        AtomicU8::compare_exchange(self, current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8> {
        AtomicU8::compare_exchange(self, current, next, Ordering::Release, Ordering::Acquire)
    }
}

impl AtomicObservationWord for AtomicU64 {
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

struct WeakPublication(AtomicU64);

impl AtomicU64Authority for WeakPublication {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
    }

    fn cross_atomic_fence(&self) {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
}

#[test]
fn primitive_core_allocates_unique_bounded_tickets() {
    loom::model(|| {
        let next = Arc::new(AtomicU64::new(1));
        let first = Arc::clone(&next);
        let second = Arc::clone(&next);
        let a = thread::spawn(move || allocate_bounded_u64(&*first, || 1, 4));
        let b = thread::spawn(move || allocate_bounded_u64(&*second, || 1, 4));
        let mut tickets = [a.join().unwrap().unwrap(), b.join().unwrap().unwrap()];
        tickets.sort_unstable();
        assert_eq!(tickets, [1, 2]);
        assert_eq!(
            allocate_bounded_u64(&*next, || 1, 2),
            Err(AllocationStepError::QueueFull)
        );
    });
}

#[test]
fn production_flow_snapshot_core_installs_snapshot_before_visibility() {
    loom::model(|| {
        let snapshot_epoch = Arc::new(AtomicU64::new(1));
        let visible_epoch = Arc::new(AtomicU64::new(1));
        let writer_snapshot = Arc::clone(&snapshot_epoch);
        let writer_visible = Arc::clone(&visible_epoch);
        let writer = thread::spawn(move || {
            let publication = LoomFlowSnapshotPublication {
                snapshot_epoch: writer_snapshot,
                visible_epoch: writer_visible,
                next_epoch: 2,
            };
            FlowSnapshotPublicationCore::new(publication)
                .install_snapshot()?
                .publish_visibility()
        });
        let reader_snapshot = Arc::clone(&snapshot_epoch);
        let reader_visible = Arc::clone(&visible_epoch);
        let reader = thread::spawn(move || {
            if reader_visible.load(Ordering::Acquire) == 2 {
                assert_eq!(reader_snapshot.load(Ordering::Relaxed), 2);
            }
        });

        assert_eq!(writer.join().expect("snapshot writer"), Ok(()));
        reader.join().expect("snapshot reader");
        assert_eq!(visible_epoch.load(Ordering::Acquire), 2);
        assert_eq!(snapshot_epoch.load(Ordering::Relaxed), 2);
    });
}

#[test]
fn primitive_core_rejects_stale_version_publication() {
    loom::model(|| {
        let version = Arc::new(AtomicU64::new(0));
        let first = Arc::clone(&version);
        let second = Arc::clone(&version);
        let a = thread::spawn(move || publish_expected_u64(&*first, 0));
        let b = thread::spawn(move || publish_expected_u64(&*second, 0));
        let outcomes = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|value| **value == Ok(1)).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| **value == Err(ExpectedPublicationError::Changed(1)))
                .count(),
            1
        );
    });
}

#[test]
#[should_panic(expected = "weakened publication exposed stale data")]
fn production_core_model_detects_weakened_release_publication() {
    loom::model(|| {
        let data = Arc::new(AtomicUsize::new(0));
        let version = Arc::new(WeakPublication(AtomicU64::new(0)));
        let writer_data = Arc::clone(&data);
        let writer_version = Arc::clone(&version);
        let reader_data = Arc::clone(&data);
        let reader_version = Arc::clone(&version);

        let writer = thread::spawn(move || {
            writer_data.store(1, Ordering::Relaxed);
            assert_eq!(publish_expected_u64(&*writer_version, 0), Ok(1));
        });
        let reader = thread::spawn(move || {
            if reader_version.load_acquire() == 1 {
                assert_eq!(
                    reader_data.load(Ordering::Relaxed),
                    1,
                    "weakened publication exposed stale data"
                );
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    });
}

#[test]
fn primitive_lane_handshake_never_hides_an_admitted_reader_from_a_closed_gate() {
    const CLOSED: u64 = 1 << 63;
    loom::model(|| {
        let gate = Arc::new(AtomicU64::new(0));
        let lane = Arc::new(AtomicU64::new(0));
        let reader_gate = Arc::clone(&gate);
        let reader_lane = Arc::clone(&lane);
        let reader = thread::spawn(move || {
            let result = acquire_epoch_lane(&*reader_gate, &*reader_lane, CLOSED);
            if let Ok(epoch) = result {
                assert_eq!(release_epoch_lane(&*reader_lane, epoch), Ok(()));
            }
            result
        });
        let writer_gate = Arc::clone(&gate);
        let writer_lane = Arc::clone(&lane);
        let writer = thread::spawn(move || {
            let closed =
                writer_gate.compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire);
            let reserved = closed.is_ok() && reserve_epoch_lane_for_writer(&*writer_lane).unwrap();
            (closed, reserved)
        });

        let reader_result = reader.join().unwrap();
        let (closed, initially_reserved) = writer.join().unwrap();
        let reserved = if closed.is_ok() && !initially_reserved {
            reserve_epoch_lane_for_writer(&*lane).unwrap()
        } else {
            initially_reserved
        };
        let observed_lane = lane.load(Ordering::Acquire);
        if reader_result.is_ok() && closed.is_ok() {
            assert!(reserved);
            assert_ne!(
                observed_lane, 0,
                "a closed gate must observe a reader that completed admission"
            );
        }
        if closed.is_ok() && reserved {
            assert_eq!(release_writer_epoch_lane(&*lane), Ok(()));
        }
    });
}

#[test]
#[should_panic(expected = "weakened lane handshake hid an admitted reader")]
fn weakened_lane_store_and_scan_recreates_hidden_reader() {
    const CLOSED: u64 = 1 << 63;
    loom::model(|| {
        let gate = Arc::new(AtomicU64::new(0));
        let lane = Arc::new(AtomicU64::new(0));

        let reader_gate = Arc::clone(&gate);
        let reader_lane = Arc::clone(&lane);
        let reader = thread::spawn(move || {
            let observed = reader_gate.load(Ordering::Acquire);
            if observed & CLOSED != 0 {
                return false;
            }
            reader_lane.store(1, Ordering::Release);
            reader_gate.load(Ordering::Acquire) == observed
        });

        let writer_gate = Arc::clone(&gate);
        let writer_lane = Arc::clone(&lane);
        let writer = thread::spawn(move || {
            let closed = writer_gate
                .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            closed && writer_lane.load(Ordering::Acquire) == 0
        });

        if reader.join().unwrap() && writer.join().unwrap() {
            panic!("weakened lane handshake hid an admitted reader");
        }
    });
}

#[test]
fn primitive_epoch_lane_guard_releases_during_unwind() {
    const CLOSED: u64 = 1 << 63;
    loom::model(|| {
        let gate = AtomicU64::new(0);
        let owner = LoomEpochLaneOwner {
            lane: AtomicU64::new(0),
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let epoch = acquire_epoch_lane(&gate, &owner.lane, CLOSED).unwrap();
            let _guard = EpochLaneGuard::new(&owner, 0, epoch);
            panic!("exercise shared production lane guard unwind");
        }));
        assert!(outcome.is_err());
        assert_eq!(owner.lane.load(Ordering::Acquire), 0);
        assert_eq!(gate.load(Ordering::Acquire), 0);
    });
}

#[test]
fn primitive_lane_drain_never_sleeps_past_the_last_reader_wake() {
    loom::model(|| {
        let lane = Arc::new(AtomicU64::new(1));
        let wake_generation = Arc::new(AtomicU64::new(0));
        let reader_lane = Arc::clone(&lane);
        let reader_generation = Arc::clone(&wake_generation);
        let reader = thread::spawn(move || {
            reader_lane.store(0, Ordering::Release);
            reader_generation.fetch_add(1, Ordering::AcqRel);
        });

        let observed_generation = wake_generation.load(Ordering::Acquire);
        let lanes_active = lane.load(Ordering::Acquire) != 0;
        let current_generation = wake_generation.load(Ordering::Acquire);
        let should_wait =
            lane_drain_wait_required(lanes_active, observed_generation, current_generation, false);
        reader.join().unwrap();
        if lane.load(Ordering::Acquire) == 0
            && wake_generation.load(Ordering::Acquire) != observed_generation
        {
            assert!(
                !should_wait || lanes_active,
                "writer cannot sleep after observing the last-reader generation change"
            );
        }
    });
}

#[test]
fn primitive_activity_lane_never_exposes_a_mixed_epoch_and_tick() {
    loom::model(|| {
        let sequence = Arc::new(AtomicU64::new(0));
        let epoch = Arc::new(AtomicU64::new(1));
        let tick = Arc::new(AtomicU64::new(10));
        let writer_sequence = Arc::clone(&sequence);
        let writer_epoch = Arc::clone(&epoch);
        let writer_tick = Arc::clone(&tick);
        let writer = thread::spawn(move || {
            publish_activity_lane(&*writer_sequence, &*writer_epoch, &*writer_tick, 2, 20)
        });
        let reader_sequence = Arc::clone(&sequence);
        let reader_epoch = Arc::clone(&epoch);
        let reader_tick = Arc::clone(&tick);
        let reader = thread::spawn(move || {
            read_activity_lane(&*reader_sequence, &*reader_epoch, &*reader_tick, 2)
        });
        assert_eq!(
            writer.join().unwrap(),
            Ok::<_, ActivityPublicationError>(())
        );
        if let Some(observed) = reader.join().unwrap() {
            assert_eq!(observed, 20);
        }
        assert_eq!(read_activity_lane(&*sequence, &*epoch, &*tick, 2), Some(20));
    });
}

#[test]
fn production_idle_transition_revalidates_activity_after_reader_drain() {
    const CLOSED: u64 = 1 << 63;
    const FLOW_GENERATION: u64 = 1;
    const TIMEOUT_CUTOFF: u64 = 15;
    const NEW_ACTIVITY: u64 = 20;
    for publish_new_activity in [false, true] {
        let mut model = loom::model::Builder::new();
        model.max_threads = 3;
        model.preemption_bound = Some(2);
        model.check(move || {
        let gate = Arc::new(AtomicU64::new(0));
        let reader_lane = Arc::new(AtomicU64::new(0));
        let activity_sequence = Arc::new(AtomicU64::new(0));
        let activity_generation = Arc::new(AtomicU64::new(FLOW_GENERATION));
        let activity_tick = Arc::new(AtomicU64::new(10));
        let (reader_admitted, wait_for_reader_admission) = mpsc::channel();
        let activity_published = Arc::new(AtomicBool::new(false));
        let gate_closed = Arc::new(AtomicBool::new(false));
        let revalidated_tick = Arc::new(AtomicU64::new(u64::MAX));
        let reader_drain = Arc::new((Mutex::new(()), Condvar::new()));

        let packet_gate = Arc::clone(&gate);
        let packet_lane = Arc::clone(&reader_lane);
        let packet_sequence = Arc::clone(&activity_sequence);
        let packet_generation = Arc::clone(&activity_generation);
        let packet_tick = Arc::clone(&activity_tick);
        let packet_published = Arc::clone(&activity_published);
        let packet_drain = Arc::clone(&reader_drain);
        let packet = thread::spawn(move || {
            let Ok(epoch) = acquire_epoch_lane(&*packet_gate, &*packet_lane, CLOSED) else {
                return;
            };
            reader_admitted.send(()).unwrap();
            if publish_new_activity {
                let publication = publish_activity_lane(
                    &*packet_sequence,
                    &*packet_generation,
                    &*packet_tick,
                    FLOW_GENERATION,
                    NEW_ACTIVITY,
                );
                assert_eq!(publication, Ok(()));
                packet_published.store(true, Ordering::Release);
            }
            let release = release_epoch_lane(&*packet_lane, epoch);
            assert_eq!(release, Ok(()));
            let (coordination, wake) = &*packet_drain;
            let guard = coordination.lock().unwrap();
            wake.notify_all();
            drop(guard);
        });

        let watchdog_gate = Arc::clone(&gate);
        let watchdog_lane = Arc::clone(&reader_lane);
        let watchdog_sequence = Arc::clone(&activity_sequence);
        let watchdog_generation = Arc::clone(&activity_generation);
        let watchdog_tick = Arc::clone(&activity_tick);
        let watchdog_closed = Arc::clone(&gate_closed);
        let watchdog_revalidated_tick = Arc::clone(&revalidated_tick);
        let watchdog_drain = Arc::clone(&reader_drain);
        wait_for_reader_admission.recv().unwrap();
        let watchdog = thread::spawn(move || {
            let transition = LoomIdleTransition {
                gate: watchdog_gate,
                lane: watchdog_lane,
                current: LoomActivityPublication {
                    sequence: watchdog_sequence,
                    generation: watchdog_generation,
                    tick: watchdog_tick,
                },
                retired: None,
                drain: watchdog_drain,
                gate_closed: Some(watchdog_closed),
                revalidated_tick: Some(watchdog_revalidated_tick),
                expected_generation: FLOW_GENERATION,
                timeout_cutoff: TIMEOUT_CUTOFF,
                closed_state: CLOSED,
                reopened_state: 1,
            };
            let result = attempt_idle_transition(transition);
            let authorized = matches!(result, Ok(IdleTransitionAttempt::Authorized(_)));
            drop(result);
            authorized
        });

        packet.join().unwrap();
        let timeout_authorized = watchdog.join().unwrap();
        if activity_published.load(Ordering::Acquire) {
            assert!(
                !timeout_authorized,
                "current-flow activity published by an admitted reader must cancel timeout; revalidated_tick={}",
                revalidated_tick.load(Ordering::Acquire)
            );
        } else {
            assert!(
                timeout_authorized,
                "timeout may commit only after the admitted reader drains without newer activity"
            );
        }
        if gate_closed.load(Ordering::Acquire) {
            assert_eq!(
                gate.load(Ordering::Acquire),
                1,
                "cancelled or completed transition must reopen at a fresh epoch"
            );
        }
        });
    }
}

#[test]
fn production_idle_transition_ignores_retired_flow_activity() {
    const CLOSED: u64 = 1 << 63;
    const CURRENT_FLOW_GENERATION: u64 = 2;
    const TIMEOUT_CUTOFF: u64 = 15;
    loom::model(|| {
        let gate = Arc::new(AtomicU64::new(0));
        let lane = Arc::new(AtomicU64::new(0));
        let current_sequence = Arc::new(AtomicU64::new(0));
        let current_generation = Arc::new(AtomicU64::new(CURRENT_FLOW_GENERATION));
        let current_tick = Arc::new(AtomicU64::new(10));
        let retired_sequence = Arc::new(AtomicU64::new(0));
        let retired_generation = Arc::new(AtomicU64::new(1));
        let retired_tick = Arc::new(AtomicU64::new(20));

        let transition = LoomIdleTransition {
            gate: Arc::clone(&gate),
            lane: Arc::clone(&lane),
            current: LoomActivityPublication {
                sequence: current_sequence,
                generation: current_generation,
                tick: current_tick,
            },
            retired: Some(LoomActivityPublication {
                sequence: retired_sequence,
                generation: retired_generation,
                tick: retired_tick,
            }),
            drain: Arc::new((Mutex::new(()), Condvar::new())),
            gate_closed: None,
            revalidated_tick: None,
            expected_generation: CURRENT_FLOW_GENERATION,
            timeout_cutoff: TIMEOUT_CUTOFF,
            closed_state: CLOSED,
            reopened_state: 1,
        };
        let result = attempt_idle_transition(transition);
        assert!(matches!(result, Ok(IdleTransitionAttempt::Authorized(_))));
        drop(result);
        assert_eq!(gate.load(Ordering::Acquire), 1);
    });
}

#[test]
fn primitive_observation_publication_never_exposes_a_mixed_binding() {
    loom::model(|| {
        const POLLING: u64 = 5;
        const OBSERVED: u64 = 6;
        let state = Arc::new(AtomicU64::new(POLLING));
        let binding = Arc::new([AtomicU64::new(0)]);
        let tick = Arc::new(AtomicU64::new(0));
        let writer_state = Arc::clone(&state);
        let writer_binding = Arc::clone(&binding);
        let writer_tick = Arc::clone(&tick);
        let writer = thread::spawn(move || {
            publish_observation_words(
                &*writer_state,
                &*writer_binding,
                &*writer_tick,
                POLLING,
                OBSERVED,
                &[41],
                73,
            )
        });
        let reader_state = Arc::clone(&state);
        let reader_binding = Arc::clone(&binding);
        let reader_tick = Arc::clone(&tick);
        let reader = thread::spawn(move || {
            read_observation_binding(
                reader_state.as_ref(),
                reader_binding.as_ref(),
                reader_tick.as_ref(),
                0b11,
                0b10,
            )
        });
        assert_eq!(writer.join().unwrap(), Ok(()));
        if let Some((binding, observed_tick)) = reader.join().unwrap() {
            assert_eq!((binding[0], observed_tick), (41, 73));
        }
    });
}

#[test]
fn primitive_wake_pending_clear_requires_authoritative_recheck() {
    loom::model(|| {
        let wake_state = Arc::new(AtomicU64::new(1));
        let producer_state = Arc::clone(&wake_state);
        let producer =
            thread::spawn(move || publish_wake_generation(&*producer_state).expect("publish"));
        let consumer_state = Arc::clone(&wake_state);
        let consumer = thread::spawn(move || {
            let cleared_generation = clear_wake_pending(&*consumer_state);
            (
                cleared_generation,
                wake_drain_is_stable(&*consumer_state, cleared_generation),
            )
        });

        let publication = producer.join().unwrap();
        let (cleared_generation, stable) = consumer.join().unwrap();
        if stable {
            assert!(
                publication.send_wake || publication.generation <= cleared_generation,
                "a coalesced publication must be included in the stable drained generation"
            );
        }
    });
}

#[test]
fn production_maintenance_publication_owns_repair_and_never_exposes_stale_late_deadline() {
    loom::model(|| {
        let epoch = Arc::new(AtomicU64::new(0));
        let deadline = Arc::new(AtomicU64::new(u64::MAX));
        let owner = Arc::new(AtomicBool::new(false));
        let writer_epoch = Arc::clone(&epoch);
        let writer_deadline = Arc::clone(&deadline);
        let writer_owner = Arc::clone(&owner);
        let writer = thread::spawn(move || {
            let core =
                MaintenanceRepairCore::new(&*writer_epoch, &*writer_deadline, &*writer_owner);
            core.try_begin()
                .expect("claim maintenance repair")
                .publish(1, 7);
        });
        let reader_epoch = Arc::clone(&epoch);
        let reader_deadline = Arc::clone(&deadline);
        let reader = thread::spawn(move || {
            if reader_epoch.load(Ordering::Acquire) == 1 {
                assert_eq!(
                    reader_deadline.load(Ordering::Acquire),
                    7,
                    "published maintenance epoch exposed a stale-late deadline"
                );
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(epoch.load(Ordering::Acquire), 1);
        assert_eq!(deadline.load(Ordering::Acquire), 7);
        assert!(!owner.load(Ordering::Acquire));
    });
}

#[test]
fn production_descriptor_borrow_rejects_revoked_generation_publication() {
    const CLOSED: u64 = 1_u64 << (u64::BITS - 1);

    let mut model = loom::model::Builder::new();
    model.max_threads = 3;
    model.preemption_bound = Some(3);
    model.max_branches = 10_000;
    model.check(|| {
        let gate = Arc::new(AtomicU64::new(7));
        let registered = Arc::new(AtomicBool::new(false));
        let requested = Arc::new(AtomicU64::new(0));
        let acknowledged = Arc::new(AtomicU64::new(0));
        let published_generation = Arc::new(AtomicU64::new(1));
        let lane = Arc::new(AtomicU64::new(0));
        let using_descriptor = Arc::new(AtomicBool::new(false));
        let descriptor_live = Arc::new(AtomicBool::new(false));
        let (registered_tx, registered_rx) = mpsc::channel();

        let worker_gate = Arc::clone(&gate);
        let worker_registered = Arc::clone(&registered);
        let worker_requested = Arc::clone(&requested);
        let worker_acknowledged = Arc::clone(&acknowledged);
        let worker_published_generation = Arc::clone(&published_generation);
        let worker_lane = Arc::clone(&lane);
        let worker_using_descriptor = Arc::clone(&using_descriptor);
        let worker_descriptor_live = Arc::clone(&descriptor_live);
        let worker = thread::spawn(move || {
            let mut cache = DescriptorCacheCore::new();
            let registration = cache
                .register_with(&*worker_registered, &*worker_gate, CLOSED, 1, || {
                    worker_descriptor_live.store(true, Ordering::Release);
                    Ok::<_, ()>(LoomCachedDescriptor(worker_descriptor_live))
                })
                .expect("modeled descriptor acquisition");
            if registration == DescriptorCacheRegistration::SlotOccupied {
                panic!("one worker unexpectedly collided with its own empty cache slot");
            }
            assert!(cache.descriptor_for_io(1, 7).is_some());
            registered_tx
                .send(())
                .expect("publish registered descriptor cache");
            if let Ok(epoch) = acquire_epoch_lane(&*worker_gate, &*worker_lane, CLOSED) {
                let generation = worker_published_generation.load(Ordering::Acquire);
                if cache.descriptor_for_io(generation, epoch).is_some() {
                    worker_using_descriptor.store(true, Ordering::Release);
                    assert_eq!(generation, 1);
                    assert_eq!(worker_published_generation.load(Ordering::Acquire), 1);
                    worker_using_descriptor.store(false, Ordering::Release);
                }
                assert_eq!(release_epoch_lane(&*worker_lane, epoch), Ok(()));
            }
            thread::yield_now();
            let generation = worker_published_generation.load(Ordering::Acquire);
            if generation == 2 {
                assert!(
                    cache.descriptor_for_io(generation, 7).is_none(),
                    "a generation-1 descriptor cannot authorize generation-2 I/O"
                );
            }
            if cache.acknowledge(&*worker_requested, &*worker_acknowledged) {
                assert!(!cache.has_descriptor());
                assert!(cache.descriptor_for_io(2, 7).is_none());
                assert_ne!(worker_gate.load(Ordering::Acquire) & CLOSED, 0);
            }
        });

        let manager_gate = Arc::clone(&gate);
        let manager_registered = Arc::clone(&registered);
        let manager_requested = Arc::clone(&requested);
        let manager_published_generation = Arc::clone(&published_generation);
        let manager_lane = Arc::clone(&lane);
        let manager_using_descriptor = Arc::clone(&using_descriptor);
        let manager = thread::spawn(move || {
            registered_rx
                .recv()
                .expect("wait for registered descriptor cache");
            close_expected_epoch_gate(&*manager_gate, 7, CLOSED)
                .expect("close production descriptor admission gate");
            while manager_lane.load(Ordering::Acquire) != 0 {
                thread::yield_now();
            }
            assert!(!manager_using_descriptor.load(Ordering::Acquire));
            request_descriptor_cache_revocation(&*manager_registered, &*manager_requested, 1);
            manager_published_generation.store(2, Ordering::Release);
        });

        worker.join().expect("worker");
        manager.join().expect("manager");
        if !descriptor_cache_revocation_pending(&*registered, &*acknowledged, 1) {
            assert!(!descriptor_live.load(Ordering::Acquire));
        }
    });
}
