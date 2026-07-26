#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::group_publication::{
    COMPONENT_DESCRIPTOR_ASSOCIATION, COMPONENT_FLOW_VISIBILITY, COMPONENT_MANAGER_METADATA,
    COMPONENT_MANAGER_VERSION, COMPONENT_RECEIVER, COMPONENT_SOCKET_GATES,
    CommittedGroupPublication, GroupPublicationCore, GroupPublicationPhase, PublicationStep,
};
use crate::atomic_core::{AtomicU64Authority, AtomicU64Value};
use crate::atomic_core::{
    ClosedEpochGate, acquire_epoch_lane, release_epoch_lane, reopen_epoch_gate,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::sync::mpsc;
use loom::thread;

const COMPONENTS: u8 = COMPONENT_DESCRIPTOR_ASSOCIATION
    | COMPONENT_RECEIVER
    | COMPONENT_MANAGER_METADATA
    | COMPONENT_MANAGER_VERSION
    | COMPONENT_SOCKET_GATES
    | COMPONENT_FLOW_VISIBILITY;
const FLOW_GATE_CLOSED: u64 = 1 << 63;

struct LoomState(Arc<AtomicU64>);

struct ModeledTopology {
    descriptor_association: AtomicU64,
    receiver_generation: AtomicU64,
    manager_metadata: AtomicU64,
    manager_version: AtomicU64,
    socket_gate: AtomicU64,
    flow_gate: AtomicU64,
    flow_lane: AtomicU64,
}

impl ModeledTopology {
    fn old() -> Self {
        Self {
            descriptor_association: AtomicU64::new(0),
            receiver_generation: AtomicU64::new(0),
            manager_metadata: AtomicU64::new(0),
            manager_version: AtomicU64::new(0),
            socket_gate: AtomicU64::new(0),
            flow_gate: AtomicU64::new(FLOW_GATE_CLOSED),
            flow_lane: AtomicU64::new(0),
        }
    }

    fn assert_complete_new(&self) {
        assert_eq!(self.descriptor_association.load(Ordering::Acquire), 1);
        assert_eq!(self.receiver_generation.load(Ordering::Acquire), 1);
        assert_eq!(self.manager_metadata.load(Ordering::Acquire), 1);
        assert_eq!(self.manager_version.load(Ordering::Acquire), 2);
        assert_eq!(self.socket_gate.load(Ordering::Acquire), 1);
    }
}

struct LoomPublication {
    topology: Arc<ModeledTopology>,
    fail_receiver: bool,
}

impl CommittedGroupPublication for LoomPublication {
    type Error = u8;
    type Output = ();

    fn publish_receiver(&mut self, _step: PublicationStep<'_, 0>) -> Result<(), Self::Error> {
        if self.fail_receiver {
            return Err(1);
        }
        self.topology
            .receiver_generation
            .store(1, Ordering::Release);
        Ok(())
    }

    fn publish_manager_metadata(
        &mut self,
        _step: PublicationStep<'_, 1>,
    ) -> Result<(), Self::Error> {
        self.topology.manager_metadata.store(1, Ordering::Release);
        Ok(())
    }

    fn publish_manager(
        &mut self,
        _step: PublicationStep<'_, 2>,
        index: usize,
    ) -> Result<(), Self::Error> {
        self.topology
            .manager_version
            .store(index as u64 + 1, Ordering::Release);
        Ok(())
    }

    fn publish_socket_topology(
        &mut self,
        _step: PublicationStep<'_, 3>,
    ) -> Result<(), Self::Error> {
        self.topology
            .descriptor_association
            .store(1, Ordering::Release);
        self.topology.socket_gate.store(1, Ordering::Release);
        Ok(())
    }

    fn commit_manager_reservations(
        &mut self,
        _step: PublicationStep<'_, 4>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn publish_flow_visibility(
        &mut self,
        _step: PublicationStep<'_, 5>,
    ) -> Result<(), Self::Error> {
        reopen_epoch_gate(
            &self.topology.flow_gate,
            ClosedEpochGate {
                previous_epoch: 0,
                next_epoch: 1,
            },
            FLOW_GATE_CLOSED,
        )
        .map_err(|_| 2)
    }

    fn finish(self, _step: PublicationStep<'_, 6>) {}
}

impl AtomicU64Authority for LoomState {
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

impl AtomicU64Value for LoomState {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.0.store(value, Ordering::Release);
    }
}

#[test]
fn production_group_publication_core_exposes_only_complete_published_state() {
    loom::model(|| {
        let publication_state = Arc::new(AtomicU64::new(0));
        let core =
            GroupPublicationCore::new(LoomState(Arc::clone(&publication_state)), 2, COMPONENTS)
                .expect("core");
        let topology = Arc::new(ModeledTopology::old());
        let writer_topology = Arc::clone(&topology);
        let writer = thread::spawn(move || {
            core.publish_committed(LoomPublication {
                topology: Arc::clone(&writer_topology),
                fail_receiver: false,
            })
            .expect("publish committed topology");
        });
        let reader_topology = Arc::clone(&topology);
        let reader = thread::spawn(move || {
            if let Ok(epoch) = acquire_epoch_lane(
                &reader_topology.flow_gate,
                &reader_topology.flow_lane,
                FLOW_GATE_CLOSED,
            ) {
                reader_topology.assert_complete_new();
                release_epoch_lane(&reader_topology.flow_lane, epoch).expect("release flow lane");
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
    });
}

#[test]
fn production_group_publication_core_poison_is_terminal_after_session_commit() {
    loom::model(|| {
        let publication_state = Arc::new(AtomicU64::new(0));
        let core =
            GroupPublicationCore::new(LoomState(Arc::clone(&publication_state)), 1, COMPONENTS)
                .expect("core");
        let topology = Arc::new(ModeledTopology::old());
        let publication = thread::spawn(move || {
            core.publish_committed(LoomPublication {
                topology,
                fail_receiver: true,
            })
        });
        assert!(publication.join().expect("publication").is_err());
        assert_eq!(
            GroupPublicationPhase::decode(publication_state.load(Ordering::Acquire)),
            Some(GroupPublicationPhase::Poisoned)
        );
    });
}

#[test]
fn production_group_publication_core_validates_before_mutation_and_poison_on_failure() {
    loom::model(|| {
        let publication_state = Arc::new(AtomicU64::new(0));
        let core =
            GroupPublicationCore::new(LoomState(Arc::clone(&publication_state)), 1, COMPONENTS)
                .expect("core");
        let topology = Arc::new(ModeledTopology::old());
        assert!(
            core.publish_committed(LoomPublication {
                topology,
                fail_receiver: true,
            })
            .is_err()
        );
        assert_eq!(
            GroupPublicationPhase::decode(publication_state.load(Ordering::Acquire)),
            Some(GroupPublicationPhase::Poisoned)
        );
    });
}

#[test]
#[should_panic(expected = "weakened split publication exposed mixed topology")]
fn weakened_split_manager_and_receiver_publication_exposes_mixed_state() {
    loom::model(|| {
        let manager_generation = Arc::new(AtomicU64::new(1));
        let receiver_generation = Arc::new(AtomicU64::new(1));
        let (manager_published, observe_manager) = mpsc::channel();
        let (mixed_observed, continue_publication) = mpsc::channel();

        let writer_manager = Arc::clone(&manager_generation);
        let writer_receiver = Arc::clone(&receiver_generation);
        let writer = thread::spawn(move || {
            writer_manager.store(2, Ordering::Release);
            manager_published
                .send(())
                .expect("publish manager boundary");
            continue_publication
                .recv()
                .expect("reader must inspect split publication");
            writer_receiver.store(2, Ordering::Release);
        });

        let reader_manager = Arc::clone(&manager_generation);
        let reader_receiver = Arc::clone(&receiver_generation);
        let reader = thread::spawn(move || {
            observe_manager.recv().expect("manager publication");
            let manager = reader_manager.load(Ordering::Acquire);
            let receiver = reader_receiver.load(Ordering::Acquire);
            mixed_observed.send(()).expect("release weakened writer");
            assert!(
                manager != 2 || receiver == 2,
                "weakened split publication exposed mixed topology"
            );
        });

        reader.join().expect("reader actor");
        writer.join().expect("writer actor");
    });
}
