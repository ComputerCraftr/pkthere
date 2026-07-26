#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::topology_typestate::{ReservedTopologyTransaction, TopologyTransactionOwner};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

struct ModeledTopologyOwner {
    phase: Arc<AtomicU64>,
    visible_epoch: Arc<AtomicU64>,
}

impl TopologyTransactionOwner for ModeledTopologyOwner {
    type Error = ();
    type Receipt = u64;

    fn apply_socket_transitions(&mut self) -> Result<(), Self::Error> {
        self.phase.store(1, Ordering::Release);
        Ok(())
    }

    fn prepare_manager_state(&mut self) -> Result<(), Self::Error> {
        assert_eq!(self.phase.load(Ordering::Acquire), 1);
        self.phase.store(2, Ordering::Release);
        Ok(())
    }

    fn commit_session_state(
        &mut self,
        expected_flow_epoch: u64,
        resulting_flow_epoch: u64,
    ) -> Result<Self::Receipt, Self::Error> {
        assert_eq!(self.phase.load(Ordering::Acquire), 2);
        assert!(resulting_flow_epoch >= expected_flow_epoch);
        self.phase.store(3, Ordering::Release);
        Ok(resulting_flow_epoch)
    }

    fn publish_manager_state(self) -> Result<(), Self::Error> {
        assert_eq!(self.phase.load(Ordering::Acquire), 2);
        self.visible_epoch.store(1, Ordering::Release);
        Ok(())
    }

    fn publish_committed_state(self, receipt: Self::Receipt) -> Result<(), Self::Error> {
        assert_eq!(self.phase.load(Ordering::Acquire), 3);
        self.visible_epoch.store(receipt, Ordering::Release);
        Ok(())
    }
}

#[test]
fn flow_topology_typestate_publishes_only_after_consuming_session_commit() {
    loom::model(|| {
        let phase = Arc::new(AtomicU64::new(0));
        let visible_epoch = Arc::new(AtomicU64::new(0));
        let writer_phase = Arc::clone(&phase);
        let writer_visible = Arc::clone(&visible_epoch);
        let writer = thread::spawn(move || {
            ReservedTopologyTransaction::new(ModeledTopologyOwner {
                phase: writer_phase,
                visible_epoch: writer_visible,
            })
            .socket_transitions_applied()
            .expect("socket transition")
            .manager_state_prepared()
            .expect("manager preparation")
            .commit_session(4, 5)
            .expect("session commit")
            .publish()
            .expect("publication");
        });
        let reader_phase = Arc::clone(&phase);
        let reader_visible = Arc::clone(&visible_epoch);
        let reader = thread::spawn(move || {
            let visible = reader_visible.load(Ordering::Acquire);
            if visible == 5 {
                assert_eq!(reader_phase.load(Ordering::Acquire), 3);
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
        assert_eq!(visible_epoch.load(Ordering::Acquire), 5);
    });
}
