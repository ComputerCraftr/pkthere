#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::diagnostic_capture::DiagnosticCaptureTransaction;
use crate::atomic_core::{
    acquire_epoch_lane, close_epoch_gate, release_epoch_lane, release_writer_epoch_lane,
    reopen_epoch_gate, reserve_epoch_lane_for_writer,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

const CLOSED: u64 = 1 << 63;

struct ModeledFlowLease {
    lane: Arc<AtomicU64>,
    epoch: u64,
}

impl Drop for ModeledFlowLease {
    fn drop(&mut self) {
        release_epoch_lane(self.lane.as_ref(), self.epoch).expect("release modeled flow lease");
    }
}

#[test]
fn production_diagnostic_capture_never_holds_flow_while_recapturing_manager() {
    loom::model(|| {
        let gate = Arc::new(AtomicU64::new(0));
        let lane = Arc::new(AtomicU64::new(0));
        let manager_publication = Arc::new(AtomicU64::new(1));
        let flow_publication = Arc::new(AtomicU64::new(1));

        let reader = {
            let gate = Arc::clone(&gate);
            let lane = Arc::clone(&lane);
            let manager_publication = Arc::clone(&manager_publication);
            let flow_publication = Arc::clone(&flow_publication);
            thread::spawn(move || {
                DiagnosticCaptureTransaction::run(
                    || Ok::<_, ()>(manager_publication.load(Ordering::Acquire)),
                    || {
                        let epoch = acquire_epoch_lane(gate.as_ref(), lane.as_ref(), CLOSED)
                            .map_err(|_| ())?;
                        Ok(ModeledFlowLease {
                            lane: Arc::clone(&lane),
                            epoch,
                        })
                    },
                    |_| flow_publication.load(Ordering::Acquire),
                    |lease| gate.load(Ordering::Acquire) == lease.epoch,
                    |before, after| before == after,
                )
            })
        };

        let writer = {
            let gate = Arc::clone(&gate);
            let lane = Arc::clone(&lane);
            let manager_publication = Arc::clone(&manager_publication);
            let flow_publication = Arc::clone(&flow_publication);
            thread::spawn(move || {
                let closed = match close_epoch_gate(gate.as_ref(), CLOSED) {
                    Ok(closed) => closed,
                    Err(_) => return,
                };
                if !reserve_epoch_lane_for_writer(lane.as_ref()).expect("reserve writer lane") {
                    reopen_epoch_gate(gate.as_ref(), closed, CLOSED)
                        .expect("cancel writer publication");
                    return;
                }
                manager_publication.store(2, Ordering::Release);
                flow_publication.store(2, Ordering::Release);
                reopen_epoch_gate(gate.as_ref(), closed, CLOSED)
                    .expect("publish grouped diagnostic state");
                release_writer_epoch_lane(lane.as_ref()).expect("release writer lane");
            })
        };

        let capture = reader.join().expect("diagnostic reader");
        writer.join().expect("diagnostic writer");
        if let Ok((manager, flow)) = capture {
            assert_eq!(manager, flow);
        }
    });
}
