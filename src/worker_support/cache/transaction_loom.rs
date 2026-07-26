#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::WorkerStateTransaction;
use crate::atomic_core::{
    acquire_epoch_lane, close_epoch_gate, reacquire_expected_epoch_lane, release_epoch_lane,
    release_writer_epoch_lane, reopen_epoch_gate, reserve_epoch_lane_for_writer,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

const CLOSED: u64 = 1 << 63;

#[test]
fn production_worker_state_transaction_never_publishes_mixed_resources() {
    loom::model(|| {
        let flow_gate = Arc::new(AtomicU64::new(0));
        let flow_lane = Arc::new(AtomicU64::new(0));
        let manager_version = Arc::new(AtomicU64::new(1));
        let handles_version = Arc::new(AtomicU64::new(0));
        let descriptor_cache_version = Arc::new(AtomicU64::new(0));
        let expected_epoch = acquire_epoch_lane(flow_gate.as_ref(), flow_lane.as_ref(), CLOSED)
            .expect("acquire initial production flow lane");

        let reader = {
            let flow_gate = Arc::clone(&flow_gate);
            let flow_lane = Arc::clone(&flow_lane);
            let manager_version = Arc::clone(&manager_version);
            let handles_version = Arc::clone(&handles_version);
            let descriptor_cache_version = Arc::clone(&descriptor_cache_version);
            thread::spawn(move || {
                WorkerStateTransaction::run(
                    || {
                        release_epoch_lane(flow_lane.as_ref(), expected_epoch).map_err(|_| ())?;
                        let staged = manager_version.load(Ordering::Acquire);
                        Ok(staged)
                    },
                    |staged| {
                        descriptor_cache_version.store(staged, Ordering::Release);
                        handles_version.store(staged, Ordering::Release);
                        let installed = staged;
                        reacquire_expected_epoch_lane(
                            flow_gate.as_ref(),
                            flow_lane.as_ref(),
                            expected_epoch,
                            CLOSED,
                        )
                        .map_err(|_| ())?;
                        let handles = handles_version.load(Ordering::Acquire);
                        let cache = descriptor_cache_version.load(Ordering::Acquire);
                        let manager = manager_version.load(Ordering::Acquire);
                        if installed != manager || handles != manager || cache != manager {
                            release_epoch_lane(flow_lane.as_ref(), expected_epoch)
                                .map_err(|_| ())?;
                            return Err(());
                        }
                        release_epoch_lane(flow_lane.as_ref(), expected_epoch).map_err(|_| ())?;
                        Ok(manager)
                    },
                )
            })
        };

        let writer = {
            let flow_gate = Arc::clone(&flow_gate);
            let flow_lane = Arc::clone(&flow_lane);
            let manager_version = Arc::clone(&manager_version);
            thread::spawn(move || {
                let closed = match close_epoch_gate(flow_gate.as_ref(), CLOSED) {
                    Ok(closed) => closed,
                    Err(_) => return,
                };
                if !reserve_epoch_lane_for_writer(flow_lane.as_ref()).expect("reserve writer lane")
                {
                    reopen_epoch_gate(flow_gate.as_ref(), closed, CLOSED)
                        .expect("cancel publication around an active reader");
                    return;
                }
                manager_version.store(2, Ordering::Release);
                reopen_epoch_gate(flow_gate.as_ref(), closed, CLOSED)
                    .expect("publish new flow epoch");
                release_writer_epoch_lane(flow_lane.as_ref()).expect("release writer lane");
            })
        };

        let refreshed = reader.join().expect("refresh actor");
        writer.join().expect("publication actor");
        if let Ok(version) = refreshed {
            assert_eq!(version, 1);
        }
    });
}
