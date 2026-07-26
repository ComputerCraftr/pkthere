use super::lease_due_sync_send;
use crate::flow_state::FlowRuntimeState;
use crate::worker_support::GlobalSyncPacer;
use std::time::{Duration, Instant};

#[test]
fn busy_sync_slot_does_not_consume_the_global_pacing_interval() {
    let flow_state = FlowRuntimeState::new();
    let pacer = GlobalSyncPacer::new(Duration::from_millis(100));
    let now = Instant::now();
    let held = flow_state
        .lease_sync_send()
        .expect("lease state")
        .expect("hold sync slot");

    assert!(
        lease_due_sync_send(&flow_state, &pacer, now)
            .expect("busy slot is not an invariant failure")
            .is_none()
    );
    assert!(pacer.is_due(now));

    flow_state
        .complete_sync_send(held, false)
        .expect("release held slot");
    let acquired = lease_due_sync_send(&flow_state, &pacer, now)
        .expect("lease due slot")
        .expect("pacing interval remains available");
    assert!(!pacer.is_due(now));
    flow_state
        .complete_sync_send(acquired, false)
        .expect("release acquired slot");
}
