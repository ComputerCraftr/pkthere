use super::{WorkerPairThreadIds, validate_authority_lane_capacity};
use crate::cli::{MAX_WORKER_PAIRS, WorkerFlowMode};

#[test]
fn maximum_worker_pairs_fit_the_authority_lane_budget() {
    for mode in [WorkerFlowMode::SharedFlow, WorkerFlowMode::SingleFlow] {
        validate_authority_lane_capacity(MAX_WORKER_PAIRS, mode)
            .expect("maximum supported workers fit the synchronization-lane budget");
    }
}

#[test]
fn worker_count_above_the_fixed_lane_capacity_is_rejected() {
    for mode in [WorkerFlowMode::SharedFlow, WorkerFlowMode::SingleFlow] {
        assert!(
            validate_authority_lane_capacity(MAX_WORKER_PAIRS + 1, mode).is_err(),
            "worker count above the fixed authority-lane capacity must fail"
        );
    }
}

#[test]
fn every_worker_direction_has_a_unique_socket_lane() {
    let mut previous_upstream = None;
    for pair in 0..MAX_WORKER_PAIRS {
        let ids = WorkerPairThreadIds::checked(pair).expect("worker pair IDs");
        assert_eq!(ids.client, pair * 2);
        assert_eq!(ids.upstream, ids.client + 1);
        if let Some(previous) = previous_upstream {
            assert!(previous < ids.client);
        }
        previous_upstream = Some(ids.upstream);
    }
    assert_eq!(
        previous_upstream.map(|id| id + 1),
        Some(MAX_WORKER_PAIRS * 2)
    );
}
