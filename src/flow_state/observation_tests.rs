use super::FlowRuntimeState;
use std::time::Instant;

#[test]
fn polling_without_control_clears_exactly_once_and_allows_the_next_receive() {
    let state = FlowRuntimeState::with_session_pool_size_and_reader_lanes(1, 1);
    let reservation = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("reserve polling observation")
        .observe(Instant::now());

    assert!(
        reservation
            .finish(None)
            .expect("finish non-control receive")
            .is_none()
    );
    assert_eq!(state.control_observation_count_for_tests(), 0);

    let next = state
        .reserve_control_observation(0, state.flow_epoch(), false)
        .expect("the cleared lane must accept the next receive");
    drop(next);
    assert_eq!(state.control_observation_count_for_tests(), 0);
}
