#![cfg(all(test, not(miri)))]

use super::render::capture_diagnostic_flow;
use crate::flow_state::FlowRuntimeState;
use crate::worker_support::test_support::{udp_socket, unused_manager};

#[test]
fn production_diagnostic_capture_releases_flow_before_manager_revalidation() {
    let upstream = udp_socket()
        .local_addr()
        .expect("upstream test address")
        .as_socket()
        .expect("upstream test IP address");
    let manager = unused_manager(upstream);
    let flow = FlowRuntimeState::new();

    let snapshot = capture_diagnostic_flow(&manager, &flow)
        .expect("capture diagnostics through the production transaction");
    assert!(!snapshot.locked);
}
