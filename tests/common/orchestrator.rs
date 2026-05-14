#![allow(dead_code, unused_imports)]

#[path = "forwarder.rs"]
pub mod forwarder;
#[path = "matrix.rs"]
pub mod matrix;
#[path = "raw_icmp.rs"]
mod raw_icmp;
#[path = "runtime_asserts.rs"]
mod runtime_asserts;
#[path = "timing.rs"]
mod timing;
#[path = "user_policy.rs"]
pub mod user_policy;

pub use forwarder::{
    ForwarderConfig, ForwarderSession, OutputCapture, collect_forwarder_output, launch_forwarder,
    snapshot_forwarder_output, snapshot_forwarder_output_tail, terminate_forwarder,
    try_launch_forwarder, wait_for_child_exit_success,
};
pub use matrix::{
    ALL_CONNECT_MODES, ALL_IP_FAMILIES, IPV4_ONLY_FAMILIES, IpFamily, LoopbackAliasGuard,
    MatrixCase, NODE1_IPV4, NODE1_IPV4_STR, NODE2_IPV4, NODE2_IPV4_STR, NODE3_IPV4, NODE3_IPV4_STR,
    bind_client_or_skip, bind_udp_client, default_test_icmp_upstream_arg,
    default_test_upstream_arg, ensure_loopback_ip, localhost_addr, random_unprivileged_port,
    render_canonical_ip_id, render_icmp_arg, render_icmp_arg_with_reply_id, run_matrix_cases,
    spawn_echo_or_skip, spawn_udp_echo_server, spawn_upstream_echo_or_skip,
};
pub use raw_icmp::{
    platform_supports_dgram_icmp, require_bound_raw_icmp_loopback_request_delivery,
    require_kernel_echo_reply_supported, require_raw_icmp_supported,
};
pub use runtime_asserts::{
    StatsWaitOutcome, expect_no_echo, expect_session_stats_matching, json_addr, send_until_locked,
    wait_for_locked_client_from, wait_for_session_stats_matching, wait_for_stats_match_or_last,
    wait_for_stats_matching,
};
pub use timing::{
    ALL_SUPPORTED_PROTOCOLS, CLIENT_WAIT_MS, DRAIN_WAIT_MS, JSON_WAIT_MS, MAX_WAIT_SECS,
    TIMEOUT_SECS,
};
