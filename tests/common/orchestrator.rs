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

pub use forwarder::{
    ForwarderConfig, SocketMode, launch_forwarder, try_launch_forwarder,
    wait_for_child_exit_success,
};
pub use matrix::{
    IPV4_ONLY_FAMILIES, IpFamily, MatrixCase, SOCKET_MODES, bind_client_or_skip, bind_udp_client,
    default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
    random_unprivileged_port, run_matrix_cases, spawn_echo_or_skip, spawn_udp_echo_server,
};
pub use raw_icmp::{
    platform_requires_raw_privilege_for_any_icmp, raw_icmp_test_supported,
    skip_unless_raw_icmp_supported,
};
pub use runtime_asserts::{
    CLIENT_WAIT_MS, expect_no_echo, json_addr, send_until_locked, wait_for_locked_client_from,
    wait_for_stats_matching,
};
pub use timing::{JSON_WAIT_MS, MAX_WAIT_SECS, SUPPORTED_PROTOCOLS, TIMEOUT_SECS};
