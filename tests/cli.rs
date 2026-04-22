#[path = "common/cli.rs"]
mod common;

use crate::common::{assert_cli_accepts_running, assert_cli_rejects};
use std::time::Duration;

const CLI_WAIT: Duration = Duration::from_millis(150);

#[test]
fn rejects_missing_required_flags_here() {
    assert_cli_rejects(&["--there", "UDP:127.0.0.1:53"], &["missing", "--here"]);
}

#[test]
fn rejects_missing_required_flags_there() {
    assert_cli_rejects(&["--here", "UDP:127.0.0.1:12345"], &["missing", "--there"]);
}

#[test]
fn rejects_duplicate_here() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--here",
            "UDP:127.0.0.1:2",
            "--there",
            "UDP:127.0.0.1:53",
        ],
        &["--here specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_there() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:53",
            "--there",
            "UDP:127.0.0.1:54",
        ],
        &["--there specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_optional_flags() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:53",
            "--timeout-secs",
            "5",
            "--timeout-secs",
            "10",
        ],
        &["--timeout-secs specified multiple times"],
    );
}

#[test]
fn rejects_invalid_on_timeout_value() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:53",
            "--on-timeout",
            "nope",
        ],
        &["--on-timeout", "must be"],
    );
}

#[test]
fn rejects_invalid_numeric_values() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:53",
            "--max-payload",
            "notanumber",
        ],
        &["--max-payload"],
    );
}

#[test]
fn rejects_invalid_reresolve_mode() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:53",
            "--reresolve-mode",
            "invalid",
        ],
        &["--reresolve-mode", "upstream"],
    );
}

#[test]
fn rejects_invalid_here_value() {
    assert_cli_rejects(
        &["--here", "XYZ:127.0.0.1:abc", "--there", "UDP:127.0.0.1:53"],
        &["--here"],
    );
}

#[test]
fn rejects_invalid_there_value() {
    assert_cli_rejects(
        &["--here", "UDP:127.0.0.1:1", "--there", "UDP:not-an-addr"],
        &["--there"],
    );
}

#[test]
fn rejects_invalid_debug_value() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--debug",
            "foo",
        ],
        &["--debug", "no-connect", "log-drops"],
    );
}

#[test]
fn accepts_valid_minimal_udp_config() {
    assert_cli_accepts_running(
        &["--here", "UDP:127.0.0.1:0", "--there", "UDP:127.0.0.1:9"],
        CLI_WAIT,
        &[
            "missing required flag",
            "unknown arg",
            "usage:",
            "--here must be",
        ],
    );
}

#[test]
fn accepts_valid_zero_icmp_sync_pps_with_udp_upstream() {
    assert_cli_accepts_running(
        &[
            "--here",
            "UDP:127.0.0.1:0",
            "--there",
            "UDP:127.0.0.1:9",
            "--icmp-sync-pps",
            "0",
        ],
        CLI_WAIT,
        &[
            "--icmp-sync-pps requires --there icmp",
            "missing required flag",
            "usage:",
        ],
    );
}

#[test]
fn rejects_icmp_sync_pps_with_non_icmp_upstream() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--icmp-sync-pps",
            "10",
        ],
        &["--icmp-sync-pps requires --there ICMP"],
    );
}

#[test]
fn rejects_workers_zero() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--workers",
            "0",
        ],
        &["--workers must be >= 1"],
    );
}

#[test]
fn accepts_worker_flow_mode_shared_flow() {
    assert_cli_accepts_running(
        &[
            "--here",
            "UDP:127.0.0.1:0",
            "--there",
            "UDP:127.0.0.1:2",
            "--worker-flow-mode",
            "shared-flow",
        ],
        CLI_WAIT,
        &["--worker-flow-mode"],
    );
}

#[test]
fn accepts_worker_flow_mode_single_flow() {
    assert_cli_accepts_running(
        &[
            "--here",
            "UDP:127.0.0.1:0",
            "--there",
            "UDP:127.0.0.1:2",
            "--worker-flow-mode",
            "single-flow",
        ],
        CLI_WAIT,
        &["--worker-flow-mode"],
    );
}

#[test]
fn rejects_invalid_worker_flow_mode() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--worker-flow-mode",
            "linux-bpf",
        ],
        &["--worker-flow-mode must be shared-flow|single-flow"],
    );
}

#[test]
fn rejects_max_payload_too_large() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--max-payload",
            "65508",
        ],
        &["exceeds the maximum supported by the selected protocols and address families (65507)"],
    );
}

#[test]
fn rejects_max_payload_exceeding_icmp_tunnel_limit() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "ICMP:127.0.0.1:1234",
            "--max-payload",
            "65507",
        ],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn accepts_max_payload_for_pure_ipv6() {
    assert_cli_accepts_running(
        &[
            "--here",
            "UDP:[::1]:0",
            "--there",
            "UDP:[::1]:0",
            "--max-payload",
            "65527",
        ],
        CLI_WAIT,
        &[],
    );
}

#[test]
fn rejects_max_payload_for_mixed_ipv4_ipv6() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "ICMP:[::1]:1234",
            "--max-payload",
            "65526",
        ],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn rejects_duplicate_icmp_sync_pps() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "ICMP:127.0.0.1:2222",
            "--icmp-sync-pps",
            "10",
            "--icmp-sync-pps",
            "20",
        ],
        &["--icmp-sync-pps specified multiple times"],
    );
}

#[cfg(unix)]
#[test]
fn rejects_duplicate_user_flags() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--user",
            "nobody",
            "--user",
            "daemon",
        ],
        &["--user specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_reresolve_mode() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--reresolve-mode",
            "upstream",
            "--reresolve-mode",
            "both",
        ],
        &["--reresolve-mode specified multiple times"],
    );
}

#[cfg(unix)]
#[test]
fn rejects_missing_user_value() {
    assert_cli_rejects(
        &[
            "--here",
            "UDP:127.0.0.1:1",
            "--there",
            "UDP:127.0.0.1:2",
            "--user",
        ],
        &["--user requires a value"],
    );
}
