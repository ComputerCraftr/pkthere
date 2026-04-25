#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/cli.rs"]
mod common;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;

use crate::common::{assert_cli_rejects, assert_cli_runs, render_app_bin_path};
use crate::common::{run_cli_args_expect_running_with_stdout, run_cli_args_with_stdout};
use crate::orchestrator::{
    IpFamily, NODE1_IPV4_STR, default_test_icmp_upstream_arg, default_test_upstream_arg,
    localhost_addr,
};
use std::time::Duration;

const CLI_WAIT: Duration = Duration::from_millis(500);
const CLI_REJECT_WAIT: Duration = Duration::from_secs(2);

#[test]
fn rejects_missing_required_flags_here() {
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(&["--there", &there], &["missing", "--here"]);
}

#[test]
fn rejects_missing_required_flags_there() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 12345));
    assert_cli_rejects(&["--here", &here], &["missing", "--there"]);
}

#[test]
fn rejects_duplicate_here() {
    let here1 = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let here2 = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &["--here", &here1, "--here", &here2, "--there", &there],
        &["--here specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_there() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there1 = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    let there2 = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 54));
    assert_cli_rejects(
        &["--here", &here, "--there", &there1, "--there", &there2],
        &["--there specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_optional_flags() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
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
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--on-timeout", "nope"],
        &["--on-timeout", "must be"],
    );
}

#[test]
fn rejects_invalid_numeric_values() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--max-payload",
            "notanumber",
        ],
        &["--max-payload"],
    );
}

#[test]
fn rejects_invalid_reresolve_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--reresolve-mode",
            "invalid",
        ],
        &["--reresolve-mode", "upstream"],
    );
}

#[test]
fn rejects_invalid_here_value() {
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 53));
    assert_cli_rejects(
        &[
            "--here",
            &format!("XYZ:{}:abc", NODE1_IPV4_STR),
            "--there",
            &there,
        ],
        &["--here"],
    );
}

#[test]
fn rejects_invalid_there_value() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    assert_cli_rejects(
        &["--here", &here, "--there", "UDP:not-an-addr"],
        &["--there"],
    );
}

#[test]
fn rejects_udp_upstream_port_zero() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    assert_cli_rejects(
        &["--here", &here, "--there", &there],
        &[
            "--there udp:host:0 is invalid",
            "fixed remote destination port",
        ],
    );
}

#[test]
fn rejects_udp_upstream_port_zero_ipv6() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 0));
    assert_cli_rejects(
        &["--here", &here, "--there", &there],
        &[
            "--there udp:host:0 is invalid",
            "fixed remote destination port",
        ],
    );
}

#[test]
fn expect_running_sees_ipv6_udp_upstream_zero_as_immediate_parse_failure() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 0));
    let (early_code, out, err) = run_cli_args_expect_running_with_stdout(
        &["--here", &here, "--there", &there],
        CLI_REJECT_WAIT,
    );
    assert_eq!(
        early_code,
        Some(2),
        "expected invalid IPv6 UDP upstream :0 to exit during CLI parsing; bin: {}; stdout: {out}; stderr: {err}",
        render_app_bin_path()
    );
}

#[test]
fn rejects_invalid_debug_value() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--debug-log", "foo"],
        &["--debug-log", "drops", "handles"],
    );
}

#[test]
fn rejects_removed_legacy_debug_flag() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--debug", "no-connect"],
        &["unknown arg: --debug"],
    );
}

#[test]
fn runs_with_explicit_debug_flags() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 9));
    assert_cli_runs(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--debug-no-connect",
            "--debug-fast-stats",
            "--debug-log",
            "drops",
            "--debug-log",
            "handles",
        ],
        CLI_WAIT,
        &["unknown arg", "--debug-log expects"],
    );
}

#[test]
fn runs_valid_minimal_udp_config() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 9));
    assert_cli_runs(
        &["--here", &here, "--there", &there],
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
fn rejects_zero_icmp_sync_pps_with_udp_upstream() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 9));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--icmp-sync-pps", "0"],
        &["--icmp-sync-pps requires --there ICMP"],
    );
}

#[test]
fn rejects_icmp_sync_pps_with_non_icmp_upstream() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--icmp-sync-pps", "10"],
        &["--icmp-sync-pps requires --there ICMP"],
    );
}

#[test]
fn rejects_workers_zero() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--workers", "0"],
        &["--workers must be >= 1"],
    );
}

#[test]
fn runs_with_worker_flow_mode_shared_flow() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_runs(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--worker-flow-mode",
            "shared-flow",
        ],
        CLI_WAIT,
        &["--worker-flow-mode"],
    );
}

#[test]
fn runs_with_worker_flow_mode_single_flow() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_runs(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--worker-flow-mode",
            "single-flow",
        ],
        CLI_WAIT,
        &["--worker-flow-mode"],
    );
}

#[test]
fn rejects_invalid_worker_flow_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--worker-flow-mode",
            "linux-bpf",
        ],
        &["--worker-flow-mode must be shared-flow|single-flow"],
    );
}

#[test]
fn help_mentions_worker_mode_and_dynamic_port_id_semantics() {
    let (code, _out, err) = run_cli_args_with_stdout(&["--help"]);
    assert_eq!(code, Some(0), "expected --help to exit 0, stderr: {err}");
    let err_lower = err.to_lowercase();
    for expected in [
        "--workers n              number of listener/upstream worker pairs, not flows",
        "shared-flow = one global locked flow across worker pairs",
        "single-flow = worker-pair-local locked flows and worker-pair-local icmp sync state",
        "worker modes affect ownership/distribution only; they do not scale shared/global options upward",
        "single-flow with --workers 1 is valid but behaves like shared-flow for ownership",
        "--here udp:host:0        bind an ephemeral local udp port",
        "--here icmp:host:0       wildcard-learn icmp listener",
        "fixed icmp listener id n (requires raw sockets on linux/android)",
        "--there icmp:host:0      dynamic local icmp source id",
        "fixed remote icmp peer/listener id n (requires raw sockets on linux/android)",
        "--icmp-sync-pps n        global total best-effort icmp sync request target in packets/s",
        "--debug-no-connect       keep sockets unconnected for debug/relock behavior",
        "--debug-fast-stats       shorten stats cadence for tests/debugging",
        "--debug-log what         enable debug log category what = drops|handles",
    ] {
        assert!(
            err_lower.contains(expected),
            "help output missing {:?}: {}",
            expected,
            err
        );
    }
}

#[test]
fn startup_logs_clarify_single_flow_with_one_worker() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 9));
    let (early_code, out, err) = run_cli_args_expect_running_with_stdout(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--workers",
            "1",
            "--worker-flow-mode",
            "single-flow",
        ],
        CLI_WAIT,
    );
    assert_eq!(
        early_code, None,
        "expected config to still be running; early_code={early_code:?}; stdout: {out}; stderr: {err}"
    );
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains(
            "worker flow mode: single-flow (worker-pair-local locked flows and worker-pair-local icmp sync state)"
        ),
        "stdout missing single-flow startup line: {out}"
    );
    assert!(
        out_lower.contains(
            "single-flow with --workers 1 is valid but has no distribution benefit; flow ownership behaves like shared-flow"
        ),
        "stdout missing single-flow workers=1 clarification: {out}"
    );
    assert!(
        !out_lower.contains("icmp sync pace:"),
        "unexpected sync pace log without --icmp-sync-pps: {out}"
    );
}

#[test]
fn startup_logs_clarify_dynamic_icmp_upstream_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip());
    let (early_code, out, err) =
        run_cli_args_expect_running_with_stdout(&["--here", &here, "--there", &there], CLI_WAIT);
    assert_eq!(
        early_code, None,
        "expected config to still be running; early_code={early_code:?}; stdout: {out}; stderr: {err}"
    );
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains("icmp upstream mode: dynamic local source id"),
        "stdout missing dynamic ICMP upstream clarification: {out}"
    );
    assert!(
        !out_lower.contains("icmp sync pace:"),
        "unexpected sync pace log without --icmp-sync-pps: {out}"
    );
}

#[test]
fn startup_logs_clarify_global_icmp_sync_budget() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip());
    let (early_code, out, err) = run_cli_args_expect_running_with_stdout(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--icmp-sync-pps",
            "7",
            "--workers",
            "2",
            "--worker-flow-mode",
            "single-flow",
        ],
        CLI_WAIT,
    );
    assert_eq!(
        early_code, None,
        "expected config to still be running; early_code={early_code:?}; stdout: {out}; stderr: {err}"
    );
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains(
            "icmp sync pace: global total best-effort target 7 packet(s)/s shared across all workers and flows"
        ),
        "stdout missing global icmp sync pace clarification: {out}"
    );
}

#[test]
fn rejects_max_payload_too_large() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65508"],
        &["exceeds the maximum supported by the selected protocols and address families (65507)"],
    );
}

#[test]
fn rejects_max_payload_exceeding_icmp_tunnel_limit() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = format!("ICMP:{}:1234", localhost_addr(IpFamily::V4, 0).ip());
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65507"],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn runs_with_max_payload_for_pure_ipv6() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V6, 9));
    assert_cli_runs(
        &["--here", &here, "--there", &there, "--max-payload", "65527"],
        CLI_WAIT,
        &[],
    );
}

#[test]
fn rejects_max_payload_for_mixed_ipv4_ipv6() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = format!("ICMP:{}:1234", localhost_addr(IpFamily::V6, 0).ip());
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65526"],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn rejects_duplicate_icmp_sync_pps() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = format!("ICMP:{}:2222", localhost_addr(IpFamily::V4, 0).ip());
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
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
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &[
            "--here", &here, "--there", &there, "--user", "nobody", "--user", "daemon",
        ],
        &["--user specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_reresolve_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
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
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--user"],
        &["--user requires a value"],
    );
}
