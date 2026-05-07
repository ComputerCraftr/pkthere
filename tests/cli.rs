#![allow(
    clippy::duplicate_mod,
    clippy::expect_fun_call,
    clippy::manual_contains
)]

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
    localhost_addr, render_icmp_arg,
};
use std::time::Duration;

const CLI_WAIT: Duration = Duration::from_millis(500);
const CLI_REJECT_WAIT: Duration = Duration::from_secs(2);

fn udp_cli_pair(family: IpFamily, here_port: u16, there_port: u16) -> (String, String) {
    (
        default_test_upstream_arg("UDP", localhost_addr(family, here_port)),
        default_test_upstream_arg("UDP", localhost_addr(family, there_port)),
    )
}

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
        &["--debug-log", "exactly one", "drops", "handles", "packets"],
    );
}

#[test]
fn rejects_comma_separated_debug_log_values() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 2));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--debug-log",
            "drops,handles",
        ],
        &["--debug-log", "exactly one", "drops,handles"],
    );
}

#[test]
fn rejects_invalid_single_value_cli_options_against_base_udp_config() {
    let (here, there) = udp_cli_pair(IpFamily::V4, 1, 2);
    for (extra_args, expected) in [
        (
            vec!["--debug", "invalid-option"],
            vec!["unknown arg: --debug"],
        ),
        (
            vec!["--icmp-sync-pps", "10"],
            vec!["--icmp-sync-pps requires --there ICMP"],
        ),
        (vec!["--workers", "0"], vec!["--workers must be >= 1"]),
        (
            vec!["--max-payload", "65508"],
            vec![
                "exceeds the maximum supported by the selected protocols and address families (65507)",
            ],
        ),
    ] {
        let mut args = vec!["--here", here.as_str(), "--there", there.as_str()];
        args.extend(extra_args);
        assert_cli_rejects(&args, &expected);
    }
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
            "--debug-client-unconnected",
            "--debug-upstream-unconnected",
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
fn runs_with_each_supported_worker_flow_mode() {
    let (here, there) = udp_cli_pair(IpFamily::V4, 0, 2);
    for mode in ["shared-flow", "single-flow"] {
        assert_cli_runs(
            &[
                "--here",
                &here,
                "--there",
                &there,
                "--worker-flow-mode",
                mode,
            ],
            CLI_WAIT,
            &["--worker-flow-mode"],
        );
    }
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
        "--reresolve-mode what    which sockets to re-resolve: upstream|listen|both|none (default: upstream)",
        "--debug-client-unconnected leave locked client/listener socket unconnected for debug/relock behavior",
        "--debug-upstream-unconnected leave upstream socket unconnected and always send via send_to for debugging",
        "--debug-fast-stats       shorten stats cadence for tests/debugging",
        "--debug-log what         enable one debug log category what = drops|handles|packets (repeatable)",
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
fn rejects_unrecognized_debug_flags() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 9));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--debug-invalid-option"],
        &["unknown arg: --debug-invalid-option"],
    );
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
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn startup_logs_clarify_dynamic_icmp_upstream_mode() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

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
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn startup_logs_clarify_global_icmp_sync_budget() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

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
fn rejects_max_payload_exceeding_icmp_tunnel_limit() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = render_icmp_arg(localhost_addr(IpFamily::V4, 0).ip(), 1234);
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
    let there = render_icmp_arg(localhost_addr(IpFamily::V6, 0).ip(), 1234);
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65526"],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn rejects_duplicate_icmp_sync_pps() {
    let here = default_test_upstream_arg("UDP", localhost_addr(IpFamily::V4, 1));
    let there = render_icmp_arg(localhost_addr(IpFamily::V4, 0).ip(), 2222);
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

#[test]
fn rejects_malformed_ipv6_icmp_upstream_shapes() {
    let (here, _there) = udp_cli_pair(IpFamily::V6, 0, 9);
    for (there, expected) in [
        ("ICMP:::1:1234", "ICMP IPv6 addresses must use brackets"),
        (
            "ICMP:[::1]:1:2:3",
            "must use ICMP:<host>:<remote_id> or ICMP:[<ipv6>]:<remote_id>[:<local_id>]",
        ),
    ] {
        assert_cli_rejects(&["--here", &here, "--there", there], &[expected]);
    }
}

#[test]
fn rejects_duplicate_single_value_flags() {
    let (here, there) = udp_cli_pair(IpFamily::V4, 1, 2);
    #[cfg(unix)]
    let cases = vec![
        (
            vec!["--reresolve-mode", "upstream", "--reresolve-mode", "both"],
            vec!["--reresolve-mode specified multiple times"],
        ),
        (
            vec!["--user", "nobody", "--user", "daemon"],
            vec!["--user specified multiple times"],
        ),
    ];
    #[cfg(not(unix))]
    let cases = vec![(
        vec!["--reresolve-mode", "upstream", "--reresolve-mode", "both"],
        vec!["--reresolve-mode specified multiple times"],
    )];

    for (extra_args, expected) in cases {
        let mut args = vec!["--here", here.as_str(), "--there", there.as_str()];
        args.extend(extra_args);
        assert_cli_rejects(&args, &expected);
    }
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
