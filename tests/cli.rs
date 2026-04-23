use pkthere_test_support::cli::{
    RunningObservation, assert_cli_rejects, assert_cli_runs, render_app_bin_path,
    run_cli_args_expect_running_with_stdout, run_cli_args_with_stdout,
};
use pkthere_test_support::network::{
    NODE1_IPV4_STR, default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
    render_icmp_arg,
};
use pkthere_test_support::timing::{CLI_COMPLETION_WAIT, CLI_OBSERVATION_WAIT};
use socket2::Domain;
use std::time::Duration;

fn expect_running_output(args: &[&str], wait: Duration) -> (String, String) {
    match run_cli_args_expect_running_with_stdout(args, wait) {
        RunningObservation::Running(output) => (output.stdout_lossy(), output.stderr_lossy()),
        RunningObservation::Exited(completed) => panic!(
            "expected config to remain running; exit={}; stdout: {}; stderr: {}",
            completed.exit,
            completed.output.stdout_lossy(),
            completed.output.stderr_lossy()
        ),
    }
}

fn udp_cli_pair(family: Domain, here_port: u16, there_port: u16) -> (String, String) {
    (
        default_test_upstream_arg("UDP", localhost_addr(family, here_port)),
        default_test_upstream_arg("UDP", localhost_addr(family, there_port)),
    )
}

#[test]
fn rejects_missing_required_flags_here() {
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
    assert_cli_rejects(&["--there", &there], &["missing", "--here"]);
}

#[test]
fn rejects_missing_required_flags_there() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 12345));
    assert_cli_rejects(&["--here", &here], &["missing", "--there"]);
}

#[test]
fn rejects_duplicate_here() {
    let here1 = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let here2 = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
    assert_cli_rejects(
        &["--here", &here1, "--here", &here2, "--there", &there],
        &["--here specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_there() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there1 = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
    let there2 = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 54));
    assert_cli_rejects(
        &["--here", &here, "--there", &there1, "--there", &there2],
        &["--there specified multiple times"],
    );
}

#[test]
fn rejects_duplicate_optional_flags() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
    for option in ["--timeout-secs", "--icmp-handshake-timeout-secs"] {
        assert_cli_rejects(
            &[
                "--here", &here, "--there", &there, option, "5", option, "10",
            ],
            &[&format!("{option} specified multiple times")],
        );
    }
}

#[test]
fn rejects_invalid_on_timeout_value() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--on-timeout", "nope"],
        &["--on-timeout", "must be"],
    );
}

#[test]
fn rejects_invalid_numeric_values() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
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
fn accepts_all_reresolve_modes_with_nonzero_interval() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));

    for mode in ["none", "upstream", "listen", "both"] {
        assert_cli_runs(
            &[
                "--here",
                &here,
                "--there",
                &there,
                "--reresolve-secs",
                "1",
                "--reresolve-mode",
                mode,
                "--timeout-secs",
                "1",
                "--on-timeout",
                "exit",
            ],
            CLI_OBSERVATION_WAIT,
            &[],
        );
    }
}

#[test]
fn rejects_invalid_here_value() {
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 53));
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    assert_cli_rejects(
        &["--here", &here, "--there", "UDP:not-an-addr"],
        &["--there"],
    );
}

#[test]
fn rejects_udp_upstream_port_zero() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 0));
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 0));
    let completed = match run_cli_args_expect_running_with_stdout(
        &["--here", &here, "--there", &there],
        CLI_COMPLETION_WAIT,
    ) {
        RunningObservation::Exited(completed) => completed,
        RunningObservation::Running(output) => panic!(
            "expected invalid IPv6 UDP upstream :0 to exit during CLI parsing; stdout: {}; stderr: {}",
            output.stdout_lossy(),
            output.stderr_lossy()
        ),
    };
    let out = completed.output.stdout_lossy();
    let err = completed.output.stderr_lossy();
    assert_eq!(
        completed.exit.code,
        Some(2),
        "expected invalid IPv6 UDP upstream :0 to exit during CLI parsing; bin: {}; stdout: {out}; stderr: {err}",
        render_app_bin_path()
    );
}

#[test]
fn rejects_invalid_debug_value() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--debug-log", "foo"],
        &[
            "--debug-log",
            "exactly one",
            "drops",
            "handshake",
            "handles",
            "packets",
            "packet-dump",
        ],
    );
}

#[test]
fn rejects_comma_separated_debug_log_values() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
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
fn rejects_icmp_kernel_echo_self_handshake_without_icmp_upstream() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--debug-icmp-kernel-echo-self-handshake",
        ],
        &["--debug-icmp-kernel-echo-self-handshake requires --there ICMP"],
    );
}

#[test]
fn rejects_force_raw_icmp_wildcard_upstream_without_wildcard_icmp_upstream() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let udp_there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
    assert_cli_rejects(
        &[
            "--here",
            &here,
            "--there",
            &udp_there,
            "--debug-force-raw-icmp-wildcard-upstream",
        ],
        &["--debug-force-raw-icmp-wildcard-upstream requires wildcard --there ICMP"],
    );
}

#[test]
fn rejects_invalid_single_value_cli_options_against_base_udp_config() {
    let (here, there) = udp_cli_pair(Domain::IPV4, 1, 2);
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
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
            "--debug-log",
            "handshake",
            "--debug-log",
            "packet-dump",
            "--icmp-handshake-timeout-secs",
            "2",
        ],
        CLI_OBSERVATION_WAIT,
        &["unknown arg", "--debug-log expects"],
    );
}

#[test]
fn runs_valid_minimal_udp_config() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
    assert_cli_runs(
        &["--here", &here, "--there", &there],
        CLI_OBSERVATION_WAIT,
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--icmp-sync-pps", "0"],
        &["--icmp-sync-pps requires --there ICMP"],
    );
}

#[test]
fn runs_with_each_supported_worker_flow_mode() {
    let (here, there) = udp_cli_pair(Domain::IPV4, 0, 2);
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
            CLI_OBSERVATION_WAIT,
            &["--worker-flow-mode"],
        );
    }
}

#[test]
fn rejects_invalid_worker_flow_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
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
        "--here udp:host:0                  bind an ephemeral local udp port",
        "--there udp:host:port              fixed remote udp destination port",
        "--there-source-id port|0           upstream udp/icmp local source id",
        "--here icmp:host:d                 listen for icmp destination id d",
        "--here-source-id s                 icmp listener logical source id",
        "--here-reply-id r                  icmp listener advertised reply destination id",
        "--there icmp:host:d                send to remote icmp destination id d",
        "--there-source-id s                icmp upstream logical source id",
        "--there-reply-id r                 icmp upstream local reply destination id",
        "--icmp-sync-pps n        global total best-effort icmp sync request target in packets/s",
        "--icmp-handshake-timeout-secs n",
        "--reresolve-mode what    which sockets to re-resolve: upstream|listen|both|none (default: upstream)",
        "--debug-reresolve-address-file path",
        "--debug-client-unconnected leave locked client/listener socket unconnected for debug/relock behavior",
        "--debug-upstream-unconnected leave upstream socket unconnected and always send via send_to for debugging",
        "--debug-icmp-kernel-echo-self-handshake allow icmp dgram kernel-echo self reflection",
        "--debug-fast-stats       shorten stats cadence for tests/debugging",
        "--debug-log what         enable one debug log category what = drops|handshake|handles|packets|packet-dump (repeatable)",
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--debug-invalid-option"],
        &["unknown arg: --debug-invalid-option"],
    );
}

#[test]
fn startup_logs_clarify_single_flow_with_one_worker() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
    let (out, _err) = expect_running_output(
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
        CLI_OBSERVATION_WAIT,
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
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn startup_logs_clarify_dynamic_icmp_upstream_mode() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_icmp_upstream_arg(localhost_addr(Domain::IPV4, 0).ip());
    let (out, _err) =
        expect_running_output(&["--here", &here, "--there", &there], CLI_OBSERVATION_WAIT);
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains("icmp upstream mode: dynamic/wildcard local reply id"),
        "stdout missing dynamic ICMP upstream clarification: {out}"
    );
    assert!(
        !out_lower.contains("icmp sync pace:"),
        "unexpected sync pace log without --icmp-sync-pps: {out}"
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn startup_logs_clarify_global_icmp_sync_budget() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_icmp_upstream_arg(localhost_addr(Domain::IPV4, 0).ip());
    let (out, _err) = expect_running_output(
        &[
            "--here",
            &here,
            "--there",
            &there,
            "--icmp-sync-pps",
            "7",
            "--workers",
            "1",
            "--worker-flow-mode",
            "shared-flow",
        ],
        CLI_OBSERVATION_WAIT,
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
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn rejects_multi_worker_single_flow_without_kernel_flow_affinity() {
    let (here, there) = udp_cli_pair(Domain::IPV4, 0, 2);
    let (code, _out, err) = run_cli_args_with_stdout(&[
        "--here",
        &here,
        "--there",
        &there,
        "--workers",
        "2",
        "--worker-flow-mode",
        "single-flow",
    ]);
    assert_ne!(code, Some(0), "unsupported worker mode unexpectedly ran");
    assert!(
        err.contains("requires kernel reuse-port flow affinity on this platform"),
        "missing worker distribution policy diagnostic: {err}"
    );
}

#[test]
fn rejects_max_payload_exceeding_icmp_tunnel_limit() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = render_icmp_arg(localhost_addr(Domain::IPV4, 0).ip(), 1234);
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65507"],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn runs_with_max_payload_for_pure_ipv6() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV6, 9));
    assert_cli_runs(
        &["--here", &here, "--there", &there, "--max-payload", "65527"],
        CLI_OBSERVATION_WAIT,
        &[],
    );
}

#[test]
fn rejects_max_payload_for_mixed_ipv4_ipv6() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = render_icmp_arg(localhost_addr(Domain::IPV6, 0).ip(), 1234);
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--max-payload", "65526"],
        &["exceeds the maximum supported by the selected protocols and address families (65506)"],
    );
}

#[test]
fn rejects_duplicate_icmp_sync_pps() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = render_icmp_arg(localhost_addr(Domain::IPV4, 0).ip(), 2222);
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
    let (here, _there) = udp_cli_pair(Domain::IPV6, 0, 9);
    for (there, expected) in [
        ("ICMP:::1:1234", "ICMP IPv6 addresses must use brackets"),
        ("ICMP:[::1]:1:2:3:4", "exactly one endpoint ID"),
    ] {
        assert_cli_rejects(&["--here", &here, "--there", there], &[expected]);
    }
}

#[test]
fn rejects_removed_endpoint_id_flags() {
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 0));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 9));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--here-id", "0"],
        &["unknown arg: --here-id"],
    );
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--there-id", "9"],
        &["unknown arg: --there-id"],
    );
}

#[test]
fn rejects_duplicate_single_value_flags() {
    let (here, there) = udp_cli_pair(Domain::IPV4, 1, 2);
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
    let here = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 1));
    let there = default_test_upstream_arg("UDP", localhost_addr(Domain::IPV4, 2));
    assert_cli_rejects(
        &["--here", &here, "--there", &there, "--user"],
        &["--user requires a value"],
    );
}
