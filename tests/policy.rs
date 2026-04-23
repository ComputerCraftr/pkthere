#[path = "common/harness_policy.rs"]
mod harness_policy;
#[path = "common/path_naming_policy.rs"]
mod path_naming_policy;
#[path = "common/policy.rs"]
mod policy;

#[test]
fn rust_source_files_stay_under_1000_lines() {
    policy::assert_rust_source_files_stay_under_1000_lines();
}

#[test]
fn internal_source_paths_use_snake_case() {
    path_naming_policy::assert_source_paths_follow_naming_policy();
}

#[test]
fn tests_do_not_depend_on_ipv4_loopback_aliases() {
    policy::assert_tests_do_not_use_loopback_aliases();
}

#[test]
fn oversized_subsystem_mod_files_are_small_facades() {
    policy::assert_scoped_mod_files_are_small_facades();
}

#[test]
fn syntactic_direct_recursion_is_forbidden() {
    policy::assert_syntactic_direct_recursion_is_forbidden();
}

#[test]
fn dead_code_allows_are_forbidden() {
    policy::assert_dead_code_allows_are_forbidden();
}

#[test]
fn no_wildcard_imports_in_project_rust_sources() {
    policy::assert_no_wildcard_imports_in_project_rust_sources();
}

#[test]
fn no_exact_duplicate_bodies_in_workspace() {
    policy::assert_no_exact_duplicate_bodies_in_workspace();
}

#[test]
fn portable_build_configuration_is_structurally_valid() {
    policy::assert_portable_build_configuration();
}

#[test]
fn retired_text_scanners_cannot_return() {
    policy::assert_legacy_text_scanners_are_forbidden();
}

#[test]
fn test_harness_lifecycle_boundaries_are_centralized() {
    harness_policy::assert_test_harness_lifecycle_boundaries();
}

#[test]
fn native_ci_uses_shared_raw_capability_and_test_runners() {
    let workflow = include_str!("../.github/workflows/rust.yml").replace("\r\n", "\n");
    for duplicated_command in [
        "sudo setcap",
        "sudo chown",
        "find target/debug/deps",
        "PKTHERE_ALLOW_RAW_ICMP=1\" >> \"$GITHUB_ENV",
    ] {
        assert!(
            !workflow.contains(duplicated_command),
            "native CI must delegate '{duplicated_command}' to its checked-in helper"
        );
    }
    assert_eq!(
        workflow
            .matches(".github/scripts/grant_raw_capability.sh")
            .count(),
        2,
        "debug and release jobs must share one privilege implementation"
    );
    assert_eq!(
        workflow
            .matches(".github/scripts/ci_test_runner.py native")
            .count(),
        1,
        "every native platform must use one cross-platform test dispatcher"
    );
    assert_eq!(
        workflow
            .matches(".github/scripts/ci_test_runner.py raw-reality")
            .count(),
        1,
        "every native platform must use one cross-platform RAW reality dispatcher"
    );
    assert!(
        workflow.contains(
            "- os: windows-latest\n            platform: windows\n            label: Windows\n            raw_icmp_override: 1"
        ),
        "Windows native CI must enable the privileged IPv4 RAW owners verified by socket reality"
    );
    assert!(workflow.contains("shellcheck .github/scripts/*.sh"));
    assert!(workflow.contains("docker://mvdan/shfmt:"));
    assert!(workflow.contains("ruff==0.15.22 format --check ."));
    assert!(workflow.contains("ruff==0.15.22 check ."));
    assert!(workflow.contains("mypy==2.3.0 --strict"));
    assert!(workflow.contains("taplo fmt --check"));
    assert!(workflow.contains("taplo check"));
    assert!(workflow.contains("prettier@3.9.6 --check"));
    for (job, next_job, timeout_minutes) in [
        ("quality", Some("test"), 30),
        ("test", Some("stress-release"), 30),
        ("stress-release", Some("aarch64-musl"), 15),
        ("aarch64-musl", Some("alpine-socket-reality"), 30),
        ("alpine-socket-reality", None, 20),
    ] {
        let job_start = workflow
            .find(&format!("  {job}:\n"))
            .unwrap_or_else(|| panic!("missing CI job {job}"));
        let job_end = next_job.map_or(workflow.len(), |next| {
            workflow
                .find(&format!("  {next}:\n"))
                .unwrap_or_else(|| panic!("missing CI job {next}"))
        });
        assert!(
            workflow[job_start..job_end].contains(&format!("timeout-minutes: {timeout_minutes}")),
            "CI job {job} must retain its deadlock timeout of {timeout_minutes} minutes"
        );
    }
    assert_eq!(
        workflow.matches("uses: actions/upload-artifact@").count(),
        3,
        "native, cross, and Alpine jobs must each upload evidence"
    );
    assert_eq!(
        workflow.matches("if: always()").count(),
        3,
        "all artifact uploads must run after success or failure"
    );

    let test_manifest = include_str!("../docker/alpine/pkthere_harness/test_manifest.py");
    let native_tests = include_str!("../.github/scripts/ci_test_runner.py");
    for raw_test in [
        "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node",
        "raw_icmp_locked_flow_rejects_wrong_source_id",
        "test_raw_icmp_independent_ids",
        "raw_icmp_wildcard_upstream_locks_on_localhost",
    ] {
        assert!(
            test_manifest.contains(raw_test),
            "authoritative privileged test manifest must contain {raw_test}"
        );
    }
    assert!(
        native_tests.contains("privileged_icmp_tests_for_platform(platform)")
            && native_tests.contains("native_platform_name()")
            && test_manifest.contains("\"--exact\"")
            && test_manifest.contains("\"--ignored\"")
            && test_manifest.contains("\"--nocapture\"")
            && test_manifest.contains("platforms=frozenset"),
        "only exact privileged ICMP lock owners must run sequentially from the manifest"
    );
    assert!(
        !native_tests.contains("--test-threads=1")
            && !workflow.contains("--test-threads=1")
            && !include_str!("../docker/alpine/pkthere_harness/reality.py")
                .contains("--test-threads=1"),
        "ordinary suites and exact single-test invocations must keep default parallelism"
    );
    assert!(
        include_str!("../docker/alpine/pkthere_harness/reality.py")
            .contains("privileged_icmp_tests_for_platform(\"linux\")"),
        "Alpine and native runners must consume the same privileged test manifest"
    );

    assert!(
        include_str!("../.github/scripts/grant_raw_capability.sh").contains("set -euo pipefail"),
        "the privilege-specific shell helper must fail on command and pipeline errors"
    );
}

#[test]
fn protocol_helpers_do_not_emit_unrequested_debug_logs() {
    policy::assert_protocol_helpers_do_not_emit_unrequested_debug_logs();
}
