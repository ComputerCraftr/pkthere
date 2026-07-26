use serde_yaml_ng::Value;

use super::{read, repo_root};

const APPROVED_CI_ACTIONS: &[&str] = &[
    "./.github/actions/enable_icmp_ping",
    "Swatinem/rust-cache@v2",
    "actions/cache/restore@v6",
    "actions/cache/save@v6",
    "actions/checkout@v7",
    "actions/setup-node@v7",
    "actions/setup-python@v7",
    "actions/upload-artifact@v7",
    "docker/build-push-action@v7",
    "docker/setup-buildx-action@v4",
    "dtolnay/rust-toolchain@v1",
    "vmactions/freebsd-vm@v1.5.2",
];

fn active(step: &Value) -> bool {
    match step.get("if") {
        Some(Value::Bool(false)) => false,
        Some(Value::String(condition)) if condition.trim().eq_ignore_ascii_case("false") => false,
        _ => true,
    }
}

fn jobs(workflow: &Value) -> &serde_yaml_ng::Mapping {
    workflow
        .get("jobs")
        .and_then(Value::as_mapping)
        .expect("workflow jobs mapping")
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    jobs(workflow)
        .get(Value::from(name))
        .unwrap_or_else(|| panic!("missing CI job {name}"))
}

fn steps(job: &Value) -> &[Value] {
    job.get("steps")
        .and_then(Value::as_sequence)
        .map(Vec::as_slice)
        .expect("CI job steps")
}

fn active_steps(job: &Value) -> impl Iterator<Item = &Value> {
    steps(job).iter().filter(|step| active(step))
}

fn executable_blocks(step: &Value) -> impl Iterator<Item = &str> {
    let direct = step.get("run").and_then(Value::as_str);
    let action_inputs = ["prepare", "run"].into_iter().filter_map(|name| {
        step.get("with")
            .and_then(|configuration| configuration.get(name))
            .and_then(Value::as_str)
    });
    direct.into_iter().chain(action_inputs)
}

fn executable_processes(step: &Value) -> impl Iterator<Item = &str> {
    let direct = step.get("run").and_then(Value::as_str);
    let action_run = step
        .get("with")
        .and_then(|configuration| configuration.get("run"))
        .and_then(Value::as_str);
    direct.into_iter().chain(action_run)
}

fn executable_lines(step: &Value) -> impl Iterator<Item = &str> {
    executable_blocks(step)
        .flat_map(str::lines)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

pub(super) fn active_command_count(workflow: &Value, needle: &str) -> usize {
    jobs(workflow)
        .values()
        .flat_map(active_steps)
        .flat_map(executable_lines)
        .map(|line| line.matches(needle).count())
        .sum()
}

pub(super) fn unauthorized_process_count(workflow: &Value) -> usize {
    jobs(workflow)
        .values()
        .flat_map(active_steps)
        .map(|step| {
            let unauthorized_runs = executable_processes(step)
                .filter(|command| {
                    let command = command.trim();
                    !command.starts_with("python -m ci.pkthere_ci ")
                        && !command.starts_with("python3 -m ci.pkthere_ci ")
                        && !command.starts_with("python3.13 -m ci.pkthere_ci ")
                })
                .count();
            let unauthorized_prepare = step
                .get("with")
                .and_then(|configuration| configuration.get("prepare"))
                .and_then(Value::as_str)
                .is_some_and(|prepare| {
                    step.get("uses").and_then(Value::as_str) != Some("vmactions/freebsd-vm@v1.5.2")
                        || prepare != "/bin/sh .github/scripts/prepare_freebsd_ci.sh v1"
                });
            unauthorized_runs + usize::from(unauthorized_prepare)
        })
        .sum()
}

fn active_job_command_count(workflow: &Value, job_name: &str, needle: &str) -> usize {
    active_steps(job(workflow, job_name))
        .flat_map(executable_lines)
        .map(|line| line.matches(needle).count())
        .sum()
}

fn named_step<'a>(workflow: &'a Value, job_name: &str, step_name: &str) -> &'a Value {
    active_steps(job(workflow, job_name))
        .find(|step| step.get("name").and_then(Value::as_str) == Some(step_name))
        .unwrap_or_else(|| panic!("missing active CI step {job_name}/{step_name}"))
}

fn env_contains_key(value: &Value, key: &str) -> bool {
    value
        .get("env")
        .and_then(Value::as_mapping)
        .is_some_and(|env| env.contains_key(Value::from(key)))
}

fn assert_approved_action_tags(workflow: &Value) {
    for action in jobs(workflow)
        .values()
        .flat_map(active_steps)
        .filter_map(|step| step.get("uses").and_then(Value::as_str))
    {
        assert!(
            APPROVED_CI_ACTIONS.contains(&action),
            "CI action is not on the audited current-tag inventory: {action}"
        );
    }
}

fn assert_canonical_workflow_inventory(root: &std::path::Path) {
    let paths = crate::common::source_layout_policy::tracked_repository_paths()
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(root)
                .ok()
                .map(std::path::Path::to_path_buf)
        })
        .filter(|path| path.starts_with(".github/workflows"))
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>();
    let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(
        canonical_workflow_paths(&path_refs).is_ok(),
        "WORKFLOW-CANONICAL-OWNER-001: rust.yml must be the sole workflow owner"
    );
    let metadata =
        std::fs::symlink_metadata(root.join(&paths[0])).expect("canonical workflow metadata");
    assert!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "canonical workflow must be a regular non-symlink file"
    );
}

pub(super) fn canonical_workflow_paths(paths: &[&str]) -> Result<(), &'static str> {
    if paths == [".github/workflows/rust.yml"] {
        Ok(())
    } else {
        Err("WORKFLOW-CANONICAL-OWNER-001")
    }
}

pub(super) fn assert_ci_workflow_has_executable_semantics() {
    let root = repo_root();
    assert_canonical_workflow_inventory(&root);
    let workflow: Value = serde_yaml_ng::from_str(&read(&root.join(".github/workflows/rust.yml")))
        .expect("parse Rust workflow YAML");

    assert_eq!(
        unauthorized_process_count(&workflow),
        0,
        "Rust workflow executable processes must delegate to the canonical runner"
    );
    assert_approved_action_tags(&workflow);

    for (name, timeout) in [
        ("quality", 30),
        ("msrv", 30),
        ("macos-profile", 30),
        ("miri-production-units", 30),
        ("test", 30),
        ("stress-release", 15),
        ("aarch64-musl", 30),
        ("alpine-socket-reality", 20),
    ] {
        assert_eq!(
            job(&workflow, name)
                .get("timeout-minutes")
                .and_then(Value::as_u64),
            Some(timeout),
            "CI job {name} must retain its bounded timeout"
        );
    }

    for command in [
        "-m ci.pkthere_ci aarch64-musl",
        "-m ci.pkthere_ci alpine-build",
        "-m ci.pkthere_ci alpine-runtime",
        "-m ci.pkthere_ci bootstrap-quality-tools",
        "-m ci.pkthere_ci ci-tool-outputs",
        "-m ci.pkthere_ci quality",
        "-m ci.pkthere_ci msrv",
        "-m ci.pkthere_ci release-stress",
        "-m ci.pkthere_ci miri-boundaries",
    ] {
        assert_eq!(
            active_command_count(&workflow, command),
            1,
            "active workflow must execute {command} exactly once"
        );
    }

    assert_eq!(
        active_job_command_count(&workflow, "test", "-m ci.pkthere_ci platform-ci"),
        1,
        "Linux, macOS, and Windows must share one matrix-owned platform lifecycle"
    );
    assert_eq!(
        active_job_command_count(&workflow, "freebsd", "-m ci.pkthere_ci platform-ci-vm",),
        1,
        "FreeBSD must delegate its VM lifecycle to the same canonical runner"
    );
    for forbidden in [
        "sudo setcap",
        "sudo chown",
        "find target/debug/deps",
        "cargo clean",
        "cache-targets: false",
        "cargo miri test --locked --workspace",
        "net::managed_socket::receive_tests -- --nocapture",
        ".github/scripts/grant_raw_capability.sh",
        "cargo check --locked --workspace",
        "cargo clippy --locked --workspace",
        "cargo fmt --all",
        "cargo test --locked --workspace",
        "git ls-files",
        "python3 -m docker.alpine",
        "cargo miri setup",
        "cargo install cross",
        "sudo apt-get",
    ] {
        assert_eq!(
            active_command_count(&workflow, forbidden),
            0,
            "forbidden/dead workflow command became executable: {forbidden}"
        );
    }

    assert_eq!(
        active_job_command_count(&workflow, "stress-release", "ci.pkthere_ci release-stress",),
        1,
        "workflow must delegate the complete stress profile to one command owner"
    );
    for active_job in jobs(&workflow).values() {
        let has_runner_command = active_steps(active_job).any(|step| {
            step.get("run")
                .and_then(Value::as_str)
                .is_some_and(|command| command.contains("python -m ci.pkthere_ci "))
        });
        if has_runner_command {
            assert!(
                active_steps(active_job).any(|step| {
                    step.get("uses").and_then(Value::as_str) == Some("actions/setup-python@v7")
                }),
                "every canonical Python runner job must install the pinned Python"
            );
        }
    }

    let native = named_step(&workflow, "test", "Run canonical native platform lifecycle");
    let native_command = native
        .get("run")
        .and_then(Value::as_str)
        .expect("native lifecycle command");
    assert!(native_command.contains("--app-bin \"${{ matrix.app_source }}\""));
    assert!(native_command.contains("--privileged-app-bin \"${{ matrix.test_app }}\""));
    let native_matrix = job(&workflow, "test")
        .get("strategy")
        .and_then(|strategy| strategy.get("matrix"))
        .and_then(|matrix| matrix.get("include"))
        .and_then(Value::as_sequence)
        .expect("native CI matrix rows");
    assert!(native_matrix.iter().all(|row| {
        row.get("os").and_then(Value::as_str).is_some()
            && row.get("platform").is_none()
            && row.get("label").is_none()
    }));

    assert!(jobs(&workflow).values().all(|job| {
        !env_contains_key(job, "PKTHERE_ALLOW_RAW_ICMP")
            && steps(job)
                .iter()
                .all(|step| !env_contains_key(step, "PKTHERE_ALLOW_RAW_ICMP"))
    }));

    let uploads: Vec<_> = jobs(&workflow)
        .values()
        .flat_map(active_steps)
        .filter(|step| {
            step.get("uses")
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .collect();
    assert_eq!(uploads.len(), 5);
    assert!(
        uploads
            .iter()
            .all(|step| step.get("if").and_then(Value::as_str) == Some("always()"))
    );

    assert_eq!(
        active_job_command_count(&workflow, "quality", "ci.pkthere_ci quality"),
        1,
        "quality tools and inventories must have one command-plan owner"
    );
    let ping_setup_uses = jobs(&workflow)
        .values()
        .flat_map(active_steps)
        .filter(|step| {
            step.get("uses").and_then(Value::as_str) == Some("./.github/actions/enable_icmp_ping")
        })
        .count();
    assert_eq!(ping_setup_uses, 5);
    assert!(active_steps(job(&workflow, "authority-audit")).any(|step| {
        step.get("uses").and_then(Value::as_str) == Some("./.github/actions/enable_icmp_ping")
    }));
    assert!(
        active_command_count(&workflow, "ping_group_range") == 0,
        "Linux socket setup command must remain owned by its composite action"
    );

    let dockerfile = super::portable_policy::DockerfilePolicy::parse(&read(
        &root.join("docker/alpine/Dockerfile"),
    ));
    assert!(!dockerfile.contains("PKTHERE_ALLOW_RAW_ICMP"));

    assert_freebsd_workflow(&workflow);
}

fn assert_freebsd_workflow(workflow: &Value) {
    let freebsd = job(workflow, "freebsd");
    assert_eq!(
        freebsd.get("timeout-minutes").and_then(Value::as_u64),
        Some(60),
        "FreeBSD native and authority suites require a bounded VM allowance"
    );
    assert_eq!(
        freebsd
            .get("strategy")
            .and_then(|strategy| strategy.get("fail-fast"))
            .and_then(Value::as_bool),
        Some(false)
    );
    let releases = freebsd
        .get("strategy")
        .and_then(|strategy| strategy.get("matrix"))
        .and_then(|matrix| matrix.get("release"))
        .and_then(Value::as_sequence)
        .expect("FreeBSD release matrix")
        .iter()
        .map(|release| release.as_str().expect("quoted FreeBSD release"))
        .collect::<Vec<_>>();
    assert_eq!(releases, ["14.4", "15.1"]);

    let environment = freebsd
        .get("env")
        .and_then(Value::as_mapping)
        .expect("FreeBSD Cargo cache environment");
    for (name, suffix) in [
        ("CARGO_HOME", "cargo-home"),
        ("CARGO_TARGET_DIR", "target"),
        ("PKTHERE_AUTHORITY_TARGET_DIR", "authority-target"),
    ] {
        let value = environment
            .get(Value::from(name))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing FreeBSD cache environment {name}"));
        assert!(value.starts_with(".freebsd-cache/${{ matrix.release }}/"));
        assert!(value.ends_with(suffix));
    }

    let restore = named_step(workflow, "freebsd", "Restore FreeBSD Cargo cache");
    assert_eq!(
        restore.get("uses").and_then(Value::as_str),
        Some("actions/cache/restore@v6")
    );
    let save = named_step(workflow, "freebsd", "Save FreeBSD Cargo cache");
    assert_eq!(
        save.get("uses").and_then(Value::as_str),
        Some("actions/cache/save@v6")
    );
    assert_eq!(
        save.get("if").and_then(Value::as_str),
        Some("always() && steps.freebsd-cargo-cache.outputs.cache-hit != 'true'")
    );
    for cache_step in [restore, save] {
        let cache = cache_step
            .get("with")
            .and_then(Value::as_mapping)
            .expect("FreeBSD Cargo cache configuration");
        assert_eq!(
            cache.get(Value::from("path")).and_then(Value::as_str),
            Some(".freebsd-cache/${{ matrix.release }}")
        );
        let key = cache
            .get(Value::from("key"))
            .and_then(Value::as_str)
            .expect("FreeBSD Cargo cache key");
        assert!(key.contains("freebsd-${{ matrix.release }}-rust-v1-"));
        assert!(key.contains("hashFiles('Cargo.lock')"));
        assert!(key.contains("github.sha"));
    }

    let lifecycle = named_step(
        workflow,
        "freebsd",
        "Run canonical FreeBSD platform lifecycle",
    );
    assert_eq!(
        lifecycle.get("uses").and_then(Value::as_str),
        Some("vmactions/freebsd-vm@v1.5.2")
    );
    let configuration = lifecycle
        .get("with")
        .and_then(Value::as_mapping)
        .expect("FreeBSD VM configuration");
    assert_eq!(
        configuration
            .get(Value::from("sync"))
            .and_then(Value::as_str),
        Some("rsync")
    );
    assert_eq!(
        configuration
            .get(Value::from("copyback"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        configuration
            .get(Value::from("cache-after-prepare"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        configuration
            .get(Value::from("envs"))
            .and_then(Value::as_str),
        Some("CARGO_HOME CARGO_TARGET_DIR PKTHERE_AUTHORITY_TARGET_DIR")
    );
    let prepare = configuration
        .get(Value::from("prepare"))
        .and_then(Value::as_str)
        .expect("FreeBSD package preparation");
    assert_eq!(prepare, "/bin/sh .github/scripts/prepare_freebsd_ci.sh v1");
    let command = configuration
        .get(Value::from("run"))
        .and_then(Value::as_str)
        .expect("FreeBSD canonical runner command");
    assert_eq!(
        active_job_command_count(workflow, "freebsd", "-m ci.pkthere_ci platform-ci-vm",),
        1
    );
    assert!(
        command
            .trim()
            .starts_with("python3.13 -m ci.pkthere_ci platform-ci-vm")
    );
    assert!(command.contains("--result freebsd-${{ matrix.release }}.result.json"));
    for forbidden in [
        "export ",
        "python -c",
        "python3 -c",
        "cargo build",
        "cargo check",
        "cargo clippy",
        "cargo test",
        "cargo clean",
        "PKTHERE_ALLOW_RAW_ICMP",
    ] {
        assert!(
            !command.contains(forbidden),
            "FreeBSD VM duplicated canonical command authority: {forbidden}"
        );
    }

    let uploads = active_steps(freebsd)
        .filter(|step| {
            step.get("uses")
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .collect::<Vec<_>>();
    assert_eq!(uploads.len(), 1);
    assert_eq!(
        uploads[0].get("if").and_then(Value::as_str),
        Some("always()")
    );
    let verification = named_step(
        workflow,
        "freebsd",
        "Verify canonical FreeBSD platform result",
    );
    assert_eq!(
        verification.get("if").and_then(Value::as_str),
        Some("always()")
    );
    let verification_command = verification
        .get("run")
        .and_then(Value::as_str)
        .expect("FreeBSD result verification command");
    assert!(verification_command.contains("-m ci.pkthere_ci platform-ci-result"));
    assert!(verification_command.contains("--result freebsd-${{ matrix.release }}.result.json"));
}
