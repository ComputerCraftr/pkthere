use crate::app_bin;
use crate::managed_child::{
    CapturedOutput, ChildIdentity, ChildLimits, CompletedChild, ManagedChild,
};
use crate::test_paths;
use crate::timing::{
    CAPTURE_DRAIN_WAIT, CHILD_CLEANUP_WAIT, CLI_COMPLETION_WAIT, TEST_POLL_INTERVAL,
};
use crate::user_policy;

use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub use pkthere_socket_policy::TimeoutAction;
pub use pkthere_wire::SupportedProtocol;

#[derive(Clone, Debug)]
pub enum RunningObservation {
    Running(CapturedOutput),
    Exited(CompletedChild),
}

pub fn app_bin_path() -> PathBuf {
    app_bin::find_app_bin().expect("could not find app binary")
}

fn spawn_cli(args: &[&str], context: &str) -> ManagedChild {
    let binary = app_bin_path();
    let mut command = Command::new(&binary);
    command.args(args);
    user_policy::apply_root_user_args(&mut command);
    ManagedChild::spawn(
        &mut command,
        ChildIdentity::new(context),
        ChildLimits::default(),
    )
    .unwrap_or_else(|error| panic!("spawn {context}: {error}"))
}

fn run_cli_completed(args: &[&str]) -> CompletedChild {
    spawn_cli(args, "CLI command")
        .wait_until(Instant::now() + CLI_COMPLETION_WAIT)
        .unwrap_or_else(|error| panic!("CLI command did not complete: {error}"))
}

pub fn run_cli_args(args: &[&str]) -> (Option<i32>, String) {
    let completed = run_cli_completed(args);
    (completed.exit.code, completed.output.stderr_lossy())
}

pub fn run_cli_args_with_stdout(args: &[&str]) -> (Option<i32>, String, String) {
    let completed = run_cli_completed(args);
    (
        completed.exit.code,
        completed.output.stdout_lossy(),
        completed.output.stderr_lossy(),
    )
}

pub fn run_cli_args_expect_running_with_stdout(
    args: &[&str],
    wait: Duration,
) -> RunningObservation {
    let mut child = spawn_cli(args, "CLI running observation");
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        match child.try_status() {
            Ok(Some(_)) => {
                let completed = child
                    .wait_until(Instant::now() + CAPTURE_DRAIN_WAIT)
                    .expect("collect output from early CLI exit");
                return RunningObservation::Exited(completed);
            }
            Ok(None) => thread::sleep(
                TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(error) => panic!("observe CLI command: {error}"),
        }
    }

    let observed = child.output_snapshot();
    let cleanup_deadline = Instant::now() + CHILD_CLEANUP_WAIT;
    child
        .terminate_and_reap(cleanup_deadline)
        .unwrap_or_else(|error| panic!("clean up observed CLI command: {error}"));
    RunningObservation::Running(observed)
}

pub fn render_app_bin_path() -> String {
    test_paths::render_test_path(&app_bin_path())
}

pub fn assert_cli_rejects(args: &[&str], expected_substrings: &[&str]) {
    let (code, error_output) = run_cli_args(args);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {code:?}; stderr: {error_output}"
    );

    let error_lowercase = error_output.to_lowercase();
    for expected in expected_substrings {
        assert!(
            error_lowercase.contains(&expected.to_lowercase()),
            "stderr missing {expected:?}: {error_output}"
        );
    }
}

pub fn assert_cli_runs(args: &[&str], wait: Duration, forbidden_substrings: &[&str]) {
    let output = match run_cli_args_expect_running_with_stdout(args, wait) {
        RunningObservation::Running(output) => output,
        RunningObservation::Exited(completed) => panic!(
            "expected valid config to still be running after {wait:?}; exit={}; stderr: {}",
            completed.exit,
            completed.output.stderr_lossy()
        ),
    };
    let error_output = output.stderr_lossy();
    let error_lowercase = error_output.to_lowercase();
    for forbidden in forbidden_substrings {
        assert!(
            !error_lowercase.contains(&forbidden.to_lowercase()),
            "unexpected CLI parse/usage error containing {forbidden:?}: {error_output}"
        );
    }
}
