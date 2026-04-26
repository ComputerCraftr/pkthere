#[path = "app_bin.rs"]
mod app_bin;
#[path = "child_guard.rs"]
mod child_guard;
#[path = "path_policy.rs"]
mod path_policy;
#[path = "user_policy.rs"]
mod user_policy;

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use child_guard::ChildGuard;

pub fn app_bin_path() -> PathBuf {
    app_bin::find_app_bin().expect("could not find app binary")
}

pub fn run_cli_args(args: &[&str]) -> (Option<i32>, String) {
    let bin = app_bin_path();
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    user_policy::apply_root_user_args(&mut cmd);

    let child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");
    let mut child = ChildGuard::new(child);

    let status = child.wait().expect("wait failed");
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code(), err)
}

pub fn run_cli_args_with_stdout(args: &[&str]) -> (Option<i32>, String, String) {
    let bin = app_bin_path();
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    user_policy::apply_root_user_args(&mut cmd);

    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");
    let mut child = ChildGuard::new(child);

    let status = child.wait().expect("wait failed");
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code(), out, err)
}

pub fn run_cli_args_expect_running_with_stdout(
    args: &[&str],
    wait: Duration,
) -> (Option<i32>, String, String) {
    let bin = app_bin_path();
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    user_policy::apply_root_user_args(&mut cmd);

    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");
    let mut child = ChildGuard::new(child);

    let deadline = std::time::Instant::now() + wait;
    let early_exit_code = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status.code();
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };

    if early_exit_code.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (early_exit_code, out, err)
}

pub fn render_app_bin_path() -> String {
    path_policy::render_test_path(&app_bin_path())
}

pub fn assert_cli_rejects(args: &[&str], expected_substrings: &[&str]) {
    let (code, err) = run_cli_args(args);
    assert_eq!(
        code,
        Some(2),
        "expected exit code 2, got {:?}; stderr: {}",
        code,
        err
    );

    let err_lower = err.to_lowercase();
    for expected in expected_substrings {
        assert!(
            err_lower.contains(&expected.to_lowercase()),
            "stderr missing {:?}: {}",
            expected,
            err
        );
    }
}

pub fn assert_cli_runs(args: &[&str], wait: Duration, forbidden_substrings: &[&str]) {
    let (early_code, _out, err) = run_cli_args_expect_running_with_stdout(args, wait);
    assert_eq!(
        early_code, None,
        "expected valid config to still be running after {:?}; early_code={:?}; stderr: {}",
        wait, early_code, err
    );

    let err_lower = err.to_lowercase();
    for forbidden in forbidden_substrings {
        assert!(
            !err_lower.contains(&forbidden.to_lowercase()),
            "unexpected CLI parse/usage error containing {:?}: {}",
            forbidden,
            err
        );
    }
}
