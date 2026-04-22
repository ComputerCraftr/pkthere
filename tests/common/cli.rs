#[path = "app_bin.rs"]
mod app_bin;
#[path = "child_guard.rs"]
mod child_guard;

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use child_guard::ChildGuard;

pub fn run_cli_args(args: &[&str]) -> (Option<i32>, String) {
    let bin = app_bin::find_app_bin().expect("could not find app binary");
    let child = Command::new(bin)
        .args(args)
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

pub fn run_cli_args_expect_running(args: &[&str], wait: Duration) -> (Option<i32>, String) {
    let bin = app_bin::find_app_bin().expect("could not find app binary");
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");
    let mut child = ChildGuard::new(child);

    thread::sleep(wait);
    let early_exit_code = child
        .try_wait()
        .expect("try_wait failed")
        .map(|status| status.code())
        .unwrap_or(None);

    if early_exit_code.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (early_exit_code, err)
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

pub fn assert_cli_accepts_running(args: &[&str], wait: Duration, forbidden_substrings: &[&str]) {
    let (early_code, err) = run_cli_args_expect_running(args, wait);
    assert_ne!(
        early_code,
        Some(2),
        "expected valid config not to fail CLI parsing; early_code={:?}; stderr: {}",
        early_code,
        err
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
