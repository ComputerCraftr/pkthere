use pkthere_test_support::managed_child::{
    ChildHarnessError, ChildIdentity, ChildLimits, ManagedChild, OutputCursor,
};
use pkthere_test_support::raw_icmp::acquire_raw_icmp_lock;
use pkthere_test_support::timing::{
    CHILD_CLEANUP_WAIT, MAX_WAIT_SECS, TEST_POLL_INTERVAL, TEST_RETRY_INTERVAL,
};

use std::process::Command;
use std::time::Instant;

fn spawn_helper(mode: &str) -> ManagedChild {
    spawn_helper_with_limits(mode, ChildLimits::default())
}

fn spawn_helper_with_limits(mode: &str, limits: ChildLimits) -> ManagedChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_harness-child"));
    command.arg(mode);
    ManagedChild::spawn(
        &mut command,
        ChildIdentity::new(format!("harness child {mode}")),
        limits,
    )
    .expect("spawn harness child")
}

#[test]
fn delayed_exit_is_reaped_with_its_final_output() {
    let completed = spawn_helper("delayed-exit")
        .wait_until(Instant::now() + MAX_WAIT_SECS)
        .expect("delayed child completion");
    assert!(completed.exit.success);
    assert!(completed.output.stdout_lossy().contains("delayed-final"));
}

#[test]
fn first_matching_json_record_returns_without_waiting_for_process_exit() {
    let mut child = spawn_helper("json-record");
    let mut cursor = OutputCursor::default();
    let started = Instant::now();
    let sequence = child
        .wait_for_json_record(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "JSON readiness record",
            |record| {
                record["ready"]
                    .as_bool()?
                    .then_some(record["sequence"].as_u64()?)
            },
        )
        .expect("matching JSON record");
    assert_eq!(sequence, 7);
    assert!(started.elapsed() < MAX_WAIT_SECS);
    child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate JSON helper");
}

#[test]
fn line_wait_honors_the_original_deadline() {
    let mut child = spawn_helper("sleep");
    let mut cursor = child.output_cursor_at_end();
    let started = Instant::now();
    let error = child
        .wait_for_line(
            &mut cursor,
            Instant::now() + TEST_RETRY_INTERVAL,
            "line that never appears",
            |line| (line == "never").then_some(()),
        )
        .expect_err("missing line must time out");
    assert!(matches!(error, ChildHarnessError::DeadlineExpired { .. }));
    assert!(started.elapsed() < MAX_WAIT_SECS);
    child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate deadline helper");
}

#[test]
fn explicit_error_exit_is_completed_not_running() {
    let completed = spawn_helper("exit-error")
        .wait_until(Instant::now() + MAX_WAIT_SECS)
        .expect("error child completion");
    assert!(!completed.exit.success);
    assert_eq!(completed.exit.code, Some(23));
}

#[test]
fn pipe_saturation_drains_both_streams_before_waiting() {
    const EXPECTED_BYTES: usize = 256 * 1024;
    let completed = spawn_helper("pipe-flood")
        .wait_until(Instant::now() + MAX_WAIT_SECS)
        .expect("pipe flood completion");
    assert!(completed.exit.success);
    assert_eq!(completed.output.stdout.len(), EXPECTED_BYTES);
    assert_eq!(completed.output.stderr.len(), EXPECTED_BYTES);
}

#[cfg(unix)]
#[test]
fn final_output_written_during_termination_is_retained() {
    let mut child = spawn_helper("final-line-on-term");
    let mut cursor = OutputCursor::default();
    child
        .wait_for_line(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "helper readiness",
            |line| line.contains("ready").then_some(()),
        )
        .expect("helper ready");
    let completed = child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate helper");
    assert!(
        completed
            .output
            .stderr_lossy()
            .contains("final-line-during-termination")
    );
}

#[test]
fn raw_lock_wait_is_bounded_and_reports_holder() {
    let mut holder = spawn_helper("hold-raw-lock");
    let mut cursor = OutputCursor::default();
    holder
        .wait_for_line(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "RAW lock holder readiness",
            |line| line.contains("lock-ready").then_some(()),
        )
        .expect("lock holder ready");
    let error = match acquire_raw_icmp_lock(
        Instant::now() + TEST_POLL_INTERVAL,
        "raw_lock_wait_is_bounded_and_reports_holder",
    ) {
        Ok(_) => panic!("second RAW lock unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(
        error
            .holder
            .as_deref()
            .is_some_and(|holder| holder.contains("harness_child_lock_holder"))
    );
    holder
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate lock holder");
    acquire_raw_icmp_lock(
        Instant::now() + MAX_WAIT_SECS,
        "raw_lock_wait_is_bounded_and_reports_holder",
    )
    .expect("lock succeeds after holder exits");
}

#[cfg(unix)]
#[test]
fn process_group_termination_removes_descendants() {
    let mut parent = spawn_helper("spawn-descendant");
    let mut cursor = OutputCursor::default();
    let descendant = parent
        .wait_for_line(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "descendant pid",
            |line| line.trim().strip_prefix("descendant=")?.parse::<i32>().ok(),
        )
        .expect("descendant pid");
    parent
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate process group");

    wait_for_process_absence(descendant);
}

#[cfg(unix)]
#[test]
fn capture_timeout_preserves_partial_output_from_a_pipe_holding_descendant() {
    let mut parent = spawn_helper("spawn-escaped-pipe");
    let mut cursor = OutputCursor::default();
    let escaped = parent
        .wait_for_line(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "escaped descendant pid",
            |line| line.trim().strip_prefix("escaped=")?.parse::<i32>().ok(),
        )
        .expect("escaped descendant pid");
    let error = parent
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect_err("escaped descendant must keep capture incomplete");
    let output = error.output().expect("capture timeout output");
    assert!(output.stdout_lossy().contains("escaped="));
    wait_for_process_absence(escaped);
}

#[cfg(unix)]
#[test]
fn forced_deadline_transfers_child_until_background_reaper_collects_it() {
    let limits = ChildLimits {
        termination_grace: std::time::Duration::ZERO,
        forced_reap_wait: std::time::Duration::ZERO,
        ..ChildLimits::default()
    };
    let mut child = spawn_helper_with_limits("ignore-term", limits);
    let mut cursor = OutputCursor::default();
    let pid = child
        .wait_for_line(
            &mut cursor,
            Instant::now() + MAX_WAIT_SECS,
            "ignored-termination pid",
            |line| line.trim().strip_prefix("pid=")?.parse::<i32>().ok(),
        )
        .expect("ignored-termination pid");
    let result = child.terminate_and_reap(Instant::now());
    if let Err(error) = result {
        assert!(matches!(error, ChildHarnessError::TerminationFailed { .. }));
    }
    wait_for_process_absence(pid);
}

#[cfg(unix)]
fn wait_for_process_absence(pid: i32) {
    let deadline = Instant::now() + MAX_WAIT_SECS;
    loop {
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        assert!(Instant::now() < deadline, "process {pid} was not reaped");
        std::thread::sleep(TEST_POLL_INTERVAL);
    }
}
