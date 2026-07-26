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
fn line_cursor_retains_a_second_record_captured_in_the_same_batch() {
    let mut child = spawn_helper("two-json-records");
    let mut cursor = OutputCursor::default();
    for expected in [1, 2] {
        let sequence = child
            .wait_for_json_record(
                &mut cursor,
                Instant::now() + MAX_WAIT_SECS,
                "ordered JSON readiness record",
                |record| record["sequence"].as_u64(),
            )
            .expect("matching ordered JSON record");
        assert_eq!(sequence, expected);
    }
    child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate two-record helper");
}

#[test]
fn stderr_cursor_retains_ordered_records_without_rescanning_output() {
    let mut child = spawn_helper("two-json-records");
    let mut cursor = child.stderr_cursor();
    for expected in [1, 2] {
        let sequence = child
            .wait_for_json_record(
                &mut cursor,
                Instant::now() + MAX_WAIT_SECS,
                "ordered stderr JSON record",
                |record| record["sequence"].as_u64(),
            )
            .expect("matching ordered stderr JSON record");
        assert_eq!(sequence, expected);
    }
    child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate stderr two-record helper");
}

#[test]
fn one_shot_output_snapshot_returns_without_waiting_for_a_second_change() {
    let mut child = spawn_helper("json-record");
    let started = Instant::now();
    let output = child
        .wait_for_output_snapshot(
            Instant::now() + MAX_WAIT_SECS,
            "one-shot output",
            |snapshot| snapshot.stdout_lossy().contains("\"ready\":true"),
        )
        .expect("observe one-shot output");
    assert!(output.stdout_lossy().contains("\"sequence\":7"));
    assert!(started.elapsed() < MAX_WAIT_SECS);
    child
        .terminate_and_reap(Instant::now() + CHILD_CLEANUP_WAIT)
        .expect("terminate one-shot output helper");
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

    wait_for_process_termination(descendant);
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
    wait_for_process_termination(escaped);
}

#[cfg(unix)]
#[test]
fn zero_deadline_cleanup_remains_bounded_and_process_is_reaped() {
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
    match result {
        Ok(_) => {}
        Err(error)
            if matches!(
                error,
                ChildHarnessError::TerminationFailed { .. }
                    | ChildHarnessError::CaptureIncomplete { .. }
            ) =>
        {
            assert!(
                error
                    .output()
                    .is_some_and(|output| output.stdout_lossy().contains(&format!("pid={pid}"))),
                "zero-deadline cleanup must preserve the readiness diagnostic: {error:?}"
            );
        }
        Err(error) => panic!("unexpected zero-deadline cleanup result: {error:?}"),
    }
    wait_for_process_termination(pid);
}

#[cfg(unix)]
fn wait_for_process_termination(pid: i32) {
    let deadline = Instant::now() + MAX_WAIT_SECS;
    loop {
        if !process_is_running(pid) {
            return;
        }
        assert!(Instant::now() < deadline, "process {pid} remained alive");
        std::thread::sleep(TEST_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: i32) -> bool {
    let stat_path = format!("/proc/{pid}/stat");
    match std::fs::read_to_string(&stat_path) {
        Ok(stat) => {
            let state = stat
                .rsplit_once(") ")
                .and_then(|(_, suffix)| suffix.chars().next())
                .unwrap_or_else(|| panic!("malformed process status in {stat_path}"));
            // A container without an init process can retain an orphaned
            // descendant as a zombie. It owns no descriptors and executes no
            // code, so process-tree termination has completed even though PID
            // namespace reaping remains PID 1's responsibility.
            !matches!(state, 'Z' | 'X')
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("read {stat_path}: {error}"),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_running(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}
