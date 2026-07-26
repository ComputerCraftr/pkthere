use super::{
    ProcessIcmpLock, acquire_icmp_dgram_session_lock, acquire_raw_icmp_lock, icmp_lock_path,
};
use crate::timing::{RAW_ICMP_LOCK_WAIT, TEST_POLL_INTERVAL};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

static FAIRNESS_TEST_LOCK: ProcessIcmpLock = ProcessIcmpLock::new();

#[test]
fn raw_lock_path_is_scoped_and_lock_is_reacquirable() {
    let path = icmp_lock_path("wire-integration");
    assert!(
        path.file_name()
            .expect("lock filename")
            .to_string_lossy()
            .starts_with("pkthere-raw-icmp-")
    );
    let guard = acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_lock_path_is_scoped_and_lock_is_reacquirable",
    )
    .expect("first RAW lock");
    drop(guard);
    acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_lock_path_is_scoped_and_lock_is_reacquirable",
    )
    .expect("reacquired RAW lock");
}

#[test]
fn raw_and_dgram_tests_share_one_icmp_wire_lock() {
    let raw_guard = acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_and_dgram_tests_share_one_icmp_wire_lock_raw",
    )
    .expect("acquire RAW ICMP wire lock");
    let dgram_error = match acquire_icmp_dgram_session_lock(
        Instant::now() + TEST_POLL_INTERVAL,
        "raw_and_dgram_tests_share_one_icmp_wire_lock_dgram",
    ) {
        Ok(_) => panic!("ICMP DGRAM lock bypassed active RAW wire lock"),
        Err(error) => error,
    };
    assert_eq!(
        dgram_error.path,
        icmp_lock_path("wire-integration"),
        "RAW and DGRAM lock attempts must use the same OS lock file"
    );
    drop(raw_guard);
    acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_and_dgram_tests_share_one_icmp_wire_lock_reacquire",
    )
    .expect("acquire DGRAM lock after RAW guard release");
}

#[test]
fn process_lock_serves_waiters_in_arrival_order() {
    let first = FAIRNESS_TEST_LOCK
        .acquire(Instant::now() + RAW_ICMP_LOCK_WAIT)
        .expect("first process lock");
    let (sender, receiver) = mpsc::channel();

    let sender_b = sender.clone();
    let waiter_b = thread::spawn(move || {
        let _guard = FAIRNESS_TEST_LOCK
            .acquire(Instant::now() + RAW_ICMP_LOCK_WAIT)
            .expect("second process lock");
        sender_b.send('b').expect("report second waiter");
    });
    wait_for_waiter_count(1);

    let waiter_c = thread::spawn(move || {
        let _guard = FAIRNESS_TEST_LOCK
            .acquire(Instant::now() + RAW_ICMP_LOCK_WAIT)
            .expect("third process lock");
        sender.send('c').expect("report third waiter");
    });
    wait_for_waiter_count(2);

    drop(first);
    assert_eq!(
        receiver
            .recv_timeout(RAW_ICMP_LOCK_WAIT)
            .expect("first queued waiter result"),
        'b'
    );
    assert_eq!(
        receiver
            .recv_timeout(RAW_ICMP_LOCK_WAIT)
            .expect("second queued waiter result"),
        'c'
    );
    waiter_b.join().expect("join second waiter");
    waiter_c.join().expect("join third waiter");
}

fn wait_for_waiter_count(expected: usize) {
    let deadline = Instant::now() + RAW_ICMP_LOCK_WAIT;
    while FAIRNESS_TEST_LOCK.waiting_count() < expected {
        assert!(
            Instant::now() < deadline,
            "process lock did not enqueue {expected} waiter(s)"
        );
        thread::sleep(TEST_POLL_INTERVAL);
    }
}
