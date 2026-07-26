use super::{BufferedPayload, FlowRuntimeState, SyncSendCompletion};
use crate::cli::SupportedProtocol;
use crate::net::payload::PayloadEvent;
use std::sync::{Arc, Barrier};
use std::thread;

fn payload(bytes: &'static [u8]) -> BufferedPayload {
    BufferedPayload::from_event(
        &PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes),
        None,
    )
}

#[test]
fn replacement_and_send_lease_share_one_flow_authority() {
    let state = FlowRuntimeState::new();
    assert!(state.replace_sync_payload(payload(b"first")).is_none());
    let mut lease = state.lease_sync_send().expect("lease").expect("available");
    assert_eq!(
        lease.payload.as_ref().map(BufferedPayload::payload_len),
        Some(5)
    );
    assert!(state.replace_sync_payload(payload(b"second")).is_none());
    assert!(state.lease_sync_send().expect("second lease").is_none());
    assert_eq!(
        state
            .complete_sync_send(lease, false)
            .expect("complete failed send"),
        SyncSendCompletion::Superseded
    );
    lease = state
        .lease_sync_send()
        .expect("lease replacement")
        .expect("replacement available");
    assert_eq!(
        lease.payload.as_ref().map(BufferedPayload::payload_len),
        Some(6)
    );
    lease.payload = None;
    assert_eq!(
        state
            .complete_sync_send(lease, true)
            .expect("complete replacement"),
        SyncSendCompletion::Completed
    );
}

#[test]
fn failed_sync_retry_moves_one_owned_payload_without_copying_its_bytes_again() {
    let state = FlowRuntimeState::new();
    let (owned, initial_copies) =
        crate::allocation_test_support::count_payload_copies(|| payload(b"retry-owned"));
    assert_eq!(initial_copies, 1);
    let (_, store_copies) =
        crate::allocation_test_support::count_payload_copies(|| state.replace_sync_payload(owned));
    assert_eq!(store_copies, 0);

    let (lease, first_lease_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state.lease_sync_send().expect("lease").expect("payload")
    });
    assert_eq!(first_lease_copies, 0);
    let (_, completion_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .complete_sync_send(lease, false)
            .expect("restore failed send")
    });
    assert_eq!(completion_copies, 0);
    let (retry, retry_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .lease_sync_send()
            .expect("retry lease")
            .expect("retry payload")
    });
    assert_eq!(retry_copies, 0);
    assert_eq!(
        retry.payload.as_ref().map(BufferedPayload::payload_len),
        Some(11)
    );
}

#[test]
fn reset_during_sync_send_prevents_failed_payload_restoration() {
    let state = FlowRuntimeState::new();
    assert!(state.replace_sync_payload(payload(b"owned")).is_none());
    let lease = state.lease_sync_send().expect("lease").expect("available");
    state.reset();
    assert_eq!(
        state
            .complete_sync_send(lease, false)
            .expect("reset completion"),
        SyncSendCompletion::ResetWon
    );
    let next = state
        .lease_sync_send()
        .expect("post-reset lease")
        .expect("cadence lease");
    assert!(next.payload.is_none());
}

#[test]
fn shared_flow_workers_cannot_lease_or_restore_the_same_sync_payload_twice() {
    let state = Arc::new(FlowRuntimeState::new());
    assert!(state.replace_sync_payload(payload(b"first")).is_none());
    let leased = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker_state = Arc::clone(&state);
    let worker_leased = Arc::clone(&leased);
    let worker_release = Arc::clone(&release);
    let worker = thread::spawn(move || {
        let lease = worker_state
            .lease_sync_send()
            .expect("worker lease")
            .expect("payload available");
        worker_leased.wait();
        worker_release.wait();
        worker_state
            .complete_sync_send(lease, false)
            .expect("worker completion")
    });

    leased.wait();
    assert!(state.lease_sync_send().expect("competing lease").is_none());
    assert!(state.replace_sync_payload(payload(b"newer")).is_none());
    release.wait();
    assert_eq!(
        worker.join().expect("worker join"),
        SyncSendCompletion::Superseded
    );
    let lease = state
        .lease_sync_send()
        .expect("replacement lease")
        .expect("replacement available");
    assert_eq!(
        lease.payload.as_ref().map(BufferedPayload::payload_len),
        Some(5)
    );
}
