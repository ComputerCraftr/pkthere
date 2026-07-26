#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::recovery_core::{
    RecoveryRecognitionDecision, RecoverySendCore, RecoverySendLease, RecoveryTimeoutDecision,
};
use super::{RecoveryPayloadSendToken, SessionId};
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::time::{Duration, Instant};

fn token() -> RecoveryPayloadSendToken {
    RecoveryPayloadSendToken {
        session: SessionId::new(7).expect("session"),
        attempt: 1,
    }
}

fn sending_core() -> (RecoverySendCore<u8>, RecoverySendLease<u8>) {
    let now = Instant::now();
    let mut core = RecoverySendCore::new(41);
    core.record_initial_send_result(false, now)
        .expect("schedule retry");
    let lease = core
        .lease_due(token().session, now)
        .expect("lease ownership")
        .expect("due lease");
    assert_eq!(lease.token, token());
    core.prepare_sequence(&token(), 9).expect("prepare");
    (core, lease)
}

#[test]
fn production_recovery_core_timeout_and_completion_have_one_terminal_owner() {
    loom::model(|| {
        let (initial, lease) = sending_core();
        let core = Arc::new(Mutex::new(initial));
        let timeout_core = Arc::clone(&core);
        let timeout =
            thread::spawn(move || timeout_core.lock().expect("timeout lock").request_timeout());
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_send(
                    lease,
                    true,
                    Some((2, Instant::now() + Duration::from_millis(1))),
                )
        });
        let timeout_decision = timeout.join().expect("timeout actor");
        let completion = completion.join().expect("completion actor");
        match (timeout_decision, completion) {
            (RecoveryTimeoutDecision::AwaitCompletion, Ok(decision)) => {
                assert!(decision.timeout_requested);
                assert!(decision.remove);
            }
            (RecoveryTimeoutDecision::Remove, Ok(decision)) => assert!(!decision.remove),
            (RecoveryTimeoutDecision::Remove, Err(_)) => {}
            (RecoveryTimeoutDecision::AwaitCompletion, Err(_)) => {
                panic!("in-flight timeout must retain completion ownership")
            }
        }
        assert!(core.lock().expect("terminal lock").is_terminal());
    });
}

#[test]
fn production_recovery_core_recognition_and_send_completion_do_not_lose_ownership() {
    loom::model(|| {
        let (initial, lease) = sending_core();
        let core = Arc::new(Mutex::new(initial));
        let recognition_core = Arc::clone(&core);
        let recognition = thread::spawn(move || {
            recognition_core
                .lock()
                .expect("recognition lock")
                .observe_recognition()
        });
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_send(
                    lease,
                    true,
                    Some((2, Instant::now() + Duration::from_millis(1))),
                )
        });
        let recognition = recognition.join().expect("recognition actor");
        let completion = completion.join().expect("completion actor");
        match (recognition, completion) {
            (Ok(RecoveryRecognitionDecision::Retain), Ok(decision)) => assert!(decision.remove),
            (Ok(RecoveryRecognitionDecision::Remove), Ok(decision)) => {
                assert!(!decision.remove)
            }
            (Err(_), Ok(decision)) => assert!(decision.remove),
            (Ok(RecoveryRecognitionDecision::Remove), Err(_)) => {}
            other => panic!("invalid recognition/completion ownership: {other:?}"),
        }
        assert!(core.lock().expect("terminal lock").is_terminal());
    });
}

#[test]
fn production_recovery_core_deferred_reset_is_returned_exactly_once() {
    loom::model(|| {
        let (initial, lease) = sending_core();
        let core = Arc::new(Mutex::new(initial));
        let reset = crate::net::framing_shim::ResetRequired::new(
            token().session,
            9,
            None,
            std::num::NonZeroU64::new(3).expect("challenge"),
        );
        let reset_core = Arc::clone(&core);
        let defer =
            thread::spawn(move || reset_core.lock().expect("reset lock").defer_reset(reset));
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_send(
                    lease,
                    false,
                    Some((2, Instant::now() + Duration::from_millis(1))),
                )
        });
        let deferred = defer.join().expect("reset actor");
        let completion = completion.join().expect("completion actor");
        if deferred {
            assert_eq!(completion.expect("completion").pending_reset, Some(reset));
        } else if let Ok(decision) = completion {
            assert_eq!(decision.pending_reset, None);
        }
    });
}
