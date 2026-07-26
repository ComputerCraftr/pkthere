#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::super::MAX_HANDSHAKE_RETRY_ATTEMPTS;
use super::super::session_lifecycles::ControlSendCore;
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::time::{Duration, Instant};

#[test]
fn production_control_send_core_keeps_ack_evidence_during_success_completion() {
    loom::model(|| {
        let now = Instant::now();
        let mut initial = ControlSendCore::new(now, now + Duration::from_secs(4));
        let attempt = initial
            .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)
            .expect("lease state")
            .expect("due lease");
        initial.record_sequence(&attempt, 17).expect("sequence");
        let core = Arc::new(Mutex::new(initial));

        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_sequence(attempt, 17, true, now + Duration::from_secs(1))
        });
        let observation_core = Arc::clone(&core);
        let observation = thread::spawn(move || {
            observation_core
                .lock()
                .expect("observation lock")
                .acknowledges(17)
        });

        assert!(
            completion
                .join()
                .expect("completion actor")
                .expect("completion")
        );
        assert!(observation.join().expect("observation actor"));
        let final_state = core.lock().expect("final lock");
        assert!(final_state.was_sent(17));
        assert!(!final_state.in_flight());
    });
}

#[test]
fn production_control_send_core_failure_and_retry_retain_one_lease_owner() {
    loom::model(|| {
        let now = Instant::now();
        let retry_at = now + Duration::from_secs(1);
        let mut initial = ControlSendCore::new(now, now + Duration::from_secs(4));
        let attempt = initial
            .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)
            .expect("lease state")
            .expect("due lease");
        initial.record_sequence(&attempt, 19).expect("sequence");
        let core = Arc::new(Mutex::new(initial));

        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_sequence(attempt, 19, false, retry_at)
        });
        let retry_core = Arc::clone(&core);
        let retry = thread::spawn(move || {
            retry_core
                .lock()
                .expect("retry lock")
                .lease_due(retry_at, MAX_HANDSHAKE_RETRY_ATTEMPTS)
        });

        assert!(
            completion
                .join()
                .expect("completion actor")
                .expect("completion")
        );
        let retry = retry.join().expect("retry actor").expect("retry state");
        let final_state = core.lock().expect("final lock");
        assert!(!final_state.was_sent(19));
        if retry.is_some() {
            assert!(final_state.in_flight());
        } else {
            assert!(!final_state.in_flight());
        }
    });
}

#[test]
fn production_control_send_core_restart_cannot_clear_an_owned_send() {
    loom::model(|| {
        let now = Instant::now();
        let mut initial = ControlSendCore::new(now, now + Duration::from_secs(4));
        let attempt = initial
            .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)
            .expect("lease state")
            .expect("due lease");
        initial.record_sequence(&attempt, 23).expect("sequence");
        let core = Arc::new(Mutex::new(initial));

        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete_sequence(attempt, 23, true, now + Duration::from_secs(1))
        });
        let restart_core = Arc::clone(&core);
        let restart = thread::spawn(move || {
            restart_core
                .lock()
                .expect("restart lock")
                .restart(now + Duration::from_secs(2))
        });

        assert!(
            completion
                .join()
                .expect("completion actor")
                .expect("completion")
        );
        let restart = restart.join().expect("restart actor");
        let final_state = core.lock().expect("final lock");
        assert!(final_state.was_sent(23));
        assert!(!final_state.in_flight());
        if restart.is_err() {
            assert!(final_state.next_attempt() >= now + Duration::from_secs(1));
        }
    });
}

#[test]
fn production_control_send_core_unsequenced_release_consumes_its_attempt() {
    loom::model(|| {
        let now = Instant::now();
        let retry_at = now + Duration::from_secs(1);
        let mut core = ControlSendCore::new(now, now + Duration::from_secs(4));
        let attempt = core
            .lease_due(now, MAX_HANDSHAKE_RETRY_ATTEMPTS)
            .expect("lease state")
            .expect("due lease");
        core.release_unsequenced(attempt, retry_at)
            .expect("release exact attempt");
        assert!(!core.in_flight());
        assert_eq!(core.next_attempt(), retry_at);
    });
}
