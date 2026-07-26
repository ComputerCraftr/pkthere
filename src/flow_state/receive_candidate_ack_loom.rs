#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::session_lifecycles::{ReceiveCandidateAckCore, ReceiveCandidateAckTransaction};
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::time::{Duration, Instant};

struct CandidateModel {
    core: ReceiveCandidateAckCore,
    next_installation_order: u64,
}

#[test]
fn production_candidate_core_concurrent_success_and_failure_have_one_ready_state() {
    loom::model(|| {
        let now = Instant::now();
        let model = Arc::new(Mutex::new(CandidateModel {
            core: ReceiveCandidateAckCore::new(now + Duration::from_secs(1)),
            next_installation_order: 7,
        }));
        let mut model_guard = model.lock().expect("initial lock");
        let CandidateModel {
            core,
            next_installation_order,
        } = &mut *model_guard;
        let first = ReceiveCandidateAckTransaction::new(core, next_installation_order)
            .begin_send(now)
            .expect("first lease")
            .expect("first order");
        let second = ReceiveCandidateAckTransaction::new(core, next_installation_order)
            .begin_send(now)
            .expect("second lease")
            .expect("second order");
        assert_eq!(first.installation_order(), second.installation_order());
        drop(model_guard);

        let success_model = Arc::clone(&model);
        let success = thread::spawn(move || {
            success_model
                .lock()
                .expect("success lock")
                .core
                .complete_send(first, true)
        });
        let failure_model = Arc::clone(&model);
        let failure = thread::spawn(move || {
            failure_model
                .lock()
                .expect("failure lock")
                .core
                .complete_send(second, false)
        });

        success.join().expect("success actor").expect("success");
        failure.join().expect("failure actor").expect("failure");
        let final_state = model.lock().expect("final lock");
        assert_eq!(final_state.core.ready_installation_order(), Some(7));
        assert_eq!(final_state.next_installation_order, 8);
    });
}

#[test]
fn production_candidate_core_all_failed_leases_return_to_negotiating() {
    loom::model(|| {
        let now = Instant::now();
        let model = Arc::new(Mutex::new(CandidateModel {
            core: ReceiveCandidateAckCore::new(now + Duration::from_secs(1)),
            next_installation_order: 11,
        }));
        let mut model_guard = model.lock().expect("initial lock");
        let CandidateModel {
            core,
            next_installation_order,
        } = &mut *model_guard;
        let first = ReceiveCandidateAckTransaction::new(core, next_installation_order)
            .begin_send(now)
            .expect("first lease")
            .expect("first order");
        let second = ReceiveCandidateAckTransaction::new(core, next_installation_order)
            .begin_send(now)
            .expect("second lease")
            .expect("second order");
        drop(model_guard);

        let first_model = Arc::clone(&model);
        let first_failure = thread::spawn(move || {
            first_model
                .lock()
                .expect("first failure lock")
                .core
                .complete_send(first, false)
        });
        let second_model = Arc::clone(&model);
        let second_failure = thread::spawn(move || {
            second_model
                .lock()
                .expect("second failure lock")
                .core
                .complete_send(second, false)
        });

        first_failure
            .join()
            .expect("first actor")
            .expect("first failure");
        second_failure
            .join()
            .expect("second actor")
            .expect("second failure");
        let final_state = model.lock().expect("final lock");
        assert!(final_state.core.is_negotiating());
        assert_eq!(final_state.core.ready_installation_order(), None);
    });
}

#[test]
fn production_candidate_core_rejects_expired_and_stale_send_authority() {
    loom::model(|| {
        let now = Instant::now();
        let mut core = ReceiveCandidateAckCore::new(now);
        let mut next_installation_order = 13;
        assert!(
            ReceiveCandidateAckTransaction::new(&mut core, &mut next_installation_order)
                .begin_send(now)
                .is_err()
        );
        assert_eq!(next_installation_order, 13);
        let mut foreign = ReceiveCandidateAckCore::new(now + Duration::from_secs(1));
        let foreign_permit =
            ReceiveCandidateAckTransaction::new(&mut foreign, &mut next_installation_order)
                .begin_send(now)
                .expect("foreign candidate is live")
                .expect("foreign candidate issues a permit");
        assert!(core.complete_send(foreign_permit, true).is_err());
        assert!(core.is_expired(now));
        assert!(core.is_negotiating());
    });
}
