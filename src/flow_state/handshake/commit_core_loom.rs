#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::commit_core::{
    HandshakeCommitCore, HandshakeCommitPhase, HandshakeRollbackDecision, HandshakeSendDecision,
    HandshakeSessionPublication,
};
use loom::sync::{Arc, Mutex, mpsc};
use loom::thread;

struct LoomSessionPublication(Option<u64>);

impl HandshakeSessionPublication for LoomSessionPublication {
    type Output = u64;

    fn publish_session(&mut self, instance: u64) {
        assert!(self.0.replace(instance).is_none());
    }

    fn finish(self) -> Self::Output {
        self.0.expect("session publication")
    }
}

fn publish_session<Payload>(
    core: &mut HandshakeCommitCore<Payload>,
    receipt: super::commit_core::HandshakeManagerReceipt,
) -> super::commit_core::HandshakeActivationLease {
    let (activation, published) = core
        .commit_session(receipt, LoomSessionPublication(None))
        .expect("session commit");
    assert_eq!(published, core.token());
    activation
}

#[test]
fn production_handshake_core_timeout_and_commit_have_one_payload_disposition() {
    loom::model(|| {
        let mut initial = HandshakeCommitCore::new(7, 41_u8);
        let receipt = initial.manager_published(7).expect("manager publication");
        let activation = publish_session(&mut initial, receipt);
        let core = Arc::new(Mutex::new(initial));
        let timeout_core = Arc::clone(&core);
        let timeout =
            thread::spawn(move || timeout_core.lock().expect("timeout lock").request_timeout());
        let commit_core = Arc::clone(&core);
        let commit = thread::spawn(move || {
            commit_core
                .lock()
                .expect("commit lock")
                .begin_send(activation)
        });
        timeout.join().expect("timeout actor");
        let lease = commit.join().expect("commit actor").expect("commit");
        assert_eq!(*lease.payload(), 41);

        let decision = core
            .lock()
            .expect("completion lock")
            .complete_success(lease)
            .expect("complete send");
        assert_eq!(decision, HandshakeSendDecision::Cancelled);
        assert_eq!(
            core.lock().expect("phase lock").phase(),
            HandshakeCommitPhase::Terminal
        );
    });
}

#[test]
fn production_handshake_core_reset_and_manager_rollback_cannot_restore_retry() {
    loom::model(|| {
        let core = Arc::new(Mutex::new(HandshakeCommitCore::new(9, 43_u8)));
        let (reset_published, await_reset) = mpsc::channel();
        let reset_core = Arc::clone(&core);
        let reset = thread::spawn(move || {
            reset_core.lock().expect("reset lock").request_reset();
            reset_published.send(()).expect("publish reset boundary");
        });
        let rollback_core = Arc::clone(&core);
        let rollback = thread::spawn(move || {
            await_reset.recv().expect("reset publication");
            rollback_core
                .lock()
                .expect("rollback lock")
                .rollback(9, false)
        });
        reset.join().expect("reset actor");
        let decision = rollback.join().expect("rollback actor").expect("rollback");
        assert_eq!(decision, HandshakeRollbackDecision::ResetApplied(43));
        assert_eq!(
            core.lock().expect("phase lock").phase(),
            HandshakeCommitPhase::Terminal
        );
    });
}

#[test]
fn production_handshake_core_rejects_stale_and_duplicate_completion_tokens() {
    loom::model(|| {
        let mut core = HandshakeCommitCore::new(11, 47_u8);
        assert!(core.manager_published(10).is_err());
        let receipt = core.manager_published(11).expect("matching manager token");
        let activation = publish_session(&mut core, receipt);
        let payload = core.begin_send(activation).expect("matching commit");
        assert_eq!(*payload.payload(), 47);
        let failed = core.complete_failure(payload).expect("failed send");
        assert_eq!(failed, HandshakeSendDecision::Retryable);
        assert!(core.manager_published(11).is_err());
        let retry_payload = core.begin_retry(11).expect("retry");
        assert_eq!(*retry_payload.payload(), 47);
        assert_eq!(
            core.complete_success(retry_payload).expect("retry success"),
            HandshakeSendDecision::Acked
        );
    });
}

#[test]
fn production_handshake_core_never_leases_payload_before_receive_activation() {
    loom::model(|| {
        let mut core = HandshakeCommitCore::new(13, 53_u8);
        let receipt = core.manager_published(13).expect("manager publication");
        assert!(core.payload().is_some());
        let activation = publish_session(&mut core, receipt);
        assert_eq!(core.phase(), HandshakeCommitPhase::SessionCommitted);
        assert!(core.payload().is_some());
        let payload = core.begin_send(activation).expect("activation publication");
        assert_eq!(*payload.payload(), 53);
        assert_eq!(core.phase(), HandshakeCommitPhase::Sending);
    });
}

#[test]
fn production_handshake_core_poison_after_session_commit_is_terminal() {
    loom::model(|| {
        let mut core = HandshakeCommitCore::new(15, 59_u8);
        let receipt = core.manager_published(15).expect("manager publication");
        let activation = publish_session(&mut core, receipt);
        core.poison_after_session_commit(activation)
            .expect("poison activation");
        assert_eq!(core.phase(), HandshakeCommitPhase::Poisoned);
        assert!(core.payload().is_some());
        assert!(core.rollback(15, false).is_err());
    });
}
