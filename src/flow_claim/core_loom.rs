use super::core::{FlowClaimOwnershipCore, reserve_flow_claim};
use crate::atomic_core::LoomAtomicU64;
use loom::sync::Arc;
use loom::thread;

#[test]
fn delayed_old_flow_claim_release_cannot_clear_a_new_generation() {
    loom::model(|| {
        let core = Arc::new(FlowClaimOwnershipCore {
            state: LoomAtomicU64::default(),
        });
        reserve_flow_claim(&core, 1).expect("first claim");
        core.commit(1).expect("commit first claim");
        core.take_committed(1).expect("take first claim");
        assert!(core.release(1).expect("release first claim"));
        reserve_flow_claim(&core, 2).expect("replacement claim");
        let old = Arc::clone(&core);
        let release = thread::spawn(move || old.release(1));
        let replacement = Arc::clone(&core);
        let commit = thread::spawn(move || replacement.commit(2));
        assert!(!release.join().expect("old release").expect("release state"));
        commit
            .join()
            .expect("replacement commit")
            .expect("commit state");
        assert_eq!(core.generation(), Some(2));
    });
}
