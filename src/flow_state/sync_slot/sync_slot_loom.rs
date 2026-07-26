#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::{SyncPayloadSlot, SyncSendCompletion};
use loom::sync::{Arc, Mutex};
use loom::thread;

fn model_reset_and_completion() {
    loom::model(|| {
        let mut initial = SyncPayloadSlot::default();
        assert_eq!(initial.replace(17_u8), None);
        let lease = initial.lease().expect("lease").expect("payload");
        let core = Arc::new(Mutex::new(initial));

        let reset_core = Arc::clone(&core);
        let reset = thread::spawn(move || reset_core.lock().expect("reset lock").reset());
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete(lease, false)
        });

        reset.join().expect("reset actor");
        let completion = completion
            .join()
            .expect("completion actor")
            .expect("completion");
        assert!(matches!(
            completion,
            SyncSendCompletion::ResetWon | SyncSendCompletion::Restored
        ));
        let mut core = core.lock().expect("final lock");
        let next = core.lease().expect("next lease").expect("cadence lease");
        match completion {
            SyncSendCompletion::ResetWon => assert_eq!(next.payload, None),
            SyncSendCompletion::Restored => assert!(matches!(next.payload, None | Some(17))),
            SyncSendCompletion::Completed | SyncSendCompletion::Superseded => {
                panic!("failed send lost ownership through an invalid terminal state")
            }
        }
    });
}

fn model_replacement_and_failure() {
    loom::model(|| {
        let mut initial = SyncPayloadSlot::default();
        assert_eq!(initial.replace(17_u8), None);
        let lease = initial.lease().expect("lease").expect("payload");
        let core = Arc::new(Mutex::new(initial));

        let replacement_core = Arc::clone(&core);
        let replacement = thread::spawn(move || {
            replacement_core
                .lock()
                .expect("replacement lock")
                .replace(23)
        });
        let completion_core = Arc::clone(&core);
        let completion = thread::spawn(move || {
            completion_core
                .lock()
                .expect("completion lock")
                .complete(lease, false)
        });

        let displaced = replacement.join().expect("replacement actor");
        let completion = completion
            .join()
            .expect("completion actor")
            .expect("completion");
        let mut owned = Vec::new();
        if let Some(payload) = displaced {
            owned.push(payload);
        }
        let next = core
            .lock()
            .expect("final lock")
            .lease()
            .expect("next lease")
            .expect("next payload");
        if let Some(payload) = next.payload {
            owned.push(payload);
        }
        owned.sort_unstable();
        match completion {
            SyncSendCompletion::Restored => assert_eq!(owned, vec![17, 23]),
            SyncSendCompletion::Superseded => assert_eq!(owned, vec![23]),
            SyncSendCompletion::Completed | SyncSendCompletion::ResetWon => {
                panic!("replacement race produced an invalid completion state")
            }
        }
    });
}

#[test]
fn production_sync_core_models_reset_and_replacement_ownership() {
    model_reset_and_completion();
    model_replacement_and_failure();
}
