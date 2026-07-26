#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::retirement_core::{SocketRetirementOwner, retire_socket};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU8, Ordering};
use loom::thread;

struct ModeledDescriptorOwner {
    phase: Arc<AtomicU8>,
    visibility: Arc<AtomicU8>,
}

impl SocketRetirementOwner for ModeledDescriptorOwner {
    type Error = ();

    fn retire_descriptor(&mut self) -> Result<(), Self::Error> {
        self.phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn bind_replacement(&mut self) -> Result<(), Self::Error> {
        self.phase
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn publish_retirement(self) -> Result<(), Self::Error> {
        let phase = self.phase.load(Ordering::Acquire);
        if phase != 1 && phase != 2 {
            return Err(());
        }
        self.visibility.store(phase, Ordering::Release);
        Ok(())
    }
}

#[test]
fn socket_retirement_typestate_publishes_only_retired_or_replacement_bound_owner() {
    loom::model(|| {
        let phase = Arc::new(AtomicU8::new(0));
        let visibility = Arc::new(AtomicU8::new(0));
        let writer_phase = Arc::clone(&phase);
        let writer_visibility = Arc::clone(&visibility);
        let writer = thread::spawn(move || {
            retire_socket(ModeledDescriptorOwner {
                phase: writer_phase,
                visibility: writer_visibility,
            })
            .expect("retire descriptor")
            .replacement_bound()
            .expect("bind replacement")
            .commit()
            .expect("publish retirement");
        });
        let reader_phase = Arc::clone(&phase);
        let reader_visibility = Arc::clone(&visibility);
        let reader = thread::spawn(move || {
            if reader_visibility.load(Ordering::Acquire) == 2 {
                assert_eq!(reader_phase.load(Ordering::Acquire), 2);
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
        assert_eq!(visibility.load(Ordering::Acquire), 2);
    });
}
