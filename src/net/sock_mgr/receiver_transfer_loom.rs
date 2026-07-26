#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::receiver_transfer::{
    ReceiverGenerationView, ReceiverTransferCore, ReceiverTransferError,
};
use loom::sync::atomic::AtomicU64;
use loom::sync::{Arc, Mutex, mpsc};
use loom::thread;

type LoomReceiverCore = ReceiverTransferCore<u64, AtomicU64, Arc<AtomicU64>>;
type LoomGenerationView = ReceiverGenerationView<AtomicU64, Arc<AtomicU64>>;

fn core(receiver: u64) -> (LoomReceiverCore, LoomGenerationView) {
    ReceiverTransferCore::new(receiver, Arc::new(AtomicU64::new(1)))
}

#[test]
fn production_receiver_core_allows_exactly_one_initial_owner() {
    loom::model(|| {
        let (core, _generation) = core(1);
        let core = Arc::new(Mutex::new(core));
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || first_core.lock().expect("first claim lock").claim(7));
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || second_core.lock().expect("second claim lock").claim(8));

        let first = first.join().expect("first claim actor");
        let second = second.join().expect("second claim actor");
        assert!(matches!(
            (first, second),
            (Ok((1, 1)), Err(ReceiverTransferError::AlreadyOwned))
                | (Err(ReceiverTransferError::AlreadyOwned), Ok((1, 1)))
        ));
    });
}

#[test]
fn production_receiver_core_publishes_resource_before_transfer_generation() {
    loom::model(|| {
        let (core, published) = core(1);
        let core = Arc::new(Mutex::new(core));
        let (claimed_generation, initial_receiver) = core
            .lock()
            .expect("initial claim lock")
            .claim(7)
            .expect("claim");
        assert_eq!(initial_receiver, 1);

        let writer_core = Arc::clone(&core);
        let writer = thread::spawn(move || {
            let mut state = writer_core.lock().expect("publication lock");
            state.publish_replacement(2).expect("publish replacement");
        });

        let reader_core = Arc::clone(&core);
        let reader = thread::spawn(move || {
            if published.changed(claimed_generation).is_none() {
                return None;
            }
            let mut state = reader_core.lock().expect("transfer lock");
            let (generation, receiver) = state
                .transfer_replacement_to_owner(7, claimed_generation)
                .expect("transfer ownership")?;
            assert_eq!(receiver, generation);
            Some(generation)
        });

        writer.join().expect("publication actor");
        let first_transfer = reader.join().expect("transfer actor");
        if first_transfer.is_none() {
            let mut state = core.lock().expect("eventual transfer lock");
            let (generation, receiver) = state
                .transfer_replacement_to_owner(7, claimed_generation)
                .expect("eventual transfer")
                .expect("new generation");
            assert_eq!(receiver, generation);
        }
    });
}

#[test]
fn production_receiver_core_exit_and_replacement_never_leave_claimable_authority() {
    loom::model(|| {
        let (core, _generation) = core(1);
        let core = Arc::new(Mutex::new(core));
        core.lock()
            .expect("initial claim lock")
            .claim(7)
            .expect("claim");

        let exit_core = Arc::clone(&core);
        let exit = thread::spawn(move || {
            let mut state = exit_core.lock().expect("exit lock");
            state.owner_exit(7).expect("owner exit");
        });

        let publish_core = Arc::clone(&core);
        let publish = thread::spawn(move || {
            let mut state = publish_core.lock().expect("publish lock");
            state.publish_replacement(2)
        });

        exit.join().expect("exit actor");
        let publication = publish.join().expect("publish actor");
        let mut state = core.lock().expect("final state lock");
        assert_eq!(state.claim(8), Err(ReceiverTransferError::OwnerExited));
        assert!(matches!(
            publication,
            Ok(2) | Err(ReceiverTransferError::OwnerExited)
        ));
        assert!(!state.snapshot().receiver_available);
    });
}

#[test]
#[should_panic(
    expected = "weakened receiver publication exposed a generation without its resource"
)]
fn weakened_split_receiver_generation_exposes_missing_resource() {
    loom::model(|| {
        let generation = Arc::new(AtomicU64::new(1));
        let resource = Arc::new(Mutex::new(None::<u64>));
        let (generation_ready, observe_generation) = mpsc::channel();
        let (observed, finish_publication) = mpsc::channel();

        let writer_generation = Arc::clone(&generation);
        let writer_resource = Arc::clone(&resource);
        let writer = thread::spawn(move || {
            writer_generation.store(2, loom::sync::atomic::Ordering::Release);
            generation_ready
                .send(())
                .expect("publish generation boundary");
            finish_publication.recv().expect("reader observation");
            *writer_resource.lock().expect("late receiver publication") = Some(2);
        });

        let reader_generation = Arc::clone(&generation);
        let reader_resource = Arc::clone(&resource);
        let reader = thread::spawn(move || {
            observe_generation.recv().expect("generation publication");
            let published = reader_generation.load(loom::sync::atomic::Ordering::Acquire);
            let receiver = *reader_resource.lock().expect("receiver observation");
            observed.send(()).expect("release weakened writer");
            assert!(
                published != 2 || receiver == Some(2),
                "weakened receiver publication exposed a generation without its resource"
            );
        });

        reader.join().expect("reader actor");
        writer.join().expect("writer actor");
    });
}
