use super::topology_batch::TopologyReservationBatch;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

#[test]
fn production_topology_batch_parks_all_resources_before_publication_in_reverse_order() {
    loom::model(|| {
        let parked = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(Mutex::new(Vec::new()));

        let writer_parked = Arc::clone(&parked);
        let writer_published = Arc::clone(&published);
        let writer_order = Arc::clone(&order);
        let writer = thread::spawn(move || {
            let mut batch =
                TopologyReservationBatch::try_with_capacity(2).expect("bounded topology batch");
            batch.push(0_usize);
            batch.push(1_usize);
            assert!(
                batch
                    .try_finish_reverse(|_step, resource| {
                        writer_order.lock().expect("parking order").push(resource);
                        writer_parked.fetch_add(1, Ordering::AcqRel);
                        Ok::<(), ()>(())
                    })
                    .is_ok(),
                "park complete topology batch"
            );
            writer_published.store(1, Ordering::Release);
        });

        let reader_parked = Arc::clone(&parked);
        let reader_published = Arc::clone(&published);
        let reader = thread::spawn(move || {
            if reader_published.load(Ordering::Acquire) == 1 {
                assert_eq!(reader_parked.load(Ordering::Acquire), 2);
            }
        });

        writer.join().expect("topology writer");
        reader.join().expect("topology reader");
        assert_eq!(*order.lock().expect("final parking order"), [1, 0]);
        assert_eq!(parked.load(Ordering::Acquire), 2);
        assert_eq!(published.load(Ordering::Acquire), 1);
    });
}

#[test]
fn production_topology_batch_returns_remaining_resources_for_reverse_rollback() {
    loom::model(|| {
        let disposition = Arc::new(Mutex::new(Vec::new()));
        let apply_disposition = Arc::clone(&disposition);
        let rollback_disposition = Arc::clone(&disposition);
        let writer = thread::spawn(move || {
            let mut batch =
                TopologyReservationBatch::try_with_capacity(3).expect("bounded topology batch");
            batch.push(0_usize);
            batch.push(1_usize);
            batch.push(2_usize);
            let failure = match batch.try_finish_reverse(|_step, resource| {
                apply_disposition
                    .lock()
                    .expect("apply disposition")
                    .push((resource, "apply"));
                (resource != 1).then_some(()).ok_or(())
            }) {
                Ok(()) => panic!("middle resource must fail"),
                Err(failure) => failure,
            };
            assert_eq!(failure.source, ());
            assert_eq!(
                failure.remaining.rollback_reverse(|_step, resource| {
                    rollback_disposition
                        .lock()
                        .expect("rollback disposition")
                        .push((resource, "rollback"));
                    Ok::<(), ()>(())
                }),
                None
            );
        });
        writer.join().expect("topology transaction");
        assert_eq!(
            *disposition.lock().expect("final disposition"),
            [(2, "apply"), (1, "apply"), (0, "rollback")]
        );
    });
}
