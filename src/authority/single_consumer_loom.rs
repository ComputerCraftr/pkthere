use super::SingleConsumerBootstrap;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;

#[test]
fn single_consumer_bootstrap_moves_payload_to_exactly_one_runtime_owner() {
    loom::model(|| {
        let consumed = Arc::new(AtomicUsize::new(0));
        let token = SingleConsumerBootstrap::new(Arc::clone(&consumed));
        let owner = thread::spawn(move || {
            token.transfer().fetch_add(1, Ordering::AcqRel);
        });
        owner.join().expect("single consumer owner");
        assert_eq!(consumed.load(Ordering::Acquire), 1);
    });
}
