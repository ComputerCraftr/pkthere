use super::allocation_test_support::{
    count_allocations, count_endpoint_normalizations, count_payload_copies,
    record_endpoint_normalization, record_payload_copy,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const EXACT_DELIVERY_WINDOW: usize = 64;

pub(crate) struct ExactDatagramDeliveryProgress {
    received: Arc<AtomicUsize>,
    sent: usize,
}

impl ExactDatagramDeliveryProgress {
    pub(crate) fn new() -> (Self, Arc<AtomicUsize>) {
        let received = Arc::new(AtomicUsize::new(0));
        (
            Self {
                received: Arc::clone(&received),
                sent: 0,
            },
            received,
        )
    }

    pub(crate) fn record_receive(received: &AtomicUsize, count: usize) {
        received.store(count, Ordering::Release);
    }

    pub(crate) fn record_send(&mut self) {
        self.sent += 1;
        while self
            .sent
            .saturating_sub(self.received.load(Ordering::Acquire))
            >= EXACT_DELIVERY_WINDOW
        {
            std::thread::yield_now();
        }
    }
}

#[test]
fn nested_payload_copy_scopes_preserve_inner_and_outer_counts() {
    let ((_, inner), outer) = count_payload_copies(|| {
        record_payload_copy();
        let inner = count_payload_copies(record_payload_copy).1;
        record_payload_copy();
        ((), inner)
    });
    assert_eq!(inner, 1);
    assert_eq!(outer, 3);
}

#[test]
fn endpoint_normalization_scope_counts_only_explicit_conversions() {
    let (_, normalizations) = count_endpoint_normalizations(record_endpoint_normalization);
    assert_eq!(normalizations, 1);
}

#[test]
fn allocation_scope_restores_tracking_after_unwind() {
    let panic = std::panic::catch_unwind(|| {
        count_allocations(|| panic!("injected allocation scope panic"));
    });
    assert!(panic.is_err());
    let (_, allocations) = count_allocations(|| ());
    assert_eq!(allocations, 0);
}

#[test]
fn payload_copy_scope_restores_tracking_after_unwind() {
    let panic = std::panic::catch_unwind(|| {
        count_payload_copies(|| {
            record_payload_copy();
            panic!("injected payload scope panic");
        });
    });
    assert!(panic.is_err());
    record_payload_copy();
    let (_, copies) = count_payload_copies(|| ());
    assert_eq!(copies, 0);
}
