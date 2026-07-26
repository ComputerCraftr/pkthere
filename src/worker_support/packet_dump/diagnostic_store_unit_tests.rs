use super::DiagnosticClass;
use super::diagnostic_store::{
    DirectionDiagnosticStore, LOST_DIAGNOSTIC_STORES, TERMINAL_TRACE_CAPACITY,
    try_lock_diagnostic_store,
};
use crate::diagnostics::PacketTraceId;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn pending_diagnostic_capacity_never_overwrites_a_live_trace() {
    let now = Instant::now();
    let mut store = DirectionDiagnosticStore::new(now);
    for packet_id in 0..TERMINAL_TRACE_CAPACITY as u64 {
        assert!(store.begin(
            PacketTraceId {
                worker_id: 77,
                c2u: true,
                packet_id,
            },
            DiagnosticClass::Accepted,
            now + Duration::from_secs(packet_id),
        ));
    }
    let live = store.in_flight.keys().copied().collect::<HashSet<_>>();
    assert!(!store.begin(
        PacketTraceId {
            worker_id: 77,
            c2u: true,
            packet_id: TERMINAL_TRACE_CAPACITY as u64,
        },
        DiagnosticClass::Accepted,
        now + Duration::from_secs(TERMINAL_TRACE_CAPACITY as u64),
    ));
    assert_eq!(
        store.in_flight.keys().copied().collect::<HashSet<_>>(),
        live
    );
    assert_eq!(store.pending_trace_suppressed, 1);
}

#[test]
fn poisoned_diagnostic_store_is_cleared_instead_of_recovered() {
    let store = Arc::new(crate::authority::AuthorityMutex::new(
        DirectionDiagnosticStore::new(Instant::now()),
        crate::authority::AuthorityInstance::singleton(crate::authority::AuthorityId::Diagnostic),
    ));
    let poisoned = Arc::clone(&store);
    assert!(
        thread::spawn(move || {
            let _guard = poisoned.lock().expect("diagnostic store");
            std::panic::panic_any("poison diagnostics");
        })
        .join()
        .is_err()
    );
    let resets_before = LOST_DIAGNOSTIC_STORES.load(Ordering::Relaxed);
    assert!(
        try_lock_diagnostic_store(&store)
            .expect("reset poisoned diagnostic store")
            .in_flight
            .is_empty()
    );
    assert_eq!(
        LOST_DIAGNOSTIC_STORES.load(Ordering::Relaxed),
        resets_before + 1
    );
}

#[test]
fn noise_output_budget_cannot_consume_accepted_evidence() {
    let now = Instant::now();
    let mut store = DirectionDiagnosticStore::new(now);
    for packet_id in 0..4 {
        let trace = PacketTraceId {
            worker_id: 78,
            c2u: false,
            packet_id,
        };
        assert!(store.begin(trace, DiagnosticClass::ReceiveNoise, now));
        assert!(store.finish(trace, super::super::PacketDisposition::ReceiveNoise, None));
    }
    assert!(!store.begin(
        PacketTraceId {
            worker_id: 78,
            c2u: false,
            packet_id: 5,
        },
        DiagnosticClass::ReceiveNoise,
        now,
    ));
    assert!(store.begin(
        PacketTraceId {
            worker_id: 78,
            c2u: false,
            packet_id: 6,
        },
        DiagnosticClass::Accepted,
        now,
    ));
}
