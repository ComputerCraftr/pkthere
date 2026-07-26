use super::ManagedWakePair;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[test]
fn repeated_notifications_coalesce_to_one_drained_generation() {
    let wake = ManagedWakePair::new().expect("create wake pair");
    for _ in 0..1_000 {
        wake.notify().expect("coalesce notification");
    }
    wake.drain().expect("drain coalesced notification");
    assert_eq!(wake.wake_state.load(Ordering::Acquire), 2_000);
    let mut byte = [0_u8; 1];
    assert_eq!(
        wake.receiver
            .recv(&mut byte)
            .expect_err("wake queue is empty")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn concurrent_notify_and_drain_repairs_pending_state() {
    let wake = Arc::new(ManagedWakePair::new().expect("create wake pair"));
    let producer = {
        let wake = Arc::clone(&wake);
        std::thread::spawn(move || {
            for _ in 0..10_000 {
                wake.notify().expect("publish wake");
                std::thread::yield_now();
            }
        })
    };
    for _ in 0..1_000 {
        wake.drain().expect("drain wake race");
        std::thread::yield_now();
    }
    producer.join().expect("join wake producer");
    wake.drain().expect("repair final pending state");
    assert_eq!(wake.wake_state.load(Ordering::Acquire), 20_000);
    let mut byte = [0_u8; 1];
    assert_eq!(
        wake.receiver
            .recv(&mut byte)
            .expect_err("wake queue is empty")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}
