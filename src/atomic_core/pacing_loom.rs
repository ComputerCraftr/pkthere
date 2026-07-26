use super::{NEVER_PACED, PacingAtomic, PacingCore};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

impl PacingAtomic for AtomicU64 {
    fn load_relaxed(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }

    fn compare_relaxed_weak(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
    }
}

#[test]
fn production_pacing_core_elects_one_sender_per_interval() {
    loom::model(|| {
        let core = Arc::new(PacingCore::new(AtomicU64::new(NEVER_PACED)));
        let first_core = Arc::clone(&core);
        let first = thread::spawn(move || first_core.try_claim(10, 5));
        let second_core = Arc::clone(&core);
        let second = thread::spawn(move || second_core.try_claim(10, 5));

        let winners = u8::from(first.join().expect("first pacing claimant"))
            + u8::from(second.join().expect("second pacing claimant"));
        assert_eq!(winners, 1);
        assert_eq!(core.last_send_tick(), 10);
    });
}

#[test]
fn production_pacing_core_does_not_overwrite_a_newer_claim() {
    loom::model(|| {
        let core = Arc::new(PacingCore::new(AtomicU64::new(0)));
        let earlier_core = Arc::clone(&core);
        let earlier = thread::spawn(move || earlier_core.try_claim(5, 5));
        let later_core = Arc::clone(&core);
        let later = thread::spawn(move || later_core.try_claim(10, 5));

        let _ = earlier.join().expect("earlier pacing claimant");
        assert!(later.join().expect("later pacing claimant"));
        assert_eq!(core.last_send_tick(), 10);
    });
}
