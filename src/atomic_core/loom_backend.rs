use super::AtomicU64Authority;
use loom::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct LoomAtomicU64(AtomicU64);

impl AtomicU64Authority for LoomAtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }

    fn cross_atomic_fence(&self) {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
}
