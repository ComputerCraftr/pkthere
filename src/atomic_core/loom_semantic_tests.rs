#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::{
    acknowledge_descriptor_cache_revocation, descriptor_cache_revocation_pending,
    request_descriptor_cache_revocation, unregister_descriptor_cache,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use loom::thread;

struct LoomCachedDescriptor(Arc<AtomicBool>);

impl Drop for LoomCachedDescriptor {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[test]
fn primitive_descriptor_revocation_ack_follows_cached_descriptor_drop() {
    loom::model(|| {
        let registered = Arc::new(AtomicBool::new(true));
        let requested = Arc::new(AtomicU64::new(0));
        let acknowledged = Arc::new(AtomicU64::new(0));
        let descriptor_live = Arc::new(AtomicBool::new(true));

        let worker_requested = Arc::clone(&requested);
        let worker_acknowledged = Arc::clone(&acknowledged);
        let worker_descriptor_live = Arc::clone(&descriptor_live);
        let worker = thread::spawn(move || {
            let mut generation = 0;
            let mut epoch = 7;
            let mut descriptor = Some(LoomCachedDescriptor(worker_descriptor_live));
            acknowledge_descriptor_cache_revocation(
                &*worker_requested,
                &*worker_acknowledged,
                &mut generation,
                &mut epoch,
                &mut descriptor,
            )
        });

        let manager_registered = Arc::clone(&registered);
        let manager_requested = Arc::clone(&requested);
        let manager_acknowledged = Arc::clone(&acknowledged);
        let manager_descriptor_live = Arc::clone(&descriptor_live);
        let manager = thread::spawn(move || {
            request_descriptor_cache_revocation(&*manager_registered, &*manager_requested, 1);
            if !descriptor_cache_revocation_pending(&*manager_registered, &*manager_acknowledged, 1)
            {
                assert!(!manager_descriptor_live.load(Ordering::Acquire));
            }
        });

        worker.join().expect("worker");
        manager.join().expect("manager");
    });
}

#[test]
fn primitive_descriptor_unregister_publishes_only_after_descriptor_drop() {
    loom::model(|| {
        let registered = Arc::new(AtomicBool::new(true));
        let descriptor_live = Arc::new(AtomicBool::new(true));
        let worker_registered = Arc::clone(&registered);
        let worker_descriptor_live = Arc::clone(&descriptor_live);
        let worker = thread::spawn(move || {
            let mut generation = 0;
            let mut epoch = 7;
            let mut descriptor = Some(LoomCachedDescriptor(worker_descriptor_live));
            unregister_descriptor_cache(
                &*worker_registered,
                &mut generation,
                &mut epoch,
                &mut descriptor,
            );
        });
        let manager_registered = Arc::clone(&registered);
        let manager_descriptor_live = Arc::clone(&descriptor_live);
        let manager = thread::spawn(move || {
            if !manager_registered.load(Ordering::Acquire) {
                assert!(!manager_descriptor_live.load(Ordering::Acquire));
            }
        });
        worker.join().expect("worker");
        manager.join().expect("manager");
    });
}
