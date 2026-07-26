#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::reresolve_publication::{
    FlowVisibilityPublication, ManagerTopologyPublication, ReresolvePublicationCore,
};
use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, Ordering};
use loom::thread;

struct ManagerBundle(Arc<AtomicBool>);

impl ManagerTopologyPublication for ManagerBundle {
    type Error = ();
    type Output = ();

    fn publish_manager_topology(self) -> Result<(), ()> {
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

struct FlowBundle(Arc<AtomicBool>);

impl FlowVisibilityPublication for FlowBundle {
    type Error = ();

    fn publish_flow_visibility(self) -> Result<(), ()> {
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

#[test]
fn production_reresolve_core_never_exposes_flow_before_manager_topology() {
    loom::model(|| {
        let manager = Arc::new(AtomicBool::new(false));
        let flow = Arc::new(AtomicBool::new(false));
        let writer_manager = Arc::clone(&manager);
        let writer_flow = Arc::clone(&flow);
        let writer = thread::spawn(move || {
            ReresolvePublicationCore::new(ManagerBundle(writer_manager), FlowBundle(writer_flow))
                .publish()
                .expect("publish re-resolution");
        });
        let reader = thread::spawn(move || {
            if flow.load(Ordering::Acquire) {
                assert!(manager.load(Ordering::Acquire));
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
    });
}

#[test]
#[should_panic(expected = "weakened re-resolution exposed flow before manager topology")]
fn weakened_split_reresolution_publication_exposes_mixed_state() {
    loom::model(|| {
        let manager = Arc::new(AtomicBool::new(false));
        let flow = Arc::new(AtomicBool::new(false));
        let writer_manager = Arc::clone(&manager);
        let writer_flow = Arc::clone(&flow);
        let writer = thread::spawn(move || {
            writer_flow.store(true, Ordering::Release);
            thread::yield_now();
            writer_manager.store(true, Ordering::Release);
        });
        let reader = thread::spawn(move || {
            if flow.load(Ordering::Acquire) {
                assert!(
                    manager.load(Ordering::Acquire),
                    "weakened re-resolution exposed flow before manager topology"
                );
            }
        });
        writer.join().expect("writer");
        reader.join().expect("reader");
    });
}
