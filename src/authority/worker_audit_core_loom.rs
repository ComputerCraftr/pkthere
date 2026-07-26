use super::worker_audit_core::{AUDIT_TERMINAL, AuditSlotPayload, AuditSlotPublicationCore};
use crate::atomic_core::AtomicU8Authority;
use loom::sync::atomic::{AtomicU8, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

struct LoomState(AtomicU8);

impl AtomicU8Authority for LoomState {
    fn load_acquire(&self) -> u8 {
        self.0.load(Ordering::Acquire)
    }
    fn store_release(&self, value: u8) {
        self.0.store(value, Ordering::Release);
    }
    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }
    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }
}

struct Payload(Mutex<(Option<u8>, Option<u8>)>);

impl AuditSlotPayload<u8, u8> for Payload {
    fn install_identity(&self, identity: u8) -> Result<(), &'static str> {
        let Ok(mut payload) = self.0.lock() else {
            return Err("identity payload poisoned");
        };
        if payload.0.is_some() {
            return Err("duplicate identity");
        }
        payload.0 = Some(identity);
        Ok(())
    }
    fn clear_identity(&self) {
        if let Ok(mut payload) = self.0.lock() {
            payload.0 = None;
        }
    }
    fn identity_matches(&self, identity: u8) -> Result<bool, &'static str> {
        self.0
            .lock()
            .map(|payload| payload.0 == Some(identity))
            .map_err(|_| "identity payload poisoned")
    }
    fn install_record(&self, record: u8) -> Result<(), &'static str> {
        let Ok(mut payload) = self.0.lock() else {
            return Err("record payload poisoned");
        };
        if payload.1.replace(record).is_some() {
            return Err("duplicate record");
        }
        Ok(())
    }
    fn terminal_record(&self) -> Result<Option<u8>, &'static str> {
        self.0
            .lock()
            .map(|payload| payload.1)
            .map_err(|_| "record payload poisoned")
    }
}

type Core = AuditSlotPublicationCore<LoomState, Payload, u8, u8>;

#[test]
fn audit_slot_publication_never_exposes_terminal_without_its_record() {
    loom::model(|| {
        let core = Arc::new(Core::new(
            LoomState(AtomicU8::new(0)),
            Payload(Mutex::new((None, None))),
        ));
        core.register(7).expect("register");
        core.begin(7).expect("begin");
        let publisher = Arc::clone(&core);
        let publish = thread::spawn(move || publisher.seal(9));
        let observer = Arc::clone(&core);
        let observe = thread::spawn(move || {
            if observer.state() == AUDIT_TERMINAL {
                assert_eq!(observer.terminal_record().expect("record"), Some(9));
            }
        });
        assert_eq!(publish.join().expect("publisher"), Ok(()));
        observe.join().expect("observer");
        assert_eq!(core.terminal_record().expect("final record"), Some(9));
    });
}
