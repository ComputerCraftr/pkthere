use super::{AssociationAuthorityState, AssociationState};
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn association_authority_publishes_state_and_required_bind_coherently() {
    loom::model(|| {
        let old_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7);
        let new_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        let state = Arc::new(Mutex::new(AssociationAuthorityState::new(
            AssociationState::Unconnected { epoch: 1 },
            old_bind,
        )));
        let writer_state = Arc::clone(&state);
        let writer = thread::spawn(move || {
            writer_state
                .lock()
                .expect("association writer")
                .publish(AssociationState::Unconnected { epoch: 2 }, new_bind);
        });
        let reader_state = Arc::clone(&state);
        let reader = thread::spawn(move || {
            let observed = reader_state.lock().expect("association reader").snapshot();
            assert!(
                observed == (AssociationState::Unconnected { epoch: 1 }, old_bind)
                    || observed == (AssociationState::Unconnected { epoch: 2 }, new_bind)
            );
        });
        writer.join().expect("association writer");
        reader.join().expect("association reader");
    });
}
