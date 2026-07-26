use super::lifecycle::listener_relock_transition_keys;
use crate::packet_diagnostics::DiagnosticLogIndex;
use pkthere_socket_policy::{ListenerClearStrategy, ListenerLockLifecycle};
use socket2::Domain;

fn replacement_diagnostics() -> DiagnosticLogIndex {
    DiagnosticLogIndex::parse(
        "",
        r#"[DEBUG] socket-evidence {"diagnostic_schema":3,"diagnostic_sequence":1,"event":"socket_evidence","action":"replace-listener-on-clear","key":{"process_id":9,"role":"listener","domain":"ipv6","socket_slot":1,"generation":2},"getsockname":"[::1]:40000"}"#,
    )
    .expect("valid replacement diagnostics")
}

#[test]
fn every_replacement_lifecycle_uses_the_explicit_same_slot_generation_evidence() {
    let diagnostics = replacement_diagnostics();
    for lifecycle in [
        ListenerLockLifecycle::StayUnconnectedReplaceOnClear,
        ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ReplaceOwnerSameBind,
        },
    ] {
        let (old, new, update) =
            listener_relock_transition_keys(&diagnostics, Some(lifecycle), "listener")
                .expect("replacement evidence");
        assert_eq!(old.socket_slot, 1);
        assert_eq!(new.socket_slot, 1);
        assert_eq!(old.domain, Domain::IPV6);
        assert_eq!(new.domain, Domain::IPV6);
        assert_eq!(old.generation, 1);
        assert_eq!(new.generation, 2);
        assert_eq!(update.as_deref(), Some("replaced"));
    }
}
