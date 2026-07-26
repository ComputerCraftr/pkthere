use super::disconnect::verify;
use crate::socket_reality::evidence::{
    CallResult, DatagramBindShape, DatagramDisconnectAttempt, DatagramDisconnectEvidence,
    DatagramQueueIsolationEvidence, OsErrorEvidence, ReceiveEvidence,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const PAYLOAD: &[u8] = b"disconnect";

fn attempt(
    bind_shape: DatagramBindShape,
    bound: SocketAddr,
    local_after: SocketAddr,
) -> DatagramDisconnectAttempt {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_002);
    DatagramDisconnectAttempt {
        bind_shape,
        bound_before: bound,
        original_destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port()),
        connected_local: bound,
        new_peer: peer,
        disconnect_result: CallResult::OsError(OsErrorEvidence {
            raw_os_error: Some(47),
            kind: io::ErrorKind::Other,
            message: "raw disconnect status".to_string(),
        }),
        peer_after_disconnect: CallResult::Ok(None),
        local_after_disconnect: CallResult::Ok(local_after),
        receive_after_disconnect: CallResult::Ok(ReceiveEvidence {
            bytes: PAYLOAD.to_vec(),
            source: Some(peer),
        }),
        reconnect_result: CallResult::Ok(()),
        peer_after_reconnect: CallResult::Ok(peer),
        local_after_reconnect: CallResult::Ok(bound),
        peer_received_after_reconnect: CallResult::Ok(PAYLOAD.to_vec()),
        queue_isolation: CallResult::Ok(DatagramQueueIsolationEvidence {
            queued_before_disconnect: b"old-before".to_vec(),
            queued_while_gate_closed: b"old-closed".to_vec(),
            fresh_after_reconnect: b"fresh".to_vec(),
            received_after_reconnect: vec![ReceiveEvidence {
                bytes: b"fresh".to_vec(),
                source: Some(peer),
            }],
        }),
    }
}

#[test]
fn syscall_error_does_not_override_proven_disconnect_postconditions() {
    let concrete = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001);
    let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 40_001);
    let evidence = DatagramDisconnectEvidence {
        sent_bytes: PAYLOAD.to_vec(),
        attempts: vec![
            attempt(DatagramBindShape::ConcreteEphemeralPort, concrete, wildcard),
            attempt(DatagramBindShape::WildcardEphemeralPort, wildcard, wildcard),
            attempt(DatagramBindShape::ConcreteFixedPort, concrete, wildcard),
            attempt(DatagramBindShape::WildcardFixedPort, wildcard, wildcard),
        ],
    };
    let verified = verify(&evidence).expect("verify postcondition evidence");
    let crate::socket_reality::verify::DerivedFacts::DatagramDisconnect { capability, .. } =
        verified
    else {
        panic!("wrong derived fact");
    };
    assert!(capability.association_clear_supported);
    assert!(
        capability
            .ephemeral_port_bind
            .concrete_bind
            .local_port_preserved
    );
    assert!(
        !capability
            .ephemeral_port_bind
            .concrete_bind
            .exact_local_bind_preserved
    );
    assert!(
        capability
            .fixed_port_bind
            .wildcard_bind
            .exact_local_bind_preserved
    );
    assert!(capability.stale_receive_queue_isolated);
}

#[test]
fn queued_pre_clear_datagram_disqualifies_same_descriptor_relock() {
    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 40_001);
    let mut attempts = [
        DatagramBindShape::ConcreteEphemeralPort,
        DatagramBindShape::WildcardEphemeralPort,
        DatagramBindShape::ConcreteFixedPort,
        DatagramBindShape::WildcardFixedPort,
    ]
    .map(|shape| attempt(shape, bound, bound));
    for attempt in &mut attempts {
        let CallResult::Ok(queue) = &mut attempt.queue_isolation else {
            panic!("test queue evidence must be present");
        };
        queue.received_after_reconnect.insert(
            0,
            ReceiveEvidence {
                bytes: queue.queued_before_disconnect.clone(),
                source: Some(attempt.new_peer),
            },
        );
    }
    let evidence = DatagramDisconnectEvidence {
        sent_bytes: PAYLOAD.to_vec(),
        attempts: attempts.into(),
    };
    let verified = verify(&evidence).expect("verify retained-queue evidence");
    let crate::socket_reality::verify::DerivedFacts::DatagramDisconnect { capability, .. } =
        verified
    else {
        panic!("wrong derived fact");
    };
    assert!(!capability.stale_receive_queue_isolated);
    assert!(!capability.supports_safe_same_descriptor_relock());
}

#[test]
fn mixed_queue_observations_conservatively_disable_same_descriptor_relock() {
    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 40_001);
    let mut attempts = [
        DatagramBindShape::ConcreteEphemeralPort,
        DatagramBindShape::ConcreteEphemeralPort,
        DatagramBindShape::WildcardEphemeralPort,
        DatagramBindShape::ConcreteFixedPort,
        DatagramBindShape::WildcardFixedPort,
    ]
    .map(|shape| attempt(shape, bound, bound));
    let CallResult::Ok(queue) = &mut attempts[1].queue_isolation else {
        panic!("test queue evidence must be present");
    };
    queue.received_after_reconnect.insert(
        0,
        ReceiveEvidence {
            bytes: queue.queued_before_disconnect.clone(),
            source: Some(attempts[1].new_peer),
        },
    );
    let evidence = DatagramDisconnectEvidence {
        sent_bytes: PAYLOAD.to_vec(),
        attempts: attempts.into(),
    };
    let verified = verify(&evidence).expect("verify mixed queue evidence");
    let crate::socket_reality::verify::DerivedFacts::DatagramDisconnect { capability, .. } =
        verified
    else {
        panic!("wrong derived fact");
    };
    assert!(!capability.stale_receive_queue_isolated);
    assert!(!capability.supports_safe_same_descriptor_relock());
}

#[test]
fn intermittent_disconnect_postconditions_are_rejected() {
    let same = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 40_001);
    let changed = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let concrete = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001);
    let evidence = DatagramDisconnectEvidence {
        sent_bytes: PAYLOAD.to_vec(),
        attempts: vec![
            attempt(DatagramBindShape::ConcreteEphemeralPort, concrete, concrete),
            attempt(DatagramBindShape::WildcardEphemeralPort, same, same),
            attempt(DatagramBindShape::WildcardEphemeralPort, same, changed),
            attempt(DatagramBindShape::ConcreteFixedPort, concrete, concrete),
            attempt(DatagramBindShape::WildcardFixedPort, same, same),
        ],
    };
    assert!(verify(&evidence).is_err());
}
