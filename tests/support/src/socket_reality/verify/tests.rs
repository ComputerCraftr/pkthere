use super::availability::{CollectionAvailability, classify_availability};
use super::implementation::require_same_packet_ids;
use super::raw::verify_forwarder_kernel_evidence;
use super::{VerificationErrorKind, verify};
use crate::packet_diagnostics::DiagnosticLogIndex;
use crate::socket_reality::case::{RealityCase, RealityOperation, RealitySocketPath};
use crate::socket_reality::collect::collect_udp_datagram;
use crate::socket_reality::evidence::{CallResult, ForwarderEvidence, ForwarderProcessEvidence};
use crate::socket_reality::evidence::{ProbeSocketId, RealityEvidence, SocketCall};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

fn udp_case() -> RealityCase {
    RealityCase {
        domain: Domain::IPV4,
        target_domain: None,
        protocol: SupportedProtocol::UDP,
        socket_type: Type::DGRAM,
        socket_path: RealitySocketPath::Datagram,
        policy_role: SocketRole::Listener,
        connected: false,
        operation: RealityOperation::DatagramReceiveEvidence,
    }
}

fn udp_evidence(case: RealityCase) -> RealityEvidence {
    RealityEvidence::DatagramReceive(collect_udp_datagram(&case).expect("collect UDP evidence"))
}

#[test]
fn valid_evidence_verifies_without_collector_conclusions() {
    let case = udp_case();
    verify(case, &udp_evidence(case)).expect("verify valid evidence");
}

#[test]
fn changing_each_requested_dimension_is_rejected() {
    let case = udp_case();
    let evidence = udp_evidence(case);
    let alternatives = [
        RealityCase {
            domain: Domain::IPV6,
            ..case
        },
        RealityCase {
            protocol: SupportedProtocol::ICMP,
            ..case
        },
        RealityCase {
            socket_type: Type::RAW,
            socket_path: RealitySocketPath::RawIcmp,
            ..case
        },
        RealityCase {
            policy_role: SocketRole::Upstream,
            ..case
        },
        RealityCase {
            connected: true,
            ..case
        },
        RealityCase {
            operation: RealityOperation::ConnectedPeerFiltering,
            ..case
        },
        RealityCase {
            socket_path: RealitySocketPath::RawIcmp,
            ..case
        },
    ];
    for alternative in alternatives {
        assert!(
            verify(alternative, &evidence).is_err(),
            "tampered requested dimension was accepted: {alternative:?}"
        );
    }
}

#[test]
fn independent_requirement_availability_outcomes_are_typed() {
    assert_eq!(
        classify_availability(true, false, CollectionAvailability::Executed),
        Err(VerificationErrorKind::PolicyCapabilityContradiction)
    );
    assert_eq!(
        classify_availability(true, true, CollectionAvailability::AuthoritativeUnsupported),
        Err(VerificationErrorKind::RequiredButUnavailable)
    );
    assert_eq!(
        classify_availability(
            false,
            true,
            CollectionAvailability::AuthoritativeUnsupported
        ),
        Err(VerificationErrorKind::UnsupportedByRuntime)
    );
}

#[test]
fn changing_probe_socket_identity_is_rejected() {
    let case = udp_case();
    let RealityEvidence::DatagramReceive(mut evidence) = udp_evidence(case) else {
        unreachable!()
    };
    evidence.receiver = ProbeSocketId(99);
    assert!(verify(case, &RealityEvidence::DatagramReceive(evidence)).is_err());
}

#[test]
fn splicing_getsockname_from_another_socket_is_rejected() {
    let case = udp_case();
    let RealityEvidence::DatagramReceive(mut evidence) = udp_evidence(case) else {
        unreachable!()
    };
    let sender_addr = evidence
        .direct
        .socket(evidence.sender)
        .expect("sender evidence")
        .calls
        .iter()
        .rev()
        .find_map(|call| match &call.call {
            SocketCall::GetSockName { result } => result.as_ok().copied(),
            _ => None,
        })
        .expect("sender getsockname");
    let receiver = evidence
        .direct
        .sockets
        .iter_mut()
        .find(|socket| socket.create.socket_id == evidence.receiver)
        .expect("receiver evidence");
    for call in &mut receiver.calls {
        if let SocketCall::GetSockName { result } = &mut call.call {
            *result = crate::socket_reality::evidence::CallResult::Ok(sender_addr);
        }
    }
    assert!(verify(case, &RealityEvidence::DatagramReceive(evidence)).is_err());
}

#[test]
fn removing_connection_lifecycle_is_rejected() {
    let case = RealityCase {
        connected: true,
        operation: RealityOperation::ConnectedPeerFiltering,
        ..udp_case()
    };
    let mut evidence = crate::socket_reality::collect::collect_udp_connected_filter(&case)
        .expect("collect connected evidence");
    let receiver = evidence
        .direct
        .sockets
        .iter_mut()
        .find(|socket| socket.create.socket_id == evidence.receiver)
        .expect("receiver evidence");
    receiver
        .calls
        .retain(|call| !matches!(call.call, SocketCall::Connect { .. }));
    assert!(verify(case, &RealityEvidence::ConnectedFilter(evidence)).is_err());
}

#[test]
fn changing_socket_event_order_is_rejected() {
    let case = udp_case();
    let RealityEvidence::DatagramReceive(mut evidence) = udp_evidence(case) else {
        unreachable!()
    };
    evidence.direct.sockets[0].calls[0].sequence = 99;
    assert!(verify(case, &RealityEvidence::DatagramReceive(evidence)).is_err());
}

#[test]
fn changing_recorded_send_bytes_is_rejected_without_parallel_payload_state() {
    let case = udp_case();
    let RealityEvidence::DatagramReceive(mut evidence) = udp_evidence(case) else {
        unreachable!()
    };
    let sender = evidence
        .direct
        .sockets
        .iter_mut()
        .find(|socket| socket.create.socket_id == evidence.sender)
        .expect("sender evidence");
    let sent = sender
        .calls
        .iter_mut()
        .find_map(|call| match &mut call.call {
            SocketCall::Send { bytes, .. } => Some(bytes),
            _ => None,
        })
        .expect("send evidence");
    sent[0] ^= 0xff;
    assert!(verify(case, &RealityEvidence::DatagramReceive(evidence)).is_err());
}

#[test]
fn collector_evidence_has_no_policy_or_conclusion_fields() {
    let source = include_str!("../evidence.rs");
    for forbidden in [
        "SocketRealityReport",
        "executed_case",
        "measured:",
        "saw_",
        "MismatchObserved",
        "ResolvedSocketPolicy",
        "probe_payload:",
        "requested_echo_id:",
        "sent_packet:",
    ] {
        assert!(
            !source.contains(forbidden),
            "collector evidence contains conclusion field {forbidden}"
        );
    }
}

#[test]
fn collectors_do_not_resolve_production_policy() {
    for source in [
        include_str!("../collect/direct.rs"),
        include_str!("../collect/forwarder.rs"),
    ] {
        assert!(!source.contains("resolve_socket_policy"));
        assert!(!source.contains("upstream_reresolve_capability"));
        assert!(!source.contains("listener_relock_capability"));
    }
}

#[test]
fn source_and_destination_ids_from_separate_packets_are_rejected() {
    let stderr = [
        serde_json::json!({
            "diagnostic_schema": 2,
            "diagnostic_sequence": 1,
            "event": "packet_dump",
            "worker": 1,
            "direction": "c2u",
            "packet_id": 1,
            "stage": "admission",
            "admission": {"result": "accepted"},
            "parse": {"headers": {"icmp": {
                "logical_source_id": 40000,
                "logical_destination_id": 1111,
            }}},
        }),
        serde_json::json!({
            "diagnostic_schema": 2,
            "diagnostic_sequence": 2,
            "event": "packet_dump",
            "worker": 1,
            "direction": "c2u",
            "packet_id": 2,
            "stage": "admission",
            "admission": {"result": "accepted"},
            "parse": {"headers": {"icmp": {
                "logical_source_id": 2222,
                "logical_destination_id": 9999,
            }}},
        }),
    ]
    .map(|value| format!("packet-dump {value}"))
    .join("\n");
    let diagnostics = DiagnosticLogIndex::parse("", &stderr).expect("valid diagnostics");
    assert!(require_same_packet_ids(&diagnostics, 40000, 9999).is_err());
}

#[test]
fn packet_dump_and_getsockname_from_different_slots_are_rejected() {
    let socket_key = serde_json::json!({
        "process_id": 7,
        "role": "upstream",
        "domain": "ipv4",
        "socket_slot": 0,
        "generation": 1,
    });
    let dump_key = serde_json::json!({
        "process_id": 7,
        "role": "upstream",
        "domain": "ipv4",
        "socket_slot": 1,
        "generation": 1,
    });
    let stderr = format!(
        "socket-evidence {}\npacket-dump {}\n",
        serde_json::json!({
            "diagnostic_schema": 2,
            "diagnostic_sequence": 1,
            "event": "socket_evidence",
            "key": socket_key,
            "getsockname": "127.0.0.1:0",
        }),
        serde_json::json!({
            "diagnostic_schema": 2,
            "diagnostic_sequence": 2,
            "event": "packet_dump",
            "worker": 1,
            "direction": "u2c",
            "packet_id": 1,
            "stage": "admission",
            "socket": {
                "evidence_key": dump_key,
                "local_kernel_addr": "127.0.0.1:0",
            },
            "receive": {"socket_source": "127.0.0.1:9999"},
            "parse": {"headers": {
                "ip_version": 4,
                "icmp": {"echo_identifier": 9999},
            }},
        }),
    );
    let evidence = ForwarderEvidence {
        processes: vec![ForwarderProcessEvidence {
            label: "node-a".to_string(),
            command_arguments: Vec::new(),
            stdout: String::new(),
            stderr,
            exit_status: None,
        }],
        client_sent: Vec::new(),
        client_received: CallResult::Ok(Vec::new()),
    };
    assert!(
        verify_forwarder_kernel_evidence(&evidence, Domain::IPV4, SocketRole::Upstream,).is_err()
    );
}

#[test]
fn missing_raw_wire_observation_is_rejected() {
    let evidence = ForwarderEvidence {
        processes: vec![ForwarderProcessEvidence {
            label: "node-a".to_string(),
            command_arguments: Vec::new(),
            stdout: String::new(),
            stderr: "socket-evidence {\"event\":\"socket_evidence\"}".to_string(),
            exit_status: None,
        }],
        client_sent: Vec::new(),
        client_received: CallResult::Ok(Vec::new()),
    };
    assert!(
        verify_forwarder_kernel_evidence(&evidence, Domain::IPV4, SocketRole::Upstream,).is_err()
    );
}
