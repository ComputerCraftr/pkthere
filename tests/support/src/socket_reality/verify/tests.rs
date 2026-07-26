use super::availability::classify_creation_failure;
use super::availability::{CollectionAvailability, classify_availability};
use super::contract::require_case_contract;
use super::implementation::{require_same_packet_ids, require_untrusted_raw_kernel_id};
use super::raw::verify_forwarder_kernel_evidence;
use super::{VerificationErrorKind, verify};
use crate::packet_diagnostics::DiagnosticLogIndex;
use crate::socket_reality::case::{
    ConnectionScenario, RealityCase, RealityOperation, RealitySocketPath,
};
use crate::socket_reality::collect::collect_udp_datagram;
use crate::socket_reality::evidence::{CallResult, ForwarderEvidence, ForwarderProcessEvidence};
use crate::socket_reality::evidence::{
    IcmpDgramCollectionOutcome, IcmpDgramEvidence, OsErrorEvidence, ProbeSocketEvidence,
    SocketCreateEvidence,
};
use crate::socket_reality::evidence::{ProbeSocketId, RealityEvidence, SocketCall};
use crate::socket_reality::requirement::{
    CollectionAuthority, RealityPlatform, RealityRequirement,
};
use pkthere_socket_policy::SocketCreationFailureClass;
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::Protocol;
use socket2::{Domain, Type};

fn udp_case() -> RealityCase {
    RealityCase {
        domain: Domain::IPV4,
        target_domain: None,
        protocol: SupportedProtocol::UDP,
        socket_type: Type::DGRAM,
        socket_path: RealitySocketPath::Datagram,
        policy_role: SocketRole::Listener,
        connection_scenario: ConnectionScenario::DirectUnconnected,
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
fn raw_disconnect_contract_accepts_both_production_roles() {
    for policy_role in [SocketRole::Listener, SocketRole::Upstream] {
        require_case_contract(RealityCase {
            domain: Domain::IPV4,
            target_domain: None,
            protocol: SupportedProtocol::ICMP,
            socket_type: Type::RAW,
            socket_path: RealitySocketPath::RawIcmp,
            policy_role,
            connection_scenario: ConnectionScenario::DirectConnected,
            operation: RealityOperation::SocketDisconnect,
        })
        .unwrap_or_else(|error| panic!("{policy_role:?} RAW disconnect contract: {error}"));
    }
}

#[test]
fn raw_kernel_port_must_be_distinct_from_the_wire_echo_id() {
    require_untrusted_raw_kernel_id(1, 0x6111).expect("protocol number is not an Echo ID");
    require_untrusted_raw_kernel_id(58, 0x6111).expect("IPv6 protocol number is not an Echo ID");
    require_untrusted_raw_kernel_id(0, 0x6111).expect("zero kernel port is not an Echo ID");
    assert!(require_untrusted_raw_kernel_id(0x6111, 0x6111).is_err());
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
            connection_scenario: ConnectionScenario::DirectConnected,
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
        classify_availability(false, CollectionAvailability::Executed),
        Ok(())
    );
    assert_eq!(
        classify_availability(
            true,
            CollectionAvailability::AuthoritativeUnsupported(
                SocketCreationFailureClass::UnsupportedCandidate
            )
        ),
        Ok(())
    );
    assert_eq!(
        classify_availability(
            false,
            CollectionAvailability::AuthoritativeUnsupported(
                SocketCreationFailureClass::UnsupportedCandidate
            )
        ),
        Err(VerificationErrorKind::RequiredButUnavailable)
    );
    assert_eq!(
        classify_availability(
            true,
            CollectionAvailability::Failed(SocketCreationFailureClass::PermissionDenied)
        ),
        Err(VerificationErrorKind::EvidenceMismatch)
    );
}

#[cfg(unix)]
#[test]
fn reality_creation_failure_classes_match_the_fallback_contract() {
    let unsupported = std::io::Error::from_raw_os_error(libc::EPROTONOSUPPORT);
    assert_eq!(
        classify_creation_failure(&OsErrorEvidence::from(&unsupported)),
        SocketCreationFailureClass::UnsupportedCandidate
    );
    let exhausted = std::io::Error::from_raw_os_error(libc::EMFILE);
    assert_eq!(
        classify_creation_failure(&OsErrorEvidence::from(&exhausted)),
        SocketCreationFailureClass::ResourceExhausted
    );
}

#[test]
#[cfg(unix)]
fn unix_unsupported_primary_is_recorded_when_exact_fallback_accepts_it() {
    assert_unsupported_production_primary_is_recorded(libc::EPROTONOSUPPORT);
}

#[cfg(windows)]
#[test]
fn windows_unsupported_primary_is_recorded_when_exact_fallback_accepts_it() {
    assert_unsupported_production_primary_is_recorded(
        windows_sys::Win32::Networking::WinSock::WSAEPROTONOSUPPORT,
    );
}

#[cfg(windows)]
#[test]
fn windows_reality_creation_failure_classes_match_the_fallback_contract() {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAEPROTONOSUPPORT};

    let unsupported = std::io::Error::from_raw_os_error(WSAEPROTONOSUPPORT);
    assert_eq!(
        classify_creation_failure(&OsErrorEvidence::from(&unsupported)),
        SocketCreationFailureClass::UnsupportedCandidate
    );
    let exhausted = std::io::Error::from_raw_os_error(WSAEMFILE);
    assert_eq!(
        classify_creation_failure(&OsErrorEvidence::from(&exhausted)),
        SocketCreationFailureClass::ResourceExhausted
    );
}

fn assert_unsupported_production_primary_is_recorded(error_code: i32) {
    let case = RealityCase {
        domain: Domain::IPV4,
        target_domain: None,
        protocol: SupportedProtocol::ICMP,
        socket_type: Type::DGRAM,
        socket_path: RealitySocketPath::Datagram,
        policy_role: SocketRole::Upstream,
        connection_scenario: ConnectionScenario::DirectConnected,
        operation: RealityOperation::IcmpDgramReceiveId,
    };
    let socket_id = ProbeSocketId(1);
    let unsupported = std::io::Error::from_raw_os_error(error_code);
    let evidence = RealityEvidence::IcmpDgram(IcmpDgramEvidence {
        direct: crate::socket_reality::evidence::DirectSocketEvidence {
            sockets: vec![ProbeSocketEvidence {
                create: SocketCreateEvidence {
                    socket_id,
                    domain: case.domain,
                    socket_type: case.socket_type,
                    protocol: Some(Protocol::ICMPV4),
                    result: CallResult::OsError(OsErrorEvidence::from(&unsupported)),
                },
                calls: Vec::new(),
            }],
        },
        socket: socket_id,
        outcome: IcmpDgramCollectionOutcome::NotAttempted,
        zero_checksum_sequence: None,
        zero_checksum_outcome: None,
    });
    let verified = super::verify_requirement(
        RealityRequirement {
            platform: RealityPlatform::current(),
            case,
            collection_authority: CollectionAuthority::DirectSocket,
            required: true,
            coverage_owner: "unsupported_primary_fallback_regression",
        },
        &evidence,
    )
    .expect("unsupported primary candidate must follow its exact fallback contract");

    assert!(matches!(
        verified.facts,
        super::DerivedFacts::SocketUnavailable {
            failure_class: SocketCreationFailureClass::UnsupportedCandidate,
            raw_os_error: Some(code),
        } if code == error_code
    ));
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
        connection_scenario: ConnectionScenario::DirectConnected,
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
fn source_and_destination_ids_from_separate_packets_are_rejected() {
    let stderr = [
        serde_json::json!({
            "diagnostic_schema": 3,
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
            "diagnostic_schema": 3,
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
            "diagnostic_schema": 3,
            "diagnostic_sequence": 1,
            "event": "socket_evidence",
            "key": socket_key,
            "getsockname": "127.0.0.1:0",
        }),
        serde_json::json!({
            "diagnostic_schema": 3,
            "diagnostic_sequence": 2,
            "event": "packet_dump",
            "worker": 1,
            "direction": "u2c",
            "packet_id": 1,
            "stage": "admission",
            "socket": {
                "evidence_key": dump_key,
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
