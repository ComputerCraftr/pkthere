use pkthere_test_support::socket_reality::case::RealityCase;
use pkthere_test_support::socket_reality::requirement::{
    RealityProfile, RealityRequirement, requirements,
};
use pkthere_test_support::socket_reality::verify::DerivedFacts;
use pkthere_test_support::socket_reality::{collect, diagnostic, verify};
use pkthere_wire::SupportedProtocol;
#[cfg(unix)]
use socket2::Protocol;
#[cfg(windows)]
use socket2::SockAddr;
use socket2::{Domain, Socket, Type};
#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
#[ignore = "the RAW privilege boundary is measured in the canonical unprivileged platform phase"]
fn unprivileged_raw_privilege_boundary_is_enforced() {
    assert_unprivileged_raw_privilege_boundary();
}

#[cfg(unix)]
fn assert_unprivileged_raw_privilege_boundary() {
    for (domain, protocol) in [
        (Domain::IPV4, Protocol::ICMPV4),
        (Domain::IPV6, Protocol::ICMPV6),
    ] {
        let error = Socket::new(domain, Type::RAW, Some(protocol))
            .err()
            .unwrap_or_else(|| panic!("unprivileged process unexpectedly opened {domain:?} RAW"));
        eprintln!(
            "socket-unprivileged-raw-boundary stage=creation domain={domain:?} kind={:?} os_code={:?}",
            error.kind(),
            error.raw_os_error()
        );
    }
}

#[cfg(windows)]
fn assert_unprivileged_raw_privilege_boundary() {
    let specification = pkthere_socket_policy::socket_create_spec(
        pkthere_socket_policy::SocketCreationPath::WindowsProtocolZeroCapture,
        SupportedProtocol::ICMP,
        Domain::IPV4,
    );
    let socket = match Socket::new(
        specification.domain,
        specification.socket_type,
        specification.protocol,
    ) {
        Ok(socket) => socket,
        Err(error) => {
            require_permission_denied("protocol-zero RAW creation", &error);
            return;
        }
    };
    let address = SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    if let Err(error) = socket.bind(&address) {
        require_permission_denied("protocol-zero interface bind", &error);
        return;
    }
    let error = collect::configure_protocol_zero_capture(&socket)
        .err()
        .unwrap_or_else(|| panic!("unprivileged process unexpectedly enabled SIO_RCVALL"));
    require_permission_denied("SIO_RCVALL", &error);
}

#[cfg(windows)]
fn require_permission_denied(stage: &str, error: &io::Error) {
    assert_eq!(
        error.kind(),
        io::ErrorKind::PermissionDenied,
        "unprivileged {stage} failed for a non-privilege reason: {error}"
    );
    eprintln!(
        "socket-unprivileged-raw-boundary stage={stage} kind={:?} os_code={:?}",
        error.kind(),
        error.raw_os_error()
    );
}

#[test]
#[ignore = "native unprivileged socket reality runs through the canonical platform lifecycle"]
fn udp_reality_matches_policy() {
    for domain in [Domain::IPV4, Domain::IPV6] {
        collect::route_probe_bind_before_connect_required(domain).unwrap_or_else(|error| {
            panic!("collect route-probe bind reality for {domain:?}: {error}")
        });
    }
    run_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::UDP && !case.operation.uses_forwarder_lifecycle()
    });
}

#[test]
#[ignore = "native UDP lifecycle reality runs through the canonical pre-privilege platform phase"]
fn udp_lifecycle_reality_matches_policy() {
    run_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::UDP && case.operation.uses_forwarder_lifecycle()
    });
}

#[test]
#[ignore = "native unprivileged socket reality runs through the canonical platform lifecycle"]
fn icmp_dgram_reality_matches_policy() {
    let required_cases = matching_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::DGRAM
    });
    assert!(
        !required_cases.is_empty(),
        "every native platform requires ICMP DGRAM creation evidence"
    );
    run_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::DGRAM
    });
}

#[test]
#[ignore = "privileged RAW socket reality runs explicitly after platform capability setup"]
fn raw_icmp_forwarder_packet_dump_matches_policy() {
    assert!(
        pkthere_test_support::runtime_capability::raw_icmp_socket_io(),
        "privileged RAW socket reality requires explicit enablement and platform RAW socket support"
    );
    run_requirements(RealityProfile::Privileged, |case| {
        case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::RAW
    });
}

fn run_requirements(profile: RealityProfile, include: impl Fn(RealityCase) -> bool) {
    let selected = matching_requirements(profile, include);
    assert!(
        !selected.is_empty(),
        "socket reality selection must contain at least one authoritative requirement"
    );
    let failures = selected
        .into_iter()
        .filter_map(|requirement| run_requirement(requirement).err())
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "socket reality matrix contained {} failure(s):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

fn reality_mismatch(case: RealityCase, detail: impl std::fmt::Display) -> String {
    format!("socket reality mismatch for {case:?}: {detail}")
}

fn require_policy_match<T>(
    case: RealityCase,
    committed: T,
    measured: T,
    context: &str,
) -> Result<(), String>
where
    T: std::fmt::Debug + PartialEq,
{
    if committed == measured {
        Ok(())
    } else {
        Err(reality_mismatch(
            case,
            format_args!("{context}; committed={committed:?}, measured={measured:?}"),
        ))
    }
}

fn matching_requirements(
    profile: RealityProfile,
    include: impl Fn(RealityCase) -> bool,
) -> Vec<RealityRequirement> {
    requirements(profile)
        .into_iter()
        .filter(|requirement| include(requirement.case))
        .collect()
}

fn run_requirement(requirement: RealityRequirement) -> Result<(), String> {
    let case = requirement.case;
    let evidence = collect::collect(requirement)
        .map_err(|error| reality_mismatch(case, format_args!("collection failed: {error}")))?;
    let verified = verify::verify_requirement(requirement, &evidence).map_err(|error| {
        reality_mismatch(
            case,
            format_args!("verification failed: {error}; recorded evidence: {evidence:#?}"),
        )
    })?;
    eprintln!(
        "socket-reality {}",
        diagnostic::diagnostic_json(&verified, &evidence)
    );
    if let DerivedFacts::ListenerOwnerReplacement { supported, .. } = &verified.facts {
        let worker = pkthere_socket_policy::listener_worker_socket_policy(2, false);
        let committed_supported = pkthere_socket_policy::same_bind_replacement_lifecycle_supported(
            pkthere_socket_policy::SameBindReplacementRealityKey {
                disconnect: pkthere_socket_policy::DisconnectRealityKey {
                    platform: pkthere_socket_policy::SocketPlatform::current(),
                    family: case.domain,
                    protocol: case.protocol,
                    socket_type: case.socket_type,
                    role: case.policy_role,
                    creation_path: case.socket_path,
                    bind_shape: pkthere_socket_policy::DisconnectBindShape::ConcreteEphemeral,
                    reuse_address: worker.reuse_address,
                    reuse_port: worker.reuse_port,
                    v6_only: None,
                    receive_header: verified.policy.receive_header,
                    protocol_zero_capture: false,
                    bound_interface: None,
                    connected_peer_mode: verified.policy.peer_verification,
                },
                distribution: worker.distribution,
                stale_handles_retained: true,
            },
        );
        require_policy_match(
            case,
            committed_supported,
            *supported,
            "production same-bind replacement lifecycle differs from independent kernel evidence",
        )?;
    }
    if let DerivedFacts::DatagramDisconnect { capability, .. } = &verified.facts {
        let committed =
            pkthere_socket_policy::datagram_disconnect_evidence(case.protocol, case.domain);
        require_policy_match(
            case,
            committed,
            pkthere_socket_policy::CapabilityEvidence::Measured {
                capability: *capability,
                evidence_id: pkthere_socket_policy::CapabilityEvidenceId::DatagramUdpPlatformMatrix,
            },
            "committed datagram disconnect policy differs from independent kernel evidence",
        )?;
    }
    if let DerivedFacts::SocketDisconnect {
        evidence_id,
        association_clear_supported,
        exact_local_bind_preserved,
        reconnect_after_disconnect_supported,
        peer_inspection_supported,
        stale_receive_queue_isolated,
    } = &verified.facts
    {
        let committed = pkthere_socket_policy::socket_disconnect_evidence(
            pkthere_socket_policy::DisconnectRealityKey {
                platform: pkthere_socket_policy::SocketPlatform::current(),
                family: case.domain,
                protocol: case.protocol,
                socket_type: case.socket_type,
                role: case.policy_role,
                creation_path: case.socket_path,
                bind_shape: pkthere_socket_policy::DisconnectBindShape::ConcreteEphemeral,
                reuse_address: false,
                reuse_port: false,
                v6_only: None,
                receive_header: verified.policy.receive_header,
                protocol_zero_capture: case.socket_path
                    == pkthere_socket_policy::SocketCreationPath::WindowsProtocolZeroCapture,
                bound_interface: None,
                connected_peer_mode: verified.policy.peer_verification,
            },
        );
        require_policy_match(
            case,
            committed,
            pkthere_socket_policy::CapabilityEvidence::Measured {
                capability: pkthere_socket_policy::SocketDisconnectCapability {
                    association_clear_supported: *association_clear_supported,
                    exact_local_bind_preserved: *exact_local_bind_preserved,
                    reconnect_after_disconnect_supported: *reconnect_after_disconnect_supported,
                    peer_inspection_supported: *peer_inspection_supported,
                    stale_receive_queue_isolated: *stale_receive_queue_isolated,
                },
                evidence_id: *evidence_id,
            },
            "committed socket disconnect policy differs from independent runtime evidence",
        )?;
    }
    Ok(())
}
