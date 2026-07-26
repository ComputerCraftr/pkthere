use super::{
    CollectionAuthority, RealityPlatform, RealityProfile, icmp_dgram_requirements,
    lifecycle_requirements, raw_requirements, requirements,
};
use crate::socket_reality::case::{ConnectionScenario, RealityOperation};
use pkthere_socket_policy::{SocketPlatform, SocketRole, icmp_platform_capabilities};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Protocol, Type};
use std::collections::HashSet;

#[test]
fn requirement_manifest_is_unique_and_required() {
    for profile in [RealityProfile::Native, RealityProfile::Privileged] {
        let rows = requirements(profile);
        let unique = rows
            .iter()
            .map(|requirement| format!("{:?}", requirement.case))
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), rows.len());
        assert!(rows.iter().all(|row| row.required));
    }
}

#[test]
fn native_manifest_always_requires_udp_for_both_families() {
    let rows = requirements(RealityProfile::Native);
    for domain in [Domain::IPV4, Domain::IPV6] {
        for operation in [
            RealityOperation::DatagramReceiveEvidence,
            RealityOperation::DatagramDisconnect,
            RealityOperation::ConnectedPeerFiltering,
            RealityOperation::ReusePortFanout,
        ] {
            assert!(rows.iter().any(|row| {
                row.case.domain == domain
                    && row.case.protocol == SupportedProtocol::UDP
                    && row.case.operation == operation
            }));
        }
        assert!(rows.iter().any(|row| {
            row.case.domain == domain
                && row.case.operation == RealityOperation::ListenerOwnerReplacement
        }));
        for role in [SocketRole::Listener, SocketRole::Upstream] {
            assert!(rows.iter().any(|row| {
                row.case.domain == domain
                    && row.case.operation == RealityOperation::ConnectedPeerFiltering
                    && row.case.policy_role == role
            }));
        }
    }
    assert_eq!(rows[0].platform, RealityPlatform::current());
}

#[test]
fn icmp_dgram_manifest_separates_dynamic_and_fixed_id_kernel_evidence() {
    for platform in [
        RealityPlatform::Linux,
        RealityPlatform::Android,
        RealityPlatform::Macos,
        RealityPlatform::Windows,
        RealityPlatform::Freebsd,
    ] {
        let rows = icmp_dgram_requirements(platform);
        for domain in [Domain::IPV4, Domain::IPV6] {
            for operation in [
                RealityOperation::IcmpDgramReceiveId,
                RealityOperation::IcmpDgramFixedId,
                RealityOperation::IcmpDgramSharedId,
                RealityOperation::SocketDisconnect,
            ] {
                assert!(rows.iter().any(|row| {
                    row.case.domain == domain
                        && row.case.operation == operation
                        && row.case.protocol == SupportedProtocol::ICMP
                        && row.case.socket_type == Type::DGRAM
                        && row.case.policy_role == SocketRole::Upstream
                        && row.case.connection_scenario == ConnectionScenario::DirectConnected
                }));
            }
        }
    }
}

#[test]
fn every_platform_attempts_icmp_dgram_as_the_production_primary_candidate() {
    for platform in [RealityPlatform::Windows, RealityPlatform::Freebsd] {
        let rows = icmp_dgram_requirements(platform);
        assert!(!rows.is_empty());
        for domain in [Domain::IPV4, Domain::IPV6] {
            assert!(rows.iter().any(|row| {
                row.platform == platform
                    && row.case.domain == domain
                    && row.case.protocol == SupportedProtocol::ICMP
                    && row.case.socket_type == Type::DGRAM
                    && row.collection_authority == CollectionAuthority::DirectSocket
            }));
        }
    }
}

#[test]
fn windows_raw_manifest_probes_regular_raw_and_protocol_zero_paths_once() {
    let capabilities = icmp_platform_capabilities(SocketPlatform::Windows);
    assert!(
        !capabilities.raw_to_bound_raw_loopback,
        "global protocol-zero capture is not isolated bound-socket routing"
    );

    let rows = raw_requirements(RealityPlatform::Windows);
    let raw_receive_rows = rows
        .iter()
        .filter(|row| row.case.operation == RealityOperation::RawReceiveEvidence)
        .collect::<Vec<_>>();
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        for (domain, path, protocol) in [
            (
                Domain::IPV4,
                crate::socket_reality::case::RealitySocketPath::RawIcmp,
                Protocol::ICMPV4,
            ),
            (
                Domain::IPV6,
                crate::socket_reality::case::RealitySocketPath::RawIcmp,
                Protocol::ICMPV6,
            ),
        ] {
            assert!(raw_receive_rows.iter().any(|row| {
                row.case.domain == domain
                    && row.case.socket_path == path
                    && row.case.policy_role == role
                    && row.case.socket_create_spec().protocol == Some(protocol)
            }));
        }
    }
    for row in raw_receive_rows {
        let spec = row.case.socket_create_spec();
        assert_eq!(spec.socket_type, Type::RAW);
        assert_eq!(
            row.collection_authority,
            CollectionAuthority::DirectSocket,
            "regular Windows RAW support must be proven directly"
        );
    }
    let four_id_rows = rows
        .iter()
        .filter(|row| row.case.operation == RealityOperation::RawFourIdForwarding)
        .collect::<Vec<_>>();
    assert_eq!(four_id_rows.len(), 1);
    assert_eq!(
        four_id_rows[0].case.socket_path,
        crate::socket_reality::case::RealitySocketPath::WindowsProtocolZeroCapture
    );
    assert_eq!(
        four_id_rows[0].case.socket_create_spec().protocol,
        Some(Protocol::from(0))
    );
    assert_eq!(
        four_id_rows[0].collection_authority,
        CollectionAuthority::PreparedForwarder
    );
    let protocol_zero_disconnect_rows = rows
        .iter()
        .filter(|row| {
            row.case.operation == RealityOperation::SocketDisconnect
                && row.case.socket_path
                    == crate::socket_reality::case::RealitySocketPath::WindowsProtocolZeroCapture
        })
        .collect::<Vec<_>>();
    assert_eq!(protocol_zero_disconnect_rows.len(), 2);
    for row in protocol_zero_disconnect_rows {
        assert_eq!(row.collection_authority, CollectionAuthority::DirectSocket);
        assert_eq!(
            row.case.socket_create_spec().protocol,
            Some(Protocol::from(0))
        );
    }
    let ordinary_ipv4_raw_rows = rows.iter().filter(|row| {
        row.case.domain == Domain::IPV4
            && row.case.socket_path == crate::socket_reality::case::RealitySocketPath::RawIcmp
    });
    assert_eq!(ordinary_ipv4_raw_rows.count(), 4);
}

#[test]
fn native_ci_platforms_require_every_lifecycle_operation() {
    for platform in [
        RealityPlatform::Linux,
        RealityPlatform::Macos,
        RealityPlatform::Windows,
        RealityPlatform::Freebsd,
    ] {
        let rows = lifecycle_requirements(platform);
        for operation in [
            RealityOperation::UpstreamReconnect,
            RealityOperation::ListenerRelock,
            RealityOperation::ListenerRebind,
        ] {
            assert!(
                rows.iter().any(|row| row.case.operation == operation),
                "{platform:?} omitted {operation:?}"
            );
        }
    }
}

#[test]
fn lifecycle_manifest_covers_production_and_forced_unconnected_debug_udp_lifecycles() {
    for platform in [
        RealityPlatform::Linux,
        RealityPlatform::Macos,
        RealityPlatform::Windows,
        RealityPlatform::Freebsd,
    ] {
        let rows = lifecycle_requirements(platform);
        for domain in [Domain::IPV4, Domain::IPV6] {
            for connection_scenario in [
                ConnectionScenario::ProductionPolicy,
                ConnectionScenario::ForcedUnconnectedDebug,
            ] {
                assert!(rows.iter().any(|row| {
                    row.case.domain == domain
                        && row.case.target_domain == Some(domain)
                        && row.case.protocol == SupportedProtocol::UDP
                        && row.case.operation == RealityOperation::UpstreamReconnect
                        && row.case.connection_scenario == connection_scenario
                }));
            }
            for connection_scenario in [
                ConnectionScenario::ProductionPolicy,
                ConnectionScenario::ForcedUnconnectedDebug,
            ] {
                assert!(rows.iter().any(|row| {
                    row.case.domain == domain
                        && row.case.target_domain == Some(domain)
                        && row.case.protocol == SupportedProtocol::UDP
                        && row.case.operation == RealityOperation::ListenerRelock
                        && row.case.connection_scenario == connection_scenario
                }));
            }
        }
    }
}

#[test]
fn privileged_manifest_separates_raw_socket_io_from_bound_raw_request_delivery() {
    for platform in [
        RealityPlatform::Linux,
        RealityPlatform::Android,
        RealityPlatform::Macos,
        RealityPlatform::Windows,
        RealityPlatform::Freebsd,
    ] {
        let rows = raw_requirements(platform);
        for domain in [Domain::IPV4, Domain::IPV6] {
            assert!(rows.iter().any(|row| {
                row.case.domain == domain
                    && row.case.operation == RealityOperation::RawReceiveEvidence
                    && row.collection_authority
                        == if platform == RealityPlatform::Windows {
                            CollectionAuthority::DirectSocket
                        } else {
                            CollectionAuthority::DirectSocketOrPreparedPrivilegedForwarder
                        }
            }));
            assert!(rows.iter().any(|row| {
                row.case.domain == domain
                    && row.case.operation == RealityOperation::SocketDisconnect
                    && row.case.protocol == SupportedProtocol::ICMP
                    && row.case.socket_type == Type::RAW
                    && row.case.connection_scenario == ConnectionScenario::DirectConnected
                    && row.collection_authority == CollectionAuthority::DirectSocket
            }));
        }
        assert_eq!(
            rows.iter()
                .any(|row| row.case.operation == RealityOperation::RawFourIdForwarding),
            matches!(
                platform,
                RealityPlatform::Linux | RealityPlatform::Android | RealityPlatform::Windows
            )
        );
    }
}
