use super::case::{RealityCase, RealityOperation, RealitySocketPath};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealityPlatform {
    Linux,
    Android,
    Macos,
    Windows,
    Freebsd,
    Other,
}

impl RealityPlatform {
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "freebsd") {
            Self::Freebsd
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealityProfile {
    Native,
    Privileged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealityRequirement {
    pub platform: RealityPlatform,
    pub case: RealityCase,
    pub required: bool,
    pub coverage_owner: &'static str,
}

pub fn requirements(profile: RealityProfile) -> Vec<RealityRequirement> {
    let platform = RealityPlatform::current();
    let mut rows = native_udp_requirements(platform);
    if matches!(
        platform,
        RealityPlatform::Linux | RealityPlatform::Android | RealityPlatform::Macos
    ) {
        rows.extend(icmp_dgram_requirements(platform));
    }
    if matches!(
        platform,
        RealityPlatform::Linux | RealityPlatform::Macos | RealityPlatform::Windows
    ) {
        rows.extend(lifecycle_requirements(platform));
    }
    if profile == RealityProfile::Privileged {
        rows.extend(raw_requirements(platform));
    }
    rows
}

fn lifecycle_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    let mut rows = Vec::new();
    for domain in [Domain::IPV4, Domain::IPV6] {
        for connected in [true, false] {
            rows.push(required(
                platform,
                RealityCase {
                    domain,
                    target_domain: Some(domain),
                    protocol: SupportedProtocol::UDP,
                    socket_type: Type::DGRAM,
                    socket_path: RealitySocketPath::Datagram,
                    policy_role: SocketRole::Upstream,
                    connected,
                    operation: RealityOperation::UpstreamReconnect,
                },
                if connected {
                    "connected_upstream_reconnect_external_witness"
                } else {
                    "unconnected_upstream_metadata_refresh_external_witness"
                },
            ));
        }
        for connected in [true, false] {
            rows.push(required(
                platform,
                RealityCase {
                    domain,
                    target_domain: Some(domain),
                    protocol: SupportedProtocol::UDP,
                    socket_type: Type::DGRAM,
                    socket_path: RealitySocketPath::Datagram,
                    policy_role: SocketRole::Listener,
                    connected,
                    operation: RealityOperation::ListenerRelock,
                },
                if connected {
                    "listener_policy_relock_external_witness"
                } else {
                    "listener_unconnected_relock_external_witness"
                },
            ));
        }
    }
    for (operation, role) in [
        (RealityOperation::UpstreamReconnect, SocketRole::Upstream),
        (RealityOperation::ListenerRebind, SocketRole::Listener),
    ] {
        rows.push(required(
            platform,
            RealityCase {
                domain: Domain::IPV4,
                target_domain: Some(Domain::IPV6),
                protocol: SupportedProtocol::UDP,
                socket_type: Type::DGRAM,
                socket_path: RealitySocketPath::Datagram,
                policy_role: role,
                connected: operation == RealityOperation::UpstreamReconnect,
                operation,
            },
            "cross_family_socket_replacement_external_witness",
        ));
    }
    rows.push(required(
        platform,
        RealityCase {
            domain: Domain::IPV4,
            target_domain: Some(Domain::IPV4),
            protocol: SupportedProtocol::UDP,
            socket_type: Type::DGRAM,
            socket_path: RealitySocketPath::Datagram,
            policy_role: SocketRole::Listener,
            connected: false,
            operation: RealityOperation::ListenerRebind,
        },
        "listener_rebind_external_witness",
    ));
    rows
}

fn native_udp_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    [Domain::IPV4, Domain::IPV6]
        .into_iter()
        .flat_map(|domain| {
            [
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connected: false,
                        operation: RealityOperation::DatagramReceiveEvidence,
                    },
                    "udp_source_metadata_and_port_truth",
                ),
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connected: true,
                        operation: RealityOperation::ConnectedPeerFiltering,
                    },
                    "udp_connected_peer_filtering",
                ),
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connected: true,
                        operation: RealityOperation::ConnectedPeerFiltering,
                    },
                    "udp_connected_upstream_recv_filtering",
                ),
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connected: false,
                        operation: RealityOperation::ReusePortFanout,
                    },
                    "reuse_port_bind_and_flow_fanout",
                ),
            ]
        })
        .collect()
}

fn icmp_dgram_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    [Domain::IPV4, Domain::IPV6]
        .into_iter()
        .flat_map(|domain| {
            [
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connected: true,
                        operation: RealityOperation::IcmpDgramReceiveId,
                    },
                    "icmp_dgram_kernel_receive_id",
                ),
                required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connected: true,
                        operation: RealityOperation::IcmpDgramFixedId,
                    },
                    "icmp_dgram_fixed_bind_id",
                ),
            ]
        })
        .collect()
}

fn raw_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    let mut rows = Vec::new();
    for domain in [Domain::IPV4, Domain::IPV6] {
        for role in [SocketRole::Listener, SocketRole::Upstream] {
            rows.push(required(
                platform,
                RealityCase {
                    domain,
                    target_domain: None,
                    protocol: SupportedProtocol::ICMP,
                    socket_type: Type::RAW,
                    socket_path: RealitySocketPath::RawIcmp,
                    policy_role: role,
                    connected: false,
                    operation: RealityOperation::RawReceiveEvidence,
                },
                "raw_receive_layout_kernel_identity_and_disjoint_ids",
            ));
        }
    }
    rows.push(required(
        platform,
        RealityCase {
            domain: Domain::IPV4,
            target_domain: None,
            protocol: SupportedProtocol::ICMP,
            socket_type: Type::RAW,
            socket_path: if platform == RealityPlatform::Windows {
                RealitySocketPath::WindowsProtocolZeroCapture
            } else {
                RealitySocketPath::RawIcmp
            },
            policy_role: SocketRole::Upstream,
            connected: false,
            operation: RealityOperation::RawFourIdForwarding,
        },
        "raw_four_id_forwarding",
    ));
    rows
}

const fn required(
    platform: RealityPlatform,
    case: RealityCase,
    coverage_owner: &'static str,
) -> RealityRequirement {
    RealityRequirement {
        platform,
        case,
        required: true,
        coverage_owner,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RealityPlatform, RealityProfile, icmp_dgram_requirements, lifecycle_requirements,
        raw_requirements, requirements,
    };
    use crate::socket_reality::case::RealityOperation;
    use pkthere_socket_policy::SocketRole;
    use pkthere_wire::SupportedProtocol;
    use socket2::{Domain, Protocol, Type};
    use std::collections::HashSet;

    #[test]
    fn requirement_manifest_is_unique_and_policy_independent() {
        let source = include_str!("requirement.rs");
        for forbidden in [
            ["upstream", "_icmp", "_requires", "_raw"].concat(),
            ["resolve", "_socket", "_policy"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }

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
                RealityOperation::ConnectedPeerFiltering,
                RealityOperation::ReusePortFanout,
            ] {
                assert!(rows.iter().any(|row| {
                    row.case.domain == domain
                        && row.case.protocol == SupportedProtocol::UDP
                        && row.case.operation == operation
                }));
            }
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
        ] {
            let rows = icmp_dgram_requirements(platform);
            for domain in [Domain::IPV4, Domain::IPV6] {
                for operation in [
                    RealityOperation::IcmpDgramReceiveId,
                    RealityOperation::IcmpDgramFixedId,
                ] {
                    assert!(rows.iter().any(|row| {
                        row.case.domain == domain
                            && row.case.operation == operation
                            && row.case.protocol == SupportedProtocol::ICMP
                            && row.case.socket_type == Type::DGRAM
                            && row.case.policy_role == SocketRole::Upstream
                            && row.case.connected
                    }));
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_manifest_omits_unsupported_icmp_dgram_sockets() {
        assert!(
            requirements(RealityProfile::Native)
                .iter()
                .all(|row| !(row.case.protocol == SupportedProtocol::ICMP
                    && row.case.socket_type == Type::DGRAM))
        );
    }

    #[test]
    fn windows_raw_manifest_probes_regular_raw_and_protocol_zero_paths_once() {
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
    }

    #[test]
    fn native_ci_platforms_require_every_lifecycle_operation() {
        for platform in [
            RealityPlatform::Linux,
            RealityPlatform::Macos,
            RealityPlatform::Windows,
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
    fn lifecycle_manifest_covers_connected_and_unconnected_udp_reconnect_and_dual_stack_relock() {
        for platform in [
            RealityPlatform::Linux,
            RealityPlatform::Macos,
            RealityPlatform::Windows,
        ] {
            let rows = lifecycle_requirements(platform);
            for domain in [Domain::IPV4, Domain::IPV6] {
                for connected in [true, false] {
                    assert!(rows.iter().any(|row| {
                        row.case.domain == domain
                            && row.case.target_domain == Some(domain)
                            && row.case.protocol == SupportedProtocol::UDP
                            && row.case.operation == RealityOperation::UpstreamReconnect
                            && row.case.connected == connected
                    }));
                }
                for connected in [true, false] {
                    assert!(rows.iter().any(|row| {
                        row.case.domain == domain
                            && row.case.target_domain == Some(domain)
                            && row.case.protocol == SupportedProtocol::UDP
                            && row.case.operation == RealityOperation::ListenerRelock
                            && row.case.connected == connected
                    }));
                }
            }
        }
    }

    #[test]
    fn privileged_manifest_requires_raw_receive_and_four_id_forwarding() {
        for platform in [
            RealityPlatform::Linux,
            RealityPlatform::Macos,
            RealityPlatform::Windows,
        ] {
            let rows = raw_requirements(platform);
            for domain in [Domain::IPV4, Domain::IPV6] {
                assert!(rows.iter().any(|row| {
                    row.case.domain == domain
                        && row.case.operation == RealityOperation::RawReceiveEvidence
                }));
            }
            assert!(
                rows.iter()
                    .any(|row| row.case.operation == RealityOperation::RawFourIdForwarding)
            );
        }
    }
}
