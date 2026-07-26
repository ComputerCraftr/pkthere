use super::case::{ConnectionScenario, RealityCase, RealityOperation, RealitySocketPath};
use pkthere_socket_policy::{SocketPlatform, SocketRole};
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
        match SocketPlatform::current() {
            SocketPlatform::Linux => Self::Linux,
            SocketPlatform::Android => Self::Android,
            SocketPlatform::Macos | SocketPlatform::Ios => Self::Macos,
            SocketPlatform::Windows => Self::Windows,
            SocketPlatform::Freebsd => Self::Freebsd,
            SocketPlatform::Other => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealityProfile {
    Native,
    Privileged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionAuthority {
    DirectSocket,
    DirectSocketOrPreparedPrivilegedForwarder,
    PreparedForwarder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealityRequirement {
    pub platform: RealityPlatform,
    pub case: RealityCase,
    pub collection_authority: CollectionAuthority,
    pub required: bool,
    pub coverage_owner: &'static str,
}

pub fn requirements(profile: RealityProfile) -> Vec<RealityRequirement> {
    let platform = RealityPlatform::current();
    let mut rows = native_udp_requirements(platform);
    if !matches!(platform, RealityPlatform::Other) {
        rows.extend(icmp_dgram_requirements(platform));
    }
    if matches!(
        platform,
        RealityPlatform::Linux
            | RealityPlatform::Macos
            | RealityPlatform::Windows
            | RealityPlatform::Freebsd
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
        for connection_scenario in [
            ConnectionScenario::ProductionPolicy,
            ConnectionScenario::ForcedUnconnectedDebug,
        ] {
            rows.push(forwarder_required(
                platform,
                RealityCase {
                    domain,
                    target_domain: Some(domain),
                    protocol: SupportedProtocol::UDP,
                    socket_type: Type::DGRAM,
                    socket_path: RealitySocketPath::Datagram,
                    policy_role: SocketRole::Upstream,
                    connection_scenario,
                    operation: RealityOperation::UpstreamReconnect,
                },
                if connection_scenario == ConnectionScenario::ProductionPolicy {
                    "connected_upstream_reconnect_external_witness"
                } else {
                    "unconnected_upstream_metadata_refresh_external_witness"
                },
            ));
        }
        for connection_scenario in [
            ConnectionScenario::ProductionPolicy,
            ConnectionScenario::ForcedUnconnectedDebug,
        ] {
            rows.push(forwarder_required(
                platform,
                RealityCase {
                    domain,
                    target_domain: Some(domain),
                    protocol: SupportedProtocol::UDP,
                    socket_type: Type::DGRAM,
                    socket_path: RealitySocketPath::Datagram,
                    policy_role: SocketRole::Listener,
                    connection_scenario,
                    operation: RealityOperation::ListenerRelock,
                },
                if connection_scenario == ConnectionScenario::ProductionPolicy {
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
        rows.push(forwarder_required(
            platform,
            RealityCase {
                domain: Domain::IPV4,
                target_domain: Some(Domain::IPV6),
                protocol: SupportedProtocol::UDP,
                socket_type: Type::DGRAM,
                socket_path: RealitySocketPath::Datagram,
                policy_role: role,
                connection_scenario: if operation == RealityOperation::UpstreamReconnect {
                    ConnectionScenario::ProductionPolicy
                } else {
                    ConnectionScenario::DirectUnconnected
                },
                operation,
            },
            "cross_family_socket_replacement_external_witness",
        ));
    }
    rows.push(forwarder_required(
        platform,
        RealityCase {
            domain: Domain::IPV4,
            target_domain: Some(Domain::IPV4),
            protocol: SupportedProtocol::UDP,
            socket_type: Type::DGRAM,
            socket_path: RealitySocketPath::Datagram,
            policy_role: SocketRole::Listener,
            connection_scenario: ConnectionScenario::DirectUnconnected,
            operation: RealityOperation::ListenerRebind,
        },
        "listener_rebind_external_witness",
    ));
    rows
}

fn native_udp_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    let mut rows = [Domain::IPV4, Domain::IPV6]
        .into_iter()
        .flat_map(|domain| {
            [
                direct_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connection_scenario: ConnectionScenario::DirectUnconnected,
                        operation: RealityOperation::DatagramReceiveEvidence,
                    },
                    "udp_source_metadata_and_port_truth",
                ),
                direct_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::DatagramDisconnect,
                    },
                    "udp_disconnect_postconditions",
                ),
                direct_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::ConnectedPeerFiltering,
                    },
                    "udp_connected_peer_filtering",
                ),
                direct_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::ConnectedPeerFiltering,
                    },
                    "udp_connected_upstream_recv_filtering",
                ),
                direct_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::UDP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Listener,
                        connection_scenario: ConnectionScenario::DirectUnconnected,
                        operation: RealityOperation::ReusePortFanout,
                    },
                    "reuse_port_bind_and_flow_fanout",
                ),
            ]
        })
        .collect::<Vec<_>>();
    rows.extend([Domain::IPV4, Domain::IPV6].into_iter().map(|domain| {
        direct_required(
            platform,
            RealityCase {
                domain,
                target_domain: None,
                protocol: SupportedProtocol::UDP,
                socket_type: Type::DGRAM,
                socket_path: RealitySocketPath::Datagram,
                policy_role: SocketRole::Listener,
                connection_scenario: ConnectionScenario::DirectUnconnected,
                operation: RealityOperation::ListenerOwnerReplacement,
            },
            "listener_same_bind_owner_replacement_measurement",
        )
    }));
    rows
}

fn icmp_dgram_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    [Domain::IPV4, Domain::IPV6]
        .into_iter()
        .flat_map(|domain| {
            [
                icmp_dgram_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::IcmpDgramReceiveId,
                    },
                    "icmp_dgram_realized_echo_id",
                ),
                icmp_dgram_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::IcmpDgramFixedId,
                    },
                    "icmp_dgram_fixed_bind_id",
                ),
                icmp_dgram_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::IcmpDgramSharedId,
                    },
                    "icmp_dgram_shared_fixed_id_reuse",
                ),
                icmp_dgram_required(
                    platform,
                    RealityCase {
                        domain,
                        target_domain: None,
                        protocol: SupportedProtocol::ICMP,
                        socket_type: Type::DGRAM,
                        socket_path: RealitySocketPath::Datagram,
                        policy_role: SocketRole::Upstream,
                        connection_scenario: ConnectionScenario::DirectConnected,
                        operation: RealityOperation::SocketDisconnect,
                    },
                    "icmp_dgram_disconnect_postconditions",
                ),
            ]
        })
        .collect()
}

fn icmp_dgram_required(
    platform: RealityPlatform,
    case: RealityCase,
    coverage_owner: &'static str,
) -> RealityRequirement {
    direct_required(platform, case, coverage_owner)
}

fn raw_requirements(platform: RealityPlatform) -> Vec<RealityRequirement> {
    let mut rows = Vec::new();
    for domain in [Domain::IPV4, Domain::IPV6] {
        for role in [SocketRole::Listener, SocketRole::Upstream] {
            let disconnect_case = RealityCase {
                domain,
                target_domain: None,
                protocol: SupportedProtocol::ICMP,
                socket_type: Type::RAW,
                socket_path: RealitySocketPath::RawIcmp,
                policy_role: role,
                connection_scenario: ConnectionScenario::DirectConnected,
                operation: RealityOperation::SocketDisconnect,
            };
            rows.push(direct_required(
                platform,
                disconnect_case,
                if platform == RealityPlatform::Windows && domain == Domain::IPV4 {
                    "ordinary_windows_raw_l3_disconnect_evidence"
                } else {
                    "raw_l3_disconnect_postconditions"
                },
            ));
        }
        for role in [SocketRole::Listener, SocketRole::Upstream] {
            let receive_case = RealityCase {
                domain,
                target_domain: None,
                protocol: SupportedProtocol::ICMP,
                socket_type: Type::RAW,
                socket_path: RealitySocketPath::RawIcmp,
                policy_role: role,
                connection_scenario: ConnectionScenario::DirectUnconnected,
                operation: RealityOperation::RawReceiveEvidence,
            };
            rows.push(required(
                platform,
                receive_case,
                if platform == RealityPlatform::Windows {
                    CollectionAuthority::DirectSocket
                } else {
                    CollectionAuthority::DirectSocketOrPreparedPrivilegedForwarder
                },
                if platform == RealityPlatform::Windows && domain == Domain::IPV4 {
                    "ordinary_windows_raw_receive_evidence"
                } else {
                    "raw_receive_layout_kernel_identity_and_disjoint_ids"
                },
            ));
        }
    }
    if platform == RealityPlatform::Windows {
        for role in [SocketRole::Listener, SocketRole::Upstream] {
            rows.push(direct_required(
                platform,
                RealityCase {
                    domain: Domain::IPV4,
                    target_domain: None,
                    protocol: SupportedProtocol::ICMP,
                    socket_type: Type::RAW,
                    socket_path: RealitySocketPath::WindowsProtocolZeroCapture,
                    policy_role: role,
                    connection_scenario: ConnectionScenario::DirectConnected,
                    operation: RealityOperation::SocketDisconnect,
                },
                "windows_protocol_zero_rcvall_l3_connect_disconnect",
            ));
        }
    }
    if matches!(
        platform,
        RealityPlatform::Linux | RealityPlatform::Android | RealityPlatform::Windows
    ) {
        rows.push(forwarder_required(
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
                connection_scenario: ConnectionScenario::DirectUnconnected,
                operation: RealityOperation::RawFourIdForwarding,
            },
            "raw_four_id_forwarding",
        ));
    }
    rows
}

const fn required(
    platform: RealityPlatform,
    case: RealityCase,
    collection_authority: CollectionAuthority,
    coverage_owner: &'static str,
) -> RealityRequirement {
    RealityRequirement {
        platform,
        case,
        collection_authority,
        required: true,
        coverage_owner,
    }
}

const fn direct_required(
    platform: RealityPlatform,
    case: RealityCase,
    coverage_owner: &'static str,
) -> RealityRequirement {
    required(
        platform,
        case,
        CollectionAuthority::DirectSocket,
        coverage_owner,
    )
}

const fn forwarder_required(
    platform: RealityPlatform,
    case: RealityCase,
    coverage_owner: &'static str,
) -> RealityRequirement {
    required(
        platform,
        case,
        CollectionAuthority::PreparedForwarder,
        coverage_owner,
    )
}

#[cfg(test)]
mod tests;
