use super::super::listener_lifecycle::listener_lock_lifecycle_with_contract;
use super::super::{
    CapabilityEvidence, CapabilityEvidenceId, CapabilityUnsupportedReason,
    CapabilityUnverifiedReason, DisconnectBindShape, DisconnectRealityKey, IcmpChecksumMode,
    IcmpPolicyIntent, IpHeaderMode, PeerVerification, ProtocolPolicyIntent, ReceiveCaptureScope,
    ResolvedDisconnectContract, SocketCreationPath, SocketDisconnectCapability, SocketPathContext,
    SocketPlatform, SocketRole, TimeoutAction, datagram_disconnect_evidence_for,
    icmp_platform_capabilities, listener_reresolve_mode,
    listener_same_bind_replacement_lifecycle_eligible, listener_worker_socket_policy,
    resolve_receive_header_mode_for_platform,
    resolve_socket_policy_for_creation_path_with_protocol_intent, socket_disconnect_evidence,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::{Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use socket2::{Domain, Type};

fn datagram_disconnect_capability_for(
    platform: SocketPlatform,
    protocol: SupportedProtocol,
    family: Domain,
) -> super::super::DatagramDisconnectCapability {
    datagram_disconnect_evidence_for(platform, protocol, family)
        .measured()
        .expect("test platform row has measured UDP disconnect evidence")
}

#[test]
fn creation_path_selects_send_and_capture_framing() {
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        let capture = resolve_socket_policy_for_creation_path_with_protocol_intent(
            role,
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            Type::RAW,
            TimeoutAction::Drop,
            false,
            SocketPathContext {
                family: Domain::IPV4,
                creation_path: SocketCreationPath::WindowsProtocolZeroCapture,
            },
        );
        assert_eq!(
            capture.send_policy.ip_header,
            IpHeaderMode::Ipv4HeaderIncluded
        );
        assert_eq!(
            capture.send_policy.icmp_checksum,
            IcmpChecksumMode::ApplicationComputed
        );
        assert_eq!(
            capture.receive_capture_scope,
            ReceiveCaptureScope::InterfaceIpv4
        );

        let protocol_filtered = resolve_socket_policy_for_creation_path_with_protocol_intent(
            role,
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            Type::RAW,
            TimeoutAction::Drop,
            false,
            SocketPathContext {
                family: Domain::IPV4,
                creation_path: SocketCreationPath::RawIcmp,
            },
        );
        assert_eq!(
            protocol_filtered.send_policy.ip_header,
            IpHeaderMode::PayloadOnly
        );
        assert_eq!(
            protocol_filtered.receive_capture_scope,
            ReceiveCaptureScope::ProtocolFiltered
        );
    }
}

#[test]
fn icmpv6_send_policy_explicitly_delegates_checksum_to_kernel() {
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        for socket_type in [Type::DGRAM, Type::RAW] {
            let policy = resolve_socket_policy_for_creation_path_with_protocol_intent(
                role,
                ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
                socket_type,
                TimeoutAction::Drop,
                false,
                SocketPathContext {
                    family: Domain::IPV6,
                    creation_path: if socket_type == Type::DGRAM {
                        SocketCreationPath::Datagram
                    } else {
                        SocketCreationPath::RawIcmp
                    },
                },
            );
            assert_eq!(
                policy.send_policy.icmp_checksum,
                IcmpChecksumMode::KernelComputed
            );
        }
    }
}

#[test]
fn icmp_platform_capability_matrix_is_complete_and_conservative() {
    for platform in [SocketPlatform::Linux, SocketPlatform::Android] {
        let capabilities = icmp_platform_capabilities(platform);
        assert!(capabilities.shared_dgram_echo_id);
        assert!(capabilities.kernel_assigned_dgram_ids);
        assert!(capabilities.kernel_computed_dgram_checksum);
        assert!(capabilities.fixed_dgram_ids_honored);
        assert!(capabilities.dgram_to_bound_raw_loopback);
        assert!(capabilities.raw_to_bound_raw_loopback);
        assert_eq!(
            capabilities.icmp_v4_dgram_receive_header,
            ReceiveHeaderMode::TransportHeaderOnly
        );
        assert_eq!(
            capabilities.ipv4_receive_length,
            Ipv4PacketLengthEncoding::NetworkTotal
        );
    }

    let macos = icmp_platform_capabilities(SocketPlatform::Macos);
    assert!(macos.shared_dgram_echo_id);
    assert!(!macos.kernel_assigned_dgram_ids);
    assert!(!macos.kernel_computed_dgram_checksum);
    assert!(macos.fixed_dgram_ids_honored);
    assert!(!macos.dgram_to_bound_raw_loopback);
    assert!(!macos.raw_to_bound_raw_loopback);
    assert_eq!(
        macos.icmp_v4_dgram_receive_header,
        ReceiveHeaderMode::IpHeaderIncluded
    );
    assert_eq!(
        macos.ipv4_receive_length,
        Ipv4PacketLengthEncoding::DarwinHostPayload
    );

    let ios = icmp_platform_capabilities(SocketPlatform::Ios);
    assert!(!ios.shared_dgram_echo_id);
    assert!(!ios.kernel_assigned_dgram_ids);
    assert!(!ios.kernel_computed_dgram_checksum);
    assert!(!ios.fixed_dgram_ids_honored);
    assert!(!ios.raw_to_bound_raw_loopback);
    assert_eq!(
        ios.icmp_v4_dgram_receive_header,
        ReceiveHeaderMode::IpHeaderIncluded
    );
    assert_eq!(
        ios.ipv4_receive_length,
        Ipv4PacketLengthEncoding::DarwinHostPayload
    );

    let windows = icmp_platform_capabilities(SocketPlatform::Windows);
    assert!(!windows.shared_dgram_echo_id);
    assert!(!windows.kernel_assigned_dgram_ids);
    assert!(!windows.kernel_computed_dgram_checksum);
    assert!(!windows.fixed_dgram_ids_honored);
    assert!(
        !windows.raw_to_bound_raw_loopback,
        "protocol-zero capture proves Windows forwarding but not isolated routing to separately bound RAW sockets"
    );
    assert_eq!(
        windows.icmp_v4_dgram_receive_header,
        ReceiveHeaderMode::TransportHeaderOnly
    );
    assert_eq!(
        windows.ipv4_receive_length,
        Ipv4PacketLengthEncoding::NetworkTotal
    );

    for platform in [SocketPlatform::Freebsd, SocketPlatform::Other] {
        let capabilities = icmp_platform_capabilities(platform);
        assert!(!capabilities.shared_dgram_echo_id);
        assert!(!capabilities.kernel_assigned_dgram_ids);
        assert!(!capabilities.kernel_computed_dgram_checksum);
        assert!(!capabilities.fixed_dgram_ids_honored);
        assert!(!capabilities.raw_to_bound_raw_loopback);
        assert_eq!(
            capabilities.icmp_v4_dgram_receive_header,
            ReceiveHeaderMode::TransportHeaderOnly
        );
        assert_eq!(
            capabilities.ipv4_receive_length,
            Ipv4PacketLengthEncoding::NetworkTotal
        );
    }
}

#[test]
fn same_bind_listener_replacement_lifecycle_table_records_committed_measurements() {
    for family in [Domain::IPV4, Domain::IPV6] {
        for platform in [
            SocketPlatform::Linux,
            SocketPlatform::Macos,
            SocketPlatform::Windows,
            SocketPlatform::Freebsd,
        ] {
            let shared = crate::creation::listener_worker_socket_policy_for(platform, 2, false);
            assert!(listener_same_bind_replacement_lifecycle_eligible(
                platform, family, shared
            ));
            let adjacent = crate::ListenerWorkerSocketPolicy {
                reuse_port: !shared.reuse_port,
                ..shared
            };
            assert!(
                !listener_same_bind_replacement_lifecycle_eligible(platform, family, adjacent),
                "{platform:?} must not inherit replacement evidence from an adjacent reuse fingerprint"
            );
        }
        for platform in [
            SocketPlatform::Android,
            SocketPlatform::Ios,
            SocketPlatform::Other,
        ] {
            let shared = crate::creation::listener_worker_socket_policy_for(platform, 2, false);
            assert!(
                !listener_same_bind_replacement_lifecycle_eligible(platform, family, shared),
                "{platform:?} has no exact same-bind replacement lifecycle evidence"
            );
        }
    }
}

#[test]
fn measured_platforms_authorize_the_exact_same_bind_lifecycle() {
    for platform in [
        SocketPlatform::Linux,
        SocketPlatform::Macos,
        SocketPlatform::Windows,
        SocketPlatform::Freebsd,
    ] {
        let shared = crate::creation::listener_worker_socket_policy_for(platform, 2, false);
        for family in [Domain::IPV4, Domain::IPV6] {
            assert!(listener_same_bind_replacement_lifecycle_eligible(
                platform, family, shared,
            ));
        }
    }
}

#[test]
fn measured_udp_disconnect_policy_differs_by_platform_not_ip_family() {
    for platform in [
        SocketPlatform::Linux,
        SocketPlatform::Macos,
        SocketPlatform::Windows,
        SocketPlatform::Freebsd,
    ] {
        let ipv4 =
            datagram_disconnect_capability_for(platform, SupportedProtocol::UDP, Domain::IPV4);
        let ipv6 =
            datagram_disconnect_capability_for(platform, SupportedProtocol::UDP, Domain::IPV6);
        assert_eq!(ipv4, ipv6);
        assert!(ipv4.association_clear_supported);
        assert!(ipv4.reconnect_after_disconnect_supported);
        assert!(!ipv4.stale_receive_queue_isolated);
        assert!(
            !ipv4.supports_safe_same_descriptor_relock(),
            "measured disconnect/reconnect support must not authorize UDP relock without queue isolation"
        );
    }

    let linux = datagram_disconnect_capability_for(
        SocketPlatform::Linux,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    assert!(!linux.ephemeral_port_bind.concrete_bind.local_port_preserved);
    assert!(!linux.ephemeral_port_bind.wildcard_bind.local_port_preserved);
    assert!(
        linux
            .fixed_port_bind
            .concrete_bind
            .exact_local_bind_preserved
    );
    assert!(
        linux
            .fixed_port_bind
            .wildcard_bind
            .exact_local_bind_preserved
    );

    let macos = datagram_disconnect_capability_for(
        SocketPlatform::Macos,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    assert!(macos.ephemeral_port_bind.concrete_bind.local_port_preserved);
    assert!(
        macos
            .ephemeral_port_bind
            .concrete_bind
            .original_destination_receive_supported
    );
    assert!(
        !macos
            .fixed_port_bind
            .concrete_bind
            .exact_local_bind_preserved
    );
    assert!(
        macos
            .fixed_port_bind
            .wildcard_bind
            .exact_local_bind_preserved
    );

    let windows = datagram_disconnect_capability_for(
        SocketPlatform::Windows,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    assert!(windows.preserves_every_requested_bind());
}

#[test]
fn aggregate_udp_disconnect_evidence_never_fabricates_an_unmeasured_capability() {
    for family in [Domain::IPV4, Domain::IPV6] {
        assert!(matches!(
            datagram_disconnect_evidence_for(SocketPlatform::Linux, SupportedProtocol::UDP, family,),
            CapabilityEvidence::Measured {
                evidence_id: CapabilityEvidenceId::DatagramUdpPlatformMatrix,
                ..
            }
        ));
        assert!(matches!(
            datagram_disconnect_evidence_for(
                SocketPlatform::Freebsd,
                SupportedProtocol::UDP,
                family,
            ),
            CapabilityEvidence::Measured {
                evidence_id: CapabilityEvidenceId::DatagramUdpPlatformMatrix,
                ..
            }
        ));
    }

    assert_eq!(
        datagram_disconnect_evidence_for(
            SocketPlatform::Linux,
            SupportedProtocol::ICMP,
            Domain::IPV4,
        ),
        CapabilityEvidence::Unsupported(CapabilityUnsupportedReason::SocketPathDoesNotDisconnect,)
    );
}

#[test]
fn disconnect_reality_fingerprint_does_not_leak_capability_between_socket_paths() {
    let key = DisconnectRealityKey {
        platform: SocketPlatform::Macos,
        family: Domain::IPV4,
        protocol: SupportedProtocol::ICMP,
        socket_type: Type::DGRAM,
        role: SocketRole::Upstream,
        creation_path: SocketCreationPath::Datagram,
        bind_shape: DisconnectBindShape::ConcreteEphemeral,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: ReceiveHeaderMode::IpHeaderIncluded,
        protocol_zero_capture: false,
        bound_interface: None,
        connected_peer_mode: PeerVerification::ConnectSuccess,
    };
    assert_eq!(
        socket_disconnect_evidence(key),
        CapabilityEvidence::Measured {
            capability: SocketDisconnectCapability {
                association_clear_supported: true,
                exact_local_bind_preserved: true,
                reconnect_after_disconnect_supported: false,
                peer_inspection_supported: true,
                stale_receive_queue_isolated: false,
            },
            evidence_id: CapabilityEvidenceId::DarwinIcmpDatagram,
        }
    );
    for family in [Domain::IPV4, Domain::IPV6] {
        let evidence = socket_disconnect_evidence(DisconnectRealityKey {
            family,
            socket_type: Type::RAW,
            creation_path: SocketCreationPath::RawIcmp,
            receive_header: resolve_receive_header_mode_for_platform(
                SocketPlatform::Macos,
                SupportedProtocol::ICMP,
                Type::RAW,
                family,
            ),
            connected_peer_mode: PeerVerification::RequirePeerNetworkAddress,
            ..key
        });
        assert_eq!(
            evidence,
            CapabilityEvidence::Measured {
                capability: SocketDisconnectCapability {
                    association_clear_supported: true,
                    exact_local_bind_preserved: true,
                    reconnect_after_disconnect_supported: false,
                    peer_inspection_supported: true,
                    stale_receive_queue_isolated: false,
                },
                evidence_id: CapabilityEvidenceId::DarwinRawIcmp,
            }
        );
        assert!(
            !evidence.supports_safe_same_descriptor_relock(),
            "measured RAW disconnect facts must not authorize descriptor reuse"
        );
    }
    assert_eq!(
        socket_disconnect_evidence(DisconnectRealityKey {
            protocol_zero_capture: true,
            creation_path: SocketCreationPath::WindowsProtocolZeroCapture,
            ..key
        }),
        CapabilityEvidence::Unsupported(CapabilityUnsupportedReason::SocketPathDoesNotDisconnect)
    );
    assert_eq!(
        socket_disconnect_evidence(DisconnectRealityKey {
            reuse_port: true,
            ..key
        }),
        CapabilityEvidence::Unverified(CapabilityUnverifiedReason::FingerprintNotMeasured)
    );
}

#[test]
fn protocol_zero_disconnect_uses_exact_native_l3_evidence() {
    let key = DisconnectRealityKey {
        platform: SocketPlatform::Windows,
        family: Domain::IPV4,
        protocol: SupportedProtocol::ICMP,
        socket_type: Type::RAW,
        role: SocketRole::Upstream,
        creation_path: SocketCreationPath::WindowsProtocolZeroCapture,
        bind_shape: DisconnectBindShape::ConcreteEphemeral,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: resolve_receive_header_mode_for_platform(
            SocketPlatform::Windows,
            SupportedProtocol::ICMP,
            Type::RAW,
            Domain::IPV4,
        ),
        protocol_zero_capture: true,
        bound_interface: None,
        connected_peer_mode: PeerVerification::RequirePeerNetworkAddress,
    };

    assert_eq!(
        socket_disconnect_evidence(key),
        CapabilityEvidence::Measured {
            capability: SocketDisconnectCapability {
                association_clear_supported: true,
                exact_local_bind_preserved: true,
                reconnect_after_disconnect_supported: true,
                peer_inspection_supported: true,
                stale_receive_queue_isolated: false,
            },
            evidence_id: CapabilityEvidenceId::WindowsProtocolZeroRaw,
        }
    );
}

#[test]
fn windows_ordinary_raw_listener_uses_exact_native_disconnect_evidence() {
    let listener = DisconnectRealityKey {
        platform: SocketPlatform::Windows,
        family: Domain::IPV4,
        protocol: SupportedProtocol::ICMP,
        socket_type: Type::RAW,
        role: SocketRole::Listener,
        creation_path: SocketCreationPath::RawIcmp,
        bind_shape: DisconnectBindShape::ConcreteEphemeral,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: resolve_receive_header_mode_for_platform(
            SocketPlatform::Windows,
            SupportedProtocol::ICMP,
            Type::RAW,
            Domain::IPV4,
        ),
        protocol_zero_capture: false,
        bound_interface: None,
        connected_peer_mode: PeerVerification::RequirePeerNetworkAddress,
    };
    assert_eq!(
        socket_disconnect_evidence(listener),
        CapabilityEvidence::Measured {
            capability: SocketDisconnectCapability {
                association_clear_supported: true,
                exact_local_bind_preserved: true,
                reconnect_after_disconnect_supported: true,
                peer_inspection_supported: true,
                stale_receive_queue_isolated: false,
            },
            evidence_id: CapabilityEvidenceId::WindowsRawIcmp,
        }
    );
    assert_eq!(
        socket_disconnect_evidence(DisconnectRealityKey {
            role: SocketRole::Upstream,
            ..listener
        }),
        CapabilityEvidence::Measured {
            capability: SocketDisconnectCapability {
                association_clear_supported: true,
                exact_local_bind_preserved: true,
                reconnect_after_disconnect_supported: true,
                peer_inspection_supported: true,
                stale_receive_queue_isolated: false,
            },
            evidence_id: CapabilityEvidenceId::WindowsRawIcmp,
        }
    );
}

#[test]
fn measured_false_unsupported_and_unverified_disconnect_states_are_distinct() {
    let raw = DisconnectRealityKey {
        platform: SocketPlatform::Linux,
        family: Domain::IPV4,
        protocol: SupportedProtocol::ICMP,
        socket_type: Type::RAW,
        role: SocketRole::Upstream,
        creation_path: SocketCreationPath::RawIcmp,
        bind_shape: DisconnectBindShape::ConcreteEphemeral,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: resolve_receive_header_mode_for_platform(
            SocketPlatform::Linux,
            SupportedProtocol::ICMP,
            Type::RAW,
            Domain::IPV4,
        ),
        protocol_zero_capture: false,
        bound_interface: None,
        connected_peer_mode: PeerVerification::RequirePeerNetworkAddress,
    };
    let measured_false = socket_disconnect_evidence(raw);
    assert_eq!(
        measured_false,
        CapabilityEvidence::Measured {
            capability: SocketDisconnectCapability {
                association_clear_supported: false,
                exact_local_bind_preserved: false,
                reconnect_after_disconnect_supported: false,
                peer_inspection_supported: false,
                stale_receive_queue_isolated: false,
            },
            evidence_id: CapabilityEvidenceId::LinuxRawIcmp,
        }
    );

    let unsupported = socket_disconnect_evidence(DisconnectRealityKey {
        platform: SocketPlatform::Windows,
        socket_type: Type::DGRAM,
        creation_path: SocketCreationPath::Datagram,
        receive_header: resolve_receive_header_mode_for_platform(
            SocketPlatform::Windows,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            Domain::IPV4,
        ),
        connected_peer_mode: PeerVerification::ConnectSuccess,
        ..raw
    });
    assert_eq!(
        unsupported,
        CapabilityEvidence::Unsupported(CapabilityUnsupportedReason::PlatformPathUnavailable)
    );

    let unverified = socket_disconnect_evidence(DisconnectRealityKey {
        platform: SocketPlatform::Other,
        receive_header: resolve_receive_header_mode_for_platform(
            SocketPlatform::Other,
            SupportedProtocol::ICMP,
            Type::RAW,
            Domain::IPV4,
        ),
        ..raw
    });
    assert_eq!(
        unverified,
        CapabilityEvidence::Unverified(CapabilityUnverifiedReason::PlatformPathNotMeasured)
    );
}

#[test]
fn listener_reresolution_mapping_is_exhaustive_and_strategy_owned() {
    use super::super::{ListenerClearStrategy, ListenerLockLifecycle, SocketReresolveMode};

    for (lifecycle, expected) in [
        (
            ListenerLockLifecycle::StayUnconnected,
            SocketReresolveMode::ReplaceSocket,
        ),
        (
            ListenerLockLifecycle::StayUnconnectedReplaceOnClear,
            SocketReresolveMode::ReplaceSocket,
        ),
        (
            ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::DisconnectToOriginalBind,
            },
            SocketReresolveMode::ReconnectInPlace,
        ),
        (
            ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::ReplaceOwnerSameBind,
            },
            SocketReresolveMode::ReplaceSocket,
        ),
        (
            ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::ProcessExit,
            },
            SocketReresolveMode::ProcessExitOnly,
        ),
    ] {
        assert_eq!(listener_reresolve_mode(lifecycle), expected);
    }
}

#[test]
fn force_unconnected_precedes_even_a_fully_capable_disconnect_contract() {
    use super::super::ListenerLockLifecycle;

    let fingerprint = DisconnectRealityKey {
        platform: SocketPlatform::Linux,
        family: Domain::IPV4,
        protocol: SupportedProtocol::UDP,
        socket_type: Type::DGRAM,
        role: SocketRole::Listener,
        creation_path: SocketCreationPath::Datagram,
        bind_shape: DisconnectBindShape::ConcreteFixed,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: ReceiveHeaderMode::PayloadOnly,
        protocol_zero_capture: false,
        bound_interface: None,
        connected_peer_mode: PeerVerification::RequirePeerAddr,
    };
    let lifecycle = listener_lock_lifecycle_with_contract(
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
        listener_worker_socket_policy(1, false),
        ResolvedDisconnectContract {
            fingerprint,
            evidence: CapabilityEvidence::Measured {
                capability: SocketDisconnectCapability {
                    association_clear_supported: true,
                    exact_local_bind_preserved: true,
                    reconnect_after_disconnect_supported: true,
                    peer_inspection_supported: true,
                    stale_receive_queue_isolated: true,
                },
                evidence_id: CapabilityEvidenceId::DatagramUdpPlatformMatrix,
            },
        },
    );

    assert_eq!(
        lifecycle,
        ListenerLockLifecycle::StayUnconnectedReplaceOnClear
    );
}

#[test]
fn exact_disconnect_fingerprint_separates_bind_and_reuse_authority() {
    let base = DisconnectRealityKey {
        platform: SocketPlatform::Linux,
        family: Domain::IPV4,
        protocol: SupportedProtocol::UDP,
        socket_type: Type::DGRAM,
        role: SocketRole::Upstream,
        creation_path: SocketCreationPath::Datagram,
        bind_shape: DisconnectBindShape::ConcreteFixed,
        reuse_address: false,
        reuse_port: false,
        v6_only: None,
        receive_header: ReceiveHeaderMode::PayloadOnly,
        protocol_zero_capture: false,
        bound_interface: None,
        connected_peer_mode: PeerVerification::RequirePeerAddr,
    };
    assert!(matches!(
        socket_disconnect_evidence(base).measured(),
        Some(capability) if capability.exact_local_bind_preserved
    ));
    assert!(matches!(
        socket_disconnect_evidence(DisconnectRealityKey {
            bind_shape: DisconnectBindShape::ConcreteEphemeral,
            ..base
        }).measured(),
        Some(capability) if !capability.exact_local_bind_preserved
    ));
    assert_eq!(
        socket_disconnect_evidence(DisconnectRealityKey {
            reuse_port: true,
            ..base
        }),
        CapabilityEvidence::Unverified(CapabilityUnverifiedReason::FingerprintNotMeasured)
    );
}
