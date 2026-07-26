use super::{
    IcmpChecksumMode, IcmpPolicyIntent, IpHeaderMode, ListenerLockLifecycle, ProtocolPolicyIntent,
    ResolvedSocketPolicy, SocketCreationPath, SocketLifecycleContext, SocketPathContext,
    SocketPlatform, SocketPolicyContext, SocketReresolveMode, SocketReuseCapability, SocketRole,
    StartupPeerMode, TimeoutAction, current_icmp_platform_capabilities,
    datagram_disconnect_evidence, listener_relock_capability, listener_socket_creation_policy,
    listener_worker_socket_policy, resolve_icmp_socket_policy_with_intent,
    resolve_listener_socket_policy_for_creation_path_with_lifecycle,
    resolve_socket_policy_for_creation_path_with_lifecycle, upstream_reresolve_capability,
    upstream_socket_bind_policy, upstream_socket_creation_policy,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use socket2::{Domain, Protocol, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn datagram_disconnect_capability(
    protocol: SupportedProtocol,
    family: Domain,
) -> super::DatagramDisconnectCapability {
    datagram_disconnect_evidence(protocol, family)
        .measured()
        .expect("current test platform has measured UDP disconnect evidence")
}

mod evidence_tests;
mod peer_verification_tests;
mod platform_capability_tests;

fn assert_capability(actual: SocketReuseCapability, expected: SocketReuseCapability) {
    assert_eq!(actual, expected);
}

fn exact_test_policy(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_action: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> ResolvedSocketPolicy {
    exact_test_policy_with_icmp_intent(
        role,
        proto,
        sock_type,
        timeout_action,
        debug_unconnected,
        family,
        IcmpPolicyIntent::default(),
    )
}

fn exact_test_reuse_capability(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_action: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> SocketReuseCapability {
    exact_test_policy(
        role,
        proto,
        sock_type,
        timeout_action,
        debug_unconnected,
        family,
    )
    .reuse
}

fn exact_test_policy_with_icmp_intent(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_action: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    icmp_intent: IcmpPolicyIntent,
) -> ResolvedSocketPolicy {
    let protocol_intent = match proto {
        SupportedProtocol::UDP => {
            assert_eq!(icmp_intent, IcmpPolicyIntent::default());
            ProtocolPolicyIntent::Udp
        }
        SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(icmp_intent),
    };
    let creation_path = super::inferred_socket_creation_path(proto, sock_type, family);
    let worker = listener_worker_socket_policy(1, false);
    let unspecified = if family == Domain::IPV6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let concrete = if family == Domain::IPV6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    let requested_ip = if role == SocketRole::Listener {
        concrete
    } else {
        let preliminary = resolve_socket_policy_for_creation_path_with_lifecycle(
            role,
            protocol_intent,
            sock_type,
            timeout_action,
            debug_unconnected,
            SocketPolicyContext {
                path: SocketPathContext {
                    family,
                    creation_path,
                },
                lifecycle: SocketLifecycleContext::for_requested_bind(
                    SocketAddr::new(unspecified, 0),
                    false,
                    false,
                ),
            },
        );
        let bind = upstream_socket_bind_policy(preliminary, 0, 0);
        if bind.address == super::UpstreamBindAddress::RouteSelected {
            concrete
        } else {
            unspecified
        }
    };
    let requested_bind = SocketAddr::new(requested_ip, 0);
    let lifecycle = SocketLifecycleContext::for_requested_bind(
        requested_bind,
        role == SocketRole::Listener && worker.reuse_address,
        role == SocketRole::Listener && worker.reuse_port,
    );
    let context = SocketPolicyContext {
        path: SocketPathContext {
            family,
            creation_path,
        },
        lifecycle,
    };
    match role {
        SocketRole::Listener => resolve_listener_socket_policy_for_creation_path_with_lifecycle(
            protocol_intent,
            sock_type,
            timeout_action,
            debug_unconnected,
            context,
            worker,
        ),
        SocketRole::Upstream => resolve_socket_policy_for_creation_path_with_lifecycle(
            role,
            protocol_intent,
            sock_type,
            timeout_action,
            debug_unconnected,
            context,
        ),
    }
}

fn resolve_listener_test_policy(
    protocol_intent: ProtocolPolicyIntent,
    sock_type: Type,
    timeout_action: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    worker: super::ListenerWorkerSocketPolicy,
) -> ResolvedSocketPolicy {
    let ip = if family == Domain::IPV6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    resolve_listener_socket_policy_for_creation_path_with_lifecycle(
        protocol_intent,
        sock_type,
        timeout_action,
        debug_unconnected,
        SocketPolicyContext {
            path: SocketPathContext {
                family,
                creation_path: super::inferred_socket_creation_path(
                    protocol_intent.protocol(),
                    sock_type,
                    family,
                ),
            },
            lifecycle: SocketLifecycleContext::for_requested_bind(
                SocketAddr::new(ip, 0),
                worker.reuse_address,
                worker.reuse_port,
            ),
        },
        worker,
    )
}

#[test]
fn listener_udp_dgram_matrix_tracks_timeout_and_disconnect_reuse_policy() {
    let exit_policy = exact_test_reuse_capability(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
    );
    assert_capability(
        exit_policy,
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::ProcessExitOnly,
        },
    );

    let drop_policy = exact_test_reuse_capability(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    assert_capability(
        drop_policy,
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
        },
    );
}

#[test]
fn listener_raw_icmp_exit_stays_unconnected_and_not_reconnectable() {
    let policy = exact_test_reuse_capability(
        SocketRole::Listener,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
    );
    assert_capability(
        policy,
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
        },
    );
}

#[test]
fn listener_disconnect_requires_complete_safe_relock_contract() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let policy = exact_test_reuse_capability(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            family,
        );
        assert!(
            !datagram_disconnect_capability(SupportedProtocol::UDP, family)
                .supports_safe_same_descriptor_relock()
        );
        if matches!(
            SocketPlatform::current(),
            SocketPlatform::Macos | SocketPlatform::Ios
        ) {
            assert_capability(
                policy,
                SocketReuseCapability {
                    startup_peer_mode: StartupPeerMode::Unconnected,
                    reresolve_mode: SocketReresolveMode::ReplaceSocket,
                },
            );
        }
    }
}

#[test]
fn upstream_dgram_reconnect_policy_is_independent_from_listener_policy() {
    let listener = exact_test_reuse_capability(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let upstream = exact_test_reuse_capability(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );

    assert_eq!(listener.reresolve_mode, SocketReresolveMode::ReplaceSocket);
    assert_eq!(upstream.reresolve_mode, SocketReresolveMode::ReplaceSocket);
    assert_eq!(listener.startup_peer_mode, StartupPeerMode::Unconnected);
    assert_eq!(upstream.startup_peer_mode, StartupPeerMode::Connected);
}

#[test]
fn raw_icmp_upstream_uses_platform_peer_mode() {
    let policy = exact_test_reuse_capability(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let expected = SocketReuseCapability {
        startup_peer_mode: StartupPeerMode::Connected,
        reresolve_mode: SocketReresolveMode::ReplaceSocket,
    };
    assert_capability(policy, expected);
}

#[test]
fn debug_unconnected_remains_authoritative_for_raw_capture() {
    let policy = exact_test_reuse_capability(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );

    #[cfg(windows)]
    {
        assert_eq!(policy.startup_peer_mode, StartupPeerMode::Unconnected);
        assert_eq!(
            policy.reresolve_mode,
            SocketReresolveMode::MetadataOnlyWhenUnconnected
        );
    }

    #[cfg(not(windows))]
    {
        assert_eq!(policy.startup_peer_mode, StartupPeerMode::Unconnected);
    }
}

#[test]
fn protocol_zero_capture_uses_raw_l3_connected_startup_when_not_forced_unconnected() {
    let policy = resolve_socket_policy_for_creation_path_with_lifecycle(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::RAW,
        TimeoutAction::Drop,
        false,
        SocketPolicyContext {
            path: SocketPathContext {
                family: Domain::IPV4,
                creation_path: SocketCreationPath::WindowsProtocolZeroCapture,
            },
            lifecycle: SocketLifecycleContext::direct_default(),
        },
    );

    assert_eq!(
        policy.receive_capture_scope,
        super::ReceiveCaptureScope::InterfaceIpv4
    );
    assert_eq!(policy.reuse.startup_peer_mode, StartupPeerMode::Connected);
    assert_eq!(
        policy.reuse.reresolve_mode,
        SocketReresolveMode::ReplaceSocket
    );
    assert_eq!(
        policy.peer_verification,
        super::PeerVerification::RequirePeerNetworkAddress
    );
}

#[test]
fn receive_header_policy_selects_the_socket_wire_layout() {
    let udp = exact_test_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(udp.receive_header, ReceiveHeaderMode::PayloadOnly);

    for family in [Domain::IPV4, Domain::IPV6] {
        let dgram = exact_test_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            TimeoutAction::Exit,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        let expected = if family == Domain::IPV4 {
            current_icmp_platform_capabilities().icmp_v4_dgram_receive_header
        } else {
            ReceiveHeaderMode::TransportHeaderOnly
        };
        assert_eq!(dgram.receive_header, expected);
    }

    let raw_v4 = exact_test_policy_with_icmp_intent(
        SocketRole::Listener,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(raw_v4.receive_header, ReceiveHeaderMode::IpHeaderIncluded);

    let raw_v6 = exact_test_policy_with_icmp_intent(
        SocketRole::Listener,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Exit,
        false,
        Domain::IPV6,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(
        raw_v6.receive_header,
        ReceiveHeaderMode::TransportHeaderOnly
    );
}

#[test]
fn linux_android_icmp_dgram_policy_uses_kernel_checksum() {
    let policy = exact_test_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(
        policy.send_policy.icmp_checksum,
        if current_icmp_platform_capabilities().kernel_computed_dgram_checksum {
            IcmpChecksumMode::KernelComputed
        } else {
            IcmpChecksumMode::ApplicationComputed
        }
    );
    assert_eq!(policy.send_policy.ip_header, IpHeaderMode::PayloadOnly);
}

#[test]
fn udp_disconnect_capability_requires_queue_isolation_for_safe_relock() {
    let capability = datagram_disconnect_capability(SupportedProtocol::UDP, Domain::IPV4);
    let platform = SocketPlatform::current();
    if matches!(
        platform,
        SocketPlatform::Linux
            | SocketPlatform::Android
            | SocketPlatform::Macos
            | SocketPlatform::Ios
            | SocketPlatform::Windows
            | SocketPlatform::Freebsd
    ) {
        assert!(capability.association_clear_supported);
        assert!(capability.reconnect_after_disconnect_supported);
    } else {
        assert!(!capability.association_clear_supported);
        assert!(!capability.reconnect_after_disconnect_supported);
    }
    assert!(!capability.stale_receive_queue_isolated);
    assert!(!capability.supports_safe_same_descriptor_relock());
    assert_eq!(
        capability.preserves_every_requested_bind(),
        platform == SocketPlatform::Windows
    );
}

#[test]
fn role_specific_socket_capabilities_match_reuse_policy() {
    let upstream =
        upstream_reresolve_capability(SupportedProtocol::UDP, Type::DGRAM, false, Domain::IPV4);
    let disconnect = datagram_disconnect_capability(SupportedProtocol::UDP, Domain::IPV4);
    assert_eq!(
        upstream.reresolve_mode(),
        if disconnect.supports_safe_same_descriptor_relock() {
            SocketReresolveMode::ReconnectInPlace
        } else {
            SocketReresolveMode::ReplaceSocket
        }
    );
    assert_eq!(
        upstream.can_disconnect(),
        disconnect.association_clear_supported
    );
    assert_eq!(
        upstream.can_reconnect_to_new_target(),
        upstream.reresolve_mode() == SocketReresolveMode::ReconnectInPlace
    );

    let listener = listener_relock_capability(
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let listener_disconnect = datagram_disconnect_capability(SupportedProtocol::UDP, Domain::IPV4);
    assert_eq!(
        listener.can_relock_to_new_peer(),
        listener.can_lock_connected()
            && listener.can_disconnect_lock()
            && listener_disconnect.supports_safe_same_descriptor_relock()
    );
    if !listener_disconnect.supports_safe_same_descriptor_relock()
        && !listener.lifecycle.connects_after_lock()
    {
        assert_eq!(
            listener.lifecycle,
            ListenerLockLifecycle::StayUnconnectedReplaceOnClear
        );
    }
}

#[test]
fn udp_upstream_debug_unconnected_uses_metadata_only_policy() {
    let policy = exact_test_reuse_capability(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );

    assert_capability(
        policy,
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
        },
    );
}

#[test]
fn dgram_upstream_protocols_share_connected_default_and_debug_override() {
    let protocols = [SupportedProtocol::UDP, SupportedProtocol::ICMP];
    for proto in protocols {
        let default_policy = exact_test_reuse_capability(
            SocketRole::Upstream,
            proto,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
        );
        assert_capability(
            default_policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Connected,
                reresolve_mode: SocketReresolveMode::ReplaceSocket,
            },
        );

        let debug_policy = exact_test_reuse_capability(
            SocketRole::Upstream,
            proto,
            Type::DGRAM,
            TimeoutAction::Drop,
            true,
            Domain::IPV4,
        );
        assert_capability(
            debug_policy,
            SocketReuseCapability {
                startup_peer_mode: StartupPeerMode::Unconnected,
                reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
            },
        );
    }
}

#[test]
fn timeout_drop_forces_unconnected_only_when_listener_policy_requires_it() {
    assert_eq!(
        resolve_listener_test_policy(
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            Type::RAW,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            listener_worker_socket_policy(1, false),
        )
        .listener_lifecycle,
        Some(ListenerLockLifecycle::StayUnconnected)
    );

    assert_eq!(
        resolve_listener_test_policy(
            ProtocolPolicyIntent::Udp,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            listener_worker_socket_policy(1, false),
        )
        .listener_lifecycle,
        Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
    );
}

#[test]
fn listener_icmp_policy_resolves_to_raw_admission() {
    let policy = resolve_icmp_socket_policy_with_intent(
        SocketRole::Listener,
        Type::RAW,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(policy.role, SocketRole::Listener);
    assert_eq!(policy.socket_type, Type::RAW);
    assert!(policy.requires_raw_packet_admission());
    assert!(policy.can_honor_disjoint_ids());
}

#[test]
fn socket_creation_policy_centralizes_listener_and_upstream_paths() {
    let udp = listener_socket_creation_policy(SupportedProtocol::UDP, Domain::IPV4);
    assert_eq!(udp.primary.path, SocketCreationPath::Datagram);
    assert_eq!(udp.primary.socket_type, Type::DGRAM);
    assert_eq!(udp.primary.protocol, Some(Protocol::UDP));
    assert_eq!(udp.fallback, None);

    let listener_v4 = listener_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4);
    let expected_v4_path = if SocketPlatform::current() == SocketPlatform::Windows {
        SocketCreationPath::WindowsProtocolZeroCapture
    } else {
        SocketCreationPath::RawIcmp
    };
    let expected_v4_protocol = if SocketPlatform::current() == SocketPlatform::Windows {
        Protocol::from(0)
    } else {
        Protocol::ICMPV4
    };
    assert_eq!(listener_v4.primary.path, expected_v4_path);
    assert_eq!(listener_v4.primary.socket_type, Type::RAW);
    assert_eq!(listener_v4.primary.protocol, Some(expected_v4_protocol));
    assert_eq!(listener_v4.fallback, None);

    let listener_v6 = listener_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV6);
    assert_eq!(listener_v6.primary.path, SocketCreationPath::RawIcmp);
    assert_eq!(listener_v6.primary.protocol, Some(Protocol::ICMPV6));

    let disjoint =
        upstream_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4, 1001, 2002, false);
    assert_eq!(disjoint.primary.path, expected_v4_path);
    assert_eq!(disjoint.fallback, None);

    let wildcard =
        upstream_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4, 0, 0, false);
    assert_eq!(wildcard.primary.path, SocketCreationPath::Datagram);
    assert_eq!(wildcard.primary.socket_type, Type::DGRAM);
    assert_eq!(
        wildcard.fallback.map(|fallback| fallback.to.path),
        Some(expected_v4_path)
    );
}

mod policy_resolution_tests;
