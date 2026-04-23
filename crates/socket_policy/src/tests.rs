use super::{
    IcmpChecksumMode, IcmpKernelIdPolicy, IcmpPolicyIntent, IcmpSocketIdCapability,
    IcmpWildcardIdPolicy, IpHeaderMode, LockedPeerMode, SocketCreationPath, SocketEvidenceKey,
    SocketPlatform, SocketReresolveMode, SocketReuseCapability, SocketRole, StartupPeerMode,
    TimeoutAction, TimeoutClearMode, current_icmp_platform_capabilities,
    datagram_disconnect_capability, icmp_platform_capabilities, listener_relock_capability,
    listener_socket_creation_policy, listener_socket_setup_policy, listener_worker_socket_policy,
    resolve_icmp_socket_policy_with_intent, resolve_socket_policy_with_icmp_intent,
    socket_post_bind_policy, socket_reuse_capability_for_family, upstream_pre_connect_bind_id,
    upstream_reresolve_capability, upstream_socket_creation_policy,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use socket2::{Domain, Protocol, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn assert_capability(actual: SocketReuseCapability, expected: SocketReuseCapability) {
    assert_eq!(actual, expected);
}

#[test]
fn replacement_evidence_key_changes_domain_and_generation_but_not_slot() {
    let original = SocketEvidenceKey::initial(
        SocketRole::Upstream,
        7,
        "[::1]:0".parse().expect("IPv6 socket address"),
    );
    let replacement = original.replacement("127.0.0.1:0".parse().expect("IPv4 socket address"));

    assert_eq!(replacement.process_id, original.process_id);
    assert_eq!(replacement.role, original.role);
    assert_eq!(replacement.socket_slot, original.socket_slot);
    assert_eq!(replacement.generation, original.generation + 1);
    assert_eq!(original.domain, Domain::IPV6);
    assert_eq!(replacement.domain, Domain::IPV4);
}

#[test]
fn listener_udp_dgram_matrix_tracks_timeout_and_disconnect_reuse_policy() {
    let exit_policy = socket_reuse_capability_for_family(
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
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReconnectInPlace,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        },
    );

    let drop_policy = socket_reuse_capability_for_family(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let (locked_peer_mode, reresolve_mode, timeout_clear_mode) = if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd"
    )) {
        (
            LockedPeerMode::StayUnconnected,
            SocketReresolveMode::ReplaceSocket,
            TimeoutClearMode::NoConnectedState,
        )
    } else {
        (
            LockedPeerMode::ConnectAfterLock,
            SocketReresolveMode::ReconnectInPlace,
            TimeoutClearMode::DisconnectSocket,
        )
    };
    assert_capability(
        drop_policy,
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode,
            reresolve_mode,
            timeout_clear_mode,
        },
    );
}

#[test]
fn listener_raw_icmp_exit_stays_unconnected_and_not_reconnectable() {
    let policy = socket_reuse_capability_for_family(
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
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        },
    );
}

#[test]
fn macos_ipv6_udp_listener_drop_uses_unconnected_policy() {
    let policy = socket_reuse_capability_for_family(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV6,
    );

    let expected = if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "android"
    )) {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        }
    } else {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReconnectInPlace,
            timeout_clear_mode: TimeoutClearMode::DisconnectSocket,
        }
    };

    assert_capability(policy, expected);
}

#[test]
fn upstream_dgram_reconnect_policy_is_independent_from_listener_policy() {
    let listener = socket_reuse_capability_for_family(
        SocketRole::Listener,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let upstream = socket_reuse_capability_for_family(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    {
        assert_eq!(listener.locked_peer_mode, LockedPeerMode::StayUnconnected);
        assert_eq!(
            upstream.reresolve_mode,
            SocketReresolveMode::ReconnectInPlace
        );
        assert_eq!(listener.startup_peer_mode, StartupPeerMode::Unconnected);
        assert_eq!(upstream.startup_peer_mode, StartupPeerMode::Connected);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    {
        assert_eq!(
            listener.reresolve_mode,
            SocketReresolveMode::ReconnectInPlace
        );
        assert_eq!(
            upstream.reresolve_mode,
            SocketReresolveMode::ReconnectInPlace
        );
        assert_eq!(listener.startup_peer_mode, StartupPeerMode::Unconnected);
        assert_eq!(upstream.startup_peer_mode, StartupPeerMode::Connected);
    }
}

#[test]
fn raw_icmp_upstream_uses_platform_peer_mode() {
    let policy = socket_reuse_capability_for_family(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    let expected = if cfg!(windows) {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        }
    } else {
        SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        }
    };
    assert_capability(policy, expected);
}

#[test]
fn windows_raw_icmp_upstream_uses_unconnected_rcvall_path_even_with_debug_override() {
    let policy = socket_reuse_capability_for_family(
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
        assert_eq!(policy.locked_peer_mode, LockedPeerMode::StayUnconnected);
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
fn send_policy_defines_icmp_checksum_and_ip_header_modes() {
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        let policy = resolve_socket_policy_with_icmp_intent(
            role,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );

        assert_eq!(
            policy.send_policy.ip_header,
            if cfg!(windows) {
                IpHeaderMode::Ipv4HeaderIncluded
            } else {
                IpHeaderMode::PayloadOnly
            }
        );
        assert_eq!(
            policy.send_policy.icmp_checksum,
            IcmpChecksumMode::ApplicationComputed
        );
    }
}

#[test]
fn receive_header_policy_selects_the_socket_wire_layout() {
    let udp = resolve_socket_policy_with_icmp_intent(
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
        let dgram = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            TimeoutAction::Exit,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        let expected =
            if family == Domain::IPV4 && cfg!(any(target_os = "macos", target_os = "ios")) {
                ReceiveHeaderMode::IpHeaderIncluded
            } else {
                ReceiveHeaderMode::TransportHeaderOnly
            };
        assert_eq!(dgram.receive_header, expected);
    }

    let raw_v4 = resolve_socket_policy_with_icmp_intent(
        SocketRole::Listener,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(raw_v4.receive_header, ReceiveHeaderMode::IpHeaderIncluded);

    let raw_v6 = resolve_socket_policy_with_icmp_intent(
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
    let policy = resolve_socket_policy_with_icmp_intent(
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
        if cfg!(any(target_os = "linux", target_os = "android")) {
            IcmpChecksumMode::KernelComputed
        } else {
            IcmpChecksumMode::ApplicationComputed
        }
    );
    assert_eq!(policy.send_policy.ip_header, IpHeaderMode::PayloadOnly);
}

#[test]
fn udp_disconnect_capability_distinguishes_reconnect_from_listener_receive_reuse() {
    let capability = datagram_disconnect_capability(SupportedProtocol::UDP, Domain::IPV4);
    if cfg!(any(unix, windows)) {
        assert!(capability.disconnect_call_supported);
        assert!(capability.reconnect_after_disconnect_supported);
    }
    if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd"
    )) {
        assert!(!capability.listener_original_bind_receive_after_disconnect_supported);
    }
}

#[test]
fn role_specific_socket_capabilities_match_reuse_policy() {
    let upstream =
        upstream_reresolve_capability(SupportedProtocol::UDP, Type::DGRAM, false, Domain::IPV4);
    assert_eq!(
        upstream.reresolve_mode(),
        SocketReresolveMode::ReconnectInPlace
    );
    if cfg!(any(unix, windows)) {
        assert!(upstream.can_disconnect());
        assert!(upstream.can_reconnect_to_new_target());
    }

    let listener = listener_relock_capability(
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    assert_eq!(
        listener.can_relock_to_new_peer(),
        listener.can_lock_connected() && listener.can_disconnect_lock()
    );
    if !listener.can_receive_on_original_bind_after_disconnect() {
        assert_eq!(
            listener.timeout_clear_mode,
            TimeoutClearMode::NoConnectedState
        );
    }
}

#[test]
fn udp_upstream_debug_unconnected_uses_metadata_only_policy() {
    let policy = socket_reuse_capability_for_family(
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
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        },
    );
}

#[test]
fn dgram_upstream_protocols_share_connected_default_and_debug_override() {
    let mut protocols = vec![SupportedProtocol::UDP];
    if current_icmp_platform_capabilities().datagram_echo_sockets {
        protocols.push(SupportedProtocol::ICMP);
    }
    for proto in protocols {
        let default_policy = socket_reuse_capability_for_family(
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
                locked_peer_mode: LockedPeerMode::ConnectAfterLock,
                reresolve_mode: SocketReresolveMode::ReconnectInPlace,
                timeout_clear_mode: TimeoutClearMode::ProcessExit,
            },
        );

        let debug_policy = socket_reuse_capability_for_family(
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
                locked_peer_mode: LockedPeerMode::StayUnconnected,
                reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
                timeout_clear_mode: TimeoutClearMode::NoConnectedState,
            },
        );
    }
}

#[test]
fn timeout_drop_forces_unconnected_only_when_listener_policy_requires_it() {
    assert_eq!(
        socket_reuse_capability_for_family(
            SocketRole::Listener,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
        )
        .locked_peer_mode,
        LockedPeerMode::StayUnconnected
    );

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    assert_eq!(
        socket_reuse_capability_for_family(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
        )
        .locked_peer_mode,
        LockedPeerMode::StayUnconnected
    );

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    assert_eq!(
        socket_reuse_capability_for_family(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
        )
        .locked_peer_mode,
        LockedPeerMode::ConnectAfterLock
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
    let capabilities = current_icmp_platform_capabilities();
    let udp = listener_socket_creation_policy(SupportedProtocol::UDP, Domain::IPV4);
    assert_eq!(udp.primary.path, SocketCreationPath::Datagram);
    assert_eq!(udp.primary.socket_type, Type::DGRAM);
    assert_eq!(udp.primary.protocol, Some(Protocol::UDP));
    assert_eq!(udp.create_fallback, None);

    let listener_v4 = listener_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4);
    let expected_v4_path = if capabilities.windows_ipv4_protocol_zero_raw {
        SocketCreationPath::WindowsProtocolZeroCapture
    } else {
        SocketCreationPath::RawIcmp
    };
    let expected_v4_protocol = if capabilities.windows_ipv4_protocol_zero_raw {
        Protocol::from(0)
    } else {
        Protocol::ICMPV4
    };
    assert_eq!(listener_v4.primary.path, expected_v4_path);
    assert_eq!(listener_v4.primary.socket_type, Type::RAW);
    assert_eq!(listener_v4.primary.protocol, Some(expected_v4_protocol));
    assert_eq!(listener_v4.create_fallback, None);

    let listener_v6 = listener_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV6);
    assert_eq!(listener_v6.primary.path, SocketCreationPath::RawIcmp);
    assert_eq!(listener_v6.primary.protocol, Some(Protocol::ICMPV6));

    let disjoint =
        upstream_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4, 1001, 2002, false);
    assert_eq!(disjoint.primary.path, expected_v4_path);
    assert_eq!(disjoint.create_fallback, None);

    let wildcard =
        upstream_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4, 0, 0, false);
    if capabilities.datagram_echo_sockets {
        assert_eq!(wildcard.primary.path, SocketCreationPath::Datagram);
        assert_eq!(wildcard.primary.socket_type, Type::DGRAM);
        assert_eq!(
            wildcard.create_fallback.map(|spec| spec.path),
            Some(expected_v4_path)
        );
    } else {
        assert_eq!(wildcard.primary.path, expected_v4_path);
        assert_eq!(wildcard.create_fallback, None);
    }
}

#[test]
fn icmp_platform_capability_matrix_is_complete_and_conservative() {
    for platform in [SocketPlatform::Linux, SocketPlatform::Android] {
        let capabilities = icmp_platform_capabilities(platform);
        assert!(capabilities.datagram_echo_sockets);
        assert!(capabilities.dgram_to_bound_raw_loopback);
        assert!(capabilities.raw_to_bound_raw_loopback);
        assert!(!capabilities.windows_ipv4_protocol_zero_raw);
    }

    let macos = icmp_platform_capabilities(SocketPlatform::Macos);
    assert!(macos.datagram_echo_sockets);
    assert!(!macos.dgram_to_bound_raw_loopback);
    assert!(!macos.raw_to_bound_raw_loopback);

    let ios = icmp_platform_capabilities(SocketPlatform::Ios);
    assert!(!ios.datagram_echo_sockets);
    assert!(!ios.raw_to_bound_raw_loopback);

    let windows = icmp_platform_capabilities(SocketPlatform::Windows);
    assert!(!windows.datagram_echo_sockets);
    assert!(windows.windows_ipv4_protocol_zero_raw);
    assert!(windows.raw_to_bound_raw_loopback);

    let other = icmp_platform_capabilities(SocketPlatform::Other);
    assert!(!other.datagram_echo_sockets);
    assert!(!other.windows_ipv4_protocol_zero_raw);
}

#[test]
fn post_bind_setup_is_owned_by_the_protocol_zero_creation_path() {
    for path in [SocketCreationPath::Datagram, SocketCreationPath::RawIcmp] {
        let policy = socket_post_bind_policy(path);
        assert!(!policy.enable_windows_rcvall);
        assert!(!policy.set_ipv4_header_included);
    }
    let capture = socket_post_bind_policy(SocketCreationPath::WindowsProtocolZeroCapture);
    assert!(capture.enable_windows_rcvall);
    assert!(capture.set_ipv4_header_included);

    let worker = listener_worker_socket_policy(2, true);
    let setup =
        listener_socket_setup_policy(worker, SocketCreationPath::WindowsProtocolZeroCapture);
    assert_eq!(setup.worker, worker);
    assert!(setup.bind_requested_address);
    assert_eq!(setup.post_bind, capture);
}

#[test]
fn upstream_pre_connect_bind_policy_unifies_udp_ports_and_ping_ids() {
    assert_eq!(
        upstream_pre_connect_bind_id(SupportedProtocol::UDP, Type::DGRAM, 9999, 2002),
        Some(2002)
    );
    assert_eq!(
        upstream_pre_connect_bind_id(SupportedProtocol::UDP, Type::DGRAM, 9999, 0),
        None
    );
    assert_eq!(
        upstream_pre_connect_bind_id(SupportedProtocol::ICMP, Type::DGRAM, 3003, 2002),
        Some(3003)
    );
    assert_eq!(
        upstream_pre_connect_bind_id(SupportedProtocol::ICMP, Type::DGRAM, 0, 2002),
        None
    );
    assert_eq!(
        upstream_pre_connect_bind_id(SupportedProtocol::ICMP, Type::RAW, 3003, 2002),
        None
    );
}

#[test]
fn disjoint_upstream_ids_require_disjoint_capable_policy() {
    let raw = resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::RAW,
        IcmpPolicyIntent::default(),
    );
    let dgram = resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::DGRAM,
        IcmpPolicyIntent::default(),
    );

    assert!(raw.can_honor_disjoint_ids());
    assert!(raw.requires_raw_packet_admission());

    assert!(!dgram.can_honor_disjoint_ids());
    assert!(!dgram.requires_raw_packet_admission());
}

#[test]
fn dgram_upstream_id_capability_matches_platform_semantics() {
    let dgram = resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::DGRAM,
        IcmpPolicyIntent::default(),
    );
    if cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(
            dgram.id_capability,
            IcmpSocketIdCapability::KernelAssignedCollapsedId
        );
        assert_eq!(
            dgram.kernel_id_policy,
            IcmpKernelIdPolicy::DeferredKernelAssigned
        );
        assert_eq!(
            dgram.wildcard_id_policy,
            IcmpWildcardIdPolicy::UseKernelAssignedCollapsedId
        );
    } else {
        assert_eq!(
            dgram.id_capability,
            IcmpSocketIdCapability::FixedCollapsedId
        );
        assert_eq!(
            dgram.kernel_id_policy,
            IcmpKernelIdPolicy::TrustedGetsockname
        );
        assert_eq!(
            dgram.wildcard_id_policy,
            IcmpWildcardIdPolicy::GenerateFixedCollapsedId
        );
    }
}

#[test]
fn raw_debug_wildcard_policy_can_keep_raw_admission_without_disjoint_ids() {
    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent {
            disable_disjoint_ids: true,
            allow_debug_kernel_echo_self_handshake: false,
        },
    );
    let icmp = policy.icmp.expect("ICMP policy");

    assert_eq!(icmp.socket_type, Type::RAW);
    assert_eq!(icmp.id_capability, IcmpSocketIdCapability::FixedCollapsedId);
    assert_eq!(
        icmp.kernel_id_policy,
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol
    );
    assert_eq!(
        icmp.wildcard_id_policy,
        IcmpWildcardIdPolicy::GenerateFixedCollapsedId
    );
    assert!(icmp.requires_raw_packet_admission());
    assert!(!icmp.can_honor_disjoint_ids());
}

#[test]
fn raw_icmp_kernel_local_ids_are_untrusted() {
    let policy = resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::RAW,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(
        policy.kernel_id_policy,
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol
    );
    assert_eq!(
        policy.wildcard_id_policy,
        IcmpWildcardIdPolicy::GenerateDisjointIds
    );
}

#[test]
fn receive_evidence_policy_is_resolved_with_socket_layout() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let udp = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Exit,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        assert_eq!(
            udp.evidence_policy(true),
            super::ReceiveEvidencePolicy {
                peer_source: super::PeerSourceRequirement::ConnectedKernel,
                protocol_id: super::ProtocolIdRequirement::None,
            }
        );
        assert_eq!(
            udp.evidence_policy(false),
            super::ReceiveEvidencePolicy {
                peer_source: super::PeerSourceRequirement::SourceMetadata,
                protocol_id: super::ProtocolIdRequirement::None,
            }
        );
        let listener_udp = resolve_socket_policy_with_icmp_intent(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        assert_eq!(
            listener_udp.evidence_policy(true),
            super::ReceiveEvidencePolicy {
                peer_source: super::PeerSourceRequirement::SourceMetadata,
                protocol_id: super::ProtocolIdRequirement::None,
            }
        );

        let raw = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::RAW,
            TimeoutAction::Exit,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        if family == Domain::IPV4 {
            assert_eq!(
                raw.evidence_policy(true),
                super::ReceiveEvidencePolicy {
                    peer_source: super::PeerSourceRequirement::RawPacketHeader,
                    protocol_id: super::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
            assert_eq!(
                raw.evidence_policy(false),
                super::ReceiveEvidencePolicy {
                    peer_source: super::PeerSourceRequirement::RawPacketHeader,
                    protocol_id: super::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
        } else {
            assert_eq!(
                raw.evidence_policy(true),
                super::ReceiveEvidencePolicy {
                    peer_source: super::PeerSourceRequirement::ConnectedKernel,
                    protocol_id: super::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
            assert_eq!(
                raw.evidence_policy(false),
                super::ReceiveEvidencePolicy {
                    peer_source: super::PeerSourceRequirement::SourceMetadata,
                    protocol_id: super::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
        }
    }
}

#[test]
fn receive_syscall_policy_optimizes_safe_connected_roles_and_preserves_listener_metadata() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let listener_udp = resolve_socket_policy_with_icmp_intent(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        assert_eq!(
            listener_udp.receive_syscall(true),
            super::ReceiveSyscall::RecvFrom
        );
        assert_eq!(
            listener_udp.receive_syscall(false),
            super::ReceiveSyscall::RecvFrom
        );
        let upstream_udp = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        assert_eq!(
            upstream_udp.receive_syscall(true),
            super::ReceiveSyscall::Recv
        );
        assert_eq!(
            upstream_udp.receive_syscall(false),
            super::ReceiveSyscall::RecvFrom
        );

        for socket_type in [Type::DGRAM, Type::RAW] {
            let icmp = resolve_socket_policy_with_icmp_intent(
                SocketRole::Upstream,
                SupportedProtocol::ICMP,
                socket_type,
                TimeoutAction::Drop,
                false,
                family,
                IcmpPolicyIntent::default(),
            );
            assert_eq!(icmp.receive_syscall(true), super::ReceiveSyscall::Recv);
            assert_eq!(icmp.receive_syscall(false), super::ReceiveSyscall::RecvFrom);
        }
    }
}

#[test]
fn listener_worker_socket_policy_limits_separate_state_to_kernel_flow_affinity() {
    assert_eq!(
        listener_worker_socket_policy(1, true),
        super::ListenerWorkerSocketPolicy {
            reuse_address: false,
            reuse_port: false,
            distribution: super::ListenerWorkerDistribution::SingleSocket,
        }
    );

    let shared = listener_worker_socket_policy(3, false);
    assert!(shared.supports_requested_distribution());
    assert_eq!(
        shared.distribution,
        super::ListenerWorkerDistribution::SharedState
    );
    assert!(shared.reuse_address);
    assert_eq!(shared.reuse_port, cfg!(unix));

    let separate = listener_worker_socket_policy(3, true);
    assert_eq!(
        separate.distribution,
        if cfg!(any(target_os = "linux", target_os = "android")) {
            super::ListenerWorkerDistribution::KernelFlowAffinity
        } else {
            super::ListenerWorkerDistribution::UnsupportedSeparateState
        }
    );
    assert_eq!(
        separate.supports_requested_distribution(),
        cfg!(any(target_os = "linux", target_os = "android"))
    );
}

#[test]
fn upstream_reresolve_uses_only_proven_family_reconnect_capability() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let capability =
            upstream_reresolve_capability(SupportedProtocol::UDP, Type::DGRAM, false, family);
        assert!(capability.can_disconnect());
        let macos_ipv6 =
            cfg!(any(target_os = "macos", target_os = "ios")) && family == Domain::IPV6;
        assert_eq!(capability.can_reconnect_to_new_target(), !macos_ipv6);
        assert_eq!(
            capability.reresolve_mode(),
            if macos_ipv6 {
                super::SocketReresolveMode::ReplaceSocket
            } else {
                super::SocketReresolveMode::ReconnectInPlace
            }
        );
    }
}

#[test]
fn socket_evidence_generation_changes_only_on_replacement() {
    let initial = SocketEvidenceKey::initial(
        SocketRole::Upstream,
        7,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.domain, Domain::IPV4);
    assert_eq!(initial.socket_slot, 7);

    let replacement = initial.replacement(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0));
    assert_eq!(replacement.process_id, initial.process_id);
    assert_eq!(replacement.role, initial.role);
    assert_eq!(replacement.socket_slot, initial.socket_slot);
    assert_eq!(replacement.generation, initial.generation + 1);
    assert_eq!(replacement.domain, Domain::IPV6);
    assert_ne!(replacement.domain, initial.domain);
}
