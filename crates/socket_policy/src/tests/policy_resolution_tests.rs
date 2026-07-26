use super::{exact_test_policy_with_icmp_intent, resolve_listener_test_policy};
use crate::{
    IcmpKernelIdPolicy, IcmpPolicyIntent, IcmpSocketIdCapability, IcmpWildcardIdPolicy,
    Ipv4HeaderAction, ListenerClearStrategy, ListenerLockLifecycle, ProtocolPolicyIntent,
    SocketCaptureAction, SocketCreationPath, SocketLifecycleContext, SocketPathContext,
    SocketPlatform, SocketPolicyContext, SocketRole, TimeoutAction,
    current_icmp_platform_capabilities, listener_same_bind_replacement_lifecycle_eligible,
    listener_socket_bind_policy, listener_socket_setup_policy, listener_worker_socket_policy,
    resolve_icmp_socket_policy_with_intent, resolve_socket_policy_for_creation_path_with_lifecycle,
    resolve_socket_policy_with_protocol_intent, socket_post_bind_policy,
    upstream_reresolve_capability, upstream_socket_bind_policy,
};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

#[test]
fn post_bind_setup_is_owned_by_the_protocol_zero_creation_path() {
    for path in [SocketCreationPath::Datagram, SocketCreationPath::RawIcmp] {
        let policy = socket_post_bind_policy(path);
        assert_eq!(policy.capture, SocketCaptureAction::Disabled);
        assert_eq!(policy.ipv4_header, Ipv4HeaderAction::KernelManaged);
    }
    let capture = socket_post_bind_policy(SocketCreationPath::WindowsProtocolZeroCapture);
    assert_eq!(capture.capture, SocketCaptureAction::WindowsReceiveAllIp);
    assert_eq!(capture.ipv4_header, Ipv4HeaderAction::ApplicationIncluded);

    let worker = listener_worker_socket_policy(2, true);
    let setup =
        listener_socket_setup_policy(worker, SocketCreationPath::WindowsProtocolZeroCapture);
    assert_eq!(setup.worker, worker);
    assert!(setup.bind_requested_address);
    assert_eq!(setup.post_bind, capture);
}

#[test]
fn listener_bind_policy_keeps_raw_ids_out_of_sockaddr_ports() {
    assert_eq!(
        listener_socket_bind_policy(SocketCreationPath::Datagram, 9999).kernel_id,
        9999
    );
    for path in [
        SocketCreationPath::RawIcmp,
        SocketCreationPath::WindowsProtocolZeroCapture,
    ] {
        assert_eq!(listener_socket_bind_policy(path, 9999).kernel_id, 0);
    }
}

#[test]
fn upstream_bind_policy_unifies_udp_ports_and_reality_backed_ping_ids() {
    let udp = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    assert_eq!(
        upstream_socket_bind_policy(udp, 9999, 2002),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 2002,
            bind_before_connect: true,
            address: crate::UpstreamBindAddress::Wildcard,
        }
    );
    assert_eq!(
        upstream_socket_bind_policy(udp, 9999, 0),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 0,
            bind_before_connect: false,
            address: crate::UpstreamBindAddress::Wildcard,
        }
    );
    let unconnected_udp = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );
    assert_eq!(
        upstream_socket_bind_policy(unconnected_udp, 9999, 0).address,
        crate::UpstreamBindAddress::RouteSelected,
    );

    let dgram = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
    );
    assert_eq!(
        upstream_socket_bind_policy(dgram, 3003, 2002),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 3003,
            bind_before_connect: true,
            address: crate::UpstreamBindAddress::Wildcard,
        }
    );
    assert_eq!(
        upstream_socket_bind_policy(dgram, 0, 2002),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 0,
            bind_before_connect: true,
            address: crate::UpstreamBindAddress::Wildcard,
        }
    );

    let raw = resolve_socket_policy_for_creation_path_with_lifecycle(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::RAW,
        TimeoutAction::Drop,
        false,
        SocketPolicyContext {
            path: SocketPathContext {
                family: Domain::IPV4,
                creation_path: SocketCreationPath::RawIcmp,
            },
            lifecycle: SocketLifecycleContext::direct_default(),
        },
    );
    assert_eq!(
        upstream_socket_bind_policy(raw, 3003, 2002),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 0,
            bind_before_connect: false,
            address: crate::UpstreamBindAddress::Wildcard,
        }
    );
    let unconnected_raw = resolve_socket_policy_with_protocol_intent(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        Type::RAW,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
    );
    assert_eq!(
        upstream_socket_bind_policy(unconnected_raw, 3003, 2002).address,
        crate::UpstreamBindAddress::RouteSelected,
    );

    let protocol_zero = resolve_socket_policy_for_creation_path_with_lifecycle(
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
        upstream_socket_bind_policy(protocol_zero, 3003, 2002),
        crate::UpstreamSocketBindPolicy {
            kernel_id: 0,
            bind_before_connect: true,
            address: crate::UpstreamBindAddress::RouteSelected,
        }
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
    if current_icmp_platform_capabilities().kernel_assigned_dgram_ids {
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
    let policy = exact_test_policy_with_icmp_intent(
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
        let udp = exact_test_policy_with_icmp_intent(
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
            crate::ReceiveEvidencePolicy {
                peer_source: crate::PeerSourceRequirement::ConnectedKernel,
                protocol_id: crate::ProtocolIdRequirement::None,
            }
        );
        assert_eq!(
            udp.evidence_policy(false),
            crate::ReceiveEvidencePolicy {
                peer_source: crate::PeerSourceRequirement::SourceMetadata,
                protocol_id: crate::ProtocolIdRequirement::None,
            }
        );
        let listener_udp = exact_test_policy_with_icmp_intent(
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
            crate::ReceiveEvidencePolicy {
                peer_source: crate::PeerSourceRequirement::SourceMetadata,
                protocol_id: crate::ProtocolIdRequirement::None,
            }
        );

        let raw = exact_test_policy_with_icmp_intent(
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
                crate::ReceiveEvidencePolicy {
                    peer_source: crate::PeerSourceRequirement::RawPacketHeader,
                    protocol_id: crate::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
            assert_eq!(
                raw.evidence_policy(false),
                crate::ReceiveEvidencePolicy {
                    peer_source: crate::PeerSourceRequirement::RawPacketHeader,
                    protocol_id: crate::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
        } else {
            assert_eq!(
                raw.evidence_policy(true),
                crate::ReceiveEvidencePolicy {
                    peer_source: crate::PeerSourceRequirement::ConnectedKernel,
                    protocol_id: crate::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
            assert_eq!(
                raw.evidence_policy(false),
                crate::ReceiveEvidencePolicy {
                    peer_source: crate::PeerSourceRequirement::SourceMetadata,
                    protocol_id: crate::ProtocolIdRequirement::ParsedTransportIdentifier,
                }
            );
        }
    }
}

#[test]
fn ipv6_destination_scope_policy_is_explicit_and_fails_closed_to_exact_bind_evidence() {
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        for family in [Domain::IPV4, Domain::IPV6] {
            let policy = exact_test_policy_with_icmp_intent(
                role,
                SupportedProtocol::ICMP,
                Type::RAW,
                TimeoutAction::Exit,
                false,
                family,
                IcmpPolicyIntent::default(),
            );
            assert_eq!(
                policy.ipv6_destination_scope,
                if family == Domain::IPV6 {
                    crate::Ipv6DestinationScopeEvidence::ExactBoundEndpoint
                } else {
                    crate::Ipv6DestinationScopeEvidence::NotApplicable
                }
            );
        }
    }
}

#[test]
fn receive_syscall_policy_optimizes_safe_connected_roles_and_preserves_listener_metadata() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let listener_udp = exact_test_policy_with_icmp_intent(
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
            crate::ReceiveSyscall::RecvFrom
        );
        assert_eq!(
            listener_udp.receive_syscall(false),
            crate::ReceiveSyscall::RecvFrom
        );
        let upstream_udp = exact_test_policy_with_icmp_intent(
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
            crate::ReceiveSyscall::Recv
        );
        assert_eq!(
            upstream_udp.receive_syscall(false),
            crate::ReceiveSyscall::RecvFrom
        );

        for socket_type in [Type::DGRAM, Type::RAW] {
            let icmp = exact_test_policy_with_icmp_intent(
                SocketRole::Upstream,
                SupportedProtocol::ICMP,
                socket_type,
                TimeoutAction::Drop,
                false,
                family,
                IcmpPolicyIntent::default(),
            );
            assert_eq!(icmp.receive_syscall(true), crate::ReceiveSyscall::Recv);
            assert_eq!(icmp.receive_syscall(false), crate::ReceiveSyscall::RecvFrom);
        }
    }
}

#[test]
fn listener_worker_socket_policy_limits_separate_state_to_kernel_flow_affinity() {
    assert_eq!(
        listener_worker_socket_policy(1, true),
        crate::ListenerWorkerSocketPolicy {
            reuse_address: false,
            reuse_port: false,
            distribution: crate::ListenerWorkerDistribution::SingleSocket,
        }
    );

    let shared = listener_worker_socket_policy(3, false);
    assert!(shared.supports_requested_distribution());
    assert_eq!(
        shared.distribution,
        crate::ListenerWorkerDistribution::SharedState
    );
    assert!(shared.reuse_address);
    assert_eq!(shared.reuse_port, cfg!(unix));
    let listener_udp = resolve_listener_test_policy(
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        false,
        Domain::IPV4,
        shared,
    );
    let expected_shared_lifecycle = if listener_udp
        .disconnect
        .evidence
        .supports_safe_same_descriptor_relock()
    {
        ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::DisconnectToOriginalBind,
        }
    } else if listener_same_bind_replacement_lifecycle_eligible(
        SocketPlatform::current(),
        Domain::IPV4,
        shared,
    ) {
        ListenerLockLifecycle::Connected {
            clear: ListenerClearStrategy::ReplaceOwnerSameBind,
        }
    } else {
        ListenerLockLifecycle::StayUnconnectedReplaceOnClear
    };
    assert_eq!(
        listener_udp.listener_lifecycle,
        Some(expected_shared_lifecycle)
    );
    assert_eq!(
        listener_same_bind_replacement_lifecycle_eligible(
            SocketPlatform::current(),
            Domain::IPV4,
            shared,
        ),
        matches!(
            SocketPlatform::current(),
            SocketPlatform::Linux
                | SocketPlatform::Macos
                | SocketPlatform::Windows
                | SocketPlatform::Freebsd
        )
    );

    let forced_unconnected_udp = resolve_listener_test_policy(
        ProtocolPolicyIntent::Udp,
        Type::DGRAM,
        TimeoutAction::Drop,
        true,
        Domain::IPV4,
        shared,
    );
    assert_eq!(
        forced_unconnected_udp.listener_lifecycle,
        Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
    );

    let separate = listener_worker_socket_policy(3, true);
    let kernel_flow_affinity = matches!(
        SocketPlatform::current(),
        SocketPlatform::Linux | SocketPlatform::Android
    );
    assert_eq!(
        separate.distribution,
        if kernel_flow_affinity {
            crate::ListenerWorkerDistribution::KernelFlowAffinity
        } else {
            crate::ListenerWorkerDistribution::UnsupportedSeparateState
        }
    );
    assert_eq!(
        separate.supports_requested_distribution(),
        kernel_flow_affinity
    );
}

#[test]
fn reuse_port_action_is_the_single_platform_authority() {
    let expected = match crate::SocketPlatform::current() {
        crate::SocketPlatform::Linux
        | crate::SocketPlatform::Android
        | crate::SocketPlatform::Macos
        | crate::SocketPlatform::Ios
        | crate::SocketPlatform::Freebsd => crate::ReusePortAction::Enable,
        crate::SocketPlatform::Windows | crate::SocketPlatform::Other => {
            crate::ReusePortAction::Unsupported
        }
    };
    assert_eq!(
        crate::reuse_port_action(false),
        crate::ReusePortAction::Disabled
    );
    assert_eq!(crate::reuse_port_action(true), expected);
}

#[test]
fn upstream_reresolve_uses_only_proven_family_reconnect_capability() {
    for family in [Domain::IPV4, Domain::IPV6] {
        let capability =
            upstream_reresolve_capability(SupportedProtocol::UDP, Type::DGRAM, false, family);
        let measured = matches!(
            crate::SocketPlatform::current(),
            crate::SocketPlatform::Linux
                | crate::SocketPlatform::Android
                | crate::SocketPlatform::Macos
                | crate::SocketPlatform::Ios
                | crate::SocketPlatform::Windows
                | crate::SocketPlatform::Freebsd
        );
        assert_eq!(capability.can_disconnect(), measured);
        assert!(!capability.can_reconnect_to_new_target());
        assert_eq!(
            capability.reresolve_mode(),
            crate::SocketReresolveMode::ReplaceSocket
        );
    }
}

#[test]
fn shared_flow_icmp_workers_use_one_policy_owned_transport_identity() {
    let shared = crate::upstream_worker_socket_policy(
        3,
        false,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        Domain::IPV4,
    );
    let supported = crate::shared_icmp_identity_supported(crate::SharedIcmpIdentityRealityKey {
        platform: SocketPlatform::current(),
        family: Domain::IPV4,
        socket_type: Type::DGRAM,
    });
    assert_eq!(shared.supports_requested_distribution(), supported);
    assert_eq!(shared.shares_icmp_identity(), supported);
    assert_eq!(shared.reuse_address, supported);
    assert_eq!(shared.reuse_port, supported);

    let separate = crate::upstream_worker_socket_policy(
        3,
        true,
        SupportedProtocol::ICMP,
        Type::DGRAM,
        Domain::IPV4,
    );
    assert!(separate.supports_requested_distribution());
    assert!(!separate.shares_icmp_identity());
    assert!(!separate.reuse_port);

    let udp = crate::upstream_worker_socket_policy(
        3,
        false,
        SupportedProtocol::UDP,
        Type::DGRAM,
        Domain::IPV4,
    );
    assert!(udp.supports_requested_distribution());
    assert!(!udp.shares_icmp_identity());
    assert!(!udp.reuse_port);

    let raw = crate::upstream_worker_socket_policy(
        3,
        false,
        SupportedProtocol::ICMP,
        Type::RAW,
        Domain::IPV4,
    );
    assert!(raw.supports_requested_distribution());
    assert!(!raw.shares_icmp_identity());
    assert!(!raw.reuse_port);
}
