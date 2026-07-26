use super::{
    RealizedUpstreamSocket, SocketCreationAttempt, UpstreamSocketRequest,
    create_socket_from_policy_using, create_socket_with_retry_using, make_socket,
    make_upstream_socket_for, resolve_listener_endpoint_identity, resolve_route_local_ip,
    resolve_upstream_endpoint_identity, resolve_upstream_socket_identity_plan, set_reuse_address,
};
use crate::cli::{SupportedProtocol, TimeoutAction::Drop};
use crate::endpoint::LogicalEndpoint;
use pkthere_socket_policy::{
    DisconnectBindShape, IcmpPolicyIntent, ProtocolPolicyIntent, ResolvedSocketPolicy,
    SocketCreateSpec, SocketCreationFailureClass, SocketCreationPath, SocketCreationPlan,
    SocketFallbackPolicy, SocketLifecycleContext, SocketPathContext, SocketPolicyContext,
    SocketRole, UpstreamWorkerDistribution, current_icmp_platform_capabilities,
    listener_worker_socket_policy, resolve_socket_policy_for_creation_path_with_lifecycle,
    resolve_socket_policy_for_creation_path_with_protocol_intent,
    resolve_socket_policy_with_protocol_intent, upstream_socket_creation_policy,
};
use socket2::{Domain, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

#[cfg(unix)]
const UNSUPPORTED_CANDIDATE_ERROR: i32 = libc::EAFNOSUPPORT;
#[cfg(windows)]
const UNSUPPORTED_CANDIDATE_ERROR: i32 = windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT;

#[test]
fn socket_creation_fallback_accepts_only_unsupported_candidates() {
    let plan = upstream_socket_creation_policy(SupportedProtocol::ICMP, Domain::IPV4, 0, 0, false);
    let fallback = plan.fallback.expect("eligible ICMP DGRAM fallback");
    assert!(
        fallback.permits(pkthere_socket_policy::SocketCreationFailureClass::UnsupportedCandidate)
    );
    for class in [
        pkthere_socket_policy::SocketCreationFailureClass::UnavailableInCurrentExecutionDomain,
        pkthere_socket_policy::SocketCreationFailureClass::PermissionDenied,
        pkthere_socket_policy::SocketCreationFailureClass::TransientInterrupted,
        pkthere_socket_policy::SocketCreationFailureClass::ResourceExhausted,
        pkthere_socket_policy::SocketCreationFailureClass::InvalidSpecification,
        pkthere_socket_policy::SocketCreationFailureClass::Unexpected,
    ] {
        assert!(
            !fallback.permits(class),
            "fallback unexpectedly accepted {class:?}"
        );
    }
}

#[test]
fn creation_plan_falls_back_only_after_an_unsupported_primary_creation() {
    let primary = pkthere_socket_policy::socket_create_spec(
        SocketCreationPath::Datagram,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    let fallback = SocketCreateSpec {
        path: SocketCreationPath::RawIcmp,
        ..primary
    };
    let plan = SocketCreationPlan {
        primary,
        fallback: Some(SocketFallbackPolicy {
            from: primary,
            to: fallback,
            eligible_failures: &[SocketCreationFailureClass::UnsupportedCandidate],
        }),
    };
    let mut attempts = Vec::new();
    let (_, selected) = create_socket_from_policy_using(plan, |spec| {
        attempts.push(spec);
        if spec == primary {
            Err(io::Error::from_raw_os_error(UNSUPPORTED_CANDIDATE_ERROR))
        } else {
            socket2::Socket::new(Domain::IPV4, Type::DGRAM, None)
        }
    })
    .expect("unsupported primary should select its reviewed fallback");

    assert_eq!(attempts, vec![primary, fallback]);
    assert_eq!(selected, fallback);
}

#[test]
fn creation_plan_never_falls_back_for_noneligible_failures() {
    let primary = pkthere_socket_policy::socket_create_spec(
        SocketCreationPath::Datagram,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    let fallback = SocketCreateSpec {
        path: SocketCreationPath::RawIcmp,
        ..primary
    };
    let plan = SocketCreationPlan {
        primary,
        fallback: Some(SocketFallbackPolicy {
            from: primary,
            to: fallback,
            eligible_failures: &[SocketCreationFailureClass::UnsupportedCandidate],
        }),
    };

    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::Unsupported,
        io::ErrorKind::Other,
    ] {
        let mut attempts = Vec::new();
        let error = create_socket_from_policy_using(plan, |spec| {
            attempts.push(spec);
            Err(io::Error::from(kind))
        })
        .err()
        .expect("noneligible primary failure must not select fallback");
        assert_eq!(attempts, vec![primary]);
        let super::SocketCreationError::Candidate(failure) = error else {
            panic!("noneligible primary failure lost its exact candidate error");
        };
        assert_eq!(failure.spec, primary);
        assert_eq!(
            failure.class,
            super::classify_creation_error(&io::Error::from(kind))
        );
        assert_eq!(failure.attempts, 1);
    }
}

#[test]
fn interrupted_socket_creation_retries_same_candidate_and_stops_at_bound() {
    let spec = pkthere_socket_policy::socket_create_spec(
        pkthere_socket_policy::SocketCreationPath::Datagram,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    let mut attempts = 0_u8;
    let result = create_socket_with_retry_using(spec, |observed| {
        assert_eq!(observed, spec);
        attempts = attempts.checked_add(1).expect("bounded attempt count");
        Err(io::Error::from(io::ErrorKind::Interrupted))
    })
    .expect("retry deadline arithmetic");
    let SocketCreationAttempt::Failed(failure) = result else {
        panic!("interrupted creation unexpectedly produced a descriptor");
    };
    assert_eq!(attempts, super::MAX_INTERRUPTED_SOCKET_CREATE_ATTEMPTS);
    assert_eq!(failure.attempts, attempts);
    assert_eq!(
        failure.class,
        pkthere_socket_policy::SocketCreationFailureClass::TransientInterrupted
    );
}

#[test]
fn socket_creation_failure_classes_are_typed_without_fallback_inference() {
    use pkthere_socket_policy::SocketCreationFailureClass as Class;

    for (kind, expected) in [
        (io::ErrorKind::PermissionDenied, Class::PermissionDenied),
        (io::ErrorKind::Interrupted, Class::TransientInterrupted),
        (io::ErrorKind::OutOfMemory, Class::ResourceExhausted),
        (io::ErrorKind::InvalidInput, Class::InvalidSpecification),
        (
            io::ErrorKind::Unsupported,
            Class::UnavailableInCurrentExecutionDomain,
        ),
        (io::ErrorKind::Other, Class::Unexpected),
    ] {
        assert_eq!(
            super::classify_creation_error(&io::Error::from(kind)),
            expected
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_socket_creation_errno_classes_are_exact() {
    use pkthere_socket_policy::SocketCreationFailureClass as Class;

    for errno in [
        libc::EAFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT,
        libc::EPROTOTYPE,
    ] {
        assert_eq!(
            super::classify_creation_error(&io::Error::from_raw_os_error(errno)),
            Class::UnsupportedCandidate
        );
    }
    for errno in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::ENOBUFS] {
        assert_eq!(
            super::classify_creation_error(&io::Error::from_raw_os_error(errno)),
            Class::ResourceExhausted
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_socket_creation_errno_classes_are_exact() {
    use pkthere_socket_policy::SocketCreationFailureClass as Class;
    use windows_sys::Win32::Networking::WinSock::{
        WSAEAFNOSUPPORT, WSAEMFILE, WSAENOBUFS, WSAEPROTONOSUPPORT, WSAEPROTOTYPE,
        WSAESOCKTNOSUPPORT,
    };

    for error in [
        WSAEAFNOSUPPORT,
        WSAEPROTONOSUPPORT,
        WSAESOCKTNOSUPPORT,
        WSAEPROTOTYPE,
    ] {
        assert_eq!(
            super::classify_creation_error(&io::Error::from_raw_os_error(error)),
            Class::UnsupportedCandidate
        );
    }
    for error in [WSAEMFILE, WSAENOBUFS] {
        assert_eq!(
            super::classify_creation_error(&io::Error::from_raw_os_error(error)),
            Class::ResourceExhausted
        );
    }
}

#[test]
fn realizing_socket_setup_failure_closes_the_unpublished_descriptor() {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve probe address");
    let address = probe.local_addr().expect("probe address");
    drop(probe);
    let spec = pkthere_socket_policy::socket_create_spec(
        pkthere_socket_policy::SocketCreationPath::Datagram,
        SupportedProtocol::UDP,
        Domain::IPV4,
    );
    let socket = socket2::Socket::new(spec.domain, spec.socket_type, spec.protocol)
        .expect("create realizing socket");
    let realizing = crate::net::managed_socket::realization::RealizingSocket::new(socket, spec);
    let result = realizing.configure(|socket| {
        socket.bind(&socket2::SockAddr::from(address))?;
        set_reuse_address(socket)?;
        Err(std::io::Error::other("injected setup failure"))
    });
    assert!(result.is_err());
    UdpSocket::bind(address).expect("failed realization must release its exact bind");
}

fn test_policy(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
) -> ResolvedSocketPolicy {
    resolve_socket_policy_with_protocol_intent(
        role,
        match proto {
            SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
            SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        },
        sock_type,
        Drop,
        false,
        Domain::IPV4,
    )
}

fn upstream_request(dest: LogicalEndpoint, proto: SupportedProtocol) -> UpstreamSocketRequest {
    UpstreamSocketRequest {
        dest,
        proto,
        req_local_id: 0,
        timeout_act: Drop,
        debug_unconnected: false,
        force_raw_wildcard_icmp: false,
        allow_debug_kernel_echo_self_handshake: false,
        worker_socket_policy: Default::default(),
        authority_identity: None,
    }
}

fn test_policy_with_intent(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    intent: IcmpPolicyIntent,
) -> ResolvedSocketPolicy {
    resolve_socket_policy_with_protocol_intent(
        role,
        match proto {
            SupportedProtocol::UDP => {
                assert_eq!(intent, IcmpPolicyIntent::default());
                ProtocolPolicyIntent::Udp
            }
            SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(intent),
        },
        sock_type,
        Drop,
        false,
        Domain::IPV4,
    )
}

fn selected_upstream_icmp_policy(requested_id: u16) -> (ResolvedSocketPolicy, Type) {
    let family = Domain::IPV4;
    let creation = upstream_socket_creation_policy(
        SupportedProtocol::ICMP,
        family,
        requested_id,
        requested_id,
        false,
    );
    let selected = creation.primary;
    (
        resolve_socket_policy_for_creation_path_with_protocol_intent(
            SocketRole::Upstream,
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            selected.socket_type,
            Drop,
            false,
            SocketPathContext {
                family,
                creation_path: selected.path,
            },
        ),
        selected.socket_type,
    )
}

#[test]
fn listener_endpoint_identity_resolves_udp_dynamic_port() {
    let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let kernel = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45123);
    let identity = resolve_listener_endpoint_identity(
        requested,
        kernel,
        test_policy(SocketRole::Listener, SupportedProtocol::UDP, Type::DGRAM),
    );

    assert_eq!(
        identity.logical_filter,
        LogicalEndpoint::from_socket_addr(kernel)
    );
    assert_eq!(identity.kernel_addr, kernel);
}

#[test]
fn listener_endpoint_identity_ignores_untrusted_raw_kernel_id() {
    let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1101);
    let kernel = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let identity = resolve_listener_endpoint_identity(
        requested,
        kernel,
        test_policy(SocketRole::Listener, SupportedProtocol::ICMP, Type::RAW),
    );

    assert_eq!(
        identity.logical_filter,
        LogicalEndpoint::from_socket_addr(requested)
    );
    assert_eq!(identity.kernel_addr, kernel);
}

#[test]
fn listener_endpoint_identity_preserves_wildcard_raw_listener_id() {
    let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let kernel = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let identity = resolve_listener_endpoint_identity(
        requested,
        kernel,
        test_policy(SocketRole::Listener, SupportedProtocol::ICMP, Type::RAW),
    );

    assert_eq!(
        identity.logical_filter,
        LogicalEndpoint::from_socket_addr_with_id(requested, 0)
    );
    assert_eq!(identity.kernel_addr, kernel);
}

#[test]
fn upstream_endpoint_identity_resolves_udp_dynamic_local_port() {
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45123);
    let identity = resolve_upstream_endpoint_identity(
        remote,
        0,
        remote.port(),
        actual_local,
        test_policy(SocketRole::Upstream, SupportedProtocol::UDP, Type::DGRAM),
    );

    assert_eq!(
        identity.local.logical_filter,
        LogicalEndpoint::from_socket_addr(actual_local)
    );
    assert_eq!(
        identity.remote_filter,
        LogicalEndpoint::from_socket_addr(remote)
    );
    assert_eq!(identity.local.kernel_addr, actual_local);
}

#[test]
fn upstream_icmp_dgram_wildcard_defers_then_collapses_to_kernel_id() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::DGRAM);
    let plan = resolve_upstream_socket_identity_plan(0, 0, policy);
    let pre_kernel = (plan.local_id, plan.remote_id);
    if current_icmp_platform_capabilities().kernel_assigned_dgram_ids {
        assert_eq!(pre_kernel, (0, 0));
        assert_eq!(plan.bind.kernel_id, 0);
    } else {
        assert_ne!(pre_kernel.0, 0);
        assert_eq!(pre_kernel.0, pre_kernel.1);
        assert_eq!(plan.bind.kernel_id, pre_kernel.0);
    }
    assert!(plan.bind.bind_before_connect);

    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5678);
    let identity = resolve_upstream_endpoint_identity(remote, 0, 0, actual_local, policy);

    assert_eq!(identity.local.logical_filter.id(), 5678);
    assert_eq!(identity.remote_filter.id(), 5678);
    assert_eq!(identity.local.kernel_addr.port(), 5678);
}

#[test]
fn upstream_icmp_raw_wildcard_pre_socket_ids_are_disjoint_by_default() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);
    let plan = resolve_upstream_socket_identity_plan(0, 0, policy);
    let (local, remote) = (plan.local_id, plan.remote_id);

    assert_ne!(local, 0);
    assert_ne!(remote, 0);
    assert_ne!(local, remote);
    assert_eq!(plan.bind.kernel_id, 0);
}

#[test]
fn route_local_ip_resolution_maps_loopback_destination_to_loopback_source() {
    let route_target = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap_or_else(|err| panic!("bind route-lookup destination: {err}"));
    let ip = resolve_route_local_ip(route_target.local_addr().expect("route target address"))
        .expect("route-local-IP resolution");

    assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn route_local_ip_resolution_accepts_protocol_identifier_zero() {
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let ip = resolve_route_local_ip(destination).expect("route-local-IP resolution");

    assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn raw_icmp_endpoint_identity_falls_back_when_kernel_reports_zero_id() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1101);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let identity = resolve_upstream_endpoint_identity(remote, 1202, 1101, actual_local, policy);

    assert_eq!(identity.local.logical_filter.id(), 1202);
    assert_eq!(identity.remote_filter.id(), 1101);
    assert_eq!(identity.local.kernel_addr.port(), actual_local.port());
}

#[test]
fn upstream_icmp_forced_raw_wildcard_pre_socket_ids_are_collapsed() {
    let policy = test_policy_with_intent(
        SocketRole::Upstream,
        SupportedProtocol::ICMP,
        Type::RAW,
        IcmpPolicyIntent {
            disable_disjoint_ids: true,
            allow_debug_kernel_echo_self_handshake: false,
        },
    );
    let plan = resolve_upstream_socket_identity_plan(0, 0, policy);
    let (local, remote) = (plan.local_id, plan.remote_id);

    assert_ne!(local, 0);
    assert_eq!(local, remote);
    assert_eq!(plan.bind.kernel_id, 0);
}

#[test]
fn upstream_endpoint_identity_ignores_untrusted_raw_kernel_id() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1101);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let identity = resolve_upstream_endpoint_identity(remote, 1202, 1101, actual_local, policy);

    assert_eq!(identity.local.logical_filter.id(), 1202);
    assert_eq!(identity.remote_filter.id(), 1101);
    assert_eq!(identity.local.kernel_addr.port(), actual_local.port());
}

#[test]
#[ignore = "privileged RAW socket construction runs through the explicit capability owner"]
fn debug_forced_raw_wildcard_upstream_uses_collapsed_ids_when_available() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    let result = make_upstream_socket_for(UpstreamSocketRequest {
        force_raw_wildcard_icmp: true,
        ..upstream_request(dest, SupportedProtocol::ICMP)
    });
    let realized =
        result.unwrap_or_else(|err| panic!("debug forced RAW wildcard upstream socket: {err}"));

    let RealizedUpstreamSocket {
        local_filter: local,
        remote_filter: remote,
        socket_type: sock_type,
        policy,
        ..
    } = realized;

    assert_eq!(sock_type, Type::RAW);
    assert_ne!(local.id(), 0);
    assert_eq!(local.id(), remote.id());
    let icmp_policy = policy.icmp.expect("ICMP policy");
    assert!(
        !icmp_policy.can_honor_disjoint_ids(),
        "debug RAW wildcard models DGRAM no-disjoint capability"
    );
    assert!(
        icmp_policy.requires_raw_packet_admission(),
        "debug override still uses RAW packet admission"
    );
}

#[test]
fn connected_udp_upstream_local_identity_is_concrete_immediately() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
    let realized = make_upstream_socket_for(upstream_request(dest, SupportedProtocol::UDP))
        .expect("connected udp upstream socket");
    assert!(realized.socket.has_verified_realization_evidence());
    let local = realized.local_filter;
    let sock_type = realized.socket_type;
    let connected = realized.policy;
    assert_eq!(sock_type, Type::DGRAM);
    assert!(connected.reuse.starts_connected());
    assert!(
        !local.ip().is_unspecified(),
        "Connected UDP upstream local identity should be concrete immediately"
    );
}

#[test]
fn udp_listener_reports_logical_and_kernel_identity() {
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (_sock, logical, kernel, sock_type, _policy) = make_socket(
        listen_addr,
        SupportedProtocol::UDP,
        listener_worker_socket_policy(1, false),
        Drop,
        false,
        false,
    )
    .expect("udp listener socket");

    assert_eq!(sock_type, Type::DGRAM);
    assert_eq!(logical, LogicalEndpoint::from_socket_addr(kernel));
    assert_eq!(logical.ip(), listen_addr.ip());
    assert_eq!(kernel.ip(), listen_addr.ip());
    assert!(!logical.ip().is_unspecified());
    assert_ne!(logical.id(), 0);
}

#[test]
fn udp_upstream_connectedness_matches_resolved_exact_policy() {
    let proto = SupportedProtocol::UDP;
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
    let realized =
        make_upstream_socket_for(upstream_request(dest, proto)).expect("UDP upstream socket");
    let sock_type = realized.socket_type;
    let connected_policy = realized.policy;
    let policy = resolve_socket_policy_for_creation_path_with_lifecycle(
        SocketRole::Upstream,
        ProtocolPolicyIntent::Udp,
        sock_type,
        Drop,
        false,
        SocketPolicyContext {
            path: SocketPathContext {
                family: dest.domain(),
                creation_path: connected_policy.creation_path,
            },
            lifecycle: SocketLifecycleContext {
                bind_shape: DisconnectBindShape::WildcardEphemeral,
                reuse_address: false,
                reuse_port: false,
                v6_only: None,
                bound_interface: None,
            },
        },
    );
    assert_eq!(connected_policy, policy);
}

#[test]
fn debug_unconnected_forces_otherwise_connected_upstream_unconnected() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
    let realized = make_upstream_socket_for(UpstreamSocketRequest {
        debug_unconnected: true,
        ..upstream_request(dest, SupportedProtocol::UDP)
    })
    .expect("debug unconnected upstream socket");
    let connected = realized.policy;
    assert!(!connected.reuse.starts_connected());
}

#[test]
fn debug_unconnected_upstream_binds_a_concrete_local_port() {
    let probe = std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap_or_else(|err| panic!("bind UDP probe socket: {err}"));
    let dest = LogicalEndpoint::from_socket_addr(probe.local_addr().expect("probe UDP local addr"));
    let realized = make_upstream_socket_for(UpstreamSocketRequest {
        debug_unconnected: true,
        ..upstream_request(dest, SupportedProtocol::UDP)
    })
    .expect("debug unconnected upstream socket");
    let local = realized.local_filter;
    let local_kernel_addr = realized.local_kernel_addr;
    let connected = realized.policy;
    assert!(!connected.reuse.starts_connected());
    assert_eq!(
        connected.disconnect.fingerprint.bind_shape,
        DisconnectBindShape::ConcreteEphemeral
    );
    assert_ne!(local.id(), 0);
    assert_ne!(local_kernel_addr.port(), 0);
}

#[test]
fn kernel_echo_self_handshake_policy_disables_disjoint_ids() {
    for socket_type in [Type::DGRAM, Type::RAW] {
        let policy = test_policy_with_intent(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            socket_type,
            IcmpPolicyIntent {
                disable_disjoint_ids: true,
                allow_debug_kernel_echo_self_handshake: true,
            },
        );
        let icmp = policy.icmp.expect("ICMP policy");
        assert!(icmp.allow_debug_kernel_echo_self_handshake);
        assert!(!icmp.can_honor_disjoint_ids());
    }
}

#[test]
fn collapsed_icmp_identity_preserves_logical_ids_independently_of_kernel_capability() {
    let requested_id = 37_519;
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), requested_id);
    let (policy, _) = selected_upstream_icmp_policy(requested_id);
    let plan = resolve_upstream_socket_identity_plan(requested_id, requested_id, policy);
    let planned = (plan.local_id, plan.remote_id);
    assert_eq!(planned, (requested_id, requested_id));
    let icmp = policy.icmp.expect("ICMP socket policy");
    if icmp.socket_type == Type::DGRAM {
        assert_eq!(plan.bind.kernel_id, requested_id);
    } else {
        assert_eq!(plan.bind.kernel_id, 0);
    }
    let identity = resolve_upstream_endpoint_identity(remote, planned.0, planned.1, remote, policy);
    assert_eq!(identity.local.logical_filter.id(), requested_id);
    assert_eq!(identity.remote_filter.id(), requested_id);
}

#[test]
fn selected_icmp_worker_distribution_classifies_identity_authority() {
    let (policy, selected_socket_type) = selected_upstream_icmp_policy(0);
    let worker_socket_policy = pkthere_socket_policy::upstream_worker_socket_policy(
        3,
        false,
        SupportedProtocol::ICMP,
        selected_socket_type,
        Domain::IPV4,
    );
    match worker_socket_policy.distribution {
        UpstreamWorkerDistribution::PerWorkerIdentity => {
            assert!(worker_socket_policy.supports_requested_distribution());
            assert_ne!(selected_socket_type, Type::DGRAM);
        }
        UpstreamWorkerDistribution::SharedIcmpIdentity => {
            assert!(worker_socket_policy.supports_requested_distribution());
            assert!(worker_socket_policy.shares_icmp_identity());
            let realized_id = 42_311;
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), realized_id);
            let first = resolve_upstream_endpoint_identity(
                address,
                realized_id,
                realized_id,
                address,
                policy,
            );
            let second = resolve_upstream_endpoint_identity(
                address,
                first.local.logical_filter.id(),
                first.remote_filter.id(),
                address,
                policy,
            );
            assert_eq!(second.local.logical_filter, first.local.logical_filter);
            assert_eq!(second.remote_filter, first.remote_filter);
        }
        UpstreamWorkerDistribution::UnsupportedSharedIcmpIdentity => {
            assert_eq!(selected_socket_type, Type::DGRAM);
            assert!(!worker_socket_policy.supports_requested_distribution());
            assert!(!worker_socket_policy.shares_icmp_identity());
        }
    }
}

#[test]
fn unconnected_kernel_echo_wildcard_uses_platform_socket_mode_and_logical_id() {
    for destination_ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ] {
        let dest = LogicalEndpoint::from_socket_addr(SocketAddr::new(destination_ip, 0));
        let result = make_upstream_socket_for(UpstreamSocketRequest {
            debug_unconnected: true,
            allow_debug_kernel_echo_self_handshake: true,
            ..upstream_request(dest, SupportedProtocol::ICMP)
        });
        let realized = match result {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) => panic!(
                "make unconnected wildcard ICMP upstream socket for {destination_ip}: {error}"
            ),
        };
        let RealizedUpstreamSocket {
            local_filter: local,
            remote_filter: remote,
            local_kernel_addr,
            socket_type,
            policy,
            ..
        } = realized;

        let expected_type = if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos"
        )) {
            Type::DGRAM
        } else {
            Type::RAW
        };
        assert_eq!(socket_type, expected_type, "family={destination_ip}");
        assert_eq!(
            policy
                .icmp
                .expect("ICMP policy")
                .requires_raw_packet_admission(),
            socket_type == Type::RAW,
            "family={destination_ip}"
        );
        assert!(!policy.reuse.starts_connected());
        assert!(!local_kernel_addr.ip().is_unspecified());
        assert_ne!(local.id(), 0);
        assert_eq!(remote.id(), local.id());
        if socket_type == Type::DGRAM && local_kernel_addr.port() != 0 {
            assert_eq!(local.id(), local_kernel_addr.port());
        } else if socket_type == Type::RAW {
            assert_eq!(local_kernel_addr.port(), 0);
        }
    }
}
