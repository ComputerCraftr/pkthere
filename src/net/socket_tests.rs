use super::{
    UpstreamSocketRequest, make_socket, make_upstream_socket_for,
    resolve_listener_endpoint_identity, resolve_route_local_ip, resolve_upstream_endpoint_identity,
    resolve_upstream_pre_socket_ids,
};
use crate::cli::{SupportedProtocol, TimeoutAction::Drop};
use crate::endpoint::LogicalEndpoint;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ResolvedSocketPolicy, SocketRole, listener_worker_socket_policy,
    resolve_socket_policy_with_icmp_intent,
};
use socket2::{Domain, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

fn test_policy(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
) -> ResolvedSocketPolicy {
    resolve_socket_policy_with_icmp_intent(
        role,
        proto,
        sock_type,
        Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
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
        debug_handles: false,
    }
}

fn test_policy_with_intent(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    intent: IcmpPolicyIntent,
) -> ResolvedSocketPolicy {
    resolve_socket_policy_with_icmp_intent(
        role,
        proto,
        sock_type,
        Drop,
        false,
        Domain::IPV4,
        intent,
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
        identity.logical_local,
        LogicalEndpoint::from_socket_addr(kernel)
    );
    assert_eq!(identity.kernel_addr, kernel);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
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
        identity.logical_local,
        LogicalEndpoint::from_socket_addr(requested)
    );
    assert_eq!(identity.kernel_addr, kernel);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
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
        identity.logical_local,
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
        false,
    );

    assert_eq!(
        identity.local_filter,
        LogicalEndpoint::from_socket_addr(actual_local)
    );
    assert_eq!(
        identity.remote_filter,
        LogicalEndpoint::from_socket_addr(remote)
    );
    assert_eq!(identity.local_kernel_addr, actual_local);
}

#[test]
fn upstream_icmp_dgram_wildcard_defers_then_collapses_to_kernel_id() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::DGRAM);
    let pre_kernel = resolve_upstream_pre_socket_ids(0, 0, policy, false);
    if cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(pre_kernel, (0, 0));
    } else {
        assert_ne!(pre_kernel.0, 0);
        assert_eq!(pre_kernel.0, pre_kernel.1);
    }

    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5678);
    let identity = resolve_upstream_endpoint_identity(remote, 0, 0, actual_local, policy, false);

    assert_eq!(identity.local_filter.id(), 5678);
    assert_eq!(identity.remote_filter.id(), 5678);
    assert_eq!(identity.local_kernel_addr.port(), 5678);
}

#[test]
fn upstream_icmp_raw_wildcard_pre_socket_ids_are_disjoint_by_default() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);
    let (local, remote) = resolve_upstream_pre_socket_ids(0, 0, policy, false);

    assert_ne!(local, 0);
    assert_ne!(remote, 0);
    assert_ne!(local, remote);
}

#[test]
fn route_local_ip_resolution_maps_loopback_destination_to_loopback_source() {
    let route_target = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
        Ok(socket) => socket,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("bind route-lookup destination: {err}"),
    };
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
    let identity =
        resolve_upstream_endpoint_identity(remote, 1202, 1101, actual_local, policy, false);

    assert_eq!(identity.local_filter.id(), 1202);
    assert_eq!(identity.remote_filter.id(), 1101);
    assert_eq!(identity.local_kernel_addr.port(), actual_local.port());
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
    let (local, remote) = resolve_upstream_pre_socket_ids(0, 0, policy, false);

    assert_ne!(local, 0);
    assert_eq!(local, remote);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn upstream_endpoint_identity_ignores_untrusted_raw_kernel_id() {
    let policy = test_policy(SocketRole::Upstream, SupportedProtocol::ICMP, Type::RAW);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1101);
    let actual_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let identity =
        resolve_upstream_endpoint_identity(remote, 1202, 1101, actual_local, policy, false);

    assert_eq!(identity.local_filter.id(), 1202);
    assert_eq!(identity.remote_filter.id(), 1101);
    assert_eq!(identity.local_kernel_addr.port(), actual_local.port());
}

#[test]
fn test_make_upstream_socket_local_id_assigned() {
    // Use a loopback UDP address as destination to avoid privilege issues
    // while still testing the port/ID assignment logic on platforms where
    // ICMP datagram sockets are not the default connected path.
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    let (dest, proto) = (
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)),
        SupportedProtocol::UDP,
    );

    // Use ID 0 for ICMP to trigger dynamic local/remote ID assignment where
    // ICMP datagram sockets are the normal connected upstream path.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let (dest, proto) = (
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        SupportedProtocol::ICMP,
    );

    let (sock, local, remote, _local_kernel_addr, sock_type, connected_policy) =
        make_upstream_socket_for(upstream_request(dest, proto))
            .expect("make_upstream_socket_for failed");

    assert_eq!(
        sock_type,
        Type::DGRAM,
        "Upstream socket type should be DGRAM"
    );
    if proto == SupportedProtocol::ICMP && cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(
            local.id(),
            remote.id(),
            "DGRAM wildcard ICMP should be collapsed when concrete or still deferred"
        );
    } else {
        assert_ne!(remote.id(), 0, "remote logical ID should be nonzero");
        assert_ne!(local.id(), 0, "local logical ID should be assigned");
    }
    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        proto,
        sock_type,
        Drop,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    assert_eq!(connected_policy, policy);
    #[cfg(target_os = "macos")]
    assert_eq!(sock.local_addr().unwrap().as_socket().unwrap().port(), 0);
    #[cfg(not(any(target_os = "macos")))]
    assert_eq!(
        sock.local_addr().unwrap().as_socket().unwrap().port(),
        local.id()
    );
}

#[test]
fn debug_forced_raw_wildcard_upstream_uses_collapsed_ids_when_available() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    let result = make_upstream_socket_for(UpstreamSocketRequest {
        force_raw_wildcard_icmp: true,
        ..upstream_request(dest, SupportedProtocol::ICMP)
    });
    let (_sock, local, remote, _local_kernel_addr, sock_type, policy) = match result {
        Ok(parts) => parts,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("debug forced RAW wildcard upstream socket: {err}"),
    };

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
    let (_sock, local, _remote, _local_kernel_addr, sock_type, connected) =
        make_upstream_socket_for(upstream_request(dest, SupportedProtocol::UDP))
            .expect("connected udp upstream socket");
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
        1000,
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
fn upstream_connectedness_matches_platform_policy() {
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    let protocols = vec![SupportedProtocol::UDP];

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let protocols = vec![SupportedProtocol::UDP, SupportedProtocol::ICMP];

    for proto in protocols {
        let dest = match proto {
            SupportedProtocol::UDP => LogicalEndpoint::from_socket_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                9,
            )),
            SupportedProtocol::ICMP => LogicalEndpoint::from_socket_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
            )),
        };

        let (_sock, _local, _remote, _local_kernel_addr, sock_type, connected_policy) =
            make_upstream_socket_for(upstream_request(dest, proto)).expect("upstream socket");
        let policy = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            proto,
            sock_type,
            Drop,
            false,
            dest.domain(),
            IcmpPolicyIntent::default(),
        );
        assert_eq!(
            connected_policy, policy,
            "proto={:?} sock_type={:?} connected mismatch",
            proto, sock_type
        );
    }
}

#[test]
fn debug_unconnected_forces_otherwise_connected_upstream_unconnected() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
    let (_sock, _local, _remote, _local_kernel_addr, _sock_type, connected) =
        make_upstream_socket_for(UpstreamSocketRequest {
            debug_unconnected: true,
            ..upstream_request(dest, SupportedProtocol::UDP)
        })
        .expect("debug unconnected upstream socket");
    assert!(!connected.reuse.starts_connected());
}

#[test]
fn debug_unconnected_upstream_binds_a_concrete_local_port() {
    let probe = match std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
    {
        Ok(probe) => probe,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("bind UDP probe socket: {err}"),
    };
    let dest = LogicalEndpoint::from_socket_addr(probe.local_addr().expect("probe UDP local addr"));
    let (_sock, local, _remote, local_kernel_addr, _sock_type, connected) =
        make_upstream_socket_for(UpstreamSocketRequest {
            debug_unconnected: true,
            ..upstream_request(dest, SupportedProtocol::UDP)
        })
        .expect("debug unconnected upstream socket");
    assert!(!connected.reuse.starts_connected());
    assert_ne!(local.id(), 0);
    assert_ne!(local_kernel_addr.port(), 0);
}

#[test]
fn kernel_echo_self_handshake_policy_disables_disjoint_ids() {
    let dest =
        LogicalEndpoint::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    let (_, _, _, _, _, policy) = make_upstream_socket_for(UpstreamSocketRequest {
        allow_debug_kernel_echo_self_handshake: true,
        ..upstream_request(dest, SupportedProtocol::ICMP)
    })
    .expect("make upstream socket");

    let icmp = policy.icmp.expect("ICMP policy");
    assert!(icmp.allow_debug_kernel_echo_self_handshake);
    assert!(!icmp.can_honor_disjoint_ids());
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn fixed_collapsed_icmp_upstream_preserves_requested_ping_id() {
    let id_allocator = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("allocate fixed ICMP test identifier");
    let requested_id = id_allocator
        .local_addr()
        .expect("fixed ICMP test identifier address")
        .port();
    drop(id_allocator);

    let destination = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), requested_id),
        requested_id,
    );
    let (_socket, local, remote, kernel_local, socket_type, policy) =
        make_upstream_socket_for(UpstreamSocketRequest {
            req_local_id: requested_id,
            ..upstream_request(destination, SupportedProtocol::ICMP)
        })
        .expect("create fixed collapsed ICMP DGRAM upstream");

    assert_eq!(socket_type, Type::DGRAM);
    assert_eq!(local.id(), requested_id);
    assert_eq!(remote.id(), requested_id);
    if kernel_local.port() != 0 {
        assert_eq!(kernel_local.port(), requested_id);
    }
    assert!(policy.icmp.expect("ICMP socket policy").fixed_ids_honored);
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
        let (_socket, local, remote, local_kernel_addr, socket_type, policy) = match result {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) => panic!(
                "make unconnected wildcard ICMP upstream socket for {destination_ip}: {error}"
            ),
        };

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
