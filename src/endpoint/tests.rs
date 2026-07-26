use super::LogicalEndpoint;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[test]
fn exact_equality_is_transitive_for_ipv6_scopes() {
    let first = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1);
    let second = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1);
    let third = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1);
    assert_eq!(first, first);
    assert_eq!(first, second);
    assert_eq!(second, first);
    assert_eq!(second, third);
    assert_eq!(first, third);

    let scope_zero = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0);
    let scope_one = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1);
    let scope_two = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 2);
    assert_ne!(scope_one, scope_zero);
    assert_ne!(scope_zero, scope_two);
    assert_ne!(scope_one, scope_two);
}

#[test]
fn exact_hashing_distinguishes_ipv6_scopes() {
    let endpoints = HashSet::from([
        LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 1),
        LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 2),
    ]);
    assert_eq!(endpoints.len(), 2);
}

#[test]
fn filter_scope_wildcard_is_directional() {
    let wildcard = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0);
    let scoped = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 2);
    assert!(wildcard.matches_filter(scoped));
    assert!(!scoped.matches_filter(wildcard));
}

#[test]
fn resolved_ip_preserves_id_and_missing_ipv6_scope() {
    let endpoint = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 77, 4);
    let resolved = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 999, 0, 0));
    let updated = endpoint.with_resolved_ip(resolved);
    assert_eq!(updated.id(), 77);
    assert_eq!(updated.scope_id(), 4);
}

#[test]
fn udp_and_icmp_socket_projections_use_the_logical_id_once() {
    let udp_endpoint = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242);
    assert_eq!(
        udp_endpoint.to_socket_addr(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242)
    );
    let icmp_endpoint = LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 3131, 7);
    assert_eq!(
        icmp_endpoint.to_socket_addr(),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3131, 0, 7))
    );
    assert_eq!(
        icmp_endpoint
            .to_sock_addr()
            .as_socket()
            .expect("projected IP socket address"),
        icmp_endpoint.to_socket_addr()
    );
}

#[test]
fn unspecified_addresses_and_zero_ids_are_exact_not_implicit_wildcards() {
    let filter = LogicalEndpoint::from_v4(Ipv4Addr::UNSPECIFIED, 0);
    let concrete = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 9);
    assert!(!filter.matches_filter(concrete));
}

#[test]
fn display_preserves_visible_ipv6_scope() {
    assert_eq!(
        LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 0).to_string(),
        "[::1]:7"
    );
    assert_eq!(
        LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 7, 2).to_string(),
        "[::1%2]:7"
    );
}

#[test]
fn socket_flowinfo_is_not_logical_endpoint_identity() {
    let first = LogicalEndpoint::from_socket_addr(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        7,
        1,
        2,
    )));
    let second = LogicalEndpoint::from_socket_addr(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        7,
        2,
        2,
    )));
    assert_eq!(first, second);
    assert_eq!(
        first.to_socket_addr(),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7, 0, 2))
    );
}
