use super::ClientFlowKey;
use crate::endpoint::LogicalEndpoint;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[test]
fn udp_flow_key_uses_full_logical_endpoint() {
    let a = ClientFlowKey::Udp(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000));
    let b = ClientFlowKey::Udp(LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001));
    assert_ne!(a, b);
}

#[test]
fn icmp_flow_key_uses_ip_and_identifier() {
    let a = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 10));
    let b = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 11));
    let c = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::new(127, 0, 0, 2), 10));
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn icmp_v6_flow_key_preserves_scope() {
    let a = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 10, 2));
    let b = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 10, 3));
    assert_ne!(a, b);
}

#[test]
fn icmp_v6_flow_key_does_not_use_socket_flowinfo() {
    let endpoint = |flowinfo| {
        LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, flowinfo, 2)),
            10,
        )
    };
    assert_eq!(
        ClientFlowKey::Icmp(endpoint(1)),
        ClientFlowKey::Icmp(endpoint(0x000f_ffff))
    );
}
