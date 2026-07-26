use super::{
    Domain, bind_udp_client, default_test_icmp_upstream_arg, default_test_upstream_arg,
    localhost_addr, render_canonical_ip_id, render_icmp_arg, spawn_udp_echo_server,
};
use crate::timing::SOCKET_WITNESS_WAIT;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

#[test]
fn default_test_upstream_arg_preserves_protocol_specific_shape() {
    let addr = localhost_addr(Domain::IPV4, 4444);
    for (proto, expected) in [
        ("ICMP", format!("ICMP:{}:0", super::NODE1_IPV4_STR)),
        ("UDP", format!("UDP:{}:4444", super::NODE1_IPV4_STR)),
    ] {
        assert_eq!(default_test_upstream_arg(proto, addr), expected);
    }
}

#[test]
fn default_test_icmp_upstream_arg_uses_zero_id() {
    assert_eq!(
        default_test_icmp_upstream_arg(IpAddr::V4(super::NODE1_IPV4)),
        format!("ICMP:{}:0", super::NODE1_IPV4_STR)
    );
}

#[test]
fn render_icmp_arg_brackets_ipv6() {
    assert_eq!(
        render_icmp_arg(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234),
        "ICMP:[::1]:1234"
    );
    assert_eq!(
        render_canonical_ip_id(IpAddr::V6(Ipv6Addr::LOCALHOST), 77),
        "[::1]:77"
    );
}

#[test]
fn echo_server_shutdown_releases_bound_port() {
    let server = spawn_udp_echo_server(Domain::IPV4).expect("spawn UDP echo server");
    let address = server.address();
    server
        .shutdown(Instant::now() + SOCKET_WITNESS_WAIT)
        .expect("shutdown UDP echo server");
    let rebound = std::net::UdpSocket::bind(address).expect("rebind released echo address");
    drop(rebound);
}

#[test]
fn connected_echo_server_round_trips_payload_before_shutdown() {
    let server = spawn_udp_echo_server(Domain::IPV4).expect("spawn UDP echo server");
    let client = bind_udp_client(Domain::IPV4).expect("bind UDP client");
    client
        .connect(server.address())
        .expect("connect UDP echo client");
    client.send(b"echo-witness").expect("send UDP witness");
    let mut bytes = [0_u8; 32];
    let count = client.recv(&mut bytes).expect("receive UDP witness");
    assert_eq!(&bytes[..count], b"echo-witness");
    server
        .shutdown(Instant::now() + SOCKET_WITNESS_WAIT)
        .expect("shutdown UDP echo server");
}
