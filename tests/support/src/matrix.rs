use crate::network::{
    UdpEchoServer, bind_udp_client, default_test_icmp_upstream_arg, localhost_addr,
    spawn_udp_echo_server,
};
use pkthere_wire::SupportedProtocol;
use socket2::Domain;
use std::net::{SocketAddr, UdpSocket};

pub const ALL_CONNECT_MODES: [bool; 2] = [false, true];
pub const IPV4_ONLY_FAMILIES: [Domain; 1] = [Domain::IPV4];

#[derive(Clone, Copy, Debug)]
pub struct MatrixCase {
    pub family: Domain,
    pub proto: SupportedProtocol,
    pub debug_client_unconnected: bool,
    pub debug_upstream_unconnected: bool,
}

pub fn run_matrix_cases(
    families: &[Domain],
    protos: &[&str],
    client_unconnected_modes: &[bool],
    upstream_unconnected_modes: &[bool],
    mut run: impl FnMut(MatrixCase),
) {
    let cases = families
        .iter()
        .copied()
        .flat_map(|family| {
            protos.iter().map(move |proto| {
                (
                    family,
                    SupportedProtocol::from_str(proto).expect("matrix protocol must be supported"),
                )
            })
        })
        .flat_map(|(family, proto)| {
            client_unconnected_modes
                .iter()
                .copied()
                .map(move |client_unconnected| (family, proto, client_unconnected))
        })
        .flat_map(|(family, proto, debug_client_unconnected)| {
            upstream_unconnected_modes
                .iter()
                .copied()
                .map(move |debug_upstream_unconnected| MatrixCase {
                    family,
                    proto,
                    debug_client_unconnected,
                    debug_upstream_unconnected,
                })
        });

    for case in cases {
        run(case);
    }
}

pub fn bind_client_or_skip(family: Domain) -> Option<UdpSocket> {
    match bind_udp_client(family) {
        Ok(sock) => Some(sock),
        Err(e) => panic!("{family:?} loopback is required by the test matrix: {e}"),
    }
}

pub fn spawn_echo_or_skip(family: Domain) -> Option<(SocketAddr, UdpEchoServer)> {
    match spawn_udp_echo_server(family) {
        Ok(server) => Some((server.address(), server)),
        Err(e) => panic!("{family:?} echo server is required by the test matrix: {e}"),
    }
}

pub fn spawn_upstream_echo_or_skip(
    family: Domain,
    proto: &str,
) -> Option<(String, SocketAddr, Option<UdpEchoServer>)> {
    if proto.eq_ignore_ascii_case("icmp") {
        let addr = localhost_addr(family, 0);
        Some((default_test_icmp_upstream_arg(addr.ip()), addr, None))
    } else {
        spawn_echo_or_skip(family)
            .map(|(addr, server)| (format!("{proto}:{addr}"), addr, Some(server)))
    }
}
