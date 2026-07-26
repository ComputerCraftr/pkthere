use crate::network::{
    UdpEchoServer, bind_udp_client, default_test_icmp_upstream_arg, localhost_addr,
    spawn_udp_echo_server,
};
use pkthere_wire::SupportedProtocol;
use socket2::Domain;
use std::net::{SocketAddr, UdpSocket};

pub const PRODUCTION_CONNECTION_SCENARIOS: [MatrixConnectionScenario; 1] =
    [MatrixConnectionScenario::ProductionPolicy];
pub const FORCED_UNCONNECTED_DEBUG_SCENARIOS: [MatrixConnectionScenario; 1] =
    [MatrixConnectionScenario::ForcedUnconnectedDebug];
pub const IPV4_ONLY_FAMILIES: [Domain; 1] = [Domain::IPV4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatrixConnectionScenario {
    ProductionPolicy,
    ForcedUnconnectedDebug,
}

impl MatrixConnectionScenario {
    pub const fn debug_force_unconnected(self) -> bool {
        matches!(self, Self::ForcedUnconnectedDebug)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MatrixCase {
    pub family: Domain,
    pub proto: SupportedProtocol,
    pub client_connection: MatrixConnectionScenario,
    pub upstream_connection: MatrixConnectionScenario,
}

pub fn run_matrix_cases(
    families: &[Domain],
    protos: &[&str],
    client_connection_scenarios: &[MatrixConnectionScenario],
    upstream_connection_scenarios: &[MatrixConnectionScenario],
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
            client_connection_scenarios
                .iter()
                .copied()
                .map(move |client_connection| (family, proto, client_connection))
        })
        .flat_map(|(family, proto, client_connection)| {
            upstream_connection_scenarios
                .iter()
                .copied()
                .map(move |upstream_connection| MatrixCase {
                    family,
                    proto,
                    client_connection,
                    upstream_connection,
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
