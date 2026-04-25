pub use crate::core::{
    IpFamily, NODE1_IPV4, NODE1_IPV4_STR, NODE2_IPV4, NODE2_IPV4_STR, NODE3_IPV4, NODE3_IPV4_STR,
    bind_udp_client, default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
    random_unprivileged_port, spawn_udp_echo_server,
};
use crate::orchestrator::forwarder::SocketMode;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread;

pub const SOCKET_MODES: [SocketMode; 2] = [SocketMode::Connected, SocketMode::Unconnected];
pub const IPV4_ONLY_FAMILIES: [IpFamily; 1] = [IpFamily::V4];

#[derive(Clone, Copy, Debug)]
pub struct MatrixCase<'a> {
    pub family: IpFamily,
    pub proto: &'a str,
    pub mode: SocketMode,
}

impl IpFamily {
    pub fn bind_client(self) -> io::Result<UdpSocket> {
        bind_udp_client(self)
    }

    pub fn spawn_echo(self) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
        spawn_udp_echo_server(self)
    }

    pub const fn listen_arg(self) -> &'static str {
        match self {
            Self::V4 => "UDP:127.0.0.1:0",
            Self::V6 => "UDP:[::1]:0",
        }
    }

    pub const fn is_v6(self) -> bool {
        matches!(self, Self::V6)
    }
}

pub fn run_matrix_cases<'a>(
    families: &'a [IpFamily],
    protos: &'a [&'a str],
    modes: &'a [SocketMode],
    mut run: impl FnMut(MatrixCase<'a>),
) {
    for &family in families {
        for &proto in protos {
            if proto == "ICMP" && !crate::orchestrator::kernel_echo_reply_supported() {
                eprintln!(
                    "skipping ICMP matrix cases: ICMP socket support or kernel echo response unavailable"
                );
                continue;
            }
            for &mode in modes {
                run(MatrixCase {
                    family,
                    proto,
                    mode,
                });
            }
        }
    }
}

pub fn bind_client_or_skip(family: IpFamily) -> Option<UdpSocket> {
    match family.bind_client() {
        Ok(sock) => Some(sock),
        Err(e) if family.is_v6() => {
            eprintln!("IPv6 loopback not available; skipping IPv6 test: {e}");
            None
        }
        Err(e) => panic!("IPv4 loopback not available: {e}"),
    }
}

pub fn spawn_echo_or_skip(family: IpFamily) -> Option<(SocketAddr, thread::JoinHandle<()>)> {
    match family.spawn_echo() {
        Ok(pair) => Some(pair),
        Err(e) if family.is_v6() => {
            eprintln!("IPv6 echo server could not bind; skipping IPv6 test: {e}");
            None
        }
        Err(e) => panic!("IPv4 echo server could not bind: {e}"),
    }
}
