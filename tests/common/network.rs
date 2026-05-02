//! UDP test-network helpers shared across integration-style test targets.

use crate::orchestrator::CLIENT_WAIT_MS;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::thread;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

pub const ALL_IP_FAMILIES: [IpFamily; 2] = [IpFamily::V4, IpFamily::V6];

pub const NODE1_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const NODE1_IPV4_STR: &str = "127.0.0.1";
pub const NODE2_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
pub const NODE2_IPV4_STR: &str = "127.0.0.2";
pub const NODE3_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
pub const NODE3_IPV4_STR: &str = "127.0.0.3";

fn bind_udp_client_impl(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(CLIENT_WAIT_MS))?;
    sock.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    Ok(sock)
}

pub fn bind_udp_client(family: IpFamily) -> io::Result<UdpSocket> {
    match family {
        IpFamily::V4 => {
            bind_udp_client_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => bind_udp_client_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

pub fn random_unprivileged_port(family: IpFamily) -> io::Result<u16> {
    let sock = bind_udp_client(family)?;
    Ok(sock.local_addr()?.port())
}

pub fn localhost_addr(family: IpFamily, port: u16) -> SocketAddr {
    match family {
        IpFamily::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        IpFamily::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
    }
}

pub fn default_test_upstream_arg(proto: &str, addr: SocketAddr) -> String {
    if proto.eq_ignore_ascii_case("icmp") {
        render_icmp_arg(addr.ip(), 0)
    } else {
        format!("{proto}:{addr}")
    }
}

pub fn default_test_icmp_upstream_arg(ip: IpAddr) -> String {
    render_icmp_arg(ip, 0)
}

pub fn render_icmp_arg(ip: IpAddr, remote_id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("ICMP:{ip}:{remote_id}"),
        IpAddr::V6(ip) => format!("ICMP:[{ip}]:{remote_id}"),
    }
}

pub fn render_icmp_arg_with_local(ip: IpAddr, remote_id: u16, local_id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("ICMP:{ip}:{remote_id}:{local_id}"),
        IpAddr::V6(ip) => format!("ICMP:[{ip}]:{remote_id}:{local_id}"),
    }
}

pub fn render_canonical_ip_id(ip: IpAddr, id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}:{id}"),
        IpAddr::V6(ip) => format!("[{ip}]:{id}"),
    }
}

fn spawn_udp_echo_server_impl(
    addr: SocketAddr,
) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(CLIENT_WAIT_MS))?;
    sock.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    let local = sock.local_addr()?;
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut connected = false;
        loop {
            if !connected {
                if let Ok((n, src)) = sock.recv_from(&mut buf) {
                    if sock.connect(src).is_ok() {
                        connected = true;
                        let _ = sock.send(&buf[..n]);
                    }
                }
            } else if let Ok(n) = sock.recv(&mut buf) {
                let _ = sock.send(&buf[..n]);
            }
        }
    });
    Ok((local, handle))
}

pub fn spawn_udp_echo_server(family: IpFamily) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    match family {
        IpFamily::V4 => {
            spawn_udp_echo_server_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => spawn_udp_echo_server_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IpFamily, default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
        render_canonical_ip_id, render_icmp_arg, render_icmp_arg_with_local,
    };
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn default_test_upstream_arg_preserves_protocol_specific_shape() {
        let addr = localhost_addr(IpFamily::V4, 4444);
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
            render_icmp_arg_with_local(IpAddr::V6(Ipv6Addr::LOCALHOST), 2002, 1001),
            "ICMP:[::1]:2002:1001"
        );
        assert_eq!(
            render_canonical_ip_id(IpAddr::V6(Ipv6Addr::LOCALHOST), 77),
            "[::1]:77"
        );
    }
}
