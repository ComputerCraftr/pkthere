//! UDP test-network helpers shared across integration-style test targets.

use crate::timing::{CLIENT_WAIT_MS, SOCKET_WITNESS_POLL, SOCKET_WITNESS_WAIT};
use socket2::Domain;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

pub fn udp_listen_arg(addr: SocketAddr) -> String {
    format!("UDP:{}", render_canonical_ip_id(addr.ip(), addr.port()))
}

pub const ALL_IP_FAMILIES: [Domain; 2] = [Domain::IPV4, Domain::IPV6];

pub const NODE1_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const NODE1_IPV4_STR: &str = "127.0.0.1";
fn bind_udp_client_impl(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(CLIENT_WAIT_MS))?;
    sock.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    Ok(sock)
}

pub fn bind_udp_client(family: Domain) -> io::Result<UdpSocket> {
    bind_udp_client_with_port(family, 0)
}

pub fn bind_udp_client_with_port(family: Domain, port: u16) -> io::Result<UdpSocket> {
    if family == Domain::IPV4 {
        bind_udp_client_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
    } else if family == Domain::IPV6 {
        bind_udp_client_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        )))
    } else {
        Err(io::Error::other("unsupported domain"))
    }
}

pub fn random_unprivileged_port(family: Domain) -> io::Result<u16> {
    let sock = bind_udp_client(family)?;
    Ok(sock.local_addr()?.port())
}

pub fn localhost_addr(family: Domain, port: u16) -> SocketAddr {
    if family == Domain::IPV4 {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    } else if family == Domain::IPV6 {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
    } else {
        panic!("unsupported domain")
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

pub fn render_canonical_ip_id(ip: IpAddr, id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}:{id}"),
        IpAddr::V6(ip) => format!("[{ip}]:{id}"),
    }
}

#[derive(Clone, Copy)]
enum EchoMode {
    ConnectedPeer,
    MultiplePeers,
}

pub struct UdpEchoServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    completed: mpsc::Receiver<io::Result<()>>,
    thread: Option<JoinHandle<()>>,
}

impl UdpEchoServer {
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn shutdown(mut self, deadline: Instant) -> io::Result<()> {
        self.shutdown_inner(deadline)
    }

    fn shutdown_inner(&mut self, deadline: Instant) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let wait = deadline.saturating_duration_since(Instant::now());
        let result = self
            .completed
            .recv_timeout(wait)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "UDP echo server {} did not stop by its deadline",
                        self.address
                    ),
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other("UDP echo server completion channel disconnected")
                }
            })?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("UDP echo server thread panicked"))?;
        }
        result
    }
}

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.shutdown_inner(Instant::now() + SOCKET_WITNESS_WAIT);
        }
    }
}

fn spawn_udp_echo_server_impl(addr: SocketAddr, mode: EchoMode) -> io::Result<UdpEchoServer> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(SOCKET_WITNESS_POLL))?;
    socket.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    let address = socket.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let (completion_sender, completed) = mpsc::channel();
    let thread = thread::spawn(move || {
        let result = match mode {
            EchoMode::ConnectedPeer => run_connected_echo(socket, &thread_stop),
            EchoMode::MultiplePeers => run_multi_peer_echo(socket, &thread_stop),
        };
        let _ = completion_sender.send(result);
    });
    Ok(UdpEchoServer {
        address,
        stop,
        completed,
        thread: Some(thread),
    })
}

fn run_connected_echo(socket: UdpSocket, stop: &AtomicBool) -> io::Result<()> {
    let mut buf = [0u8; 65535];
    let mut connected = false;
    while !stop.load(Ordering::Acquire) {
        if !connected {
            match socket.recv_from(&mut buf) {
                Ok((count, source)) => {
                    socket.connect(source)?;
                    connected = true;
                    socket.send(&buf[..count])?;
                }
                Err(error) if is_socket_timeout(&error) => {}
                Err(error) => return Err(error),
            }
        } else {
            match socket.recv(&mut buf) {
                Ok(count) => {
                    socket.send(&buf[..count])?;
                }
                Err(error) if is_socket_timeout(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn run_multi_peer_echo(socket: UdpSocket, stop: &AtomicBool) -> io::Result<()> {
    let mut buffer = [0u8; 65535];
    while !stop.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((count, peer)) => {
                socket.send_to(&buffer[..count], peer)?;
            }
            Err(error) if is_socket_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn is_socket_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

pub fn spawn_udp_echo_server(family: Domain) -> io::Result<UdpEchoServer> {
    if family == Domain::IPV4 {
        spawn_udp_echo_server_impl(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            EchoMode::ConnectedPeer,
        )
    } else if family == Domain::IPV6 {
        spawn_udp_echo_server_impl(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
            EchoMode::ConnectedPeer,
        )
    } else {
        Err(io::Error::other("unsupported domain"))
    }
}

pub fn spawn_udp_multi_peer_echo_server(family: Domain) -> io::Result<UdpEchoServer> {
    let address = localhost_addr(family, 0);
    spawn_udp_echo_server_impl(address, EchoMode::MultiplePeers)
}

#[cfg(test)]
mod tests {
    use super::{
        Domain, default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
        render_canonical_ip_id, render_icmp_arg, spawn_udp_echo_server,
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
}
