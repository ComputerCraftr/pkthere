use serde_json::Value as Json;

use std::io::{self, BufRead, BufReader, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket,
};
use std::ops::{Deref, DerefMut};
mod app_bin;

use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT_SECS: Duration = Duration::from_secs(2);
pub const MAX_WAIT_SECS: Duration = Duration::from_secs(4);
pub const JSON_WAIT_MS: Duration = Duration::from_millis(50);

pub use app_bin::find_app_bin;

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub const SUPPORTED_PROTOCOLS: &[&str] = &["UDP", "ICMP"];

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub const SUPPORTED_PROTOCOLS: &[&str] = &["UDP"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Ensures the spawned child is terminated on drop (e.g., when a test panics).
pub struct ChildGuard(Child);

impl ChildGuard {
    pub const fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // If it's still running (or we can't tell), try to kill and wait.
        match self.0.try_wait() {
            Ok(Some(_status)) => {
                // already exited
            }
            Ok(None) | Err(_) => {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
}

pub(crate) fn strip_log_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(idx) = rest.find("] ") {
            return &rest[idx + 2..];
        }
    }
    trimmed
}

fn bind_udp_client_impl(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(1000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(1000)))?;
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

fn spawn_udp_echo_server_impl(
    addr: SocketAddr,
) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(1000)))?;
    sock.set_write_timeout(Some(Duration::from_millis(1000)))?;
    let local = sock.local_addr()?;
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut connected = false;
        loop {
            if !connected {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if sock.connect(src).is_ok() {
                            connected = true;
                            let _ = sock.send(&buf[..n]);
                        }
                    }
                    Err(_) => {}
                }
            } else {
                match sock.recv(&mut buf) {
                    Ok(n) => {
                        let _ = sock.send(&buf[..n]);
                    }
                    Err(_) => {}
                }
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

// find_app_bin lives in app_bin.rs for reuse without pulling in core helpers.

/// Take ownership of the child's stdout, returning the ChildStdout handle.
pub const fn take_child_stdout(
    child: &mut std::process::Child,
) -> Option<std::process::ChildStdout> {
    child.stdout.take()
}

/// Wait for a "Listening on ..." line from a generic reader, and parse the socket address.
pub fn wait_for_listen_addr_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let parse_sa = |line: &str| {
        let line = strip_log_prefix(line);
        // Take the left side before the first comma and strip the protocol token
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(',')
            .map(|(left, _)| left.trim())?
            .split_once(':')
            .map(|(_, right)| right)?;

        // Fast path: direct SocketAddr parse (no DNS, no allocations).
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }

        // Fallback: resolve host:port or [IPv6]:port via DNS.
        addr.to_socket_addrs().ok()?.next()
    };

    let start = Instant::now();
    let mut r = BufReader::new(reader);
    const PREFIX: &str = "Listening on ";
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                if let Some(sa) = parse_sa(&line) {
                    return Some(sa);
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    None
}

/// Wait for a JSON stats line from a generic reader.
pub fn wait_for_stats_json_from<R: Read>(reader: &mut R, max_wait: Duration) -> Option<Json> {
    let start = Instant::now();
    let mut buf = String::new();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => {
                buf.push_str(&line);
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    for l in buf.lines().rev() {
        let line = strip_log_prefix(l);
        if line.starts_with('{') && line.ends_with('}') {
            if let Ok(json) = serde_json::from_str::<Json>(line) {
                return Some(json);
            }
        }
    }
    None
}
