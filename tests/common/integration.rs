#[path = "core.rs"]
mod core;

pub use core::{
    ChildGuard, IpFamily, JSON_WAIT_MS, MAX_WAIT_SECS, SUPPORTED_PROTOCOLS, TIMEOUT_SECS,
    bind_udp_client, find_app_bin, random_unprivileged_port, spawn_udp_echo_server,
    take_child_stdout, wait_for_listen_addr_from, wait_for_stats_json_from,
};

use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub const CLIENT_WAIT_MS: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketMode {
    Connected,
    Unconnected,
}

pub const SOCKET_MODES: [SocketMode; 2] = [SocketMode::Connected, SocketMode::Unconnected];

impl SocketMode {
    pub fn apply(self, cmd: &mut Command) {
        if matches!(self, SocketMode::Unconnected) {
            cmd.arg("--debug").arg("no-connect");
        }
    }
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

pub fn run_cases(protos: &[&str], mut run: impl FnMut(&str, SocketMode) -> bool) -> bool {
    for &proto in protos {
        for &mode in &SOCKET_MODES {
            if !run(proto, mode) {
                return false;
            }
        }
    }
    true
}

/// Wait for a "Locked to single client ... (connected)" line from a generic reader,
/// and parse the socket address of the newly locked client.
pub fn wait_for_locked_client_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let parse_sa = |line: &str| {
        let line = core::strip_log_prefix(line);
        // Take the left side before the second space
        // Expected form: "<addr> (connected)\n"
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(' ')
            .map(|(left, _)| left.trim())?;

        // Fast path: direct SocketAddr parse (no DNS, no allocations).
        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }

        // Fallback: resolve host:port or [IPv6]:port via DNS.
        addr.to_socket_addrs().ok()?.next()
    };

    let start = Instant::now();
    let mut r = BufReader::new(reader);
    const PREFIX: &str = "Locked to single client ";
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

pub fn json_addr(v: &serde_json::Value) -> io::Result<SocketAddr> {
    // Expect a JSON string containing a socket address; propagate detailed errors instead of panicking.
    let s = v.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "expected string socket addr in JSON",
        )
    })?;

    // Reject explicit "null" or empty strings early with a clear message.
    if s.eq_ignore_ascii_case("null") || s.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing or null socket addr string in JSON",
        ));
    }

    s.parse::<SocketAddr>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid socket addr string in JSON: '{s}': {e}"),
        )
    })
}
