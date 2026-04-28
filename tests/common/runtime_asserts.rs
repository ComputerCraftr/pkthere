use crate::core::{strip_log_prefix, wait_for_stats_json_from};
use crate::orchestrator::{CLIENT_WAIT_MS, JSON_WAIT_MS};

use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub fn wait_for_stats_matching<R: Read>(
    reader: &mut R,
    max_wait: Duration,
    mut predicate: impl FnMut(&serde_json::Value) -> bool,
) -> Option<serde_json::Value> {
    let give_up = Instant::now() + max_wait;
    while Instant::now() < give_up {
        if let Some(candidate) = wait_for_stats_json_from(reader, JSON_WAIT_MS) {
            if predicate(&candidate) {
                return Some(candidate);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

pub fn send_until_locked<R: Read>(
    client: &UdpSocket,
    payload: &[u8],
    reader: &mut R,
    max_attempts: usize,
    wait_each: Duration,
) -> Option<SocketAddr> {
    for _ in 0..max_attempts {
        let _ = client.send(payload);
        if let Some(locked) = wait_for_locked_client_from(reader, wait_each) {
            return Some(locked);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

pub fn expect_no_echo(client: &UdpSocket, buf: &mut [u8]) {
    match client.recv(buf) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
        Err(e) => panic!("unexpected recv error: {e}"),
        Ok(n) => panic!("unexpected payload of {n} bytes"),
    }
}

pub fn wait_for_locked_client_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let parse_sa = |line: &str| {
        let line = strip_log_prefix(line);
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(' ')
            .map(|(left, _)| left.trim())?;

        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }

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
    let s = v.as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "expected string socket addr in JSON",
        )
    })?;

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
