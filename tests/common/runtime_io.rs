//! Process/stdout parsing helpers for forwarder-based tests.

use serde_json::Value as Json;

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

pub fn strip_log_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some(idx) = rest.find("] ")
    {
        return &rest[idx + 2..];
    }
    trimmed
}

pub const fn take_child_stdout(
    child: &mut std::process::Child,
) -> Option<std::process::ChildStdout> {
    child.stdout.take()
}

pub fn wait_for_listen_addr_from<R: Read>(
    reader: &mut R,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let parse_sa = |line: &str| {
        let line = strip_log_prefix(line);
        let addr = line
            .strip_prefix(PREFIX)?
            .split_once(',')
            .map(|(left, _)| left.trim())?
            .split_once(':')
            .map(|(_, right)| right)?;

        if let Ok(sa) = addr.parse::<SocketAddr>() {
            return Some(sa);
        }
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

pub fn wait_for_stats_json_from<R: Read>(reader: &mut R, max_wait: Duration) -> Option<Json> {
    let start = Instant::now();
    let mut buf = String::new();
    let mut r = BufReader::new(reader);
    while start.elapsed() < max_wait {
        let mut line = String::new();
        match r.read_line(&mut line) {
            Ok(0) => thread::sleep(Duration::from_millis(25)),
            Ok(_) => buf.push_str(&line),
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    for line in buf.lines().rev() {
        let line = strip_log_prefix(line);
        if line.starts_with('{')
            && line.ends_with('}')
            && let Ok(json) = serde_json::from_str::<Json>(line)
        {
            return Some(json);
        }
    }
    None
}
