use crate::core::{strip_log_prefix, wait_for_stats_json_from};
use crate::orchestrator::{
    CLIENT_WAIT_MS, ForwarderSession, JSON_WAIT_MS, snapshot_forwarder_output_tail,
};

use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub struct StatsWaitOutcome {
    pub matched: bool,
    pub last_seen: Option<serde_json::Value>,
    pub recent_stdout_tail: Option<String>,
    pub recent_stderr_tail: Option<String>,
}

impl StatsWaitOutcome {
    pub fn into_matched_stats(self) -> Option<serde_json::Value> {
        if self.matched { self.last_seen } else { None }
    }

    pub fn with_output_tails(mut self, stdout: String, stderr: String) -> Self {
        self.recent_stdout_tail = (!stdout.trim().is_empty()).then_some(stdout);
        self.recent_stderr_tail = (!stderr.trim().is_empty()).then_some(stderr);
        self
    }

    pub fn failure_details(&self) -> String {
        let mut parts = vec![format!(
            "last seen stats: {}",
            self.last_seen
                .as_ref()
                .map(|stats| stats.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        )];

        if let Some(stdout) = &self.recent_stdout_tail {
            parts.push(format!("recent stdout tail:\n{stdout}"));
        }
        if let Some(stderr) = &self.recent_stderr_tail {
            parts.push(format!("recent stderr tail:\n{stderr}"));
        }

        parts.join("\n")
    }
}

pub fn wait_for_stats_matching<R: Read>(
    reader: &mut R,
    max_wait: Duration,
    predicate: impl FnMut(&serde_json::Value) -> bool,
) -> StatsWaitOutcome {
    wait_for_stats_match_or_last(reader, max_wait, predicate)
}

pub fn wait_for_stats_match_or_last<R: Read>(
    reader: &mut R,
    max_wait: Duration,
    mut predicate: impl FnMut(&serde_json::Value) -> bool,
) -> StatsWaitOutcome {
    let give_up = Instant::now() + max_wait;
    let mut last_seen = None;
    while Instant::now() < give_up {
        if let Some(candidate) = wait_for_stats_json_from(reader, JSON_WAIT_MS) {
            let matched = predicate(&candidate);
            last_seen = Some(candidate);
            if matched {
                return StatsWaitOutcome {
                    matched: true,
                    last_seen,
                    recent_stdout_tail: None,
                    recent_stderr_tail: None,
                };
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    StatsWaitOutcome {
        matched: false,
        last_seen,
        recent_stdout_tail: None,
        recent_stderr_tail: None,
    }
}

pub fn wait_for_session_stats_matching(
    session: &mut ForwarderSession,
    max_wait: Duration,
    predicate: impl FnMut(&serde_json::Value) -> bool,
) -> StatsWaitOutcome {
    let outcome = wait_for_stats_match_or_last(&mut session.out, max_wait, predicate);
    match snapshot_forwarder_output_tail(session, 20) {
        Ok((stdout, stderr)) => outcome.with_output_tails(stdout, stderr),
        Err(_) => outcome,
    }
}

pub fn expect_session_stats_matching(
    session: &mut ForwarderSession,
    max_wait: Duration,
    context: &str,
    predicate: impl FnMut(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let outcome = wait_for_session_stats_matching(session, max_wait, predicate);
    assert!(outcome.matched, "{context}\n{}", outcome.failure_details());
    outcome
        .into_matched_stats()
        .expect("matched stats outcome must include last_seen")
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
