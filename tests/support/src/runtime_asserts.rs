use crate::forwarder::{ForwarderSession, snapshot_forwarder_output_tail};
use crate::runtime_io::{parse_locked_client, parse_stats_json};
use crate::timing::TEST_RETRY_INTERVAL;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub struct StatsWaitOutcome {
    pub matched: bool,
    pub last_seen: Option<serde_json::Value>,
    pub recent_stdout_tail: Option<String>,
    pub recent_stderr_tail: Option<String>,
}

impl StatsWaitOutcome {
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

pub fn wait_for_session_stats_matching(
    session: &mut ForwarderSession,
    max_wait: Duration,
    mut predicate: impl FnMut(&serde_json::Value) -> bool,
) -> StatsWaitOutcome {
    let mut last_seen = None;
    let result =
        session.wait_for_stdout_line(Instant::now() + max_wait, "matching stats JSON", |line| {
            let candidate = parse_stats_json(line)?;
            let matched = predicate(&candidate);
            last_seen = Some(candidate.clone());
            matched.then_some(candidate)
        });
    let matched = match result {
        Ok(candidate) => {
            last_seen = Some(candidate);
            true
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => false,
        Err(_) => {
            let snapshot = session.diagnostic_snapshot(20);
            return StatsWaitOutcome {
                matched: false,
                last_seen,
                recent_stdout_tail: Some(snapshot),
                recent_stderr_tail: None,
            };
        }
    };
    let outcome = StatsWaitOutcome {
        matched,
        last_seen,
        recent_stdout_tail: None,
        recent_stderr_tail: None,
    };
    match snapshot_forwarder_output_tail(session, 20) {
        Ok((stdout, stderr)) => outcome.with_output_tails(stdout, stderr),
        Err(_) => outcome,
    }
}

pub fn wait_for_session_stats_json(
    session: &mut ForwarderSession,
    max_wait: Duration,
) -> Option<serde_json::Value> {
    match session.wait_for_stdout_line(Instant::now() + max_wait, "stats JSON", parse_stats_json) {
        Ok(stats) => Some(stats),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => None,
        Err(error) => panic!(
            "forwarder exited or output capture failed while waiting for stats: {error}\n{}",
            session.diagnostic_snapshot(40)
        ),
    }
}

pub fn expect_session_stats_json(
    session: &mut ForwarderSession,
    max_wait: Duration,
    context: &str,
) -> serde_json::Value {
    wait_for_session_stats_json(session, max_wait).unwrap_or_else(|| {
        panic!(
            "{context}: did not see stats JSON line\n{}",
            session.diagnostic_snapshot(40)
        )
    })
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
        .last_seen
        .expect("matched stats outcome must include last_seen")
}

pub fn send_until_session_locked(
    client: &UdpSocket,
    payload: &[u8],
    session: &mut ForwarderSession,
    max_wait: Duration,
) -> Option<SocketAddr> {
    let deadline = Instant::now() + max_wait;
    while Instant::now() < deadline {
        if let Err(error) = client.send(payload)
            && !matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::WouldBlock
            )
        {
            panic!("send probe payload while waiting for lock: {error}");
        }
        let event_deadline = deadline.min(Instant::now() + TEST_RETRY_INTERVAL);
        match session.wait_for_stdout_line(event_deadline, "client lock", parse_locked_client) {
            Ok(address) => return Some(address),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => panic!(
                "forwarder failed while waiting for client lock: {error}\n{}",
                session.diagnostic_snapshot(40)
            ),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            thread::sleep(TEST_RETRY_INTERVAL.min(remaining));
        }
    }
    None
}

pub fn wait_for_locked_client(
    session: &mut ForwarderSession,
    max_wait: Duration,
) -> Option<SocketAddr> {
    match session.wait_for_stdout_line(
        Instant::now() + max_wait,
        "client lock",
        parse_locked_client,
    ) {
        Ok(address) => Some(address),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => None,
        Err(error) => panic!(
            "forwarder failed while waiting for client lock: {error}\n{}",
            session.diagnostic_snapshot(40)
        ),
    }
}

/*
 * Socket assertion helpers below deliberately operate on the client socket. Process output
 * waiting is centralized above through `ForwarderSession`.
 */

pub fn expect_no_echo(client: &UdpSocket, buf: &mut [u8]) {
    use crate::timing::{CLIENT_WAIT_MS, DRAIN_WAIT_MS};
    client
        .set_read_timeout(Some(DRAIN_WAIT_MS))
        .expect("set drain wait timeout");
    let res = client.recv(buf);
    client
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("restore client wait timeout");
    match res {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
        Err(e) => panic!("unexpected recv error: {e}"),
        Ok(n) => panic!("unexpected payload of {n} bytes"),
    }
}

pub fn assert_recv_payload(
    session: &ForwarderSession,
    client: &UdpSocket,
    expected: &[u8],
    buf: &mut [u8],
    context: &str,
) -> usize {
    match client.recv(buf) {
        Ok(n) => {
            assert_eq!(
                &buf[..n],
                expected,
                "{context}: received wrong payload\n{}",
                session.diagnostic_snapshot(40)
            );
            n
        }
        Err(e) => panic!(
            "{context}: recv failed: {e}\n{}",
            session.diagnostic_snapshot(40)
        ),
    }
}

pub fn assert_no_extra_payload(
    session: &ForwarderSession,
    client: &UdpSocket,
    buf: &mut [u8],
    context: &str,
) {
    match client.recv(buf) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
        Err(e) => panic!(
            "{context}: unexpected recv error: {e}\n{}",
            session.diagnostic_snapshot(40)
        ),
        Ok(n) => panic!(
            "{context}: expected no payload, got {n} bytes\n{}",
            session.diagnostic_snapshot(40)
        ),
    }
}

/// Receives a legitimate echo response from a client socket, retrying on transient errors.
/// This is useful for robust integration tests where the initial handshake or capture
/// socket initialization might drop a few packets.
pub fn recv_legitimate_echo_with_retry(
    client: &UdpSocket,
    payload: &[u8],
    buf: &mut [u8],
    case_desc: &str,
    label: &str,
) -> io::Result<usize> {
    use crate::timing::RETRY_RECV_WAIT_MS;
    client.set_read_timeout(Some(RETRY_RECV_WAIT_MS))?;
    let restore_timeout = || {
        client
            .set_read_timeout(Some(crate::timing::CLIENT_WAIT_MS))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("{case_desc}: restore standard client timeout: {error}"),
                )
            })
    };
    let deadline = Instant::now() + crate::timing::CLIENT_WAIT_MS;
    let mut got = None;
    while Instant::now() < deadline {
        match client.recv(buf) {
            Ok(n) => {
                got = Some(n);
                break;
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::ConnectionRefused =>
            {
                if let Err(error) = client.send(payload) {
                    restore_timeout()?;
                    return Err(io::Error::new(
                        error.kind(),
                        format!("{case_desc}: re-send {label}: {error}"),
                    ));
                }
                thread::sleep(
                    TEST_RETRY_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(e) => {
                restore_timeout()?;
                return Err(io::Error::new(
                    e.kind(),
                    format!("{case_desc}: recv {label}: {e}"),
                ));
            }
        }
    }
    restore_timeout()?;
    got.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{case_desc}: did not receive {label} within {:?} after retrying transient UDP errors",
                crate::timing::CLIENT_WAIT_MS
            ),
        )
    })
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

#[cfg(test)]
mod tests {
    use super::StatsWaitOutcome;

    #[test]
    fn stats_timeout_diagnostics_preserve_last_seen_stats() {
        let outcome = StatsWaitOutcome {
            matched: false,
            last_seen: Some(serde_json::json!({"locked": true})),
            recent_stdout_tail: Some("last output".to_string()),
            recent_stderr_tail: None,
        };
        let details = outcome.failure_details();
        assert!(details.contains("\"locked\":true"));
        assert!(details.contains("last output"));
    }
}
