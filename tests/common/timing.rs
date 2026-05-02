//! Shared timing/config constants for test harness helpers.

use std::time::Duration;

/// Default idle timeout for the forwarder.
pub const TIMEOUT_SECS: Duration = Duration::from_secs(3);

/// Maximum time to wait for an expected event (e.g. log line, exit).
pub const MAX_WAIT_SECS: Duration = Duration::from_secs(6);

/// Frequency of fast-stats output in debug mode.
pub const JSON_WAIT_MS: Duration = Duration::from_millis(50);

/// Standard timeout for client socket read/write operations in tests.
pub const CLIENT_WAIT_MS: Duration = Duration::from_millis(2000);

/// Small timeout for draining sockets when we expect them to be empty.
pub const DRAIN_WAIT_MS: Duration = Duration::from_millis(200);

pub const ALL_SUPPORTED_PROTOCOLS: &[&str] = &["UDP", "ICMP"];
