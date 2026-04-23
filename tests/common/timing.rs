//! Shared timing/config constants for test harness helpers.

use std::time::Duration;

pub const TIMEOUT_SECS: Duration = Duration::from_secs(2);
pub const MAX_WAIT_SECS: Duration = Duration::from_secs(4);
pub const JSON_WAIT_MS: Duration = Duration::from_millis(50);

pub const SUPPORTED_PROTOCOLS: &[&str] = &["UDP", "ICMP"];
