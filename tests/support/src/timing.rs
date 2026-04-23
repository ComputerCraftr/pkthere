//! Shared timing/config constants for test harness helpers.

use std::time::Duration;

/// Default idle timeout for the forwarder.
pub const TIMEOUT_SECS: Duration = Duration::from_secs(3);

/// Maximum time to wait for an expected event (e.g. log line, exit).
pub const MAX_WAIT_SECS: Duration = Duration::from_secs(6);

/// Maximum time to wait for a stats JSON line to appear (accommodates 1s fast-stats interval).
pub const STATS_WAIT_MS: Duration = Duration::from_millis(2000);

/// Standard timeout for client socket read/write operations in tests.
pub const CLIENT_WAIT_MS: Duration = Duration::from_millis(4000);

/// Small timeout for draining sockets when we expect them to be empty.
pub const DRAIN_WAIT_MS: Duration = Duration::from_millis(200);

/// Quiet interval between serialized ICMP DGRAM kernel-echo test sessions.
pub const ICMP_DGRAM_SESSION_QUIET_WAIT: Duration = Duration::from_millis(200);

/// Poll cadence for child stdout/stderr, stats, lock-line, and exit waits.
pub const TEST_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Cadence for retrying packets during transient UDP/ICMP test setup.
pub const TEST_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Short socket timeout used inside retry loops so one recv cannot consume the whole deadline.
pub const RETRY_RECV_WAIT_MS: Duration = Duration::from_millis(50);

/// Extra time beyond the configured forwarder idle timeout for watchdog scheduling.
pub const IDLE_TIMEOUT_GRACE: Duration = Duration::from_secs(1);

/// Grace period after requesting normal child process-tree termination.
pub const CHILD_TERMINATION_GRACE: Duration = Duration::from_millis(500);

/// Maximum additional time to reap a child after forced termination.
pub const CHILD_FORCED_REAP_WAIT: Duration = Duration::from_secs(1);

/// Maximum time to wait for stdout/stderr readers after the process exits.
pub const CAPTURE_DRAIN_WAIT: Duration = Duration::from_millis(500);

/// Full termination, forced-reap, and output-capture budget for an owned child.
pub const CHILD_CLEANUP_WAIT: Duration = Duration::from_secs(2);

/// Maximum time to serialize RAW ICMP integration tests across processes.
pub const RAW_ICMP_LOCK_WAIT: Duration = Duration::from_secs(6);

/// Standard observation window for CLI tests that expect a process to remain alive.
pub const CLI_OBSERVATION_WAIT: Duration = Duration::from_millis(500);

/// Standard completion window for short CLI validation commands.
pub const CLI_COMPLETION_WAIT: Duration = Duration::from_secs(2);

/// Standard deadline for socket witnesses to stop and release their sockets.
pub const SOCKET_WITNESS_WAIT: Duration = Duration::from_secs(1);

/// Socket read cadence used by stoppable test witnesses.
pub const SOCKET_WITNESS_POLL: Duration = Duration::from_millis(50);

/// Timeout for one direct socket-reality receive operation.
pub const SOCKET_REALITY_RECEIVE_WAIT: Duration = Duration::from_secs(1);

/// Standard duration for stress tests.
pub const STRESS_TEST_DURATION: Duration = Duration::from_secs(20);

/// Short pause between stress-test send bursts.
pub const STRESS_SEND_PAUSE: Duration = Duration::from_micros(50);
