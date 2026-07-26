use super::packet_admission::RejectionReason;
use std::time::{Duration, Instant};

pub(crate) const AUTHENTICATED_FRAME_BURST: u32 = 4_096;
pub(crate) const AUTHENTICATED_FRAME_REFILL_PER_SECOND: u32 = 4_096;
const REJECTION_LOG_BURST: u32 = 8;
const REJECTION_LOG_REFILL_PER_SECOND: u32 = 1;
const SUPPRESSION_SUMMARY_INTERVAL: Duration = Duration::from_secs(1);
const PACKET_DUMP_ACCEPTED_DETAIL_BURST: u32 = 8;
const PACKET_DUMP_FILTERED_DETAIL_BURST: u32 = 4;
const PACKET_DUMP_NOISE_DETAIL_BURST: u32 = 4;
const PACKET_DUMP_DETAIL_REFILL_PER_SECOND: u32 = 1;

struct TokenBucket {
    capacity: u32,
    refill_per_second: u32,
    tokens: u32,
    fractional_refill_nanos: u64,
    updated_at: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_per_second: u32, now: Instant) -> Self {
        Self {
            capacity,
            refill_per_second,
            tokens: capacity,
            fractional_refill_nanos: 0,
            updated_at: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.updated_at = now;
        let scaled = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.refill_per_second))
            .saturating_add(u128::from(self.fractional_refill_nanos));
        let replenished = (scaled / 1_000_000_000).min(u128::from(u32::MAX)) as u32;
        self.fractional_refill_nanos = (scaled % 1_000_000_000) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

pub(crate) struct AuthenticatedFrameBudget(TokenBucket);

impl AuthenticatedFrameBudget {
    pub(crate) fn new() -> Self {
        Self(TokenBucket::new(
            AUTHENTICATED_FRAME_BURST,
            AUTHENTICATED_FRAME_REFILL_PER_SECOND,
            Instant::now(),
        ))
    }

    pub(crate) fn take(&mut self, now: Instant) -> bool {
        self.0.take(now)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PacketDumpDetailClass {
    Accepted,
    Filtered,
    ReceiveNoise,
}

pub(crate) struct PacketDumpDetailBudget {
    accepted: TokenBucket,
    filtered: TokenBucket,
    receive_noise: TokenBucket,
}

impl PacketDumpDetailBudget {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            accepted: TokenBucket::new(
                PACKET_DUMP_ACCEPTED_DETAIL_BURST,
                PACKET_DUMP_DETAIL_REFILL_PER_SECOND,
                now,
            ),
            filtered: TokenBucket::new(
                PACKET_DUMP_FILTERED_DETAIL_BURST,
                PACKET_DUMP_DETAIL_REFILL_PER_SECOND,
                now,
            ),
            receive_noise: TokenBucket::new(
                PACKET_DUMP_NOISE_DETAIL_BURST,
                PACKET_DUMP_DETAIL_REFILL_PER_SECOND,
                now,
            ),
        }
    }

    pub(crate) fn take(&mut self, class: PacketDumpDetailClass, now: Instant) -> bool {
        match class {
            PacketDumpDetailClass::Accepted => self.accepted.take(now),
            PacketDumpDetailClass::Filtered => self.filtered.take(now),
            PacketDumpDetailClass::ReceiveNoise => self.receive_noise.take(now),
        }
    }
}

struct RejectionLogState {
    bucket: TokenBucket,
    suppressed: u64,
    last_summary: Instant,
}

pub(crate) enum RejectionLogDecision {
    Log,
    Suppress,
    LogSuppressionSummary(u64),
}

pub(crate) struct RejectionLogLimiter {
    reasons: [Option<RejectionLogState>; RejectionReason::LOG_BUCKET_COUNT],
}

impl RejectionLogLimiter {
    pub(crate) fn new() -> Self {
        Self {
            reasons: std::array::from_fn(|_| None),
        }
    }

    pub(crate) fn decide(&mut self, reason: RejectionReason, now: Instant) -> RejectionLogDecision {
        let state = self
            .reasons
            .get_mut(reason.log_bucket_index())
            .unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "rejection diagnostic bucket index exceeded its fixed capacity"
                ))
            })
            .get_or_insert_with(|| RejectionLogState {
                bucket: TokenBucket::new(REJECTION_LOG_BURST, REJECTION_LOG_REFILL_PER_SECOND, now),
                suppressed: 0,
                last_summary: now,
            });
        if state.bucket.take(now) {
            return RejectionLogDecision::Log;
        }
        state.suppressed = state.suppressed.saturating_add(1);
        if now.saturating_duration_since(state.last_summary) >= SUPPRESSION_SUMMARY_INTERVAL {
            state.last_summary = now;
            let suppressed = std::mem::take(&mut state.suppressed);
            RejectionLogDecision::LogSuppressionSummary(suppressed)
        } else {
            RejectionLogDecision::Suppress
        }
    }
}

#[cfg(test)]
mod tests;
