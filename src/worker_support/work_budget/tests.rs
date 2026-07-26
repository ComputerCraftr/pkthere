use super::{
    AUTHENTICATED_FRAME_BURST, AuthenticatedFrameBudget, PacketDumpDetailBudget,
    PacketDumpDetailClass, RejectionLogDecision, RejectionLogLimiter,
};
use crate::worker_support::packet_admission::RejectionReason;
use std::time::{Duration, Instant};

#[test]
fn authenticated_frame_budget_is_bounded_and_refills() {
    let start = Instant::now();
    let mut budget = AuthenticatedFrameBudget::new();
    for _ in 0..AUTHENTICATED_FRAME_BURST {
        assert!(budget.take(start));
    }
    assert!(!budget.take(start));
    assert!(budget.take(start + Duration::from_secs(1)));
}

#[test]
fn rejection_logs_suppress_before_formatting_and_summarize() {
    let start = Instant::now();
    let mut limiter = RejectionLogLimiter::new();
    for _ in 0..8 {
        assert!(matches!(
            limiter.decide(RejectionReason::UnexpectedRemotePeer, start),
            RejectionLogDecision::Log
        ));
    }
    assert!(matches!(
        limiter.decide(RejectionReason::UnexpectedRemotePeer, start),
        RejectionLogDecision::Suppress
    ));
    assert!(matches!(
        limiter.decide(
            RejectionReason::UnexpectedRemotePeer,
            start + Duration::from_secs(1)
        ),
        RejectionLogDecision::Log
    ));
}

#[test]
fn packet_dump_detail_is_bounded_before_hex_formatting() {
    let start = Instant::now();
    let mut budget = PacketDumpDetailBudget::new();
    for _ in 0..8 {
        assert!(budget.take(PacketDumpDetailClass::Accepted, start));
    }
    assert!(!budget.take(PacketDumpDetailClass::Accepted, start));
    assert!(budget.take(
        PacketDumpDetailClass::Accepted,
        start + Duration::from_secs(1)
    ));
}

#[test]
fn receive_noise_cannot_consume_accepted_detail_capacity() {
    let start = Instant::now();
    let mut budget = PacketDumpDetailBudget::new();
    for _ in 0..4 {
        assert!(budget.take(PacketDumpDetailClass::ReceiveNoise, start));
    }
    assert!(!budget.take(PacketDumpDetailClass::ReceiveNoise, start));
    for _ in 0..8 {
        assert!(budget.take(PacketDumpDetailClass::Accepted, start));
    }
}

#[test]
fn only_endpoint_authenticated_rejections_consume_session_work_budget() {
    use RejectionReason::{
        IcmpSessionMismatch, MalformedIcmpHeader, MissingSourceEvidence, UnexpectedRemotePeer,
    };

    assert!(IcmpSessionMismatch.consumes_authenticated_work());
    assert!(!UnexpectedRemotePeer.consumes_authenticated_work());
    assert!(!MissingSourceEvidence.consumes_authenticated_work());
    assert!(!MalformedIcmpHeader(None).consumes_authenticated_work());
}
