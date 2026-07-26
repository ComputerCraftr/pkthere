use super::icmp_dgram::{
    EchoCandidate, EchoReplyExpectation, EchoSearchDecision, ICMP_DGRAM_NOISE_PACKET_LIMIT,
    ICMP_DGRAM_NONCE_LEN, ICMP_DGRAM_NONCE_OFFSET, ICMP_DGRAM_SESSION_OFFSET, ICMP_SEQUENCE,
    build_correlated_echo, classify_echo_candidate, observe_echo_candidate,
    terminal_collection_outcome,
};
use crate::socket_reality::evidence::{IcmpDgramCollectionOutcome, ReceiveEvidence};
use socket2::Domain;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn reply_filter_correlates_id_nonce_source_direction_and_extent() {
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let expectation = expectation(peer, [0xa5; ICMP_DGRAM_NONCE_LEN]);
    let mut reflected = build_correlated_echo(
        Domain::IPV4,
        expectation.realized_echo_id,
        expectation.sequence,
        &expectation.payload_nonce,
        pkthere_socket_policy::IcmpChecksumMode::ApplicationComputed,
    );
    assert_eq!(
        classify_echo_candidate(Domain::IPV4, &receive(reflected.clone(), peer), expectation),
        EchoCandidate::ReflectedRequest
    );

    reflected[0] = 0;
    assert_eq!(
        classify_echo_candidate(Domain::IPV4, &receive(reflected.clone(), peer), expectation),
        EchoCandidate::Reply
    );

    let mut wrong_id = reflected.clone();
    wrong_id[4..6].copy_from_slice(&expectation.realized_echo_id.wrapping_add(1).to_be_bytes());
    assert_noise(wrong_id, peer, expectation);

    let mut wrong_nonce = reflected.clone();
    wrong_nonce[ICMP_DGRAM_NONCE_OFFSET] ^= 0xff;
    assert_noise(wrong_nonce, peer, expectation);

    let mut wrong_session = reflected.clone();
    wrong_session[ICMP_DGRAM_SESSION_OFFSET] ^= 0xff;
    assert_noise(wrong_session, peer, expectation);

    let mut wrong_sequence = reflected.clone();
    wrong_sequence[6..8].copy_from_slice(&expectation.sequence.wrapping_add(1).to_be_bytes());
    assert_noise(wrong_sequence, peer, expectation);

    assert_noise(
        reflected.clone(),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        expectation,
    );

    let mut trailing_capture_bytes = reflected;
    trailing_capture_bytes.push(0);
    assert_noise(trailing_capture_bytes, peer, expectation);
}

#[test]
fn reply_filter_rejects_concurrent_unreachable_noise() {
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let unreachable = [
        0x45, 0, 0, 56, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1, 3, 3, 0, 0, 0, 0, 0, 0,
    ];
    assert_noise(
        unreachable.to_vec(),
        peer,
        expectation(peer, [0x5a; ICMP_DGRAM_NONCE_LEN]),
    );
}

#[test]
fn reflected_request_does_not_consume_noise_budget_and_noise_limit_is_specific() {
    let mut observed_noise_packets = 0;
    assert_eq!(
        observe_echo_candidate(EchoCandidate::ReflectedRequest, &mut observed_noise_packets),
        EchoSearchDecision::Continue
    );
    assert_eq!(observed_noise_packets, 0);

    for expected_count in 1..ICMP_DGRAM_NOISE_PACKET_LIMIT {
        assert_eq!(
            observe_echo_candidate(EchoCandidate::Noise, &mut observed_noise_packets),
            EchoSearchDecision::Continue
        );
        assert_eq!(observed_noise_packets, expected_count);
    }
    let limit_decision = observe_echo_candidate(EchoCandidate::Noise, &mut observed_noise_packets);
    assert_eq!(
        limit_decision,
        EchoSearchDecision::NoiseLimitExceeded {
            observed_noise_packets: ICMP_DGRAM_NOISE_PACKET_LIMIT,
        }
    );
    assert_eq!(
        terminal_collection_outcome(limit_decision),
        Some(IcmpDgramCollectionOutcome::NoiseLimitExceeded {
            limit: ICMP_DGRAM_NOISE_PACKET_LIMIT,
            observed_noise_packets: ICMP_DGRAM_NOISE_PACKET_LIMIT,
        })
    );
}

#[test]
fn reflected_request_then_matching_reply_completes_search() {
    let mut observed_noise_packets = 0;
    assert_eq!(
        observe_echo_candidate(EchoCandidate::ReflectedRequest, &mut observed_noise_packets),
        EchoSearchDecision::Continue
    );
    assert_eq!(
        observe_echo_candidate(EchoCandidate::Reply, &mut observed_noise_packets),
        EchoSearchDecision::ReplyObserved
    );
    assert_eq!(observed_noise_packets, 0);
}

fn expectation(peer: IpAddr, payload_nonce: [u8; 16]) -> EchoReplyExpectation {
    EchoReplyExpectation {
        peer,
        realized_echo_id: 0x6123,
        sequence: ICMP_SEQUENCE,
        payload_nonce,
    }
}

fn assert_noise(bytes: Vec<u8>, source_ip: IpAddr, expectation: EchoReplyExpectation) {
    assert_eq!(
        classify_echo_candidate(Domain::IPV4, &receive(bytes, source_ip), expectation),
        EchoCandidate::Noise
    );
}

fn receive(bytes: Vec<u8>, source_ip: IpAddr) -> ReceiveEvidence {
    ReceiveEvidence {
        bytes,
        source: Some(SocketAddr::new(source_ip, 0)),
    }
}
