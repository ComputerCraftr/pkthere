use super::{
    ICMP_TUNNEL_COMPACT_MAX_CONTROL_LEN, ICMP_TUNNEL_COMPACT_RESET_REQUIRED_LEN,
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelControl, IcmpTunnelFrameKind, RejectedFrameEvidence,
    ReplyIdNegotiation, SHIM_IS_CADENCE, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER, SessionId,
    SessionIdentityAllocator, SessionKey, encode_icmp_control_prefix_with_source,
    encode_icmp_tunnel_prefix_with_source, parse_icmp_control, parse_icmp_reply_negotiation,
    parse_icmp_reset_required,
};
use std::num::NonZeroU64;
use std::sync::Arc;

fn test_control_body(opcode: u8, reply_id: u16) -> [u8; super::ICMP_TUNNEL_NEGOTIATE_BODY_LEN] {
    let mut body = [0; super::ICMP_TUNNEL_NEGOTIATE_BODY_LEN];
    body[0] = super::ICMP_TUNNEL_CONTROL_VERSION;
    body[1] = opcode;
    body[2..4].copy_from_slice(&reply_id.to_be_bytes());
    body[4..12].copy_from_slice(&1_u64.to_be_bytes());
    body[12..16].copy_from_slice(&0_u32.to_be_bytes());
    body[16..24].copy_from_slice(&1_u64.to_be_bytes());
    body
}

#[test]
fn framing_shim_parses_user_payload_as_no_reply_negotiation() {
    assert_eq!(
        parse_icmp_reply_negotiation(SHIM_IS_DATA, b"hi").unwrap(),
        None
    );
}

#[test]
fn session_id_allocator_is_nonzero_unique_and_concurrent() {
    let allocator = Arc::new(SessionIdentityAllocator::from_seed(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let allocator = Arc::clone(&allocator);
        threads.push(std::thread::spawn(move || {
            (0..128)
                .map(|_| allocator.allocate().expect("allocate session ID").get())
                .collect::<Vec<_>>()
        }));
    }
    let mut ids = threads
        .into_iter()
        .flat_map(|thread| thread.join().expect("session allocator thread"))
        .collect::<Vec<_>>();
    assert!(ids.iter().all(|id| *id != 0));
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 8 * 128);
}

#[test]
fn initial_session_key_rejects_an_id_without_response_identity_headroom() {
    let maximum = SessionId::new(u64::MAX).expect("maximum nonzero session");
    assert_eq!(SessionKey::initial(maximum), None);
}

#[test]
fn fresh_generation_rejects_an_id_without_response_identity_headroom() {
    let error = SessionKey::with_fresh_generation(
        SessionId::new(u64::MAX).expect("maximum nonzero session"),
    )
    .expect_err("terminal session ID cannot form a directional session key");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn session_id_allocator_fails_before_wrap() {
    let allocator = SessionIdentityAllocator {
        last_issued: crate::authority::AuthorityAtomic::new_u64(
            u64::MAX - 1,
            crate::authority::AtomicProtocolId::IdentityGeneration,
        ),
    };
    assert_eq!(
        allocator.allocate().expect("last nonwrapping ID").get(),
        u64::MAX
    );
    let error = allocator
        .allocate()
        .expect_err("allocator must fail before wrapping");
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
}

#[test]
fn directional_session_allocation_reserves_a_distinct_response_identity() {
    let allocator = SessionIdentityAllocator::from_seed(40);
    let transmit = allocator
        .allocate_directional_pair()
        .expect("allocate directional session");
    let response = transmit
        .response_session_id()
        .expect("directional session reserves its response identity");
    let next = allocator.allocate().expect("allocate after reserved pair");

    assert_eq!(transmit.get(), 41);
    assert_eq!(response.get(), 42);
    assert_eq!(next.get(), 43);
}

#[test]
fn directional_session_allocation_fails_before_response_identity_wraps() {
    let allocator = SessionIdentityAllocator {
        last_issued: crate::authority::AuthorityAtomic::new_u64(
            u64::MAX - 1,
            crate::authority::AtomicProtocolId::IdentityGeneration,
        ),
    };
    assert!(
        allocator.allocate_directional_pair().is_err(),
        "the transmit identity may not be allocated without its response identity"
    );
}

#[test]
fn terminal_random_seed_preserves_fail_before_wrap() {
    let allocator = SessionIdentityAllocator::from_seed(u64::MAX);
    assert_eq!(
        allocator.allocate().expect("last nonwrapping ID").get(),
        u64::MAX
    );
    assert!(allocator.allocate().is_err());
}

#[test]
fn session_id_allocator_reports_seed_failure() {
    let result = SessionIdentityAllocator::from_random_seed(|_| Err("rng unavailable".to_owned()));
    let error = result.expect_err("seed failure must remain fatal");
    assert_eq!(error, "rng unavailable");
}

#[test]
fn distinct_logical_sessions_receive_distinct_ids() {
    let allocator = SessionIdentityAllocator::from_seed(41);
    let client_transmit = allocator.allocate().expect("client transmit session");
    let client_receive = allocator.allocate().expect("client receive session");
    let upstream_transmit = allocator.allocate().expect("upstream transmit session");
    let upstream_receive = allocator.allocate().expect("upstream receive session");
    let mut ids = vec![
        client_transmit.get(),
        client_receive.get(),
        upstream_transmit.get(),
        upstream_receive.get(),
    ];
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 4);
}

#[test]
fn session_key_maps_the_reverse_direction_without_more_wire_metadata() {
    let transmit = SessionId::new(41).expect("transmit session");
    let key = SessionKey::new(7, 3, transmit).expect("directional key");

    assert_eq!(key.session_id().get(), 41);
    assert_eq!(key.response_session_id().get(), 42);
    assert_eq!(key.response_key().generation(), key.generation());
    assert_eq!(key.response_key().ordinal(), key.ordinal());
    assert_eq!(key.response_key().session_id().get(), 42);
    assert!(
        SessionKey::new(
            7,
            3,
            SessionId::new(u64::MAX).expect("maximum nonzero session")
        )
        .is_none(),
        "a received key must leave room for the directional response identity"
    );
}

#[test]
fn framing_shim_parses_session_control_reply_id() {
    let body = test_control_body(super::ICMP_CONTROL_NEGOTIATE, 0x3003);
    assert_eq!(
        parse_icmp_reply_negotiation(0, &body).unwrap(),
        ReplyIdNegotiation::negotiate(0x3003)
    );
}

#[test]
fn framing_shim_parses_compact_session_control() {
    let body = test_control_body(super::ICMP_CONTROL_NEGOTIATE_ACK, 0x4444);
    assert_eq!(
        parse_icmp_reply_negotiation(SHIM_SOURCE_ID_EQUALS_HEADER, &body).unwrap(),
        ReplyIdNegotiation::acknowledge(0x4444)
    );
}

#[test]
fn framing_shim_rejects_reserved_control_flags() {
    for reserved_bit in [0x01, 0x02, 0x08, 0x20, 0x40] {
        assert!(
            parse_icmp_reply_negotiation(reserved_bit, &[0x30, 0x03]).is_err(),
            "reserved shim bit {reserved_bit:#04x} was accepted"
        );
    }
}

#[test]
fn framing_shim_rejects_conflicting_frame_classes() {
    assert!(parse_icmp_reply_negotiation(SHIM_IS_DATA | SHIM_IS_CADENCE, b"").is_err());
}

#[test]
fn framing_shim_encodes_cadence_with_source_identity() {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    assert_eq!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::Cadence,
            0x1001,
            0x2002,
            SessionId::for_tests(),
            None,
            0,
            &mut scratch,
        )
        .unwrap(),
        &[SHIM_IS_CADENCE, 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 1,]
    );
}

#[test]
fn framing_shim_encodes_explicit_user_payload_source_id() {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    assert_eq!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::UserPayload,
            0x1001,
            0x2002,
            SessionId::for_tests(),
            None,
            2,
            &mut scratch,
        )
        .unwrap(),
        &[SHIM_IS_DATA, 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 1,]
    );
}

#[test]
fn framing_shim_encodes_compact_user_payload_source_id() {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    assert_eq!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::UserPayload,
            0x2002,
            0x2002,
            SessionId::for_tests(),
            None,
            2,
            &mut scratch,
        )
        .unwrap(),
        &[
            SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ]
    );
}

#[test]
fn framing_shim_encodes_explicit_session_control() {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let mut expected = vec![0, 0x20, 0x02];
    expected.extend_from_slice(&test_control_body(super::ICMP_CONTROL_NEGOTIATE, 0x3003));
    assert_eq!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::SessionControl,
            0x9999,
            0x2002,
            SessionId::for_tests(),
            ReplyIdNegotiation::negotiate(0x3003),
            0,
            &mut scratch,
        )
        .unwrap(),
        expected
    );
}

#[test]
fn framing_shim_encodes_compact_session_control() {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let mut expected = vec![SHIM_SOURCE_ID_EQUALS_HEADER];
    expected.extend_from_slice(&test_control_body(super::ICMP_CONTROL_NEGOTIATE, 0x3003));
    assert_eq!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::SessionControl,
            0x2002,
            0x2002,
            SessionId::for_tests(),
            ReplyIdNegotiation::negotiate(0x3003),
            0,
            &mut scratch,
        )
        .unwrap(),
        expected
    );
}

#[test]
fn largest_v3_control_exactly_fills_shared_scratch_and_rejects_trailing_bytes() {
    let rejected =
        SessionKey::new(7, 9, SessionId::new(11).expect("rejected session")).expect("rejected key");
    let replacement = SessionKey::new(8, 0, SessionId::new(12).expect("replacement session"))
        .expect("replacement key");
    let challenge = super::ChallengeControl::new(
        0x3003,
        NonZeroU64::new(13).expect("challenge"),
        super::PoolGeneration::new(6),
        RejectedFrameEvidence::Negotiate {
            candidate: rejected,
            sequence: 14,
        },
        replacement,
    )
    .expect("challenge control");
    let control = IcmpTunnelControl::ChallengeNegotiate(challenge);
    let mut scratch = [0_u8; ICMP_TUNNEL_SHIM_MAX_LEN];

    let compact = encode_icmp_control_prefix_with_source(control, 0x2002, 0x2002, &mut scratch)
        .expect("encode compact maximum");
    assert_eq!(compact.len(), ICMP_TUNNEL_COMPACT_MAX_CONTROL_LEN);
    assert_eq!(
        parse_icmp_control(compact[0], &compact[1..]).expect("parse compact maximum"),
        Some(control)
    );

    let explicit = encode_icmp_control_prefix_with_source(control, 0x1001, 0x2002, &mut scratch)
        .expect("encode explicit maximum");
    assert_eq!(explicit.len(), ICMP_TUNNEL_SHIM_MAX_LEN);
    assert_eq!(
        parse_icmp_control(explicit[0], &explicit[3..]).expect("parse explicit maximum"),
        Some(control)
    );
    let mut overlong = explicit[3..].to_vec();
    overlong.push(0);
    assert!(parse_icmp_control(explicit[0], &overlong).is_err());
}

#[test]
fn reset_required_is_compact_control_only_and_round_trips() {
    let reset = super::ResetRequired::new(
        SessionId::for_tests(),
        0x1234,
        super::PoolGeneration::new(9),
        NonZeroU64::new(77).expect("test challenge"),
    );
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let encoded = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::ResetRequired(reset),
        0x2002,
        0x2002,
        SessionId::for_tests(),
        None,
        0,
        &mut scratch,
    )
    .expect("encode compact reset-required");
    assert_eq!(encoded.len(), ICMP_TUNNEL_COMPACT_RESET_REQUIRED_LEN);
    assert_eq!(
        parse_icmp_reset_required(encoded[0], &encoded[1..]).expect("parse reset-required"),
        Some(reset)
    );
    assert_eq!(
        parse_icmp_reply_negotiation(encoded[0], &encoded[1..])
            .expect("reset-required is a valid non-negotiation control"),
        None
    );
}

#[test]
fn reset_required_never_echoes_user_payload() {
    let reset = super::ResetRequired::new(
        SessionId::for_tests(),
        7,
        None,
        NonZeroU64::new(5).expect("test challenge"),
    );
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    assert!(
        encode_icmp_tunnel_prefix_with_source(
            IcmpTunnelFrameKind::ResetRequired(reset),
            0x2002,
            0x2002,
            SessionId::for_tests(),
            None,
            1,
            &mut scratch,
        )
        .is_err()
    );
}
