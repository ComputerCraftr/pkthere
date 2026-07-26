use super::{
    BufferedPayload, FlowRuntimeState, ReplyIdHandshakeAck, ReplyIdHandshakeBegin, ack_for_test,
    buffered_payload,
};
use crate::cli::SupportedProtocol;
use crate::net::framing_shim::SessionId;
use crate::net::payload::PayloadEvent;
use std::time::{Duration, Instant};

#[test]
fn transmit_rekey_retains_triggering_payload_and_rejects_a_second_buffer() {
    let state = FlowRuntimeState::new();
    let old_session = SessionId::new(41).expect("old session");
    let new_session = SessionId::new(42).expect("new session");
    state.begin_upstream_reply_id_handshake(
        2002,
        old_session.get(),
        1,
        buffered_payload(b"initial"),
    );
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, old_session.get())
    else {
        panic!("activate old transmit session");
    };
    let initial = state
        .commit_upstream_reply_id_handshake(token)
        .expect("lease initial payload");
    assert_eq!(initial.payload_len(), 7);
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(initial)
            .expect("complete initial payload")
    );

    let triggering = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"rekey-first");
    let (rekey_begin, payload_copies) =
        crate::allocation_test_support::count_payload_copies(|| {
            state.begin_upstream_rekey_from_event(
                old_session,
                new_session,
                2002,
                2,
                Instant::now() + Duration::from_secs(10),
                &triggering,
                None,
                Instant::now(),
            )
        });
    assert_eq!(payload_copies, 1);
    assert!(matches!(
        rekey_begin,
        Ok(ReplyIdHandshakeBegin::Started {
            instance,
            buffered_len: 11,
            ..
        }) if instance == new_session.get()
    ));
    assert_eq!(state.upstream_session_id(), None);

    let later = state.begin_upstream_reply_id_handshake(
        2002,
        new_session.get(),
        3,
        buffered_payload(b"must-not-replace"),
    );
    assert!(matches!(
        later,
        ReplyIdHandshakeBegin::PendingReused {
            buffered_len: 11,
            ..
        }
    ));

    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, new_session.get())
    else {
        panic!("activate rekey candidate");
    };
    let retained = state
        .commit_upstream_reply_id_handshake(token)
        .expect("candidate ACK releases triggering payload");
    assert!(matches!(
        retained.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"rekey-first"
    ));
    let retained_storage = retained.payload().clone();
    let (released, failure_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .release_upstream_reply_id_payload_send(retained)
            .expect("failed critical send restores the retained payload")
    });
    assert!(!released);
    assert_eq!(failure_copies, 0);
    let (retry, retry_copies) = crate::allocation_test_support::count_payload_copies(|| {
        state
            .lease_due_upstream_reply_id_payload(Instant::now() + Duration::from_secs(1))
            .expect("critical payload retry remains available")
    });
    assert_eq!(retry_copies, 0);
    assert!(retry.payload().shares_payload_storage(&retained_storage));
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(retry)
            .expect("complete critical payload retry")
    );
}

#[test]
fn cadence_triggered_rekey_buffers_only_candidate_session_control_work() {
    let state = FlowRuntimeState::new();
    let old_session = SessionId::new(51).expect("old session");
    let new_session = SessionId::new(52).expect("new session");
    state.begin_upstream_reply_id_handshake(
        2002,
        old_session.get(),
        1,
        buffered_payload(b"initial"),
    );
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, old_session.get())
    else {
        panic!("activate old transmit session");
    };
    let initial = state
        .commit_upstream_reply_id_handshake(token)
        .expect("lease initial payload");
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(initial)
            .expect("complete initial payload")
    );

    let cadence = PayloadEvent::cadence_packet(1001, 0, new_session);
    let buffered = BufferedPayload::from_event(&cadence, None);
    assert!(matches!(
        state.begin_upstream_rekey(
            old_session,
            new_session,
            2002,
            2,
            Instant::now() + Duration::from_secs(10),
            buffered,
        ),
        Ok(ReplyIdHandshakeBegin::Started {
            instance,
            buffered_len: 0,
            ..
        }) if instance == new_session.get()
    ));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, new_session.get())
    else {
        panic!("activate cadence rekey candidate");
    };
    let retained = state
        .commit_upstream_reply_id_handshake(token)
        .expect("cadence candidate retained");
    assert!(matches!(
        retained.as_event(),
        PayloadEvent::CadencePacket { icmp, .. } if icmp.session_id() == new_session
    ));
}
