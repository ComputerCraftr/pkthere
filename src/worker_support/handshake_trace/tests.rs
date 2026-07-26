use super::{
    HandshakeAckMatched, handshake_ack_ignored_json, handshake_ack_matched_json,
    handshake_begin_json,
};
use crate::flow_state::{ReplyIdHandshakeAckIgnored, ReplyIdHandshakeBegin};

#[test]
fn begin_json_names_correlation_and_buffer_fields() {
    let value = handshake_begin_json(
        3,
        None,
        &ReplyIdHandshakeBegin::Started {
            expected_ack_destination_id: 40001,
            instance: 9,
            buffered_len: 17,
            buffered_trace: None,
        },
        17,
    )
    .expect("started handshake trace");
    assert_eq!(value["event"], "handshake-trace");
    assert_eq!(value["transition"], "begin");
    assert_eq!(value["worker"], 3);
    assert_eq!(value["direction"], "c2u");
    assert_eq!(value["expected_ack_destination_id"], 40001);
    assert_eq!(value["buffered_len"], 17);
}

#[test]
fn pending_reused_json_documents_preserved_first_payload() {
    let value = handshake_begin_json(
        4,
        None,
        &ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id: 40001,
            instance: 9,
            started_s: 3,
            buffered_len: 5,
            buffered_trace: None,
            trigger_trace: None,
        },
        6,
    )
    .expect("pending handshake trace");
    assert_eq!(value["transition"], "pending-reused");
    assert_eq!(value["buffer"], "preserved");
    assert_eq!(value["new_payload"], "dropped");
    assert_eq!(value["buffered_len"], 5);
    assert_eq!(value["new_payload_len"], 6);
    assert_eq!(value["started_s"], 3);
}

#[test]
fn ignored_ack_json_distinguishes_no_pending_and_completed() {
    let dummy_trace_1 = Some(crate::worker_support::PacketTraceId {
        worker_id: 5,
        c2u: true,
        packet_id: 100,
    });
    let dummy_trace_2 = Some(crate::worker_support::PacketTraceId {
        worker_id: 5,
        c2u: false,
        packet_id: 101,
    });

    for (reason, expected) in [
        (
            ReplyIdHandshakeAckIgnored::NoPending {
                trigger_trace: None,
            },
            "no-pending",
        ),
        (
            ReplyIdHandshakeAckIgnored::AlreadyAcked {
                trigger_trace: None,
            },
            "already-acked",
        ),
        (
            ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id: 30001,
                buffered_trace: dummy_trace_1,
                trigger_trace: dummy_trace_2,
            },
            "wrong-ack-destination-id",
        ),
    ] {
        let value = handshake_ack_ignored_json(5, reason, 40001);
        assert_eq!(
            value["transition"],
            match expected {
                "wrong-ack-destination-id" => "ack-rejected",
                _ => "ack-ignored",
            }
        );
        assert_eq!(value["worker"], 5);
        assert_eq!(value["direction"], "u2c");
        assert_eq!(value["reason"], expected);
        assert_eq!(value["observed_ack_destination_id"], 40001);

        if expected == "wrong-ack-destination-id" {
            assert_eq!(value["expected_ack_destination_id"], 30001);
            assert_eq!(value["buffered_packet_id"], 100);
            assert_eq!(value["trigger_packet_id"], 101);
        }
    }
}

#[test]
fn matched_ack_json_keeps_destination_and_peer_ids_distinct() {
    let value = handshake_ack_matched_json(
        7,
        HandshakeAckMatched {
            session_id: 9,
            sequence: 7,
            expected_ack_destination_id: 40001,
            observed_ack_destination_id: 40001,
            peer_source_id: 7777,
            peer_reply_id: 9999,
            buffered_len: 4,
            buffered_trace: None,
            trigger_trace: None,
        },
    );
    assert_eq!(value["expected_ack_destination_id"], 40001);
    assert_eq!(value["observed_ack_destination_id"], 40001);
    assert_eq!(value["peer_source_id"], 7777);
    assert_eq!(value["peer_reply_id"], 9999);
    assert_eq!(value["session_id"], 9);
    assert_eq!(value["sequence"], 7);
}
