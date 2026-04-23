use crate::cli::RuntimeConfig;
use crate::flow_state::{
    DroppedReplyIdHandshake, ExpiredReplyIdHandshake, ReplyIdHandshakeAckIgnored,
    ReplyIdHandshakeBegin,
};
use crate::packet_trace::PacketTraceId;
use serde_json::Value;
use serde_json::json;

pub(crate) fn log_handshake_begin(
    cfg: &RuntimeConfig,
    worker_id: usize,
    trace: Option<PacketTraceId>,
    outcome: &ReplyIdHandshakeBegin,
    new_payload_len: usize,
) {
    if !cfg.debug_logs.handshake {
        return;
    }
    let Some(value) = handshake_begin_json(worker_id, trace, outcome, new_payload_len) else {
        return;
    };
    log_handshake_value(value);
}

fn handshake_begin_json(
    worker_id: usize,
    trace: Option<PacketTraceId>,
    outcome: &ReplyIdHandshakeBegin,
    new_payload_len: usize,
) -> Option<Value> {
    let (mut value, buffered, trigger) = match outcome {
        ReplyIdHandshakeBegin::Started {
            expected_ack_destination_id,
            buffered_len,
            buffered_trace,
        } => (
            json!({
                "event": "handshake-trace",
                "transition": "begin",
                "worker": worker_id,
                "direction": "c2u",
                "expected_ack_destination_id": expected_ack_destination_id,
                "buffered_len": buffered_len,
            }),
            *buffered_trace,
            trace,
        ),
        ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id,
            started_s,
            buffered_len,
            buffered_trace,
            trigger_trace,
        } => (
            json!({
                "event": "handshake-trace",
                "transition": "pending-reused",
                "worker": worker_id,
                "direction": "c2u",
                "expected_ack_destination_id": expected_ack_destination_id,
                "started_s": started_s,
                "buffered_len": buffered_len,
                "new_payload_len": new_payload_len,
                "buffer": "preserved",
                "new_payload": "dropped",
            }),
            *buffered_trace,
            *trigger_trace,
        ),
        ReplyIdHandshakeBegin::Ignored => return None,
    };

    value["buffered_packet_id"] = buffered.map(|t| t.packet_id).into();
    value["buffered_direction"] = buffered.map(|t| if t.c2u { "c2u" } else { "u2c" }).into();
    value["trigger_packet_id"] = trigger.map(|t| t.packet_id).into();
    value["trigger_direction"] = trigger.map(|t| if t.c2u { "c2u" } else { "u2c" }).into();

    Some(value)
}

pub(crate) struct HandshakeAckMatched {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) observed_ack_destination_id: u16,
    pub(crate) peer_source_id: u16,
    pub(crate) peer_reply_id: u16,
    pub(crate) buffered_len: usize,
    pub(crate) buffered_trace: Option<PacketTraceId>,
    pub(crate) trigger_trace: Option<PacketTraceId>,
}

pub(crate) fn log_handshake_ack_matched(
    cfg: &RuntimeConfig,
    worker_id: usize,
    matched: HandshakeAckMatched,
) {
    if !cfg.debug_logs.handshake {
        return;
    }
    log_handshake_value(handshake_ack_matched_json(worker_id, matched));
}

fn handshake_ack_matched_json(worker_id: usize, matched: HandshakeAckMatched) -> Value {
    json!({
        "event": "handshake-trace",
        "transition": "ack-matched",
        "worker": worker_id,
        "direction": "u2c",
        "expected_ack_destination_id": matched.expected_ack_destination_id,
        "observed_ack_destination_id": matched.observed_ack_destination_id,
        "peer_source_id": matched.peer_source_id,
        "peer_reply_id": matched.peer_reply_id,
        "buffered_len": matched.buffered_len,
        "buffered_packet_id": matched.buffered_trace.map(|t| t.packet_id),
        "buffered_direction": matched.buffered_trace.map(|t| if t.c2u { "c2u" } else { "u2c" }),
        "trigger_packet_id": matched.trigger_trace.map(|t| t.packet_id),
        "trigger_direction": matched.trigger_trace.map(|t| if t.c2u { "c2u" } else { "u2c" }),
    })
}

pub(crate) fn log_handshake_ack_ignored(
    cfg: &RuntimeConfig,
    worker_id: usize,
    reason: ReplyIdHandshakeAckIgnored,
    observed_ack_destination_id: u16,
) {
    if !cfg.debug_logs.handshake {
        return;
    }
    let value = handshake_ack_ignored_json(worker_id, reason, observed_ack_destination_id);
    log_handshake_value(value);
}

fn handshake_ack_ignored_json(
    worker_id: usize,
    reason: ReplyIdHandshakeAckIgnored,
    observed_ack_destination_id: u16,
) -> Value {
    let (reason_str, expected_ack_destination_id, buffered_trace, trigger_trace, transition) =
        match reason {
            ReplyIdHandshakeAckIgnored::NoPending { trigger_trace } => {
                ("no-pending", None, None, trigger_trace, "ack-ignored")
            }
            ReplyIdHandshakeAckIgnored::AlreadyAcked { trigger_trace } => {
                ("already-acked", None, None, trigger_trace, "ack-ignored")
            }
            ReplyIdHandshakeAckIgnored::WrongDestinationId {
                expected_ack_destination_id,
                buffered_trace,
                trigger_trace,
            } => (
                "wrong-ack-destination-id",
                Some(expected_ack_destination_id),
                buffered_trace,
                trigger_trace,
                "ack-rejected",
            ),
        };
    json!({
        "event": "handshake-trace",
        "transition": transition,
        "worker": worker_id,
        "direction": "u2c",
        "reason": reason_str,
        "expected_ack_destination_id": expected_ack_destination_id,
        "observed_ack_destination_id": observed_ack_destination_id,
        "buffered_packet_id": buffered_trace.map(|t| t.packet_id),
        "buffered_direction": buffered_trace.map(|t| if t.c2u { "c2u" } else { "u2c" }),
        "trigger_packet_id": trigger_trace.map(|t| t.packet_id),
        "trigger_direction": trigger_trace.map(|t| if t.c2u { "c2u" } else { "u2c" }),
    })
}

pub(crate) fn log_handshake_timeout(
    cfg: &RuntimeConfig,
    worker_id: usize,
    expired: ExpiredReplyIdHandshake,
) {
    if !cfg.debug_logs.handshake {
        return;
    }
    log_handshake_value(json!({
        "event": "handshake-trace",
        "transition": "timeout",
        "worker": worker_id,
        "direction": "c2u",
        "expected_ack_destination_id": expired.expected_ack_destination_id,
        "started_s": expired.started_s,
        "buffered_len": expired.buffered_len,
        "buffered_packet_id": expired.buffered_trace.map(|t| t.packet_id),
        "buffered_direction": expired.buffered_trace.map(|t| if t.c2u { "c2u" } else { "u2c" }),
        "trigger_packet_id": null,
        "trigger_direction": null,
        "reason": "handshake-timeout",
    }));
}

pub(crate) fn log_handshake_reset(
    cfg: &RuntimeConfig,
    worker_id: usize,
    reason: &'static str,
    dropped: Option<DroppedReplyIdHandshake>,
) {
    if !cfg.debug_logs.handshake {
        return;
    }
    let mut value = json!({
        "event": "handshake-trace",
        "transition": "reset",
        "worker": worker_id,
        "direction": "c2u",
        "reason": reason,
        "trigger_packet_id": null,
        "trigger_direction": null,
    });
    if let Some(dropped) = dropped {
        value["expected_ack_destination_id"] = dropped.expected_ack_destination_id.into();
        value["buffered_len"] = dropped.buffered_len.into();
        value["buffered_packet_id"] = dropped.buffered_trace.map(|t| t.packet_id).into();
        value["buffered_direction"] = dropped
            .buffered_trace
            .map(|t| if t.c2u { "c2u" } else { "u2c" })
            .into();
    }
    log_handshake_value(value);
}

fn log_handshake_value(value: Value) {
    crate::log_debug!(true, "handshake-trace {}", crate::diagnostics::stamp(value));
}

#[cfg(test)]
mod tests {
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
    }
}
