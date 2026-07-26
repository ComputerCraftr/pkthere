use crate::cli::RuntimeConfig;
use crate::diagnostics::PacketTraceId;
use crate::flow_state::{
    DroppedReplyIdHandshake, ExpiredReplyIdHandshake, ReplyIdHandshakeAckIgnored,
    ReplyIdHandshakeBegin,
};
use serde_json::Value;

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
            instance,
            buffered_len,
            buffered_trace,
        } => (
            audited_json!({
                "event": "handshake-trace",
                "transition": "begin",
                "worker": worker_id,
                "direction": "c2u",
                "expected_ack_destination_id": expected_ack_destination_id,
                "session_id": instance,
                "buffered_len": buffered_len,
            }),
            *buffered_trace,
            trace,
        ),
        ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id,
            instance,
            started_s,
            buffered_len,
            buffered_trace,
            trigger_trace,
        } => (
            audited_json!({
                "event": "handshake-trace",
                "transition": "pending-reused",
                "worker": worker_id,
                "direction": "c2u",
                "expected_ack_destination_id": expected_ack_destination_id,
                "session_id": instance,
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct HandshakeAckMatched {
    pub(crate) session_id: u64,
    pub(crate) sequence: u16,
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
    audited_json!({
        "event": "handshake-trace",
        "transition": "ack-matched",
        "worker": worker_id,
        "direction": "u2c",
        "expected_ack_destination_id": matched.expected_ack_destination_id,
        "observed_ack_destination_id": matched.observed_ack_destination_id,
        "peer_source_id": matched.peer_source_id,
        "peer_reply_id": matched.peer_reply_id,
        "session_id": matched.session_id,
        "sequence": matched.sequence,
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
            ReplyIdHandshakeAckIgnored::WrongInstance {
                expected_instance: _,
                observed_instance: _,
                buffered_trace,
                trigger_trace,
            } => (
                "wrong-handshake-instance",
                None,
                buffered_trace,
                trigger_trace,
                "ack-rejected",
            ),
            ReplyIdHandshakeAckIgnored::UnsentSequence {
                observed_sequence: _,
                buffered_trace,
                trigger_trace,
            } => (
                "unsent-negotiation-sequence",
                None,
                buffered_trace,
                trigger_trace,
                "ack-rejected",
            ),
            ReplyIdHandshakeAckIgnored::CommitInProgress { trigger_trace } => (
                "commit-in-progress",
                None,
                None,
                trigger_trace,
                "ack-ignored",
            ),
            ReplyIdHandshakeAckIgnored::Expired {
                buffered_trace,
                trigger_trace,
            } => (
                "expired",
                None,
                buffered_trace,
                trigger_trace,
                "ack-rejected",
            ),
        };
    audited_json!({
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
    log_handshake_value(audited_json!({
        "event": "handshake-trace",
        "transition": "timeout",
        "worker": worker_id,
        "direction": "c2u",
        "expected_ack_destination_id": expired.expected_ack_destination_id,
        "session_id": expired.instance,
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
    let mut value = audited_json!({
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
        value["session_id"] = dropped.instance.into();
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
mod tests;
