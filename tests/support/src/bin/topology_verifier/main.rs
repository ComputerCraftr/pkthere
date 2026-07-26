use pkthere_test_support::packet_diagnostics::{DiagnosticLogIndex, DiagnosticRecord};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct TopologyExpectations {
    client_source_id: u64,
    client_reply_id: u64,
    server_destination_id: u64,
    server_source_id: u64,
    node_a_workers: u64,
    node_b_workers: u64,
    timeout_payload_len: u64,
}

fn main() {
    let verdict = match run() {
        Ok(verdict) => verdict,
        Err(error) => {
            let verdict = json!({"ok": false, "error": error.to_string()});
            println!("{verdict}");
            std::process::exit(1);
        }
    };
    println!("{verdict}");
}

fn run() -> Result<Value> {
    let mut args = std::env::args_os().skip(1);
    let profile = args.next().ok_or("missing profile: four-id|timeout")?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--log-dir")) {
        return Err("expected --log-dir PATH".into());
    }
    let log_dir = PathBuf::from(args.next().ok_or("missing --log-dir value")?);
    if args.next().is_some() {
        return Err("unexpected topology-verifier argument".into());
    }

    let expected = TopologyExpectations::from_environment()?;
    match profile.to_str() {
        Some("four-id") => verify_four_id(&log_dir, expected),
        Some("timeout") => verify_timeout(&log_dir, expected),
        _ => Err("unknown profile: expected four-id or timeout".into()),
    }
}

impl TopologyExpectations {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            client_source_id: env_u64("CLIENT_SOURCE_ID")?,
            client_reply_id: env_u64("CLIENT_REPLY_ID")?,
            server_destination_id: env_u64("SERVER_DESTINATION_ID")?,
            server_source_id: env_u64("SERVER_SOURCE_ID")?,
            node_a_workers: env_u64("NODE_A_WORKERS")?,
            node_b_workers: env_u64("NODE_B_WORKERS")?,
            timeout_payload_len: std::env::var("TIMEOUT_PAYLOAD")
                .map_err(|_| "missing TIMEOUT_PAYLOAD")?
                .len() as u64,
        })
    }
}

fn env_u64(name: &str) -> Result<u64> {
    std::env::var(name)
        .map_err(|_| format!("missing {name}"))?
        .parse()
        .map_err(|error| format!("invalid {name}: {error}").into())
}

fn verify_four_id(log_dir: &Path, expected: TopologyExpectations) -> Result<Value> {
    let node_a = read_diagnostics(log_dir, "node-a")?;
    let node_b = read_diagnostics(log_dir, "node-b")?;
    let stats_a = final_stats(&node_a, "node-a")?;
    let stats_b = final_stats(&node_b, "node-b")?;
    let client_session = require_matching_session_ids(
        stats_a,
        "icmp_upstream_transmit_session_id",
        stats_b,
        "icmp_client_receive_session_id",
    )?;
    let server_session = require_matching_session_ids(
        stats_b,
        "icmp_client_transmit_session_id",
        stats_a,
        "icmp_upstream_receive_session_id",
    )?;
    if client_session == server_session {
        return Err("four-ID directions reused one ICMP session ID".into());
    }
    require_stats_kernel_evidence(&node_a, stats_a, "upstream_socket_evidence")?;
    require_stats_kernel_evidence(&node_b, stats_b, "listen_socket_evidence")?;

    let begin = transition(&node_a, "begin")?;
    let matched = transition(&node_a, "ack-matched")?;
    let ignored = transition_after(&node_a, "ack-ignored", matched.sequence)?;
    if !(begin.sequence < matched.sequence && matched.sequence < ignored.sequence) {
        return Err(
            "handshake transitions are not ordered begin -> ack-matched -> ack-ignored".into(),
        );
    }
    require_u64(
        &matched.value,
        "expected_ack_destination_id",
        expected.client_reply_id,
    )?;
    require_u64(
        &matched.value,
        "observed_ack_destination_id",
        expected.client_reply_id,
    )?;
    require_u64(&matched.value, "peer_source_id", expected.server_source_id)?;
    let handshake_session = begin.value["session_id"]
        .as_u64()
        .filter(|session_id| *session_id != 0)
        .ok_or("handshake begin lacks a nonzero session_id")?;
    require_u64(&matched.value, "session_id", handshake_session)?;
    matched.value["sequence"]
        .as_u64()
        .ok_or("matched ACK lacks its echoed sequence")?;
    if begin.value["buffered_packet_id"] != matched.value["buffered_packet_id"] {
        return Err("begin and ack-matched refer to different buffered packets".into());
    }

    require_counter_at_least(stats_b, "malformed_packets", 5)?;
    require_counter_at_least(stats_b, "wrong_peer_drops", 1)?;
    require_counter_at_least(stats_b, "wrong_source_drops", 1)?;
    require_flow_tuple(
        stats_a,
        "upstream_flow_outbound",
        expected.client_source_id,
        expected.server_destination_id,
    )?;
    require_flow_tuple(
        stats_a,
        "upstream_flow_inbound",
        expected.server_source_id,
        expected.client_reply_id,
    )?;
    require_flow_tuple(
        stats_b,
        "listener_flow_inbound",
        expected.client_source_id,
        expected.server_destination_id,
    )?;
    require_flow_tuple(
        stats_b,
        "listener_flow_outbound",
        expected.server_source_id,
        expected.client_reply_id,
    )?;
    require_worker_state(
        stats_a,
        expected.node_a_workers,
        expected.node_a_workers,
        true,
    )?;
    require_worker_state(stats_b, expected.node_b_workers, 1, false)?;

    Ok(json!({
        "ok": true,
        "profile": "four-id",
        "flows": {
            "client_to_server": {
                "source_id": expected.client_source_id,
                "destination_id": expected.server_destination_id,
                "session_id": client_session,
            },
            "server_to_client": {
                "source_id": expected.server_source_id,
                "destination_id": expected.client_reply_id,
                "session_id": server_session,
            },
        },
        "handshake_transitions": ["begin", "ack-matched", "ack-ignored"],
        "worker_modes": {
            "node_a": {"mode": "shared-flow", "workers": expected.node_a_workers},
            "node_b": {"mode": "single-flow", "workers": expected.node_b_workers},
        },
        "attack_accounting": {
            "malformed_packets": stats_b["malformed_packets"],
            "wrong_peer_drops": stats_b["wrong_peer_drops"],
            "wrong_source_drops": stats_b["wrong_source_drops"],
        },
    }))
}

fn verify_timeout(log_dir: &Path, expected: TopologyExpectations) -> Result<Value> {
    let diagnostics = read_diagnostics(log_dir, "timeout-node")?;
    let begin = transition(&diagnostics, "begin")?;
    let timeout = transition(&diagnostics, "timeout")?;
    let reset = transition(&diagnostics, "reset")?;
    if !(begin.sequence < timeout.sequence && timeout.sequence < reset.sequence) {
        return Err("handshake transitions are not ordered begin -> timeout -> reset".into());
    }
    require_same_handshake_scope(&begin.value, &timeout.value)?;
    require_same_handshake_scope(&begin.value, &reset.value)?;
    let timeout_session = begin.value["session_id"]
        .as_u64()
        .filter(|session_id| *session_id != 0)
        .ok_or("timeout handshake begin lacks a nonzero session_id")?;
    require_u64(&timeout.value, "session_id", timeout_session)?;
    for trace in [&begin.value, &timeout.value] {
        require_u64(
            trace,
            "expected_ack_destination_id",
            expected.client_reply_id,
        )?;
        require_u64(trace, "buffered_len", expected.timeout_payload_len)?;
    }
    if timeout.value["reason"] != "handshake-timeout"
        || reset.value["reason"] != "handshake-timeout"
    {
        return Err("timeout/reset reason is not handshake-timeout".into());
    }
    let packet_id = timeout.value["buffered_packet_id"]
        .as_u64()
        .ok_or("timeout trace lacks buffered_packet_id")?;
    if begin.value["buffered_packet_id"].as_u64() != Some(packet_id) {
        return Err("begin and timeout refer to different buffered packets".into());
    }
    let stats = final_stats(&diagnostics, "timeout-node")?;
    require_u64(stats, "c2u_pkts", 0)?;
    require_u64(stats, "c2u_bytes", 0)?;

    Ok(json!({
        "ok": true,
        "profile": "timeout",
        "transitions": ["begin", "timeout", "reset"],
        "buffered_packet_id": packet_id,
        "buffered_len": expected.timeout_payload_len,
        "expected_ack_destination_id": expected.client_reply_id,
        "terminal_outcome": "handshake-timeout-drop",
    }))
}

fn read(log_dir: &Path, name: &str) -> Result<String> {
    let path = log_dir.join(name);
    fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()).into())
}

fn read_diagnostics(log_dir: &Path, label: &str) -> Result<DiagnosticLogIndex> {
    let stdout = read(log_dir, &format!("{label}.out"))?;
    let stderr = read(log_dir, &format!("{label}.err"))?;
    DiagnosticLogIndex::parse(&stdout, &stderr).map_err(Into::into)
}

fn final_stats<'a>(diagnostics: &'a DiagnosticLogIndex, label: &str) -> Result<&'a Value> {
    diagnostics
        .stats()
        .next_back()
        .map(|record| &record.value)
        .ok_or_else(|| format!("{label} output has no structured stats").into())
}

fn require_matching_session_ids(
    left_stats: &Value,
    left_field: &str,
    right_stats: &Value,
    right_field: &str,
) -> Result<u64> {
    let left = unique_locked_flow_value(left_stats, left_field)?;
    let right = unique_locked_flow_value(right_stats, right_field)?;
    if left == right && left != 0 {
        Ok(left)
    } else {
        Err(
            format!("directional session mismatch: {left_field}={left}, {right_field}={right}")
                .into(),
        )
    }
}

fn unique_locked_flow_value(stats: &Value, field: &str) -> Result<u64> {
    let values = stats["worker_flows"]
        .as_array()
        .ok_or("stats worker_flows is not an array")?
        .iter()
        .filter(|flow| flow["locked"].as_bool() == Some(true))
        .map(|flow| {
            flow[field]
                .as_u64()
                .filter(|value| *value != 0)
                .ok_or_else(|| format!("locked worker flow lacks nonzero {field}"))
        })
        .collect::<std::result::Result<HashSet<_>, _>>()?;
    if values.len() == 1 {
        Ok(*values.iter().next().expect("one value"))
    } else {
        Err(format!("locked worker flows disagree on {field}: {values:?}").into())
    }
}

fn require_stats_kernel_evidence(
    diagnostics: &DiagnosticLogIndex,
    stats: &Value,
    evidence_field: &str,
) -> Result<()> {
    let matching = stats["worker_flows"]
        .as_array()
        .ok_or("stats worker_flows is not an array")?
        .iter()
        .filter(|flow| flow["locked"].as_bool() == Some(true))
        .any(|flow| {
            let key = &flow[evidence_field];
            key.is_object()
                && diagnostics.socket_evidence().any(|sample| {
                    sample.value["key"] == *key && sample.value["getsockname"].is_string()
                })
        });
    if matching {
        Ok(())
    } else {
        Err(format!("locked {evidence_field} lacks same-key getsockname evidence").into())
    }
}

fn require_counter_at_least(stats: &Value, field: &str, minimum: u64) -> Result<()> {
    let observed = stats[field]
        .as_u64()
        .ok_or_else(|| format!("stats lack required counter {field}"))?;
    if observed >= minimum {
        Ok(())
    } else {
        Err(format!("{field} was {observed}, expected at least {minimum}").into())
    }
}

fn transition<'a>(
    diagnostics: &'a DiagnosticLogIndex,
    transition: &str,
) -> Result<&'a DiagnosticRecord> {
    diagnostics
        .handshakes()
        .find(|record| record.value["transition"] == transition)
        .ok_or_else(|| format!("missing handshake transition {transition}").into())
}

fn transition_after<'a>(
    diagnostics: &'a DiagnosticLogIndex,
    transition: &str,
    sequence: u64,
) -> Result<&'a DiagnosticRecord> {
    diagnostics
        .handshakes()
        .find(|record| record.sequence > sequence && record.value["transition"] == transition)
        .ok_or_else(|| {
            format!("missing handshake transition {transition} after sequence {sequence}").into()
        })
}

fn require_u64(record: &Value, field: &str, expected: u64) -> Result<()> {
    if record[field].as_u64() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{field} was {}, expected {expected}", record[field]).into())
    }
}

fn require_same_handshake_scope(expected: &Value, observed: &Value) -> Result<()> {
    let expected_worker = expected["worker"]
        .as_u64()
        .ok_or("handshake trace lacks worker")?;
    let expected_direction = expected["direction"]
        .as_str()
        .ok_or("handshake trace lacks direction")?;
    if observed["worker"].as_u64() == Some(expected_worker)
        && observed["direction"].as_str() == Some(expected_direction)
    {
        Ok(())
    } else {
        Err("handshake transitions belong to different worker/direction scopes".into())
    }
}

fn require_flow_tuple(
    stats: &Value,
    field: &str,
    source_id: u64,
    destination_id: u64,
) -> Result<()> {
    let expected = format!(":{source_id} -> ");
    let destination = format!(":{destination_id}");
    let found = stats["worker_flows"].as_array().is_some_and(|flows| {
        flows.iter().any(|flow| {
            flow[field]
                .as_str()
                .is_some_and(|tuple| tuple.contains(&expected) && tuple.ends_with(&destination))
        })
    });
    if found {
        Ok(())
    } else {
        Err(format!("stats lack {field} tuple {source_id} -> {destination_id}").into())
    }
}

fn require_worker_state(
    stats: &Value,
    expected_workers: u64,
    expected_locked: u64,
    shared_flow: bool,
) -> Result<()> {
    let flows = stats["worker_flows"]
        .as_array()
        .ok_or("stats worker_flows is not an array")?;
    if flows.len() as u64 != expected_workers {
        return Err(format!(
            "expected {expected_workers} worker flows, observed {}",
            flows.len()
        )
        .into());
    }
    if stats["locked_worker_pairs"].as_u64() != Some(expected_locked) {
        return Err(format!(
            "expected {expected_locked} locked worker pairs, observed {}",
            stats["locked_worker_pairs"]
        )
        .into());
    }

    let locked = flows
        .iter()
        .filter(|flow| flow["locked"].as_bool() == Some(true))
        .count() as u64;
    if locked != expected_locked {
        return Err(format!(
            "worker flow records report {locked} locks, expected {expected_locked}"
        )
        .into());
    }

    let expected_slots = (0..expected_workers).collect::<HashSet<_>>();
    for (role, field) in [
        ("listener", "listen_socket_evidence"),
        ("upstream", "upstream_socket_evidence"),
    ] {
        let slots = flows
            .iter()
            .map(|flow| {
                flow[field]["socket_slot"]
                    .as_u64()
                    .ok_or_else(|| format!("{role} worker flow lacks a socket slot"))
            })
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        if slots != expected_slots {
            return Err(
                format!("{role} socket slots are {slots:?}, expected {expected_slots:?}").into(),
            );
        }
    }

    let flow_keys = flows
        .iter()
        .filter_map(|flow| flow["flow_key"].as_str())
        .collect::<HashSet<_>>();
    let expected_flow_keys = if shared_flow {
        1
    } else {
        expected_locked as usize
    };
    if flow_keys.len() != expected_flow_keys {
        return Err(format!(
            "worker flow keys are {flow_keys:?}, expected {expected_flow_keys} distinct locked flow(s)"
        )
        .into());
    }
    if shared_flow {
        let connected_listeners = flows
            .iter()
            .map(|flow| {
                flow["listener_connected"]
                    .as_bool()
                    .ok_or("shared worker flow lacks listener_connected")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|connected| *connected)
            .count();
        if connected_listeners != 1 {
            return Err(format!(
                "shared flow has {connected_listeners} connected listener owners; shared-state reuse-port policy requires exactly one"
            )
            .into());
        }
        for field in [
            "listener_flow_inbound",
            "listener_flow_outbound",
            "upstream_flow_inbound",
            "upstream_flow_outbound",
        ] {
            let tuples = flows
                .iter()
                .map(|flow| {
                    flow[field]
                        .as_str()
                        .ok_or_else(|| format!("shared worker flow lacks {field}"))
                })
                .collect::<std::result::Result<HashSet<_>, _>>()?;
            if tuples.len() != 1 {
                return Err(format!("shared worker flows disagree on {field}: {tuples:?}").into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
