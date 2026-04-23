use pkthere_test_support::packet_diagnostics::{DiagnosticLogIndex, DiagnosticRecord, TraceKey};
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
    let client_to_server = require_same_packet_ids(
        &node_b,
        expected.client_source_id,
        expected.server_destination_id,
    )?;
    let server_to_client =
        require_same_packet_ids(&node_a, expected.server_source_id, expected.client_reply_id)?;
    require_kernel_evidence(&node_b, client_to_server)?;
    require_kernel_evidence(&node_a, server_to_client)?;

    let begin = transition(&node_a, "begin")?;
    let matched = transition(&node_a, "ack-matched")?;
    let ignored = transition(&node_a, "ack-ignored")?;
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
    if begin.value["buffered_packet_id"] != matched.value["buffered_packet_id"] {
        return Err("begin and ack-matched refer to different buffered packets".into());
    }

    let malformed = [
        "InvalidShimFlags",
        "TruncatedSourceId",
        "IllegalFrameFlags",
        "SessionControlMissingReplyId",
    ];
    let mut rejected = Vec::new();
    for reason in malformed {
        let key = require_correlated_filtered(&node_b, reason)?;
        rejected.push(json!({
            "worker": key.worker,
            "direction": key.direction,
            "packet_id": key.packet_id,
            "reason": reason,
        }));
    }
    require_any_string(
        node_b.packets().map(|record| &record.value),
        &[
            "UnexpectedLocalReceiveId",
            "IcmpSourceEndpointMismatch",
            "UnexpectedRemotePeer",
        ],
    )?;

    let stats_a = node_a
        .stats()
        .next_back()
        .map(|record| &record.value)
        .ok_or("node-a output has no structured stats")?;
    let stats_b = node_b
        .stats()
        .next_back()
        .map(|record| &record.value)
        .ok_or("node-b output has no structured stats")?;
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
            },
            "server_to_client": {
                "source_id": expected.server_source_id,
                "destination_id": expected.client_reply_id,
            },
        },
        "handshake_transitions": ["begin", "ack-matched", "ack-ignored"],
        "worker_modes": {
            "node_a": {"mode": "shared-flow", "workers": expected.node_a_workers},
            "node_b": {"mode": "single-flow", "workers": expected.node_b_workers},
        },
        "correlated_filtered": rejected,
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
    let disposition = diagnostics.packets().any(|record| {
        record.value["stage"] == "disposition"
            && record.value["packet_id"].as_u64() == Some(packet_id)
            && record.value["disposition"] == "handshake-timeout-drop"
    });
    if !disposition {
        return Err("buffered timeout packet lacks handshake-timeout-drop disposition".into());
    }

    Ok(json!({
        "ok": true,
        "profile": "timeout",
        "transitions": ["begin", "timeout", "reset"],
        "buffered_packet_id": packet_id,
        "buffered_len": expected.timeout_payload_len,
        "expected_ack_destination_id": expected.client_reply_id,
        "terminal_disposition": "handshake-timeout-drop",
    }))
}

fn read(log_dir: &Path, name: &str) -> Result<String> {
    let path = log_dir.join(name);
    fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()).into())
}

fn read_diagnostics(log_dir: &Path, label: &str) -> Result<DiagnosticLogIndex> {
    let stdout = fs::read_to_string(log_dir.join(format!("{label}.out"))).unwrap_or_default();
    let stderr = read(log_dir, &format!("{label}.err"))?;
    DiagnosticLogIndex::parse(&stdout, &stderr).map_err(Into::into)
}

fn require_same_packet_ids(
    diagnostics: &DiagnosticLogIndex,
    source: u64,
    destination: u64,
) -> Result<&DiagnosticRecord> {
    diagnostics
        .packets()
        .find(|record| {
            record.value["stage"] == "admission"
                && record.value["admission"]["result"] == "accepted"
                && record.value["parse"]["headers"]["icmp"]["logical_source_id"].as_u64()
                    == Some(source)
                && record.value["parse"]["headers"]["icmp"]["logical_destination_id"].as_u64()
                    == Some(destination)
        })
        .ok_or_else(|| {
            format!("no admitted packet carried logical IDs {source} -> {destination}").into()
        })
}

fn require_kernel_evidence(
    diagnostics: &DiagnosticLogIndex,
    packet: &DiagnosticRecord,
) -> Result<()> {
    let key = &packet.value["socket"]["evidence_key"];
    let kernel_addr = &packet.value["socket"]["local_kernel_addr"];
    if !key.is_object() || !kernel_addr.is_string() {
        return Err("accepted packet lacks a complete socket evidence reference".into());
    }
    let matching = diagnostics
        .socket_evidence()
        .any(|sample| sample.value["key"] == *key && sample.value["getsockname"] == *kernel_addr);
    if matching {
        Ok(())
    } else {
        Err("accepted packet kernel address lacks same-key getsockname evidence".into())
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

fn require_correlated_filtered(diagnostics: &DiagnosticLogIndex, reason: &str) -> Result<TraceKey> {
    let grouped = diagnostics.trace_stages();
    grouped
        .into_iter()
        .find_map(|(key, stages)| {
            let matching = stages.admission.len() == 1
                && stages.received.len() == 1
                && stages.disposition.len() == 1
                && stages.admission[0].value["admission"]["result"] == "filtered"
                && stages.admission[0].value["admission"]["malformed_reason"] == reason
                && stages.disposition[0].value["disposition"] == "filtered"
                && stages.received[0].sequence < stages.admission[0].sequence
                && stages.admission[0].sequence < stages.disposition[0].sequence;
            matching.then_some(key)
        })
        .ok_or_else(|| format!("no complete correlated filtered trace for {reason}").into())
}

fn require_any_string<'a>(
    records: impl Iterator<Item = &'a Value>,
    expected: &[&str],
) -> Result<()> {
    let mut strings = HashSet::new();
    for record in records {
        collect_strings(record, &mut strings);
    }
    if expected.iter().any(|value| strings.contains(*value)) {
        Ok(())
    } else {
        Err(format!("none of the rejection reasons were observed: {expected:?}").into())
    }
}

fn collect_strings<'a>(value: &'a Value, output: &mut HashSet<&'a str>) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) => {
                output.insert(value);
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.values()),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
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
mod tests {
    use super::{TopologyExpectations, verify_four_id, verify_timeout};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
    static NEXT_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn four_id_verifier_requires_correlated_packets_and_exact_flow_tuples() {
        let dir = temp_dir();
        let node_a = [
            socket_evidence_line("upstream"),
            packet_line(
                1,
                "admission",
                json!({
                    "admission": {"result": "accepted"},
                    "parse": {"headers": {"icmp": {
                        "logical_source_id": 7777,
                        "logical_destination_id": 40001,
                    }}},
                    "socket": packet_socket("upstream"),
                }),
            ),
            handshake_line(
                "begin",
                json!({
                    "expected_ack_destination_id": 40001,
                    "buffered_len": 28,
                    "buffered_packet_id": 1,
                }),
            ),
            handshake_line(
                "ack-matched",
                json!({
                    "expected_ack_destination_id": 40001,
                    "observed_ack_destination_id": 40001,
                    "peer_source_id": 7777,
                    "peer_reply_id": 9999,
                    "buffered_packet_id": 1,
                }),
            ),
            handshake_line("ack-ignored", json!({"reason": "no-pending"})),
        ]
        .join("\n");
        fs::write(dir.join("node-a.err"), node_a).expect("write node A");

        let mut node_b = vec![
            socket_evidence_line("listener"),
            packet_line(
                1,
                "admission",
                json!({
                    "admission": {"result": "accepted"},
                    "parse": {"headers": {"icmp": {
                        "logical_source_id": 40000,
                        "logical_destination_id": 9999,
                    }}},
                    "socket": packet_socket("listener"),
                }),
            ),
        ];
        for (packet_id, reason) in [
            (10, "InvalidShimFlags"),
            (11, "TruncatedSourceId"),
            (12, "IllegalFrameFlags"),
            (13, "SessionControlMissingReplyId"),
        ] {
            node_b.extend(filtered_trace(packet_id, reason));
        }
        node_b.push(packet_line(
            20,
            "admission",
            json!({
                "admission": {
                    "result": "filtered",
                    "reason": "UnexpectedLocalReceiveId",
                },
            }),
        ));
        fs::write(dir.join("node-b.err"), node_b.join("\n")).expect("write node B");
        fs::write(
            dir.join("node-a.out"),
            stats_line(
                "127.0.0.1:40000 -> 127.0.0.1:9999",
                "127.0.0.1:7777 -> 127.0.0.1:40001",
                json!("127.0.0.1:50000 -> 127.0.0.1:5000"),
                json!("127.0.0.1:5000 -> 127.0.0.1:50000"),
                true,
            ),
        )
        .expect("write node A stats");
        fs::write(
            dir.join("node-b.out"),
            stats_line(
                "",
                "",
                json!("127.0.0.1:40000 -> 127.0.0.1:9999"),
                json!("127.0.0.1:7777 -> 127.0.0.1:40001"),
                false,
            ),
        )
        .expect("write node B stats");

        assert_eq!(
            verify_four_id(&dir, expectations()).expect("verify four-ID")["ok"],
            true
        );
        fs::remove_dir_all(dir).expect("remove fixture");
    }

    #[test]
    fn timeout_verifier_correlates_buffered_packet_terminal_disposition() {
        let dir = temp_dir();
        let log = [
            handshake_line(
                "begin",
                json!({
                    "expected_ack_destination_id": 40001,
                    "buffered_len": 25,
                    "buffered_packet_id": 7,
                }),
            ),
            handshake_line(
                "timeout",
                json!({
                    "expected_ack_destination_id": 40001,
                    "buffered_len": 25,
                    "buffered_packet_id": 7,
                    "reason": "handshake-timeout",
                }),
            ),
            packet_line(
                7,
                "disposition",
                json!({"disposition": "handshake-timeout-drop"}),
            ),
            handshake_line("reset", json!({"reason": "handshake-timeout"})),
        ]
        .join("\n");
        fs::write(dir.join("timeout-node.err"), log).expect("write timeout log");
        assert_eq!(
            verify_timeout(&dir, expectations()).expect("verify timeout")["ok"],
            true
        );
        fs::remove_dir_all(dir).expect("remove fixture");
    }

    fn packet_line(packet_id: u64, stage: &str, extra: Value) -> String {
        let mut value = diagnostic(json!({
            "event": "packet_dump",
            "worker": 1,
            "direction": "c2u",
            "packet_id": packet_id,
            "stage": stage,
        }));
        value
            .as_object_mut()
            .expect("packet object")
            .extend(extra.as_object().expect("extra object").clone());
        format!("packet-dump {value}")
    }

    fn filtered_trace(packet_id: u64, reason: &str) -> Vec<String> {
        vec![
            packet_line(packet_id, "received", json!({})),
            packet_line(
                packet_id,
                "admission",
                json!({
                    "admission": {
                        "result": "filtered",
                        "malformed_reason": reason,
                    },
                }),
            ),
            packet_line(packet_id, "disposition", json!({"disposition": "filtered"})),
        ]
    }

    fn handshake_line(transition: &str, extra: Value) -> String {
        let mut value = diagnostic(json!({
            "event": "handshake-trace",
            "transition": transition,
            "worker": 0,
            "direction": "c2u",
        }));
        value
            .as_object_mut()
            .expect("handshake object")
            .extend(extra.as_object().expect("extra object").clone());
        format!("handshake-trace {value}")
    }

    fn packet_socket(role: &str) -> Value {
        json!({
            "evidence_key": evidence_key(role),
            "local_kernel_addr": "127.0.0.1:0",
        })
    }

    fn socket_evidence_line(role: &str) -> String {
        let value = diagnostic(json!({
            "event": "socket_evidence",
            "key": evidence_key(role),
            "getsockname": "127.0.0.1:0",
        }));
        format!("socket-evidence {value}")
    }

    fn evidence_key(role: &str) -> Value {
        json!({
            "process_id": 7,
            "role": role,
            "domain": "ipv4",
            "socket_slot": 0,
            "generation": 1,
        })
    }

    fn stats_line(
        upstream_outbound: &str,
        upstream_inbound: &str,
        listener_inbound: Value,
        listener_outbound: Value,
        shared_flow: bool,
    ) -> String {
        let worker_flows = (0..3)
            .map(|socket_slot| {
                let locked = shared_flow || socket_slot == 0;
                json!({
                    "worker_pair": socket_slot,
                    "locked": locked,
                    "flow_key": locked.then_some("fixture-flow"),
                    "upstream_flow_outbound": upstream_outbound,
                    "upstream_flow_inbound": upstream_inbound,
                    "listener_flow_inbound": locked.then_some(&listener_inbound),
                    "listener_flow_outbound": locked.then_some(&listener_outbound),
                    "listen_socket_evidence": {
                        "role": "listener",
                        "socket_slot": socket_slot,
                    },
                    "upstream_socket_evidence": {
                        "role": "upstream",
                        "socket_slot": socket_slot,
                    },
                })
            })
            .collect::<Vec<_>>();
        diagnostic(json!({
            "locked_worker_pairs": if shared_flow { 3 } else { 1 },
            "worker_flows": worker_flows,
        }))
        .to_string()
    }

    fn diagnostic(mut value: Value) -> Value {
        let object = value.as_object_mut().expect("diagnostic object");
        object.insert("diagnostic_schema".to_owned(), json!(2));
        object.insert(
            "diagnostic_sequence".to_owned(),
            json!(NEXT_DIAGNOSTIC_SEQUENCE.fetch_add(1, Ordering::Relaxed)),
        );
        value
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pkthere-topology-verifier-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create fixture directory");
        dir
    }

    fn expectations() -> TopologyExpectations {
        TopologyExpectations {
            client_source_id: 40000,
            client_reply_id: 40001,
            server_destination_id: 9999,
            server_source_id: 7777,
            node_a_workers: 3,
            node_b_workers: 3,
            timeout_payload_len: 25,
        }
    }
}
