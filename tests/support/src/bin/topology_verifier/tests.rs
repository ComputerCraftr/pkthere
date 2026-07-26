use super::{
    TopologyExpectations, read_diagnostics, require_worker_state, verify_four_id, verify_timeout,
};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
static NEXT_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[test]
fn missing_stdout_evidence_is_an_error() {
    let directory = temp_dir();
    fs::write(directory.join("node.err"), "").expect("write stderr fixture");

    let error = read_diagnostics(&directory, "node")
        .expect_err("missing required stdout evidence must fail closed");
    assert!(
        error.to_string().contains("node.out"),
        "error must identify the missing evidence path: {error}"
    );

    fs::remove_dir_all(directory).expect("remove topology verifier fixture directory");
}

#[test]
fn four_id_verifier_requires_correlated_packets_and_exact_flow_tuples() {
    let dir = temp_dir();
    let node_a = [
        socket_evidence_line("upstream"),
        handshake_line(
            "begin",
            json!({
                "expected_ack_destination_id": 40001,
                "session_id": 22,
                "buffered_len": 28,
                "buffered_packet_id": 1,
            }),
        ),
        handshake_line(
            "ack-ignored",
            json!({
                "reason": "commit-in-progress",
            }),
        ),
        handshake_line(
            "ack-matched",
            json!({
                "expected_ack_destination_id": 40001,
                "observed_ack_destination_id": 40001,
                "peer_source_id": 7777,
                "peer_reply_id": 9999,
                "session_id": 22,
                "sequence": 4,
                "buffered_packet_id": 1,
            }),
        ),
        handshake_line("ack-ignored", json!({"reason": "no-pending"})),
    ]
    .join("\n");
    fs::write(dir.join("node-a.err"), node_a).expect("write node A");

    fs::write(dir.join("node-b.err"), socket_evidence_line("listener")).expect("write node B");
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
                "session_id": 33,
                "buffered_len": 25,
                "buffered_packet_id": 7,
            }),
        ),
        handshake_line(
            "timeout",
            json!({
                "expected_ack_destination_id": 40001,
                "session_id": 33,
                "buffered_len": 25,
                "buffered_packet_id": 7,
                "reason": "handshake-timeout",
            }),
        ),
        handshake_line("reset", json!({"reason": "handshake-timeout"})),
    ]
    .join("\n");
    fs::write(
        dir.join("timeout-node.out"),
        format!(
            "[INFO] {}",
            diagnostic(json!({
                "c2u_pkts": 0,
                "c2u_bytes": 0,
                "worker_flows": [],
            }))
        ),
    )
    .expect("write timeout stdout");
    fs::write(dir.join("timeout-node.err"), log).expect("write timeout log");
    assert_eq!(
        verify_timeout(&dir, expectations()).expect("verify timeout")["ok"],
        true
    );
    fs::remove_dir_all(dir).expect("remove fixture");
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
                "listener_connected": shared_flow && socket_slot == 0,
                "flow_key": locked.then_some("fixture-flow"),
                "icmp_client_transmit_session_id": (!shared_flow && locked).then_some(22),
                "icmp_client_receive_session_id": (!shared_flow && locked).then_some(11),
                "icmp_upstream_transmit_session_id": (shared_flow && locked).then_some(11),
                "icmp_upstream_receive_session_id": (shared_flow && locked).then_some(22),
                "upstream_flow_outbound": upstream_outbound,
                "upstream_flow_inbound": upstream_inbound,
                "listener_flow_inbound": locked.then_some(&listener_inbound),
                "listener_flow_outbound": locked.then_some(&listener_outbound),
                "listen_socket_evidence": {
                    "process_id": 7,
                    "role": "listener",
                    "domain": "ipv4",
                    "socket_slot": socket_slot,
                    "generation": 1,
                },
                "upstream_socket_evidence": {
                    "process_id": 7,
                    "role": "upstream",
                    "domain": "ipv4",
                    "socket_slot": socket_slot,
                    "generation": 1,
                },
            })
        })
        .collect::<Vec<_>>();
    diagnostic(json!({
        "locked_worker_pairs": if shared_flow { 3 } else { 1 },
        "malformed_packets": if shared_flow { 0 } else { 5 },
        "wrong_peer_drops": if shared_flow { 0 } else { 1 },
        "wrong_source_drops": if shared_flow { 0 } else { 1 },
        "worker_flows": worker_flows,
    }))
    .to_string()
}

#[test]
fn shared_state_verifier_rejects_multiple_connected_reuse_port_listeners() {
    let mut stats: Value = serde_json::from_str(&stats_line(
        "127.0.0.1:2001 -> 127.0.0.1:2002",
        "127.0.0.1:2002 -> 127.0.0.1:2001",
        json!("127.0.0.1:3001 -> 127.0.0.1:3002"),
        json!("127.0.0.1:3002 -> 127.0.0.1:3001"),
        true,
    ))
    .expect("parse shared-flow stats fixture");
    stats["worker_flows"][1]["listener_connected"] = json!(true);

    let error = require_worker_state(&stats, 3, 3, true)
        .expect_err("mixed connected/unconnected shared listeners must fail");
    assert!(
        error
            .to_string()
            .contains("shared-state reuse-port policy requires exactly one")
    );
}

fn diagnostic(mut value: Value) -> Value {
    let object = value.as_object_mut().expect("diagnostic object");
    object.insert("diagnostic_schema".to_owned(), json!(3));
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
