use pkthere_test_support::fixtures::{
    LIFECYCLE_ACCEPTED_PAYLOAD, LIFECYCLE_DEFERRED_HANDSHAKE_TIMEOUT_SECS,
    LIFECYCLE_HANDSHAKE_TIMEOUT_SECS, LIFECYCLE_NODE_TIMEOUT_SECS, LIFECYCLE_OVERSIZE_PAYLOAD,
    LIFECYCLE_PENDING_FOLLOWUP_PAYLOAD, localhost_ip, udp_loopback_arg,
};
use pkthere_test_support::forwarder::{ForwarderConfig, ForwarderSession, launch_forwarder};
use pkthere_test_support::matrix::spawn_echo_or_skip;
use pkthere_test_support::network::{bind_udp_client, render_icmp_arg};
use pkthere_test_support::packet_diagnostics::{
    DiagnosticKind, DiagnosticLogIndex, TraceKey, parse_diagnostic_line,
};
use pkthere_test_support::raw_icmp::acquire_icmp_dgram_session_lock;
use pkthere_test_support::timing::{MAX_WAIT_SECS, RAW_ICMP_LOCK_WAIT};
use socket2::Domain;
use std::time::Instant;

fn assert_lifecycle_invariants(
    stderr: &str,
    expected_keys: &[TraceKey],
    check_cadence_or_ack: bool,
) {
    let index = DiagnosticLogIndex::parse("", stderr).expect("forwarder emitted valid diagnostics");
    let stages = index.trace_stages();
    let mut consumed_cadence = false;
    let mut consumed_session_control = false;

    for (key, packet_stages) in &stages {
        if packet_stages.disposition.is_empty() {
            continue;
        }
        assert!(
            !packet_stages.received.is_empty(),
            "terminal disposition references unknown received trace: {key:?}"
        );
    }

    for key in expected_keys {
        let packet_stages = stages
            .get(key)
            .unwrap_or_else(|| panic!("missing stages for key {:?}", key));

        assert_eq!(
            packet_stages.received.len(),
            1,
            "packet {key:?} must have exactly 1 received stage (got {})",
            packet_stages.received.len()
        );
        assert_eq!(
            packet_stages.admission.len(),
            1,
            "packet {key:?} must have exactly 1 admission stage (got {})",
            packet_stages.admission.len()
        );
        assert_eq!(
            packet_stages.disposition.len(),
            1,
            "packet {key:?} must have exactly 1 terminal disposition stage (got {})",
            packet_stages.disposition.len()
        );

        let rx_idx = packet_stages.received[0].sequence;
        let adm_idx = packet_stages.admission[0].sequence;
        let disp_idx = packet_stages.disposition[0].sequence;

        assert!(
            rx_idx < adm_idx,
            "received index ({rx_idx}) must precede admission index ({adm_idx}) for {key:?}"
        );
        assert!(
            adm_idx < disp_idx,
            "admission index ({adm_idx}) must precede terminal disposition index ({disp_idx}) for {key:?}"
        );

        if check_cadence_or_ack {
            let admission = &packet_stages.admission[0].value["admission"];
            let event_kind = admission.get("event_kind").and_then(|k| k.as_str());
            let disposition = packet_stages.disposition[0].value["disposition"]
                .as_str()
                .expect("disposition wire name");
            if event_kind == Some("cadence") {
                assert_eq!(
                    disposition, "consume-cadence",
                    "cadence event must terminate with consume-cadence"
                );
                consumed_cadence = true;
            } else if event_kind == Some("session-control") {
                assert!(
                    matches!(disposition, "consume-session-control" | "drop-duplicate"),
                    "session-control event must be consumed once or rejected as a duplicate, got {disposition}"
                );
                consumed_session_control |= disposition == "consume-session-control";
            }
        }
    }

    if check_cadence_or_ack {
        assert!(consumed_cadence, "expected one consumed cadence event");
        assert!(
            consumed_session_control,
            "expected one consumed session-control event"
        );
    }
}

fn wait_for_packet_dispositions(session: &mut ForwarderSession, expected: &[&str]) {
    let mut observed = vec![false; expected.len()];
    session
        .wait_for_stderr_line(
            Instant::now() + MAX_WAIT_SECS,
            "packet disposition diagnostics",
            |line| {
                let (kind, value) = parse_diagnostic_line(line).ok().flatten()?;
                if kind != DiagnosticKind::Packet || value["stage"] != "disposition" {
                    return None;
                }
                let disposition = value["disposition"].as_str()?;
                for (index, expected) in expected.iter().enumerate() {
                    if disposition == *expected {
                        observed[index] = true;
                    }
                }
                observed.iter().all(|seen| *seen).then_some(())
            },
        )
        .unwrap_or_else(|error| {
            let failure = serde_json::json!({
                "schema": 1,
                "event": "forwarder-wait",
                "expected": expected,
                "observed": observed,
                "error": error.to_string(),
            });
            panic!(
                "pkthere-test-failure {failure}\n{}",
                session.diagnostic_snapshot(80)
            )
        });
}

#[test]
fn lifecycle_forwarded_and_filtered() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let (up_addr, _upstream_echo) =
        spawn_echo_or_skip(family).expect("IPv4 UDP echo server is required");
    let there = format!("UDP:{up_addr}");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(family, 0),
        there,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(LIFECYCLE_NODE_TIMEOUT_SECS),
        max_payload: Some(10),
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "handles", "drops"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client.connect(session.listen_addr).expect("connect client");

    // Packet 1: 5 bytes (fits in max_payload=10) -> should be forwarded
    client
        .send(LIFECYCLE_ACCEPTED_PAYLOAD)
        .expect("send accepted lifecycle payload");

    // Packet 2: 20 bytes (exceeds max_payload=10) -> should be filtered
    client
        .send(LIFECYCLE_OVERSIZE_PAYLOAD)
        .expect("send oversized lifecycle payload");

    wait_for_packet_dispositions(&mut session, &["filtered", "forwarded"]);

    let completed = session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let stderr = completed.output.stderr_lossy();
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "debug kernel-echo cadence requires the reality-backed ICMP DGRAM path"
)]
fn lifecycle_cadence_consumed() {
    let _icmp_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "lifecycle_cadence_consumed",
    )
    .expect("acquire RAW ICMP lock");
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let local_ip = localhost_ip(family);

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: true,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(family, 0),
        there: render_icmp_arg(local_ip, 0),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(LIFECYCLE_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(10),
        debug_logs: &["packet-dump", "handles", "drops", "handshake"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client.connect(session.listen_addr).expect("connect client");
    client
        .send(LIFECYCLE_ACCEPTED_PAYLOAD)
        .expect("send lifecycle cadence payload");

    wait_for_packet_dispositions(
        &mut session,
        &["consume-cadence", "consume-session-control"],
    );

    let completed = session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let stderr = completed.output.stderr_lossy();
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, true);
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "handshake lifecycle requires the reality-backed ICMP DGRAM path"
)]
fn lifecycle_pending_payload_and_timeout() {
    let _icmp_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "lifecycle_pending_payload_and_timeout",
    )
    .expect("acquire RAW ICMP lock");
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let local_ip = localhost_ip(family);

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(family, 0),
        there: render_icmp_arg(local_ip, 0),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "drop",
        timeout_secs: Some(LIFECYCLE_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "handles", "drops", "handshake"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: Some(LIFECYCLE_HANDSHAKE_TIMEOUT_SECS),
    });

    client.connect(session.listen_addr).expect("connect client");
    client
        .send(LIFECYCLE_ACCEPTED_PAYLOAD)
        .expect("send first pending lifecycle payload");
    client
        .send(LIFECYCLE_PENDING_FOLLOWUP_PAYLOAD)
        .expect("send follow-up pending lifecycle payload");

    wait_for_packet_dispositions(
        &mut session,
        &["handshake-timeout-drop", "drop-handshake-pending"],
    );

    let completed = session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let stderr = completed.output.stderr_lossy();
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "handshake lifecycle requires the reality-backed ICMP DGRAM path"
)]
fn lifecycle_buffered_payload_reset() {
    let _icmp_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "lifecycle_buffered_payload_reset",
    )
    .expect("acquire RAW ICMP lock");
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let local_ip = localhost_ip(family);

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(family, 0),
        there: render_icmp_arg(local_ip, 0),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "drop",
        timeout_secs: Some(LIFECYCLE_HANDSHAKE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "handles", "drops", "handshake"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: Some(LIFECYCLE_DEFERRED_HANDSHAKE_TIMEOUT_SECS),
    });

    client.connect(session.listen_addr).expect("connect client");
    client
        .send(LIFECYCLE_ACCEPTED_PAYLOAD)
        .expect("send buffered lifecycle payload");

    wait_for_packet_dispositions(&mut session, &["handshake-reset-drop"]);

    assert!(
        session.is_running().expect("query forwarder status"),
        "forwarder process must still be running when reset drop occurred"
    );

    let completed = session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let stderr = completed.output.stderr_lossy();
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}
