use pkthere_test_support::fixtures::{
    LIFECYCLE_ACCEPTED_PAYLOAD, LIFECYCLE_DEFERRED_HANDSHAKE_TIMEOUT_SECS,
    LIFECYCLE_HANDSHAKE_TIMEOUT_SECS, LIFECYCLE_NODE_TIMEOUT_SECS, LIFECYCLE_OVERSIZE_PAYLOAD,
    LIFECYCLE_PENDING_FOLLOWUP_PAYLOAD, localhost_ip, udp_loopback_arg,
};
use pkthere_test_support::forwarder::{ForwarderConfig, ForwarderSession, launch_forwarder};
use pkthere_test_support::matrix::spawn_echo_or_skip;
use pkthere_test_support::network::{bind_udp_client, render_icmp_arg};
use pkthere_test_support::packet_diagnostics::{DiagnosticLogIndex, TraceKey};
use pkthere_test_support::raw_icmp::acquire_icmp_dgram_session_lock;
use pkthere_test_support::timing::{MAX_WAIT_SECS, RAW_ICMP_LOCK_WAIT};
use socket2::Domain;
use std::time::{Duration, Instant};

fn assert_lifecycle_invariants(
    stderr: &str,
    expected_keys: &[TraceKey],
    check_cadence_or_ack: bool,
) {
    let index = DiagnosticLogIndex::parse("", stderr).expect("forwarder emitted valid diagnostics");
    let stages = index.trace_stages();

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
            } else if event_kind == Some("session-control") {
                assert_eq!(
                    disposition, "consume-session-control",
                    "session-control event must terminate with consume-session-control"
                );
            }
        }
    }
}

fn lifecycle_snapshot_is_terminal(stderr: &str) -> bool {
    let Ok(index) = DiagnosticLogIndex::parse("", stderr) else {
        return false;
    };
    let stages = index.trace_stages();
    !stages.is_empty()
        && stages.values().all(|packet| {
            packet.received.len() == 1
                && packet.admission.len() == 1
                && packet.disposition.len() == 1
        })
}

fn poll_session_logs_until<F>(
    session: &mut ForwarderSession,
    timeout: Duration,
    mut predicate: F,
) -> String
where
    F: FnMut(&str) -> bool,
{
    session
        .wait_for_output(
            Instant::now() + timeout,
            "lifecycle stderr predicate",
            |output| predicate(&output.stderr_lossy()),
        )
        .unwrap_or_else(|error| {
            panic!(
                "timeout waiting for lifecycle stderr predicate: {error}\n{}",
                session.diagnostic_snapshot(80)
            )
        })
        .stderr_lossy()
}

#[test]
fn lifecycle_forwarded_and_filtered() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let Some((up_addr, _upstream_echo)) = spawn_echo_or_skip(family) else {
        return;
    };
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

    let stderr = poll_session_logs_until(&mut session, MAX_WAIT_SECS, |err| {
        err.contains("filtered") && err.contains("forwarded") && lifecycle_snapshot_is_terminal(err)
    });

    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}

#[test]
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

    let stderr = poll_session_logs_until(&mut session, MAX_WAIT_SECS, |err| {
        err.contains("consume-cadence")
            && err.contains("consume-session-control")
            && lifecycle_snapshot_is_terminal(err)
    });

    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, true);
}

#[test]
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

    let stderr = poll_session_logs_until(&mut session, MAX_WAIT_SECS, |err| {
        err.contains("handshake-timeout-drop")
            && err.contains("drop-handshake-pending")
            && lifecycle_snapshot_is_terminal(err)
    });

    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}

#[test]
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

    let stderr = poll_session_logs_until(&mut session, MAX_WAIT_SECS, |err| {
        err.contains("handshake-reset-drop") && lifecycle_snapshot_is_terminal(err)
    });

    assert!(
        session.is_running().expect("query forwarder status"),
        "forwarder process must still be running when reset drop occurred"
    );

    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate lifecycle forwarder");
    let expected_keys = DiagnosticLogIndex::parse("", &stderr)
        .expect("valid diagnostics")
        .received_trace_keys();
    assert_lifecycle_invariants(&stderr, &expected_keys, false);
}
