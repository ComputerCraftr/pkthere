use pkthere_test_support::fixtures::{
    FORWARD_ERROR_PAYLOAD_A, FORWARD_ERROR_PAYLOAD_B, LEGIT_PAYLOAD_1, LEGIT_PAYLOAD_2,
    QUICK_STATS_TIMEOUT_SECS, RELOCK_PAYLOAD_A, RELOCK_PAYLOAD_B, SINGLE_CLIENT_PAYLOAD_V4,
    SINGLE_CLIENT_PAYLOAD_V6, WRONG_CLIENT_PEER_PAYLOAD, WRONG_PEER_LEGIT_PORT_ID,
    WRONG_PEER_STRAY_PORT_ID, WRONG_PEER_TARGET_PORT_ID, WRONG_UPSTREAM_PEER_PAYLOAD,
    udp_loopback_arg,
};
use pkthere_test_support::forwarder::{
    ForwarderConfig, ForwarderSession, launch_forwarder, snapshot_forwarder_output,
    snapshot_forwarder_output_tail,
};
use pkthere_test_support::matrix::{
    FORCED_UNCONNECTED_DEBUG_SCENARIOS, MatrixCase, PRODUCTION_CONNECTION_SCENARIOS,
    bind_client_or_skip, run_matrix_cases, spawn_echo_or_skip, spawn_upstream_echo_or_skip,
};
use pkthere_test_support::network::{
    bind_udp_client, bind_udp_client_with_port, localhost_addr, random_unprivileged_port,
    render_canonical_ip_id, udp_listen_arg,
};
use pkthere_test_support::packet_diagnostics::{DiagnosticLogIndex, trace_key};
use pkthere_test_support::raw_icmp::acquire_icmp_dgram_session_lock;
use pkthere_test_support::runtime_asserts::{
    assert_recv_payload, exercise_max_payload_boundary, expect_no_echo,
    expect_session_stats_matching, json_addr, recv_legitimate_echo_with_retry,
    send_until_session_locked, send_until_session_stats_matching, wait_for_locked_client,
    wait_for_session_stats_json, wait_for_session_stats_matching,
};
use pkthere_test_support::socket_matrix::assert_socket_matrix_state;
use pkthere_test_support::timing::{
    CLIENT_WAIT_MS, DRAIN_WAIT_MS, IDLE_TIMEOUT_GRACE, MAX_WAIT_SECS, RAW_ICMP_LOCK_WAIT,
    STATS_WAIT_MS, TIMEOUT_SECS,
};
use pkthere_test_support::worker_flow;
use socket2::Domain;
use std::time::Instant;

mod integration_support;
use integration_support::{
    UnconnectedWrongPeerRole, assert_only_retry_duplicates_remain,
    describe_unconnected_wrong_peer_case, panic_with_session_context,
    routable_loopback_for_wildcard_bind, uses_kernel_echo_debug,
};

#[test]
fn packet_dump_debug_log_emits_structured_udp_evidence() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let (up_addr, _upstream_echo) =
        spawn_echo_or_skip(family).expect("IPv4 UDP echo server is required");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(family, 0)),
        there: format!("UDP:{up_addr}"),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(QUICK_STATS_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client.connect(session.listen_addr).expect("connect client");
    client
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set client timeout");
    client.send(LEGIT_PAYLOAD_1).expect("send payload");
    let mut buf = [0; 2048];
    let n = client.recv(&mut buf).expect("receive payload");
    assert_eq!(&buf[..n], LEGIT_PAYLOAD_1);

    session
        .wait_for_output(
            Instant::now() + STATS_WAIT_MS,
            "structured packet-dump disposition",
            |output| {
                DiagnosticLogIndex::parse(&output.stdout_lossy(), &output.stderr_lossy())
                    .is_ok_and(|index| index.has_complete_accepted_forwarded_trace("c2u"))
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "packet-dump lifecycle was incomplete: {error}\n{}",
                session.diagnostic_snapshot(40)
            )
        });
    let (_stdout, stderr) = snapshot_forwarder_output(&session).expect("snapshot output");
    assert!(stderr.contains("packet-dump {"), "{stderr}");
    assert!(stderr.contains("\"stage\":\"received\""), "{stderr}");
    assert!(stderr.contains("\"stage\":\"admission\""), "{stderr}");
    assert!(stderr.contains("\"stage\":\"disposition\""), "{stderr}");
    assert!(stderr.contains("\"udp\""), "{stderr}");
    assert!(stderr.contains("\"result\":\"accepted\""), "{stderr}");

    let diagnostics = DiagnosticLogIndex::parse("", &stderr).expect("schema-3 diagnostics");
    let accepted = diagnostics
        .packets()
        .find(|record| {
            record.value["stage"] == "admission"
                && record.value["admission"]["result"] == "accepted"
        })
        .expect("accepted admission packet dump");
    let correlation = trace_key(&accepted.value).expect("packet trace key");
    let stages = diagnostics.trace_stages();
    let correlated = stages
        .get(&correlation)
        .expect("correlated packet lifecycle");
    for stage in ["received", "admission", "disposition"] {
        let count = match stage {
            "received" => correlated.received.len(),
            "admission" => correlated.admission.len(),
            "disposition" => correlated.disposition.len(),
            _ => unreachable!(),
        };
        assert_eq!(count, 1, "missing correlated {stage}: {stderr}");
    }
    assert_eq!(
        correlated.disposition.len(),
        1,
        "contradictory terminal records: {stderr}"
    );
    assert_eq!(
        correlated.disposition[0].value["disposition"], "forwarded",
        "{stderr}"
    );
}

fn wait_for_timeout_drop(session: &mut ForwarderSession, case_desc: &str) {
    let outcome = wait_for_session_stats_matching(
        session,
        TIMEOUT_SECS + IDLE_TIMEOUT_GRACE + STATS_WAIT_MS,
        |stats| !stats["locked"].as_bool().expect("missing locked field"),
    );
    assert!(
        outcome.matched,
        "{case_desc}: lock did not clear after idle timeout\n{}",
        outcome.failure_details()
    );
    assert!(
        session
            .try_status()
            .unwrap_or_else(|error| panic!("{case_desc}: inspect forwarder state: {error}"))
            .is_none(),
        "{case_desc}: drop-mode forwarder exited after clearing its lock"
    );
}

#[test]
fn enforce_max_payload() {
    for (family, max_payload, recv_buf_len) in [
        (Domain::IPV4, 0usize, 2048usize),
        (Domain::IPV4, 548usize, 2048usize),
        (Domain::IPV6, 1232usize, 4096usize),
    ] {
        run_matrix_cases(
            &[family],
            pkthere_test_support::runtime_capability::enabled_forward_protocols(),
            &PRODUCTION_CONNECTION_SCENARIOS,
            &PRODUCTION_CONNECTION_SCENARIOS,
            |case| {
                enforce_max_payload_case(case, max_payload, recv_buf_len);
            },
        );
    }
}

fn enforce_max_payload_case(case: MatrixCase, max_payload: usize, recv_buf_len: usize) {
    let _icmp_dgram_guard = uses_kernel_echo_debug(case).then(|| {
        acquire_icmp_dgram_session_lock(
            Instant::now() + RAW_ICMP_LOCK_WAIT,
            "enforce_max_payload_case",
        )
        .expect("acquire ICMP DGRAM session lock")
    });
    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let Some((there_arg, _up_addr, _upstream_echo)) =
        spawn_upstream_echo_or_skip(case.family, case.proto.to_str())
    else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.client_connection.debug_force_unconnected(),
        debug_upstream_unconnected: case.upstream_connection.debug_force_unconnected(),
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(case.family, 0)),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: Some(max_payload),
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packets", "drops", "handles"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(session.listen_addr)
        .unwrap_or_else(|_| panic!("connect to {} forwarder (max payload)", case.proto));

    let case_desc = format!("{case:?} max_payload={max_payload}");
    let stats = exercise_max_payload_boundary(
        &mut session,
        &client_sock,
        max_payload,
        &mut vec![0u8; recv_buf_len],
        &case_desc,
    );
    let worker = worker_flow::locked_worker_flow(&stats);
    assert_socket_matrix_state(
        worker,
        case,
        pkthere_socket_policy::TimeoutAction::Exit,
        &case_desc,
    );
}

#[test]
fn single_client_forwarding_uses_production_socket_policy() {
    for (family, payload) in [
        (Domain::IPV4, SINGLE_CLIENT_PAYLOAD_V4),
        (Domain::IPV6, SINGLE_CLIENT_PAYLOAD_V6),
    ] {
        run_matrix_cases(
            &[family],
            pkthere_test_support::runtime_capability::enabled_forward_protocols(),
            &PRODUCTION_CONNECTION_SCENARIOS,
            &PRODUCTION_CONNECTION_SCENARIOS,
            |case| {
                single_client_forwarding_case(case, payload);
            },
        );
    }
}

#[test]
fn single_client_forwarding_forced_unconnected_debug_scenarios() {
    for (family, payload) in [
        (Domain::IPV4, SINGLE_CLIENT_PAYLOAD_V4),
        (Domain::IPV6, SINGLE_CLIENT_PAYLOAD_V6),
    ] {
        for (client_options, upstream_options) in [
            (
                &FORCED_UNCONNECTED_DEBUG_SCENARIOS[..],
                &[
                    pkthere_test_support::matrix::MatrixConnectionScenario::ProductionPolicy,
                    pkthere_test_support::matrix::MatrixConnectionScenario::ForcedUnconnectedDebug,
                ][..],
            ),
            (
                &PRODUCTION_CONNECTION_SCENARIOS[..],
                &FORCED_UNCONNECTED_DEBUG_SCENARIOS[..],
            ),
        ] {
            run_matrix_cases(
                &[family],
                pkthere_test_support::runtime_capability::enabled_forward_protocols(),
                client_options,
                upstream_options,
                |case| single_client_forwarding_case(case, payload),
            );
        }
    }
}

fn single_client_forwarding_case(case: MatrixCase, payload: &[u8]) {
    const COUNT: usize = 5;

    let _icmp_dgram_guard = uses_kernel_echo_debug(case).then(|| {
        acquire_icmp_dgram_session_lock(
            Instant::now() + RAW_ICMP_LOCK_WAIT,
            "single_client_forwarding_case",
        )
        .expect("acquire ICMP DGRAM session lock")
    });

    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let client_local = client_sock.local_addr().expect("client local addr");
    let Some((there_arg, up_addr, _upstream_echo)) =
        spawn_upstream_echo_or_skip(case.family, case.proto.to_str())
    else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.client_connection.debug_force_unconnected(),
        debug_upstream_unconnected: case.upstream_connection.debug_force_unconnected(),
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(case.family, 0)),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(session.listen_addr)
        .unwrap_or_else(|_| panic!("connect to {} forwarder (single client)", case.proto));
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set single-client receive timeout");

    for _ in 0..COUNT {
        client_sock
            .send(payload)
            .unwrap_or_else(|_| panic!("send to {} forwarder (single client)", case.proto));
        let mut buf = [0u8; 2048];
        let case_desc = format!("{case:?}");
        let n = assert_recv_payload(&session, &client_sock, payload, &mut buf, &case_desc);
        assert_eq!(&buf[..n], payload, "echo payload mismatch");
    }

    let stats = expect_session_stats_matching(
        &mut session,
        STATS_WAIT_MS,
        "single-client packet accounting was not published before the stats deadline",
        |stats| {
            stats["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= COUNT as u64
                && stats["u2c_pkts"].as_u64().expect("missing u2c_pkts") >= COUNT as u64
        },
    );
    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate single-client forwarder");
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().expect("missing locked field"));
    let worker = worker_flow::locked_worker_flow(&stats);

    let case_desc = format!("{case:?}");
    assert_socket_matrix_state(
        worker,
        case,
        pkthere_socket_policy::TimeoutAction::Exit,
        &case_desc,
    );

    let c2u_packets = stats["c2u_pkts"].as_u64().expect("missing c2u_pkts");
    let u2c_packets = stats["u2c_pkts"].as_u64().expect("missing u2c_pkts");
    assert_eq!(c2u_packets, COUNT as u64);
    assert_eq!(u2c_packets, COUNT as u64);

    let listener_local = worker_flow::worker_str(worker, "listener_local_filter");
    let stats_client_endpoint = client_local.to_string();
    worker_flow::assert_flow_tuple(
        worker,
        "listener_flow_outbound",
        listener_local,
        &stats_client_endpoint,
    );
    let stats_client = worker_flow::flow_tuple(worker, "listener_flow_outbound")
        .1
        .parse::<std::net::SocketAddr>()
        .expect("parse stats listener_flow_outbound remote");
    assert_eq!(stats_client, client_local, "stats client_remote mismatch");
    let actual_upstream = worker["upstream_remote_filter"]
        .as_str()
        .expect("missing upstream_remote_filter");
    if case.proto == pkthere_wire::SupportedProtocol::ICMP {
        assert!(
            actual_upstream == render_canonical_ip_id(up_addr.ip(), 0)
                || !actual_upstream.ends_with(":0"),
            "stats upstream_remote_filter mismatch for ICMP: expected IP:0 or IP:real_id, got {}",
            actual_upstream
        );
        let expected_prefix = match up_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        };
        assert!(actual_upstream.starts_with(&expected_prefix));
    } else {
        assert_eq!(
            actual_upstream,
            render_canonical_ip_id(up_addr.ip(), up_addr.port()),
            "stats upstream_remote_filter mismatch"
        );
    }

    assert_eq!(
        stats["c2u_bytes"].as_u64().expect("missing c2u_bytes"),
        payload.len() as u64 * c2u_packets,
        "c2u byte accounting must include retry packets"
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"),
        payload.len() as u64 * u2c_packets,
        "u2c byte accounting must include retry replies"
    );
    assert_eq!(
        stats["c2u_bytes_max"]
            .as_u64()
            .expect("missing c2u_bytes_max"),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"]
            .as_u64()
            .expect("missing u2c_bytes_max"),
        payload.len() as u64
    );

    for direction in ["c2u", "u2c"] {
        let required_metric = |suffix: &str| {
            let key = format!("{direction}_{suffix}");
            let Some(value) = stats.get(&key).and_then(serde_json::Value::as_u64) else {
                panic!("missing required stats metric {key}");
            };
            value
        };
        let average = required_metric("latency_ns_avg");
        let ewma = required_metric("interval_mean_latency_ns_ewma");
        let maximum = required_metric("latency_ns_max");
        let latency_sum = required_metric("latency_ns_sum");
        let queue_sum = required_metric("queue_delay_ns_sum");
        let service_sum = required_metric("send_service_ns_sum");
        let packet_count = required_metric("pkts");
        let zero_resolution_samples = required_metric("zero_resolution_samples");
        assert!(average > 0, "{direction} latency average must be nonzero");
        assert!(ewma > 0, "{direction} interval-mean EWMA must be nonzero");
        assert_eq!(
            latency_sum,
            queue_sum + service_sum,
            "{direction} end-to-end latency must equal queue plus send service time"
        );
        assert!(
            zero_resolution_samples <= packet_count,
            "{direction} zero-resolution samples cannot exceed sent user packets"
        );
        assert!(maximum >= average);
        assert!(maximum >= ewma);
    }
}

#[test]
fn relock_after_timeout_drop_uses_production_socket_policy() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &PRODUCTION_CONNECTION_SCENARIOS,
        &PRODUCTION_CONNECTION_SCENARIOS,
        |case| {
            relock_after_timeout_drop_case(case);
        },
    );
}

#[test]
fn relock_after_timeout_drop_forced_unconnected_debug_scenario() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &FORCED_UNCONNECTED_DEBUG_SCENARIOS,
        &PRODUCTION_CONNECTION_SCENARIOS,
        relock_after_timeout_drop_case,
    );
}

fn relock_after_timeout_drop_case(case: MatrixCase) {
    let _icmp_dgram_guard = uses_kernel_echo_debug(case).then(|| {
        acquire_icmp_dgram_session_lock(
            Instant::now() + RAW_ICMP_LOCK_WAIT,
            "relock_after_timeout_drop_case",
        )
        .expect("acquire ICMP DGRAM session lock")
    });
    let case_desc = format!("{case:?}");
    let client_a = bind_udp_client(case.family).expect("client_a loopback not available");
    let client_b = bind_udp_client(case.family).expect("client_b loopback not available");
    let Some((there_arg, _up_addr, _upstream_echo)) =
        spawn_upstream_echo_or_skip(case.family, case.proto.to_str())
    else {
        return;
    };
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.client_connection.debug_force_unconnected(),
        debug_upstream_unconnected: case.upstream_connection.debug_force_unconnected(),
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(case.family, 0),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_a
        .connect(session.listen_addr)
        .expect("connect A -> forwarder");

    let payload_a = RELOCK_PAYLOAD_A;
    client_a.send(payload_a).expect("send A");
    let a_locked = wait_for_locked_client(&mut session, MAX_WAIT_SECS)
        .expect("did not see lock line for client A");
    assert_eq!(
        a_locked,
        client_a.local_addr().expect("client A local addr")
    );

    let mut buf = [0u8; 2048];
    let n = recv_legitimate_echo_with_retry(&client_a, payload_a, &mut buf, &case_desc, "echo A")
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    assert_eq!(&buf[..n], payload_a);

    wait_for_timeout_drop(&mut session, &case_desc);

    client_b
        .connect(session.listen_addr)
        .expect("connect B -> forwarder");
    let payload_b = RELOCK_PAYLOAD_B;
    client_b
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client B");

    let b_locked = send_until_session_locked(&client_b, payload_b, &mut session, MAX_WAIT_SECS)
        .expect("did not see lock line for client B");
    let client_b_local = client_b.local_addr().expect("client B local addr");
    assert_eq!(
        b_locked, client_b_local,
        "forwarder locked to unexpected client B address"
    );

    let n = recv_legitimate_echo_with_retry(&client_b, payload_b, &mut buf, &case_desc, "echo B")
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    assert_eq!(&buf[..n], payload_b);

    let stats = wait_for_session_stats_json(&mut session, STATS_WAIT_MS)
        .unwrap_or_else(|| panic!("did not see stats JSON line within {:?}", STATS_WAIT_MS));
    session
        .terminate(Instant::now() + MAX_WAIT_SECS)
        .expect("terminate relock forwarder");

    let stats_client = worker_flow::flow_tuple(
        worker_flow::locked_worker_flow(&stats),
        "listener_flow_outbound",
    )
    .1
    .parse::<std::net::SocketAddr>()
    .expect("parse stats listener_flow_outbound remote");
    assert_eq!(
        stats_client, client_b_local,
        "forwarder did not relock to client B"
    );

    let c2u_pkts = stats["c2u_pkts"].as_u64().expect("missing c2u_pkts");
    let u2c_pkts = stats["u2c_pkts"].as_u64().expect("missing u2c_pkts");
    assert!(c2u_pkts >= 2, "relock retries must forward both payloads");
    assert!(u2c_pkts >= 2, "relock retries must return both payloads");
}

#[test]
fn timeout_drop_relocks_after_forward_errors_udp_uses_production_socket_policy() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &PRODUCTION_CONNECTION_SCENARIOS,
        &PRODUCTION_CONNECTION_SCENARIOS,
        |case| {
            timeout_drop_relocks_after_forward_errors_udp_case(case);
        },
    );
}

#[test]
fn timeout_drop_relocks_after_forward_errors_udp_forced_unconnected_debug_scenario() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &FORCED_UNCONNECTED_DEBUG_SCENARIOS,
        &PRODUCTION_CONNECTION_SCENARIOS,
        timeout_drop_relocks_after_forward_errors_udp_case,
    );
}

fn timeout_drop_relocks_after_forward_errors_udp_case(case: MatrixCase) {
    let client_a = bind_udp_client(case.family).expect("client_a loopback not available");
    let client_b = bind_udp_client(case.family).expect("client_b loopback not available");
    let dead_upstream_port = random_unprivileged_port(case.family).expect("dead upstream port");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.client_connection.debug_force_unconnected(),
        debug_upstream_unconnected: case.upstream_connection.debug_force_unconnected(),
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(case.family, 0),
        there: udp_loopback_arg(case.family, dead_upstream_port),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_a
        .connect(session.listen_addr)
        .expect("connect A -> forwarder");
    client_a
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client A");

    let payload_a = FORWARD_ERROR_PAYLOAD_A;
    client_a.send(payload_a).expect("send A");
    let a_locked = wait_for_locked_client(&mut session, MAX_WAIT_SECS)
        .expect("did not see lock line for client A");
    assert_eq!(
        a_locked,
        client_a.local_addr().expect("client A local addr")
    );

    expect_no_echo(&client_a, &mut [0u8; 256]);

    let stats = send_until_session_stats_matching(
        &client_a,
        payload_a,
        &mut session,
        MAX_WAIT_SECS,
        "did not see forwarding errors in stats JSON",
        |candidate| {
            candidate["locked"].as_bool().expect("missing locked")
                && (candidate["c2u_user_send_errors"]
                    .as_u64()
                    .expect("missing c2u_user_send_errors")
                    > 0
                    || candidate["u2c_receive_errors"]
                        .as_u64()
                        .expect("missing u2c_receive_errors")
                        > 0)
        },
    );
    assert_eq!(
        worker_flow::flow_tuple(
            worker_flow::locked_worker_flow(&stats),
            "listener_flow_outbound",
        )
        .1
        .parse::<std::net::SocketAddr>()
        .expect("stats listener outbound remote"),
        client_a.local_addr().expect("client A local addr")
    );

    wait_for_timeout_drop(&mut session, &format!("{case:?} forward-error relock"));

    client_b
        .connect(session.listen_addr)
        .expect("connect B -> forwarder");
    let payload_b = FORWARD_ERROR_PAYLOAD_B;
    let b_locked = send_until_session_locked(&client_b, payload_b, &mut session, MAX_WAIT_SECS)
        .expect("did not see lock line for client B");
    assert_eq!(
        b_locked,
        client_b.local_addr().expect("client B local addr")
    );
}

#[test]
fn forced_unconnected_debug_udp_rejects_wrong_peer_and_forwards_legitimate_traffic() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &FORCED_UNCONNECTED_DEBUG_SCENARIOS,
        &PRODUCTION_CONNECTION_SCENARIOS,
        |case| {
            unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::ClientSide, case);
        },
    );
    run_matrix_cases(
        &[Domain::IPV4],
        &["UDP"],
        &PRODUCTION_CONNECTION_SCENARIOS,
        &FORCED_UNCONNECTED_DEBUG_SCENARIOS,
        |case| {
            unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::UpstreamSide, case);
        },
    );
}

fn unconnected_udp_wrong_peer_case(role: UnconnectedWrongPeerRole, case: MatrixCase) {
    let _icmp_dgram_guard = uses_kernel_echo_debug(case).then(|| {
        acquire_icmp_dgram_session_lock(
            Instant::now() + RAW_ICMP_LOCK_WAIT,
            "unconnected_udp_wrong_peer_case",
        )
        .expect("acquire ICMP DGRAM session lock")
    });
    let case_desc = describe_unconnected_wrong_peer_case(role, case);
    let client_primary = bind_udp_client_with_port(case.family, WRONG_PEER_LEGIT_PORT_ID)
        .expect("primary client loopback not available");
    let client_secondary = bind_udp_client_with_port(case.family, WRONG_PEER_STRAY_PORT_ID)
        .expect("secondary client/stray loopback not available");
    let Some((there_arg, _up_addr, _upstream_echo)) =
        spawn_upstream_echo_or_skip(case.family, case.proto.to_str())
    else {
        return;
    };

    let here = match role {
        UnconnectedWrongPeerRole::ClientSide => {
            udp_loopback_arg(case.family, WRONG_PEER_TARGET_PORT_ID)
        }
        UnconnectedWrongPeerRole::UpstreamSide => udp_listen_arg(localhost_addr(case.family, 0)),
    };

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.client_connection.debug_force_unconnected(),
        debug_upstream_unconnected: case.upstream_connection.debug_force_unconnected(),
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here,
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["drops"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_primary
        .connect(session.listen_addr)
        .unwrap_or_else(|e| panic!("{case_desc}: connect primary client -> forwarder: {e}"));
    if matches!(role, UnconnectedWrongPeerRole::ClientSide) {
        client_secondary
            .connect(session.listen_addr)
            .unwrap_or_else(|e| panic!("{case_desc}: connect secondary client -> forwarder: {e}"));
    }

    let payload_1 = LEGIT_PAYLOAD_1;
    client_primary
        .send(payload_1)
        .unwrap_or_else(|e| panic!("{case_desc}: send payload 1: {e}"));
    let mut buf = [0u8; 2048];
    let n =
        recv_legitimate_echo_with_retry(&client_primary, payload_1, &mut buf, &case_desc, "echo 1")
            .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    assert_eq!(
        &buf[..n],
        payload_1,
        "{case_desc}: first legitimate payload did not round-trip"
    );

    match role {
        UnconnectedWrongPeerRole::ClientSide => {
            client_secondary
                .send(WRONG_CLIENT_PEER_PAYLOAD)
                .unwrap_or_else(|e| panic!("{case_desc}: send stray client packet: {e}"));
            client_secondary
                .set_read_timeout(Some(DRAIN_WAIT_MS))
                .unwrap_or_else(|e| panic!("{case_desc}: set secondary client timeout: {e}"));
            match client_secondary.recv(&mut buf) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    panic_with_session_context(
                        &format!(
                            "{case_desc}: unexpected recv error while verifying client-side stray packet was filtered: {e}"
                        ),
                        &session,
                    );
                }
                Ok(n) => {
                    panic_with_session_context(
                        &format!("{case_desc}: stray client peer unexpectedly received {n} bytes"),
                        &session,
                    );
                }
            }
            let stray_addr = localhost_addr(case.family, WRONG_PEER_STRAY_PORT_ID);
            let expected_drop =
                format!("dropping packet from unexpected client peer {}", stray_addr);
            wait_for_drop_log(&mut session, &expected_drop, &case_desc);
        }
        UnconnectedWrongPeerRole::UpstreamSide => {
            let stats = expect_session_stats_matching(
                &mut session,
                MAX_WAIT_SECS,
                &format!("{case_desc}: did not see locked stats for unconnected wrong-peer test"),
                |stats| {
                    stats["locked"].as_bool().expect("missing locked")
                        && stats["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 1
                        && stats["u2c_pkts"].as_u64().expect("missing u2c_pkts") >= 1
                },
            );
            let worker = worker_flow::locked_worker_flow(&stats);
            let upstream_local = routable_loopback_for_wildcard_bind(
                json_addr(&worker["upstream_local_filter"])
                    .expect("parse stats upstream_local_filter"),
            );
            client_secondary
                .send_to(WRONG_UPSTREAM_PEER_PAYLOAD, upstream_local)
                .unwrap_or_else(|e| panic!("{case_desc}: send stray upstream packet: {e}"));

            let stray_addr = localhost_addr(case.family, WRONG_PEER_STRAY_PORT_ID);
            let expected_drop = format!(
                "dropping packet from unexpected upstream peer {}",
                stray_addr
            );
            wait_for_drop_log(&mut session, &expected_drop, &case_desc);
        }
    }

    assert_only_retry_duplicates_remain(&client_primary, payload_1, &mut buf, &case_desc, &session);

    let payload_2 = LEGIT_PAYLOAD_2;
    client_primary
        .send(payload_2)
        .unwrap_or_else(|e| panic!("{case_desc}: send payload 2: {e}"));
    let n =
        recv_legitimate_echo_with_retry(&client_primary, payload_2, &mut buf, &case_desc, "echo 2")
            .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    assert_eq!(
        &buf[..n],
        payload_2,
        "{case_desc}: second legitimate payload did not round-trip"
    );

    session
        .wait_for_exit_success(MAX_WAIT_SECS)
        .expect("forwarder exit after locked-flow test");

    let stats = wait_for_session_stats_json(&mut session, STATS_WAIT_MS)
        .unwrap_or_else(|| panic!("{case_desc}: node1 stats missing"));
    assert!(
        stats["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 2,
        "{case_desc}: retry-capable client did not forward both legitimate payloads"
    );
    assert!(
        stats["u2c_pkts"].as_u64().expect("missing u2c_pkts") >= 2,
        "{case_desc}: retry-capable client did not receive both legitimate replies"
    );

    let worker = worker_flow::locked_worker_flow(&stats);
    assert_socket_matrix_state(
        worker,
        case,
        pkthere_socket_policy::TimeoutAction::Exit,
        &case_desc,
    );
}

fn wait_for_drop_log(session: &mut ForwarderSession, expected: &str, case_desc: &str) {
    session
        .wait_for_output(
            Instant::now() + STATS_WAIT_MS,
            "packet drop diagnostic",
            |output| {
                output.stdout_lossy().contains(expected) || output.stderr_lossy().contains(expected)
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "{case_desc}: forwarder did not log {expected:?}: {error}\n{}",
                session.diagnostic_snapshot(80)
            )
        });
}
