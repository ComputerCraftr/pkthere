use socket2::Domain;
use std::time::Instant;

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
    ALL_CONNECT_MODES, MatrixCase, bind_client_or_skip, run_matrix_cases, spawn_echo_or_skip,
    spawn_upstream_echo_or_skip,
};
use pkthere_test_support::network::{
    bind_udp_client, bind_udp_client_with_port, localhost_addr, random_unprivileged_port,
    render_canonical_ip_id, udp_listen_arg,
};
use pkthere_test_support::packet_diagnostics::{DiagnosticLogIndex, trace_key};
use pkthere_test_support::raw_icmp::acquire_icmp_dgram_session_lock;
use pkthere_test_support::runtime_asserts::{
    expect_no_echo, expect_session_stats_matching, json_addr, recv_legitimate_echo_with_retry,
    send_until_session_locked, wait_for_locked_client, wait_for_session_stats_json,
    wait_for_session_stats_matching,
};
use pkthere_test_support::socket_matrix::assert_socket_matrix_state;
use pkthere_test_support::timing::{
    CLIENT_WAIT_MS, DRAIN_WAIT_MS, IDLE_TIMEOUT_GRACE, MAX_WAIT_SECS, RAW_ICMP_LOCK_WAIT,
    STATS_WAIT_MS, TIMEOUT_SECS,
};
use pkthere_test_support::worker_flow;

use std::io::ErrorKind;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug)]
enum UnconnectedWrongPeerRole {
    ClientSide,
    UpstreamSide,
}

fn panic_with_session_context(context: &str, session: &ForwarderSession) -> ! {
    let (stdout, stderr) = snapshot_forwarder_output_tail(session, 20)
        .unwrap_or_else(|_| (String::new(), String::new()));
    let mut details = String::new();
    if !stdout.trim().is_empty() {
        details.push_str("\nrecent stdout tail:\n");
        details.push_str(&stdout);
    }
    if !stderr.trim().is_empty() {
        details.push_str("\nrecent stderr tail:\n");
        details.push_str(&stderr);
    }
    panic!("{context}{details}");
}

fn routable_loopback_for_wildcard_bind(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        ),
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            addr.port(),
        ),
        _ => addr,
    }
}

fn describe_unconnected_wrong_peer_case(
    role: UnconnectedWrongPeerRole,
    case: MatrixCase,
) -> String {
    let role = match role {
        UnconnectedWrongPeerRole::ClientSide => "client",
        UnconnectedWrongPeerRole::UpstreamSide => "upstream",
    };
    format!(
        "role={role} family={:?} proto={} client_unconnected={} upstream_unconnected={}",
        case.family, case.proto, case.debug_client_unconnected, case.debug_upstream_unconnected
    )
}

fn uses_kernel_echo_debug(case: MatrixCase) -> bool {
    case.proto == pkthere_wire::SupportedProtocol::ICMP
}

#[test]
fn udp_upstream_explicit_source_port_is_bound_from_cli() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let Some((up_addr, _upstream_echo)) = spawn_echo_or_skip(family) else {
        return;
    };
    let source_port = random_unprivileged_port(family).expect("source port");
    let there = format!("UDP:{up_addr}");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(family, 0)),
        there,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(source_port),
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(QUICK_STATS_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client.connect(session.listen_addr).expect("connect client");
    client
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set client timeout");
    client.send(LEGIT_PAYLOAD_1).expect("send payload");
    let mut buf = [0; 2048];
    let n = recv_legitimate_echo_with_retry(
        &client,
        LEGIT_PAYLOAD_1,
        &mut buf,
        "explicit UDP upstream source port",
        "source-port echo",
    )
    .expect("receive payload");
    assert_eq!(&buf[..n], LEGIT_PAYLOAD_1);

    let stats = expect_session_stats_matching(
        &mut session,
        STATS_WAIT_MS,
        "did not see explicit UDP upstream source port",
        |stats| {
            worker_flow::locked_worker_flow(stats)["upstream_local_filter_canonical"]
                .as_str()
                .is_some_and(|addr| addr == render_canonical_ip_id(up_addr.ip(), source_port))
        },
    );
    let worker = worker_flow::locked_worker_flow(&stats);
    assert_eq!(
        worker_flow::worker_str(worker, "upstream_local_filter_canonical"),
        render_canonical_ip_id(up_addr.ip(), source_port)
    );
}

#[test]
fn packet_dump_debug_log_emits_structured_udp_evidence() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let Some((up_addr, _upstream_echo)) = spawn_echo_or_skip(family) else {
        return;
    };

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
                output
                    .stderr_lossy()
                    .contains("\"disposition\":\"forwarded\"")
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

    let diagnostics = DiagnosticLogIndex::parse("", &stderr).expect("schema-2 diagnostics");
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
            &[false],
            &[false],
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(case.family, 0)),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(QUICK_STATS_TIMEOUT_SECS),
        max_payload: Some(max_payload),
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packets", "drops", "handles"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(session.listen_addr)
        .unwrap_or_else(|_| panic!("connect to {} forwarder (max payload)", case.proto));

    let ok = vec![255u8; max_payload];
    client_sock.send(&ok).expect("send max payload");
    let mut buf = vec![0u8; recv_buf_len];
    let case_desc = format!("{case:?} max_payload={max_payload}");
    recv_legitimate_echo_with_retry(&client_sock, &ok, &mut buf, &case_desc, "max payload echo")
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));

    // Drain any delayed packets before testing the drop, especially for empty payloads
    client_sock
        .set_read_timeout(Some(DRAIN_WAIT_MS))
        .expect("set drain timeout");
    while client_sock.recv(&mut buf).is_ok() {}

    let over = vec![255u8; max_payload + 1];
    client_sock.send(&over).expect("send oversize payload");
    expect_no_echo(&client_sock, &mut buf);

    session
        .wait_for_exit_success(MAX_WAIT_SECS)
        .expect("forwarder exit after oversize timeout");

    let stats = wait_for_session_stats_json(&mut session, STATS_WAIT_MS)
        .unwrap_or_else(|| panic!("did not see stats JSON line within {:?}", STATS_WAIT_MS));
    assert_eq!(
        stats["c2u_drops_oversize"]
            .as_u64()
            .expect("missing c2u_drops_oversize"),
        1,
        "one controlled oversize datagram must produce one oversize drop"
    );
    assert!(
        stats["locked"].as_bool().expect("missing locked field"),
        "max-payload case should remain locked after successful in-range payload"
    );
    let worker = worker_flow::locked_worker_flow(&stats);
    assert_socket_matrix_state(worker, case, "exit", &case_desc);
}

#[test]
fn single_client_forwarding() {
    for (family, payload) in [
        (Domain::IPV4, SINGLE_CLIENT_PAYLOAD_V4),
        (Domain::IPV6, SINGLE_CLIENT_PAYLOAD_V6),
    ] {
        run_matrix_cases(
            &[family],
            pkthere_test_support::runtime_capability::enabled_forward_protocols(),
            &ALL_CONNECT_MODES,
            &ALL_CONNECT_MODES,
            |case| {
                single_client_forwarding_case(case, payload);
            },
        );
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(case.family, 0)),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(QUICK_STATS_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(session.listen_addr)
        .unwrap_or_else(|_| panic!("connect to {} forwarder (single client)", case.proto));

    for _ in 0..COUNT {
        client_sock
            .send(payload)
            .unwrap_or_else(|_| panic!("send to {} forwarder (single client)", case.proto));
        let mut buf = [0u8; 2048];
        let case_desc = format!("{case:?}");
        let n = recv_legitimate_echo_with_retry(
            &client_sock,
            payload,
            &mut buf,
            &case_desc,
            "single-client echo",
        )
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
        assert_eq!(&buf[..n], payload, "echo payload mismatch");
    }

    session
        .wait_for_exit_success(MAX_WAIT_SECS)
        .expect("forwarder exit after single-client forwarding");

    let stats = wait_for_session_stats_json(&mut session, STATS_WAIT_MS)
        .unwrap_or_else(|| panic!("did not see stats JSON line within {:?}", STATS_WAIT_MS));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().expect("missing locked field"));
    let worker = worker_flow::locked_worker_flow(&stats);

    let case_desc = format!("{case:?}");
    assert_socket_matrix_state(worker, case, "exit", &case_desc);

    let c2u_packets = stats["c2u_pkts"].as_u64().expect("missing c2u_pkts");
    let u2c_packets = stats["u2c_pkts"].as_u64().expect("missing u2c_pkts");
    assert!(
        c2u_packets >= COUNT as u64,
        "retry-capable client forwarded fewer than {COUNT} requests"
    );
    assert!(
        u2c_packets >= COUNT as u64,
        "retry-capable client received fewer than {COUNT} upstream replies"
    );

    let listener_local = worker_flow::worker_str(worker, "listen_local_filter_canonical");
    let stats_client_endpoint = client_local.to_string();
    worker_flow::assert_flow_tuple(
        worker,
        "listener_flow_outbound",
        listener_local,
        &stats_client_endpoint,
    );
    let stats_client = worker_flow::flow_tuple(worker, "listener_flow_outbound")
        .1
        .parse::<SocketAddr>()
        .expect("parse stats listener_flow_outbound remote");
    assert_eq!(stats_client, client_local, "stats client_remote mismatch");
    let actual_upstream = worker["upstream_remote_filter_canonical"]
        .as_str()
        .expect("missing upstream_remote_filter_canonical");
    if case.proto == pkthere_wire::SupportedProtocol::ICMP {
        // Accept either the requested :0 or the realized ID (now that we discover it)
        assert!(
            actual_upstream == render_canonical_ip_id(up_addr.ip(), 0)
                || !actual_upstream.ends_with(":0"),
            "stats upstream_remote_filter_canonical mismatch for ICMP: expected IP:0 or IP:real_id, got {}",
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
            "stats upstream_remote_filter_canonical mismatch"
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

    let c2u_us_max = stats["c2u_us_max"].as_u64().unwrap();
    let u2c_us_max = stats["u2c_us_max"].as_u64().unwrap();
    let c2u_us_avg = stats["c2u_us_avg"].as_u64().unwrap();
    let u2c_us_avg = stats["u2c_us_avg"].as_u64().unwrap();
    let c2u_us_ewma = stats["c2u_us_ewma"].as_u64().unwrap();
    let u2c_us_ewma = stats["u2c_us_ewma"].as_u64().unwrap();

    assert!(c2u_us_avg > 0, "expected c2u_us_avg > 0, got {c2u_us_avg}");
    assert!(u2c_us_avg > 0, "expected u2c_us_avg > 0, got {u2c_us_avg}");
    assert!(
        c2u_us_ewma > 0,
        "expected c2u_us_ewma > 0, got {c2u_us_ewma}"
    );
    assert!(
        u2c_us_ewma > 0,
        "expected u2c_us_ewma > 0, got {u2c_us_ewma}"
    );
    assert!(c2u_us_max >= c2u_us_avg);
    assert!(u2c_us_max >= u2c_us_avg);
    assert!(c2u_us_max >= c2u_us_ewma);
    assert!(u2c_us_max >= u2c_us_ewma);
}

#[test]
fn relock_after_timeout_drop() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &ALL_CONNECT_MODES,
        &[false],
        |case| {
            relock_after_timeout_drop_case(case);
        },
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
    let here_port = random_unprivileged_port(case.family).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(case.family, here_port),
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
    .parse::<SocketAddr>()
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
fn timeout_drop_relocks_after_forward_errors_udp() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &ALL_CONNECT_MODES,
        &[false],
        |case| {
            timeout_drop_relocks_after_forward_errors_udp_case(case);
        },
    );
}

fn timeout_drop_relocks_after_forward_errors_udp_case(case: MatrixCase) {
    let client_a = bind_udp_client(case.family).expect("client_a loopback not available");
    let client_b = bind_udp_client(case.family).expect("client_b loopback not available");
    let dead_upstream_port = random_unprivileged_port(case.family).expect("dead upstream port");
    let here_port = random_unprivileged_port(case.family).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        debug_icmp_kernel_echo_self_handshake: uses_kernel_echo_debug(case),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_loopback_arg(case.family, here_port),
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

    let stats = expect_session_stats_matching(
        &mut session,
        MAX_WAIT_SECS,
        "did not see forwarding errors in stats JSON",
        |candidate| {
            candidate["locked"].as_bool().expect("missing locked")
                && candidate["u2c_errs"].as_u64().expect("missing u2c_errs") > 0
        },
    );
    assert_eq!(
        worker_flow::flow_tuple(
            worker_flow::locked_worker_flow(&stats),
            "listener_flow_outbound",
        )
        .1
        .parse::<SocketAddr>()
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
fn unconnected_udp_rejects_wrong_peer_and_only_forwards_legitimate_traffic() {
    run_matrix_cases(
        &[Domain::IPV4, Domain::IPV6],
        &["UDP"],
        &[true],
        &[false],
        |case| {
            unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::ClientSide, case);
        },
    );
    run_matrix_cases(&[Domain::IPV4], &["UDP"], &[false], &[true], |case| {
        unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::UpstreamSide, case);
    });
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
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
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
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
                json_addr(&worker["upstream_local_filter_canonical"])
                    .expect("parse stats upstream_local_filter_canonical"),
            );
            client_secondary
                .send_to(WRONG_UPSTREAM_PEER_PAYLOAD, upstream_local)
                .unwrap_or_else(|e| panic!("{case_desc}: send stray upstream packet: {e}"));

            expect_no_echo(&client_primary, &mut buf);

            let stray_addr = localhost_addr(case.family, WRONG_PEER_STRAY_PORT_ID);
            let expected_drop = format!(
                "dropping packet from unexpected upstream peer {}",
                stray_addr
            );
            wait_for_drop_log(&mut session, &expected_drop, &case_desc);
        }
    }

    client_primary
        .set_read_timeout(Some(DRAIN_WAIT_MS))
        .unwrap_or_else(|e| panic!("{case_desc}: set primary client timeout: {e}"));
    match client_primary.recv(&mut buf) {
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Err(e) => {
            panic_with_session_context(
                &format!(
                    "{case_desc}: unexpected recv error while verifying stray packet was filtered: {e}"
                ),
                &session,
            );
        }
        Ok(n) => {
            panic_with_session_context(
                &format!(
                    "{case_desc}: stray packet unexpectedly produced {n} client-visible bytes"
                ),
                &session,
            );
        }
    }

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
    assert_socket_matrix_state(worker, case, "exit", &case_desc);
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
