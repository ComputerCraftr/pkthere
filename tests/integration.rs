#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;
use crate::core::wait_for_stats_json_from;
use crate::orchestrator::{
    CLIENT_WAIT_MS, ForwarderConfig, IPV4_ONLY_FAMILIES, IpFamily, JSON_WAIT_MS, MAX_WAIT_SECS,
    MatrixCase, SOCKET_MODES, SUPPORTED_PROTOCOLS, bind_client_or_skip, bind_udp_client,
    default_test_icmp_upstream_arg, default_test_upstream_arg, expect_no_echo, json_addr,
    launch_forwarder, localhost_addr, random_unprivileged_port, raw_icmp_test_supported,
    run_matrix_cases, send_until_locked, skip_unless_raw_icmp_supported, spawn_echo_or_skip,
    spawn_udp_echo_server, try_launch_forwarder, wait_for_child_exit_success,
    wait_for_locked_client_from, wait_for_stats_matching,
};

use std::io::ErrorKind;
use std::thread;
use std::time::{Duration, Instant};

fn locked_worker_flow<'a>(stats: &'a serde_json::Value) -> &'a serde_json::Value {
    stats["worker_flows"]
        .as_array()
        .and_then(|flows| {
            flows.iter().find(|flow| {
                flow["locked"].as_bool().unwrap_or(false)
                    || !flow["client_addr"].is_null()
                    || !flow["flow_key"].is_null()
            })
        })
        .expect("expected at least one worker flow entry")
}

#[test]
fn icmp_sync_mode_forwards_payload_and_tracks_bytes() {
    if crate::orchestrator::platform_requires_raw_privilege_for_any_icmp()
        && !raw_icmp_test_supported()
    {
        return;
    }
    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let mut session = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (sync keepalive)");

    client_sock
        .send(b"x")
        .expect("send initial payload to establish lock");
    let mut buf = [0u8; 2048];
    let n = client_sock
        .recv(&mut buf)
        .expect("recv initial sync reply from forwarder");
    assert_eq!(n, 1, "expected 1-byte echoed payload");
    assert_eq!(&buf[..n], b"x", "expected exact echoed payload");

    let stats = wait_for_stats_json_from(&mut session.out, Duration::from_secs(2))
        .expect("did not see stats JSON line");
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap_or(0);
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap_or(0);
    assert!(
        c2u_pkts >= 1,
        "expected at least one c2u packet recorded in sync mode, got {}",
        c2u_pkts
    );
    assert_eq!(
        c2u_bytes, 1,
        "expected exactly one forwarded c2u payload byte"
    );
    assert!(
        u2c_pkts >= 1,
        "expected at least one u2c packet recorded in sync mode, got {}",
        u2c_pkts
    );
    assert_eq!(
        u2c_bytes, 1,
        "expected exactly one forwarded u2c payload byte"
    );
}

#[test]
fn icmp_sync_keepalive_replies_do_not_prevent_timeout_exit() {
    if crate::orchestrator::platform_requires_raw_privilege_for_any_icmp()
        && !raw_icmp_test_supported()
    {
        return;
    }
    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let mut session = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(2),
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (sync timeout)");

    let payload = b"sync-timeout-check";
    client_sock
        .send(payload)
        .expect("send initial payload to establish lock");

    client_sock
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("set read timeout for sync flow");

    let mut saw_echo = false;
    let mut saw_zero_len_udp_reply = false;

    let recv_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < recv_deadline {
        let mut buf = [0u8; 2048];
        match client_sock.recv(&mut buf) {
            Ok(0) => saw_zero_len_udp_reply = true,
            Ok(n) => {
                if &buf[..n] == payload {
                    saw_echo = true;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => panic!("recv sync flow packet: {e}"),
        }
    }

    assert!(saw_echo, "expected to receive echoed non-empty payload");
    assert!(
        !saw_zero_len_udp_reply,
        "pkthere must never emit zero-length UDP packets"
    );

    let exit_deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        match session.child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= exit_deadline {
                    panic!("forwarder did not exit on timeout while keepalives were active");
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("wait error: {e}"),
        }
    };

    assert!(status.success(), "forwarder did not exit cleanly: {status}");

    let stats = wait_for_stats_json_from(&mut session.out, Duration::from_secs(1))
        .expect("did not see stats JSON line after timeout exit");
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap_or(0);
    assert!(
        c2u_pkts >= 2,
        "expected at least one successful keepalive in addition to initial payload; c2u_pkts={}",
        c2u_pkts,
    );
    assert_eq!(
        c2u_bytes,
        payload.len() as u64,
        "expected keepalives to be zero-length so c2u bytes stay at initial payload size"
    );
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap_or(0);
    assert!(
        u2c_pkts >= 1 && u2c_bytes == payload.len() as u64,
        "u2c bytes should only contain echoed non-empty payload"
    );
}

#[test]
fn zero_len_udp_client_payload_round_trips_over_icmp() {
    if crate::orchestrator::platform_requires_raw_privilege_for_any_icmp()
        && !raw_icmp_test_supported()
    {
        return;
    }
    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let mut session = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder");
    client_sock
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("set read timeout");

    client_sock
        .send(&[])
        .expect("send zero-length UDP payload through ICMP hop");

    let mut buf = [0u8; 32];
    match client_sock.recv(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("expected zero-length UDP echo, got {n} bytes"),
        Err(e) => panic!("unexpected recv error: {e}"),
    }

    let stats = wait_for_stats_json_from(&mut session.out, Duration::from_secs(2))
        .expect("did not see stats JSON line");
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 0);
    assert!(stats["c2u_pkts"].as_u64().unwrap_or(0) >= 1);
    assert!(stats["u2c_pkts"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(stats["c2u_bytes"].as_u64().unwrap_or(0), 0);
    assert_eq!(stats["u2c_bytes"].as_u64().unwrap_or(0), 0);
}

#[test]
fn icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node() {
    if skip_unless_raw_icmp_supported(
        "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node",
    ) {
        return;
    }

    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let (udp_up_addr, _udp_up_thread) = IpFamily::V4
        .spawn_echo()
        .expect("IPv4 loopback upstream bind");
    let icmp_port_2 = random_unprivileged_port(IpFamily::V4).expect("ICMP listen id 2");

    let node3 = try_launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        there: format!("UDP:{udp_up_addr}"),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    })
    .expect("could not launch ICMP endpoint node on raw-capable host");
    let node2 = try_launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: format!(
            "ICMP:{}:{}",
            localhost_addr(IpFamily::V4, 0).ip(),
            icmp_port_2
        ),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
    })
    .expect("could not launch pure ICMP middle node");
    let mut node1 = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: IpFamily::V4.listen_arg().to_string(),
        there: format!(
            "ICMP:{}:{}",
            localhost_addr(IpFamily::V4, 0).ip(),
            icmp_port_2
        ),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
    });
    client_sock
        .connect(node1.listen_addr)
        .expect("connect client to first forwarder");

    // Verify node2 (pure ICMP) uses RAW listener and DGRAM upstream (where supported)
    let mut node2_out = node2.out;
    let stats2 = wait_for_stats_json_from(&mut node2_out, JSON_WAIT_MS).expect("node2 stats");
    assert_eq!(
        stats2["worker_flows"][0]["client_sock_type"], "RAW",
        "middle node listener must be RAW"
    );
    let expected_middle_upstream =
        if crate::orchestrator::platform_requires_raw_privilege_for_any_icmp() {
            "RAW"
        } else {
            "DGRAM"
        };
    assert_eq!(
        stats2["worker_flows"][0]["upstream_sock_type"], expected_middle_upstream,
        "middle node upstream must be {expected_middle_upstream}"
    );

    // Verify node3 (ICMP endpoint) uses RAW listener
    let mut node3_out = node3.out;
    let stats3 = wait_for_stats_json_from(&mut node3_out, JSON_WAIT_MS).expect("node3 stats");
    assert_eq!(
        stats3["worker_flows"][0]["client_sock_type"], "RAW",
        "endpoint node listener must be RAW"
    );

    let payload = b"multihop-icmp-bridge";
    client_sock.send(payload).expect("send multihop payload");
    let mut buf = [0u8; 2048];
    let n = client_sock.recv(&mut buf).expect("recv multihop reply");
    assert_eq!(&buf[..n], payload);

    client_sock
        .send(&[])
        .expect("send zero-length multihop payload");
    let n = client_sock
        .recv(&mut buf)
        .expect("recv multihop zero-length reply");
    assert_eq!(
        n, 0,
        "expected zero-length UDP reply through multihop ICMP bridge"
    );

    client_sock
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set read timeout");
    match client_sock.recv(&mut buf) {
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Ok(n) => panic!("expected no extra keepalive UDP packet, got {n} bytes"),
        Err(e) => panic!("unexpected recv error: {e}"),
    }

    let stats = wait_for_stats_json_from(&mut node1.out, Duration::from_secs(2))
        .expect("did not see stats JSON line");
    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert!(stats["c2u_pkts"].as_u64().unwrap_or(0) >= 2);
    assert!(stats["u2c_pkts"].as_u64().unwrap_or(0) >= 2);
}

#[test]
fn enforce_max_payload_all() {
    for (family, max_payload, recv_buf_len) in [
        (IpFamily::V4, 0usize, 2048usize),
        (IpFamily::V4, 548usize, 2048usize),
        (IpFamily::V6, 1232usize, 4096usize),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            run_enforce_max_payload(case, max_payload, recv_buf_len);
        });
    }
}

fn run_enforce_max_payload(case: MatrixCase<'_>, max_payload: usize, recv_buf_len: usize) {
    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let Some((up_addr, _up_thread)) = spawn_echo_or_skip(case.family) else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: default_test_upstream_arg(case.proto, up_addr),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: Some(max_payload),
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (max payload)");

    let ok = vec![255u8; max_payload];
    client_sock.send(&ok).expect("send max payload");
    let mut buf = vec![0u8; recv_buf_len];
    let _ = client_sock
        .recv(&mut buf)
        .expect("recv from forwarder (max payload)");

    let over = vec![255u8; max_payload + 1];
    client_sock.send(&over).expect("send oversize payload");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout");
    assert!(
        client_sock.recv(&mut buf).is_err(),
        "oversize payload should be dropped"
    );

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn single_client_forwarding_all() {
    for (family, payload) in [
        (IpFamily::V4, b"hello-through-forwarder".as_slice()),
        (IpFamily::V6, b"hello-through-forwarder-v6".as_slice()),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            run_single_client_forwarding(case, payload);
        });
    }
}

fn run_single_client_forwarding(case: MatrixCase<'_>, payload: &[u8]) {
    const COUNT: usize = 5;

    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let client_local = client_sock.local_addr().expect("client local addr");
    let Some((up_addr, _up_thread)) = spawn_echo_or_skip(case.family) else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: default_test_upstream_arg(case.proto, up_addr),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (single client)");

    for _ in 0..COUNT {
        client_sock
            .send(payload)
            .expect("send to forwarder (single client)");
        let mut buf = [0u8; 2048];
        let n = client_sock
            .recv(&mut buf)
            .expect("recv from forwarder (single client)");
        assert_eq!(&buf[..n], payload, "echo payload mismatch");
    }

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().unwrap_or(false));
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), COUNT as u64);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), COUNT as u64);

    let worker = locked_worker_flow(&stats);
    let stats_client = json_addr(&worker["client_addr"]).expect("parse stats client_addr");
    assert_eq!(stats_client, client_local, "stats client_addr mismatch");
    assert_eq!(
        worker["upstream_canonical"].as_str().unwrap_or_default(),
        if case.proto == "ICMP" {
            format!("{}:0", up_addr.ip())
        } else {
            format!("{}:{}", up_addr.ip(), up_addr.port())
        },
        "stats upstream_canonical mismatch"
    );

    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * COUNT as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        payload.len() as u64 * COUNT as u64
    );
    assert_eq!(
        stats["c2u_bytes_max"].as_u64().unwrap_or(0),
        payload.len() as u64
    );
    assert_eq!(
        stats["u2c_bytes_max"].as_u64().unwrap_or(0),
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
fn relock_after_timeout_drop_all() {
    run_matrix_cases(
        &IPV4_ONLY_FAMILIES,
        SUPPORTED_PROTOCOLS,
        &SOCKET_MODES,
        |case| {
            relock_after_timeout_drop_ipv4_case(case);
        },
    );
}

fn relock_after_timeout_drop_ipv4_case(case: MatrixCase<'_>) {
    let client_a = bind_udp_client(IpFamily::V4).expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_client(IpFamily::V4).expect("client_b IPv4 loopback not available");
    let up_addr = spawn_udp_echo_server(IpFamily::V4)
        .expect("IPv4 echo server could not bind")
        .0;
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:{}", localhost_addr(IpFamily::V4, here_port)),
        there: if case.proto == "ICMP" {
            default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip())
        } else {
            format!("{}:{up_addr}", case.proto)
        },
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_a
        .connect(session.listen_addr)
        .expect("connect A -> forwarder");

    let payload_a = b"first-client";
    client_a.send(payload_a).expect("send A");
    let a_locked = wait_for_locked_client_from(&mut session.out, MAX_WAIT_SECS)
        .expect("did not see lock line for client A");
    assert_eq!(
        a_locked,
        client_a.local_addr().expect("client A local addr")
    );

    let mut buf = [0u8; 2048];
    let n = client_a.recv(&mut buf).expect("recv echo A");
    assert_eq!(&buf[..n], payload_a);

    thread::sleep(MAX_WAIT_SECS);
    if let Ok(Some(status)) = session.child.try_wait() {
        panic!("forwarder exited unexpectedly with status: {status}");
    }

    client_b
        .connect(session.listen_addr)
        .expect("connect B -> forwarder");
    let payload_b = b"second-client";
    client_b
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client B");

    let b_locked = send_until_locked(&client_b, payload_b, &mut session.out, 40, CLIENT_WAIT_MS)
        .expect("did not see lock line for client B");
    let client_b_local = client_b.local_addr().expect("client B local addr");
    assert_eq!(
        b_locked, client_b_local,
        "forwarder locked to unexpected client B address"
    );

    let mut got: Option<usize> = None;
    for _ in 0..40 {
        match client_b.recv(&mut buf) {
            Ok(n) => {
                got = Some(n);
                break;
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::ConnectionRefused =>
            {
                let _ = client_b.send(payload_b);
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("recv echo B: {e}"),
        }
    }
    let n = got.expect("did not receive echo from forwarder after re-lock");
    assert_eq!(&buf[..n], payload_b);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    let _ = session.child.kill();

    let stats_client =
        json_addr(&locked_worker_flow(&stats)["client_addr"]).expect("parse stats client_addr");
    assert_eq!(
        stats_client, client_b_local,
        "forwarder did not relock to client B"
    );

    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    assert!(c2u_pkts >= 2 && u2c_pkts >= 2);
}

#[test]
fn timeout_drop_relocks_after_forward_errors_udp() {
    run_matrix_cases(&IPV4_ONLY_FAMILIES, &["UDP"], &SOCKET_MODES, |case| {
        timeout_drop_relocks_after_forward_errors_udp_case(case);
    });
}

fn timeout_drop_relocks_after_forward_errors_udp_case(case: MatrixCase<'_>) {
    let client_a = bind_udp_client(IpFamily::V4).expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_client(IpFamily::V4).expect("client_b IPv4 loopback not available");
    let dead_upstream_port = random_unprivileged_port(IpFamily::V4).expect("dead upstream port");
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:{}", localhost_addr(IpFamily::V4, here_port)),
        there: format!("UDP:{}", localhost_addr(IpFamily::V4, dead_upstream_port)),
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_a
        .connect(session.listen_addr)
        .expect("connect A -> forwarder");
    client_a
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout on client A");

    let payload_a = b"forward-error-client-a";
    client_a.send(payload_a).expect("send A");
    let a_locked = wait_for_locked_client_from(&mut session.out, MAX_WAIT_SECS)
        .expect("did not see lock line for client A");
    assert_eq!(
        a_locked,
        client_a.local_addr().expect("client A local addr")
    );

    expect_no_echo(&client_a, &mut [0u8; 256]);

    let stats = wait_for_stats_matching(&mut session.out, MAX_WAIT_SECS, |candidate| {
        candidate["locked"].as_bool().unwrap_or(false)
            && candidate["u2c_errs"].as_u64().unwrap_or(0) > 0
    })
    .expect("did not see forwarding errors in stats JSON");
    assert_eq!(
        json_addr(&locked_worker_flow(&stats)["client_addr"]).expect("stats client addr"),
        client_a.local_addr().expect("client A local addr")
    );

    thread::sleep(MAX_WAIT_SECS);
    if let Ok(Some(status)) = session.child.try_wait() {
        panic!("forwarder exited unexpectedly with status: {status}");
    }

    client_b
        .connect(session.listen_addr)
        .expect("connect B -> forwarder");
    let payload_b = b"forward-error-client-b";
    let b_locked = send_until_locked(&client_b, payload_b, &mut session.out, 40, CLIENT_WAIT_MS)
        .expect("did not see lock line for client B");
    assert_eq!(
        b_locked,
        client_b.local_addr().expect("client B local addr")
    );
}
