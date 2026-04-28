#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;
use crate::core::wait_for_stats_json_from;
use crate::orchestrator::{
    CLIENT_WAIT_MS, ForwarderConfig, IPV4_ONLY_FAMILIES, IpFamily, JSON_WAIT_MS, MAX_WAIT_SECS,
    MatrixCase, NODE1_IPV4_STR, NODE2_IPV4_STR, NODE3_IPV4, SOCKET_MODES, SUPPORTED_PROTOCOLS,
    bind_client_or_skip, bind_udp_client, default_test_icmp_upstream_arg, expect_no_echo,
    json_addr, launch_forwarder, localhost_addr, random_unprivileged_port, run_matrix_cases,
    send_until_locked, spawn_upstream_echo_or_skip, try_launch_forwarder,
    wait_for_child_exit_success, wait_for_locked_client_from, wait_for_stats_matching,
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
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn icmp_sync_mode_forwards_payload_and_tracks_bytes() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

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
        .expect("connect to ICMP forwarder (sync keepalive)");

    client_sock
        .send(b"x")
        .expect("send initial payload to establish lock");
    let mut buf = [0u8; 2048];
    let n = client_sock
        .recv(&mut buf)
        .expect("recv initial sync reply from ICMP forwarder");
    assert!(n >= 1, "expected at least 1-byte echoed payload, got {}", n);
    assert_eq!(&buf[..n], b"x", "expected exact echoed payload");

    let stats = wait_for_stats_json_from(&mut session.out, Duration::from_secs(2))
        .expect("did not see expected stats JSON line");

    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap_or(0);
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap_or(0);
    assert_eq!(
        c2u_pkts, 1,
        "expected exactly one c2u packet recorded in sync mode, got {}",
        c2u_pkts
    );
    assert_eq!(
        c2u_bytes, 1,
        "expected exactly one forwarded c2u payload byte, got {}",
        c2u_bytes
    );
    assert_eq!(
        u2c_pkts, 1,
        "expected exactly one u2c packet recorded in sync mode, got {}",
        u2c_pkts
    );
    assert_eq!(
        u2c_bytes, 1,
        "expected exactly one forwarded u2c payload byte, got {}",
        u2c_bytes
    );
}

#[test]
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn icmp_sync_keepalive_replies_do_not_prevent_timeout_exit() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

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
        .expect("connect to ICMP forwarder (sync timeout)");

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
    assert_eq!(
        c2u_pkts, 1,
        "expected exactly one user packet; c2u_pkts={}",
        c2u_pkts,
    );
    assert_eq!(
        c2u_bytes,
        payload.len() as u64,
        "expected exactly one user payload size, got {}",
        c2u_bytes
    );
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap_or(0);
    assert_eq!(
        u2c_pkts, 1,
        "expected exactly one user reply packet; u2c_pkts={}",
        u2c_pkts
    );
    assert_eq!(
        u2c_bytes,
        payload.len() as u64,
        "u2c bytes should exactly match echoed payload"
    );
}

#[test]
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn zero_len_udp_client_payload_round_trips_over_icmp() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

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
        .expect("connect to ICMP forwarder");
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
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), 1);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), 1);
    assert_eq!(stats["c2u_bytes"].as_u64().unwrap_or(0), 0);
    assert_eq!(stats["u2c_bytes"].as_u64().unwrap_or(0), 0);
}

#[test]
#[cfg_attr(
    not(supports_raw_icmp_capability),
    ignore = "raw ICMP tests require build-time ICMP support or PKTHERE_ALLOW_RAW_ICMP=1"
)]
fn icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node() {
    crate::orchestrator::require_raw_icmp_supported()
        .expect("ICMP multihop test was enabled, but runtime raw ICMP capability is missing");

    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let (udp_up_addr, _udp_up_thread) = IpFamily::V4
        .spawn_echo()
        .expect("IPv4 loopback upstream bind");
    let icmp_port_2 = random_unprivileged_port(IpFamily::V4).expect("ICMP listen id 2");

    let node3_ip = NODE3_IPV4;
    let node3 = try_launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: default_test_icmp_upstream_arg(node3_ip.into()),
        there: format!("UDP:{udp_up_addr}"),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    })
    .expect("could not launch ICMP endpoint node on raw-capable host");

    let node2_ip = NODE2_IPV4_STR;
    let node2 = try_launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: format!("ICMP:{node2_ip}:{icmp_port_2}"),
        there: default_test_icmp_upstream_arg(node3_ip.into()),
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
        there: format!("ICMP:{node2_ip}:{icmp_port_2}"),
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
    let expected_middle_upstream = if crate::orchestrator::platform_supports_dgram_icmp() {
        "DGRAM"
    } else {
        "RAW"
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
        .expect("did not see expected stats JSON line");

    assert_eq!(
        stats["c2u_bytes"].as_u64().unwrap_or(0),
        (2 * payload.len()) as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().unwrap_or(0),
        (2 * payload.len()) as u64
    );
    assert_eq!(stats["c2u_pkts"].as_u64().unwrap_or(0), 2);
    assert_eq!(stats["u2c_pkts"].as_u64().unwrap_or(0), 2);
}

#[test]
fn enforce_max_payload() {
    for (family, max_payload, recv_buf_len) in [
        (IpFamily::V4, 0usize, 2048usize),
        (IpFamily::V4, 548usize, 2048usize),
        (IpFamily::V6, 1232usize, 4096usize),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            enforce_max_payload_case(case, max_payload, recv_buf_len);
        });
    }
}

fn enforce_max_payload_case(case: MatrixCase<'_>, max_payload: usize, recv_buf_len: usize) {
    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let Some((there_arg, _up_addr, _up_thread)) =
        spawn_upstream_echo_or_skip(case.family, case.proto)
    else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: Some(max_payload),
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_sock.connect(session.listen_addr).expect(&format!(
        "connect to {} forwarder (max payload)",
        case.proto
    ));

    let ok = vec![255u8; max_payload];
    client_sock.send(&ok).expect("send max payload");
    let mut buf = vec![0u8; recv_buf_len];
    let _ = client_sock
        .recv(&mut buf)
        .expect(&format!("recv from {} forwarder (max payload)", case.proto));

    // Drain any delayed packets before testing the drop, especially for empty payloads
    client_sock
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set drain timeout");
    while client_sock.recv(&mut buf).is_ok() {}

    let over = vec![255u8; max_payload + 1];
    client_sock.send(&over).expect("send oversize payload");
    client_sock
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .expect("set read timeout");

    // On some platforms (like macOS), we might still see a delayed packet from a previous send
    // or an empty packet if the socket state changes. We retry a few times to ensure it's truly blocked.
    let mut success = false;
    for _ in 0..3 {
        match client_sock.recv(&mut buf) {
            Ok(n) => {
                eprintln!(
                    "Received unexpected {} bytes when expecting drop: {:?}",
                    n,
                    &buf[..n]
                );
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                success = true;
                break;
            }
            Err(e) => panic!("unexpected error while waiting for drop: {e}"),
        }
    }
    assert!(
        success,
        "oversize payload ({} bytes) should be dropped and result in timeout",
        over.len()
    );

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    assert!(
        stats["c2u_drops_oversize"].as_u64().unwrap_or(0) >= 1,
        "expected at least one oversize drop, got {}",
        stats["c2u_drops_oversize"]
    );
}

#[test]
fn single_client_forwarding() {
    for (family, payload) in [
        (IpFamily::V4, b"hello-through-forwarder".as_slice()),
        (IpFamily::V6, b"hello-through-forwarder-v6".as_slice()),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            single_client_forwarding_case(case, payload);
        });
    }
}

fn single_client_forwarding_case(case: MatrixCase<'_>, payload: &[u8]) {
    const COUNT: usize = 5;

    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let client_local = client_sock.local_addr().expect("client local addr");
    let Some((there_arg, up_addr, _up_thread)) =
        spawn_upstream_echo_or_skip(case.family, case.proto)
    else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_sock.connect(session.listen_addr).expect(&format!(
        "connect to {} forwarder (single client)",
        case.proto
    ));

    for _ in 0..COUNT {
        client_sock
            .send(payload)
            .expect(&format!("send to {} forwarder (single client)", case.proto));
        let mut buf = [0u8; 2048];
        let n = client_sock.recv(&mut buf).expect(&format!(
            "recv from {} forwarder (single client)",
            case.proto
        ));
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
    let actual_upstream = worker["upstream_canonical"].as_str().unwrap_or_default();
    if case.proto.eq_ignore_ascii_case("icmp") {
        // Accept either the requested :0 or the realized ID (now that we discover it)
        assert!(
            actual_upstream == format!("{}:0", up_addr.ip()) || !actual_upstream.ends_with(":0"),
            "stats upstream_canonical mismatch for ICMP: expected IP:0 or IP:real_id, got {}",
            actual_upstream
        );
        assert!(actual_upstream.starts_with(&up_addr.ip().to_string()));
    } else {
        assert_eq!(
            actual_upstream,
            format!("{}:{}", up_addr.ip(), up_addr.port()),
            "stats upstream_canonical mismatch"
        );
    }

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
fn relock_after_timeout_drop_ipv4() {
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
    let Some((there_arg, _up_addr, _up_thread)) =
        spawn_upstream_echo_or_skip(case.family, case.proto)
    else {
        return;
    };
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:{}", localhost_addr(IpFamily::V4, here_port)),
        there: there_arg,
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
    let n = got.expect(&format!(
        "did not receive echo from {} forwarder after re-lock",
        case.proto
    ));
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
    assert_eq!(c2u_pkts, 2);
    assert_eq!(u2c_pkts, 2);
}

#[test]
fn timeout_drop_relocks_after_forward_errors_udp_ipv4() {
    run_matrix_cases(&IPV4_ONLY_FAMILIES, &["UDP"], &SOCKET_MODES, |case| {
        timeout_drop_relocks_after_forward_errors_udp_ipv4_case(case);
    });
}

fn timeout_drop_relocks_after_forward_errors_udp_ipv4_case(case: MatrixCase<'_>) {
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

#[test]
fn unconnected_udp_listener_rejects_payloads_from_wrong_port() {
    run_matrix_cases(
        &[IpFamily::V4, IpFamily::V6],
        &["UDP"],
        &[crate::orchestrator::SocketMode::Unconnected],
        |case| {
            unconnected_udp_listener_rejects_payloads_from_wrong_port_case(case);
        },
    );
}

fn unconnected_udp_listener_rejects_payloads_from_wrong_port_case(case: MatrixCase<'_>) {
    let client_a = bind_udp_client(case.family).expect("client_a loopback not available");
    let client_b = bind_udp_client(case.family).expect("client_b loopback not available");
    let Some((there_arg, _up_addr, _up_thread)) =
        spawn_upstream_echo_or_skip(case.family, case.proto)
    else {
        return;
    };
    let here_port = random_unprivileged_port(case.family).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:{}", localhost_addr(case.family, here_port)),
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_a
        .connect(session.listen_addr)
        .expect("connect A -> forwarder");
    client_b
        .connect(session.listen_addr)
        .expect("connect B -> forwarder");

    // 1. Lock to client A
    let payload_a = b"client-a-payload";
    client_a.send(payload_a).expect("send A");
    let a_locked = wait_for_locked_client_from(&mut session.out, MAX_WAIT_SECS)
        .expect("did not see lock line for client A");
    assert_eq!(
        a_locked,
        client_a.local_addr().expect("client A local addr")
    );

    // Ensure A receives echo
    let mut buf = [0u8; 2048];
    let n = client_a.recv(&mut buf).expect("recv echo A");
    assert_eq!(&buf[..n], payload_a);

    // 2. Client B sends payload.
    // Since forwarder is in Unconnected mode, it will receive B's packet via recv_from.
    // It should manually drop it because it is locked to A.
    let payload_b = b"client-b-imposter";
    client_b.send(payload_b).expect("send B");

    // Verify B does not receive echo (timeout)
    client_b
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set timeout B");
    assert!(
        client_b.recv(&mut buf).is_err(),
        "imposter client B should not receive echo"
    );

    // 3. Client A sends another payload and receives echo
    let payload_a_2 = b"client-a-payload-2";
    client_a.send(payload_a_2).expect("send A 2");
    let n = client_a.recv(&mut buf).expect("recv echo A 2");
    assert_eq!(&buf[..n], payload_a_2);

    // Shutdown and check stats
    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect("node1 stats");

    // c2u_pkts should be 2 (only client_a's 2 packets forwarded).
    // client_b's packet should have been dropped by the manual flow key check.
    assert_eq!(
        stats["c2u_pkts"].as_u64().unwrap_or(0),
        2,
        "only client A's packets should be forwarded, expected exactly 2, got {}",
        stats["c2u_pkts"]
    );
}

#[test]
#[cfg_attr(
    not(supports_raw_icmp_capability),
    ignore = "raw ICMP tests require build-time ICMP support or PKTHERE_ALLOW_RAW_ICMP=1"
)]
fn test_raw_icmp_independent_ids() {
    crate::orchestrator::require_raw_icmp_supported()
        .expect("RAW ICMP test was enabled, but runtime support is missing");

    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback client bind");
    let (udp_up_addr, _udp_up_thread) = IpFamily::V4
        .spawn_echo()
        .expect("IPv4 loopback upstream bind");

    let addr_a = NODE1_IPV4_STR;
    let addr_b = NODE2_IPV4_STR;
    let id_a = 1001;
    let id_b = 2002;

    // Node C: ICMP:1001 -> UDP:Echo (on addr_a)
    let _node_c = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: format!("ICMP:{}:{}", addr_a, id_a),
        there: format!("UDP:{}", udp_up_addr),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    // Node B: ICMP:2002 -> ICMP:1001 (to Node C) (on addr_b)
    let mut node_b = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: format!("ICMP:{}:{}", addr_b, id_b),
        there: format!("ICMP:{}:{}", addr_a, id_a),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    // Node A: UDP -> ICMP:2002 (to Node B)
    let node_a = launch_forwarder(ForwarderConfig {
        mode: crate::orchestrator::SocketMode::Connected,
        here: IpFamily::V4.listen_arg().to_string(),
        there: format!("ICMP:{}:{}", addr_b, id_b),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
    });

    client_sock
        .connect(node_a.listen_addr)
        .expect("connect client to A");

    let payload = b"independent-icmp-ids";
    client_sock.send(payload).expect("send payload");

    let mut buf = [0u8; 2048];
    let n = client_sock
        .recv(&mut buf)
        .expect("recv reply through 3-hop ICMP chain");
    assert_eq!(&buf[..n], payload);

    // Verify Node B used the independent IDs correctly in its stats
    let stats_b = wait_for_stats_matching(&mut node_b.out, Duration::from_secs(5), |s| {
        s["c2u_pkts"].as_u64().unwrap_or(0) == 1
    })
    .expect("did not see stats for node B");

    let worker_b = locked_worker_flow(&stats_b);
    let client_addr_b = worker_b["client_addr"].as_str().expect("client_addr");
    let upstream_canonical_b = worker_b["upstream_canonical"]
        .as_str()
        .expect("upstream_canonical");

    assert!(
        client_addr_b.contains(&id_b.to_string()),
        "node B client_addr {} should contain id {}",
        client_addr_b,
        id_b
    );
    assert!(
        upstream_canonical_b.contains(&id_a.to_string()),
        "node B upstream_canonical {} should contain id {}",
        upstream_canonical_b,
        id_a
    );
}
