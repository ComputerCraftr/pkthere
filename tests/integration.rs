#![allow(clippy::duplicate_mod, clippy::expect_fun_call)]

#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;
#[path = "common/socket_matrix.rs"]
mod socket_matrix;
#[path = "common/worker_flow.rs"]
mod worker_flow;
use crate::core::wait_for_stats_json_from;
use crate::orchestrator::{
    ALL_CONNECT_MODES, ALL_SUPPORTED_PROTOCOLS, CLIENT_WAIT_MS, DRAIN_WAIT_MS, ForwarderConfig,
    IPV4_ONLY_FAMILIES, IpFamily, JSON_WAIT_MS, MAX_WAIT_SECS, MatrixCase, OutputCapture,
    bind_client_or_skip, bind_udp_client, expect_no_echo, expect_session_stats_matching, json_addr,
    launch_forwarder, localhost_addr, random_unprivileged_port, render_canonical_ip_id,
    run_matrix_cases, send_until_locked, spawn_upstream_echo_or_skip, wait_for_child_exit_success,
    wait_for_locked_client_from,
};
use crate::socket_matrix::assert_socket_matrix_state;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

const LEGIT_PAYLOAD_1: &[u8] = b"legit-payload-1";
const LEGIT_PAYLOAD_2: &[u8] = b"legit-payload-2";
const WRONG_CLIENT_PEER_PAYLOAD: &[u8] = b"wrong-client-peer";
const WRONG_UPSTREAM_PEER_PAYLOAD: &[u8] = b"wrong-upstream-peer";

#[derive(Clone, Copy, Debug)]
enum UnconnectedWrongPeerRole {
    ClientSide,
    UpstreamSide,
}

fn panic_with_session_context(context: &str, session: &crate::orchestrator::ForwarderSession) -> ! {
    let (stdout, stderr) = crate::orchestrator::snapshot_forwarder_output_tail(session, 20)
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
    case: MatrixCase<'_>,
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

#[test]
fn enforce_max_payload() {
    for (family, max_payload, recv_buf_len) in [
        (IpFamily::V4, 0usize, 2048usize),
        (IpFamily::V4, 548usize, 2048usize),
        (IpFamily::V6, 1232usize, 4096usize),
    ] {
        run_matrix_cases(
            &[family],
            ALL_SUPPORTED_PROTOCOLS,
            &ALL_CONNECT_MODES,
            &ALL_CONNECT_MODES,
            |case| {
                enforce_max_payload_case(case, max_payload, recv_buf_len);
            },
        );
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        here: case.family.listen_arg().to_string(),
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: Some(1),
        max_payload: Some(max_payload),
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
    });

    client_sock.connect(session.listen_addr).expect(&format!(
        "connect to {} forwarder (max payload)",
        case.proto
    ));

    let ok = vec![255u8; max_payload];
    client_sock.send(&ok).expect("send max payload");
    let mut buf = vec![0u8; recv_buf_len];
    let case_desc = format!("{case:?} max_payload={max_payload}");
    recv_legitimate_echo_with_retry(&client_sock, &ok, &mut buf, &case_desc, "max payload echo");

    // Drain any delayed packets before testing the drop, especially for empty payloads
    client_sock
        .set_read_timeout(Some(DRAIN_WAIT_MS))
        .expect("set drain timeout");
    while client_sock.recv(&mut buf).is_ok() {}

    let over = vec![255u8; max_payload + 1];
    client_sock.send(&over).expect("send oversize payload");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
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
        stats["c2u_drops_oversize"]
            .as_u64()
            .expect("missing c2u_drops_oversize")
            >= 1,
        "expected at least one oversize drop, got {}",
        stats["c2u_drops_oversize"]
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
        (IpFamily::V4, b"hello-through-forwarder".as_slice()),
        (IpFamily::V6, b"hello-through-forwarder-v6".as_slice()),
    ] {
        run_matrix_cases(
            &[family],
            ALL_SUPPORTED_PROTOCOLS,
            &ALL_CONNECT_MODES,
            &ALL_CONNECT_MODES,
            |case| {
                single_client_forwarding_case(case, payload);
            },
        );
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        here: case.family.listen_arg().to_string(),
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: Some(1),
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
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
        let case_desc = format!("{case:?}");
        let n = recv_legitimate_echo_with_retry(
            &client_sock,
            payload,
            &mut buf,
            &case_desc,
            "single-client echo",
        );
        assert_eq!(&buf[..n], payload, "echo payload mismatch");
    }

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    assert!(stats["uptime_s"].is_number());
    assert!(stats["locked"].as_bool().expect("missing locked field"));
    let worker = worker_flow::locked_worker_flow(&stats);

    let case_desc = format!("{case:?}");
    assert_socket_matrix_state(worker, case, "exit", &case_desc);

    assert_eq!(
        stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"),
        COUNT as u64
    );
    assert_eq!(
        stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"),
        COUNT as u64
    );

    let stats_client =
        json_addr(&worker["client_remote_canonical"]).expect("parse stats client_remote_canonical");
    assert_eq!(stats_client, client_local, "stats client_remote mismatch");
    let actual_upstream = worker["upstream_remote_filter_canonical"]
        .as_str()
        .unwrap_or_default();
    if case.proto.eq_ignore_ascii_case("icmp") {
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
        payload.len() as u64 * COUNT as u64
    );
    assert_eq!(
        stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"),
        payload.len() as u64 * COUNT as u64
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
fn relock_after_timeout_drop_ipv4() {
    run_matrix_cases(
        &IPV4_ONLY_FAMILIES,
        ALL_SUPPORTED_PROTOCOLS,
        &ALL_CONNECT_MODES,
        &[false],
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
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        here: format!("UDP:{}", localhost_addr(IpFamily::V4, here_port)),
        there: there_arg,
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
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
                client_b
                    .send(payload_b)
                    .expect("re-send payload B after transient recv error");
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
    drop(session.child.kill());

    let stats_client =
        json_addr(&worker_flow::locked_worker_flow(&stats)["client_remote_canonical"])
            .expect("parse stats client_remote_canonical");
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
    run_matrix_cases(
        &IPV4_ONLY_FAMILIES,
        &["UDP"],
        &ALL_CONNECT_MODES,
        &[false],
        |case| {
            timeout_drop_relocks_after_forward_errors_udp_ipv4_case(case);
        },
    );
}

fn timeout_drop_relocks_after_forward_errors_udp_ipv4_case(case: MatrixCase<'_>) {
    let client_a = bind_udp_client(IpFamily::V4).expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_client(IpFamily::V4).expect("client_b IPv4 loopback not available");
    let dead_upstream_port = random_unprivileged_port(IpFamily::V4).expect("dead upstream port");
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        here: format!("UDP:{}", localhost_addr(IpFamily::V4, here_port)),
        there: format!("UDP:{}", localhost_addr(IpFamily::V4, dead_upstream_port)),
        timeout_action: "drop",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
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

    let stats = expect_session_stats_matching(
        &mut session,
        MAX_WAIT_SECS,
        "did not see forwarding errors in stats JSON",
        |candidate| {
            candidate["locked"].as_bool().unwrap_or(false)
                && candidate["u2c_errs"].as_u64().unwrap_or(0) > 0
        },
    );
    assert_eq!(
        json_addr(&worker_flow::locked_worker_flow(&stats)["client_remote_canonical"])
            .expect("stats client remote"),
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
fn unconnected_udp_rejects_wrong_peer_and_only_forwards_legitimate_traffic() {
    run_matrix_cases(
        &[IpFamily::V4, IpFamily::V6],
        &["UDP"],
        &[true],
        &[false],
        |case| {
            unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::ClientSide, case);
        },
    );
    run_matrix_cases(&[IpFamily::V4], &["UDP"], &[false], &[true], |case| {
        unconnected_udp_wrong_peer_case(UnconnectedWrongPeerRole::UpstreamSide, case);
    });
}

fn unconnected_udp_wrong_peer_case(role: UnconnectedWrongPeerRole, case: MatrixCase<'_>) {
    let case_desc = describe_unconnected_wrong_peer_case(role, case);
    let client_primary =
        bind_udp_client(case.family).expect("primary client loopback not available");
    let client_secondary =
        bind_udp_client(case.family).expect("secondary client/stray loopback not available");
    let Some((there_arg, _up_addr, _up_thread)) =
        spawn_upstream_echo_or_skip(case.family, case.proto)
    else {
        return;
    };

    let here = match role {
        UnconnectedWrongPeerRole::ClientSide => {
            let here_port = random_unprivileged_port(case.family).expect("ephemeral listen port");
            format!("UDP:{}", localhost_addr(case.family, here_port))
        }
        UnconnectedWrongPeerRole::UpstreamSide => case.family.listen_arg().to_string(),
    };

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: case.debug_client_unconnected,
        debug_upstream_unconnected: case.debug_upstream_unconnected,
        here,
        there: there_arg,
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
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
        recv_legitimate_echo_with_retry(&client_primary, payload_1, &mut buf, &case_desc, "echo 1");
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
                .set_read_timeout(Some(CLIENT_WAIT_MS))
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
        }
        UnconnectedWrongPeerRole::UpstreamSide => {
            let stats = expect_session_stats_matching(
                &mut session,
                MAX_WAIT_SECS,
                &format!("{case_desc}: did not see locked stats for unconnected wrong-peer test"),
                |stats| {
                    stats["locked"].as_bool().unwrap_or(false)
                        && stats["c2u_pkts"].as_u64().unwrap_or(0) >= 1
                        && stats["u2c_pkts"].as_u64().unwrap_or(0) >= 1
                },
            );
            let worker = worker_flow::locked_worker_flow(&stats);
            let upstream_local = routable_loopback_for_wildcard_bind(
                json_addr(&worker["upstream_local_kernel_canonical"])
                    .expect("parse stats upstream_local_kernel_canonical"),
            );
            client_secondary
                .send_to(WRONG_UPSTREAM_PEER_PAYLOAD, upstream_local)
                .unwrap_or_else(|e| panic!("{case_desc}: send stray upstream packet: {e}"));
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
        recv_legitimate_echo_with_retry(&client_primary, payload_2, &mut buf, &case_desc, "echo 2");
    assert_eq!(
        &buf[..n],
        payload_2,
        "{case_desc}: second legitimate payload did not round-trip"
    );

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS)
        .unwrap_or_else(|| panic!("{case_desc}: node1 stats missing"));
    assert_eq!(
        stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"),
        2,
        "{case_desc}: expected exactly 2 c2u packets from legitimate traffic only, got {}",
        stats["c2u_pkts"]
    );
    assert_eq!(
        stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"),
        2,
        "{case_desc}: expected exactly 2 u2c packets from legitimate traffic only, got {}",
        stats["u2c_pkts"]
    );

    let worker = worker_flow::locked_worker_flow(&stats);
    assert_socket_matrix_state(worker, case, "exit", &case_desc);
}

fn recv_legitimate_echo_with_retry(
    client: &std::net::UdpSocket,
    payload: &[u8],
    buf: &mut [u8],
    case_desc: &str,
    label: &str,
) -> usize {
    let mut got = None;
    for _ in 0..40 {
        match client.recv(buf) {
            Ok(n) => {
                got = Some(n);
                break;
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::ConnectionRefused =>
            {
                client
                    .send(payload)
                    .expect("re-send payload after transient UDP recv error");
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("{case_desc}: recv {label}: {e}"),
        }
    }
    got.unwrap_or_else(|| {
        panic!(
            "{case_desc}: did not receive {label} within {:?} after retrying transient UDP errors",
            CLIENT_WAIT_MS * 2
        )
    })
}
