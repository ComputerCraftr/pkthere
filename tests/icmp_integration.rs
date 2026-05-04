#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;
#[path = "common/worker_flow.rs"]
mod worker_flow;

use crate::core::wait_for_stats_json_from;
use crate::orchestrator::{
    CLIENT_WAIT_MS, ForwarderConfig, IpFamily, JSON_WAIT_MS, NODE1_IPV4_STR, NODE2_IPV4,
    NODE2_IPV4_STR, NODE3_IPV4, OutputCapture, bind_udp_client, default_test_icmp_upstream_arg,
    ensure_loopback_ip, expect_session_stats_matching, launch_forwarder, localhost_addr,
    random_unprivileged_port, render_icmp_arg, render_icmp_arg_with_local, try_launch_forwarder,
};

use std::io::ErrorKind;
use std::time::{Duration, Instant};

const IPV4_CLIENT_BIND_ERR: &str = "IPv4 loopback client bind";
const IPV4_UPSTREAM_BIND_ERR: &str = "IPv4 loopback upstream bind";
const ICMP_LISTEN_ID_ERR: &str = "ICMP listen id 2";
const ICMP_ENDPOINT_NODE_ERR: &str = "could not launch ICMP endpoint node on raw-capable host";
const ICMP_MIDDLE_NODE_ERR: &str = "could not launch pure ICMP middle node";
const MULTIHOP_PAYLOAD: &[u8] = b"multihop-icmp-bridge";
const INDEPENDENT_IDS_PAYLOAD: &[u8] = b"independent-icmp-ids";
const DEBUG_TRACE_LOGS: &[&str] = &["packets", "drops", "handles"];

fn bind_ipv4_client() -> std::net::UdpSocket {
    bind_udp_client(IpFamily::V4).expect(IPV4_CLIENT_BIND_ERR)
}

fn spawn_ipv4_udp_echo() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    IpFamily::V4.spawn_echo().expect(IPV4_UPSTREAM_BIND_ERR)
}

fn random_icmp_listen_id() -> u16 {
    random_unprivileged_port(IpFamily::V4).expect(ICMP_LISTEN_ID_ERR)
}

fn ensure_multihop_ips() {
    ensure_loopback_ip(NODE2_IPV4);
    ensure_loopback_ip(NODE3_IPV4);
}

fn launch_icmp_endpoint_node(
    node3_ip: std::net::Ipv4Addr,
    udp_up_addr: std::net::SocketAddr,
    timeout_secs: u64,
    debug_logs: &[&str],
    capture_stderr: bool,
    capture_mode: OutputCapture,
) -> crate::orchestrator::ForwarderSession {
    try_launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: default_test_icmp_upstream_arg(std::net::IpAddr::V4(node3_ip)),
        there: format!("UDP:{udp_up_addr}"),
        timeout_action: "exit",
        timeout_secs: Some(timeout_secs),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs,
        capture_stderr,
        capture_mode,
    })
    .expect(ICMP_ENDPOINT_NODE_ERR)
}

fn launch_icmp_middle_node(
    node2_ip: &str,
    icmp_port_2: u16,
    node3_ip: std::net::Ipv4Addr,
    timeout_secs: u64,
    icmp_sync_pps: u32,
    debug_logs: &[&str],
    capture_stderr: bool,
    capture_mode: OutputCapture,
) -> crate::orchestrator::ForwarderSession {
    try_launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: format!("ICMP:{node2_ip}:{icmp_port_2}"),
        there: default_test_icmp_upstream_arg(std::net::IpAddr::V4(node3_ip)),
        timeout_action: "exit",
        timeout_secs: Some(timeout_secs),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(icmp_sync_pps),
        debug_logs,
        capture_stderr,
        capture_mode,
    })
    .expect(ICMP_MIDDLE_NODE_ERR)
}

fn finalize_debug_forwarder_output(
    name: &str,
    session: &mut crate::orchestrator::ForwarderSession,
) -> (String, String) {
    let give_up = Instant::now() + Duration::from_secs(10);
    while Instant::now() < give_up {
        match session.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error for {name}: {e}"),
        }
    }

    if session
        .child
        .try_wait()
        .expect("wait error while finalizing debug forwarder")
        .is_none()
    {
        crate::orchestrator::terminate_forwarder(session);
    }

    crate::orchestrator::collect_forwarder_output(session).unwrap_or_else(|e| {
        let snapshot = crate::orchestrator::snapshot_forwarder_output(session).unwrap_or_else(|_| {
            (
                format!("<failed to collect stdout for {name}: {e}>"),
                String::new(),
            )
        });
        panic!(
            "failed to collect {name} output cleanly: {e}\n=== partial stdout ===\n{}\n=== partial stderr ===\n{}",
            snapshot.0, snapshot.1
        );
    })
}

#[test]
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn icmp_sync_mode_forwards_payload_and_tracks_bytes() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
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

    assert_eq!(stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"), 1);
    assert_eq!(stats["c2u_bytes"].as_u64().expect("missing c2u_bytes"), 1);
    assert_eq!(stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"), 1);
    assert_eq!(stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"), 1);
}

#[test]
#[cfg_attr(
    not(supports_kernel_icmp_echo),
    ignore = "kernel ICMP echo tests require build-time ICMP support or PKTHERE_ALLOW_KERNEL_ICMP_ECHO=1"
)]
fn icmp_sync_keepalive_replies_do_not_prevent_timeout_exit() {
    crate::orchestrator::require_kernel_echo_reply_supported()
        .expect("ICMP test was enabled, but runtime ICMP support is missing");

    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(2),
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to ICMP forwarder (sync timeout)");

    let payload = b"sync-timeout-check";
    client_sock
        .send(payload)
        .expect("send initial payload to establish lock");

    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
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
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("wait error: {e}"),
        }
    };

    assert!(status.success(), "forwarder did not exit cleanly: {status}");

    let stats = wait_for_stats_json_from(&mut session.out, Duration::from_secs(1))
        .expect("did not see stats JSON line after timeout exit");
    assert_eq!(stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"), 1);
    assert_eq!(
        stats["c2u_bytes"].as_u64().expect("missing c2u_bytes"),
        payload.len() as u64
    );
    assert_eq!(stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"), 1);
    assert_eq!(
        stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"),
        payload.len() as u64
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

    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: default_test_icmp_upstream_arg(localhost_addr(IpFamily::V4, 0).ip()),
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
    client_sock
        .connect(session.listen_addr)
        .expect("connect to ICMP forwarder");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
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
    assert_eq!(
        stats["c2u_drops_oversize"]
            .as_u64()
            .expect("missing c2u_drops_oversize"),
        0
    );
    assert_eq!(stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"), 1);
    assert_eq!(stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"), 1);
    assert_eq!(stats["c2u_bytes"].as_u64().expect("missing c2u_bytes"), 0);
    assert_eq!(stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"), 0);
}

#[test]
#[cfg_attr(
    not(supports_raw_icmp_capability),
    ignore = "raw ICMP tests require build-time ICMP support or PKTHERE_ALLOW_RAW_ICMP=1"
)]
fn icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node() {
    crate::orchestrator::require_raw_icmp_supported()
        .expect("ICMP multihop test was enabled, but runtime raw ICMP capability is missing");

    ensure_multihop_ips();

    let client_sock = bind_ipv4_client();
    let (udp_up_addr, _udp_up_thread) = spawn_ipv4_udp_echo();
    let icmp_port_2 = random_icmp_listen_id();

    let node3_ip = NODE3_IPV4;
    let mut node3 =
        launch_icmp_endpoint_node(node3_ip, udp_up_addr, 10, &[], false, OutputCapture::Direct);

    let node2_ip = NODE2_IPV4_STR;
    let mut node2 = launch_icmp_middle_node(
        node2_ip,
        icmp_port_2,
        node3_ip,
        10,
        5,
        &[],
        false,
        OutputCapture::Direct,
    );

    let mut node1 = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: format!("ICMP:{node2_ip}:{icmp_port_2}"),
        timeout_action: "exit",
        timeout_secs: Some(10),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
        debug_logs: &[],
        capture_stderr: false,
        capture_mode: OutputCapture::Direct,
    });
    client_sock
        .connect(node1.listen_addr)
        .expect("connect client to first forwarder");

    let stats2 = wait_for_stats_json_from(&mut node2.out, JSON_WAIT_MS).expect("node2 stats");
    assert_eq!(stats2["worker_flows"][0]["client_sock_type"], "RAW");
    let expected_middle_upstream = if crate::orchestrator::platform_supports_dgram_icmp() {
        "DGRAM"
    } else {
        "RAW"
    };
    assert_eq!(
        stats2["worker_flows"][0]["upstream_sock_type"],
        expected_middle_upstream
    );

    let stats3 = wait_for_stats_json_from(&mut node3.out, JSON_WAIT_MS).expect("node3 stats");
    assert_eq!(stats3["worker_flows"][0]["client_sock_type"], "RAW");

    let payload = MULTIHOP_PAYLOAD;
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
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout");
    match client_sock.recv(&mut buf) {
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Ok(n) => panic!("expected no extra keepalive UDP packet, got {n} bytes"),
        Err(e) => panic!("unexpected recv error: {e}"),
    }

    for (name, session) in [
        ("node 1", &mut node1),
        ("node 2", &mut node2),
        ("node 3", &mut node3),
    ] {
        let _stats = expect_session_stats_matching(
            session,
            Duration::from_secs(5),
            &format!("did not see expected stats JSON line from {name}"),
            |stats| {
                stats["c2u_bytes"].as_u64().expect("missing c2u_bytes") == payload.len() as u64
                    && stats["u2c_bytes"].as_u64().expect("missing u2c_bytes")
                        == payload.len() as u64
                    && stats["c2u_pkts"].as_u64().expect("missing c2u_pkts") == 2
                    && stats["u2c_pkts"].as_u64().expect("missing u2c_pkts") == 2
            },
        );
    }
}

#[test]
#[ignore = "manual debug trace; run with -- --nocapture and inspect printed node logs"]
fn debug_icmp_sync_multihop_bridge_zero_len_trace_manual() {
    crate::orchestrator::require_raw_icmp_supported()
        .expect("ICMP multihop debug test was enabled, but runtime raw ICMP capability is missing");

    ensure_multihop_ips();

    let client_sock = bind_ipv4_client();
    let (udp_up_addr, _udp_up_thread) = spawn_ipv4_udp_echo();
    let icmp_port_2 = random_icmp_listen_id();

    let node3_ip = NODE3_IPV4;
    let mut node3 = launch_icmp_endpoint_node(
        node3_ip,
        udp_up_addr,
        6,
        DEBUG_TRACE_LOGS,
        true,
        OutputCapture::Buffered,
    );

    let node2_ip = NODE2_IPV4_STR;
    let mut node2 = launch_icmp_middle_node(
        node2_ip,
        icmp_port_2,
        node3_ip,
        6,
        5,
        DEBUG_TRACE_LOGS,
        true,
        OutputCapture::Buffered,
    );

    let mut node1 = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: format!("ICMP:{node2_ip}:{icmp_port_2}"),
        timeout_action: "exit",
        timeout_secs: Some(6),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
        debug_logs: DEBUG_TRACE_LOGS,
        capture_stderr: true,
        capture_mode: OutputCapture::Buffered,
    });
    client_sock
        .connect(node1.listen_addr)
        .expect("connect client to first forwarder");

    let payload = MULTIHOP_PAYLOAD;
    client_sock.send(payload).expect("send multihop payload");
    let mut buf = [0u8; 2048];
    let first_reply = client_sock.recv(&mut buf).expect("recv multihop reply");
    assert_eq!(&buf[..first_reply], payload);

    client_sock
        .send(&[])
        .expect("send zero-length multihop payload");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    let zero_reply = client_sock.recv(&mut buf);

    let (node1_stdout, node1_stderr) = finalize_debug_forwarder_output("node1", &mut node1);
    let (node2_stdout, node2_stderr) = finalize_debug_forwarder_output("node2", &mut node2);
    let (node3_stdout, node3_stderr) = finalize_debug_forwarder_output("node3", &mut node3);

    println!("=== zero-length recv result ===");
    println!("{zero_reply:?}");
    println!("=== node1 stdout ===\n{node1_stdout}");
    println!("=== node1 stderr ===\n{node1_stderr}");
    println!("=== node2 stdout ===\n{node2_stdout}");
    println!("=== node2 stderr ===\n{node2_stderr}");
    println!("=== node3 stdout ===\n{node3_stdout}");
    println!("=== node3 stderr ===\n{node3_stderr}");
}

#[test]
#[cfg_attr(
    not(supports_raw_icmp_capability),
    ignore = "raw ICMP tests require build-time ICMP support or PKTHERE_ALLOW_RAW_ICMP=1"
)]
fn test_raw_icmp_independent_ids() {
    crate::orchestrator::require_raw_icmp_supported()
        .expect("RAW ICMP test was enabled, but runtime support is missing");

    let client_sock = bind_ipv4_client();
    let (udp_up_addr, _udp_up_thread) = spawn_ipv4_udp_echo();

    let addr_a = NODE1_IPV4_STR;
    let addr_b = NODE1_IPV4_STR;
    let id_a = 1001;
    let id_b = 2002;

    let _node_c = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: render_icmp_arg(addr_a.parse().expect("node a ip"), id_a),
        there: format!("UDP:{}", udp_up_addr),
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

    let mut node_b = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: render_icmp_arg(addr_b.parse().expect("node b ip"), id_b),
        there: render_icmp_arg_with_local(addr_a.parse().expect("node a ip"), id_a, id_b),
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

    let node_a = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        here: IpFamily::V4.listen_arg().to_string(),
        there: render_icmp_arg(addr_b.parse().expect("node b ip"), id_b),
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

    client_sock
        .connect(node_a.listen_addr)
        .expect("connect client to A");
    let payload = INDEPENDENT_IDS_PAYLOAD;
    client_sock.send(payload).expect("send payload");

    let mut buf = [0u8; 2048];
    let n = client_sock
        .recv(&mut buf)
        .expect("recv reply through 3-hop ICMP chain");
    assert_eq!(&buf[..n], payload);

    let stats_b = expect_session_stats_matching(
        &mut node_b,
        Duration::from_secs(5),
        "did not see stats for node B",
        |s| s["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 1,
    );

    let worker_b = worker_flow::locked_worker_flow(&stats_b);
    let client_addr_b = worker_b["client_addr"].as_str().expect("client_addr");
    let upstream_canonical_b = worker_b["upstream_canonical"]
        .as_str()
        .expect("upstream_canonical");
    let upstream_local_canonical_b = worker_b["upstream_local_canonical"]
        .as_str()
        .expect("upstream_local_canonical");

    assert!(client_addr_b.contains(&id_b.to_string()));
    assert!(upstream_canonical_b.contains(&id_a.to_string()));
    assert!(upstream_local_canonical_b.contains(&id_b.to_string()));
}
