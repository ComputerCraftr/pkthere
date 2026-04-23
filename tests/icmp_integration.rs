use pkthere_test_support::fixtures::{
    ICMP_CADENCE_PAYLOAD, ICMP_STRAY_PAYLOAD, ICMP_SYNC_PAYLOAD, INDEPENDENT_IDS_PAYLOAD,
    LEGIT_PAYLOAD_1, LEGIT_PAYLOAD_2, MULTIHOP_NODE_TIMEOUT_SECS, MULTIHOP_PAYLOAD,
    QUICK_STATS_TIMEOUT_SECS, WRONG_PEER_LEGIT_PORT_ID, WRONG_PEER_STRAY_PORT_ID,
    WRONG_PEER_TARGET_PORT_ID, localhost_ip,
};
use pkthere_test_support::forwarder::{
    ForwarderConfig, ForwarderSession, launch_forwarder, snapshot_forwarder_output,
    try_launch_forwarder,
};
use pkthere_test_support::network::{
    bind_udp_client, default_test_icmp_upstream_arg, localhost_addr, render_canonical_ip_id,
    render_icmp_arg, spawn_udp_echo_server, udp_listen_arg,
};
use pkthere_test_support::packet_diagnostics::DiagnosticLogIndex;
use pkthere_test_support::raw_icmp::{acquire_icmp_dgram_session_lock, acquire_raw_icmp_lock};
use pkthere_test_support::runtime_asserts::{
    expect_no_echo, expect_session_stats_json, expect_session_stats_matching,
    recv_legitimate_echo_with_retry, wait_for_locked_client,
};
use pkthere_test_support::timing::{
    CLIENT_WAIT_MS, MAX_WAIT_SECS, RAW_ICMP_LOCK_WAIT, STATS_WAIT_MS, TEST_RETRY_INTERVAL,
    TIMEOUT_SECS,
};
use pkthere_test_support::worker_flow;

use socket2::Domain;
use std::io::ErrorKind;
use std::time::Instant;

const IPV4_CLIENT_BIND_ERR: &str = "IPv4 loopback client bind";
const IPV4_UPSTREAM_BIND_ERR: &str = "IPv4 loopback upstream bind";
const MULTIHOP_NODE2_LISTEN_ID: u16 = 1101;
const MULTIHOP_NODE2_REPLY_ID: u16 = 1202;
const MULTIHOP_NODE3_LISTEN_ID: u16 = 1303;
const MULTIHOP_NODE3_REPLY_ID: u16 = 1404;
const ICMP_ENDPOINT_NODE_ERR: &str = "could not launch ICMP endpoint node on raw-capable host";
const ICMP_MIDDLE_NODE_ERR: &str = "could not launch pure ICMP middle node";
const DEBUG_TRACE_LOGS: &[&str] = &["packets", "drops", "handles"];

fn bind_ipv4_client() -> std::net::UdpSocket {
    bind_udp_client(Domain::IPV4).expect(IPV4_CLIENT_BIND_ERR)
}

fn launch_icmp_endpoint_node(
    here: String,
    here_source_id: u16,
    udp_up_addr: std::net::SocketAddr,
    timeout_secs: u64,
    debug_logs: &[&str],
    diagnostic_label: Option<&str>,
) -> ForwarderSession {
    try_launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here,
        there: format!("UDP:{udp_up_addr}"),
        here_source_id: Some(here_source_id),
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(timeout_secs),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs,
        diagnostic_label,
        icmp_handshake_timeout_secs: None,
    })
    .unwrap_or_else(|err| panic!("{ICMP_ENDPOINT_NODE_ERR}:\n{err}"))
}

struct IcmpMiddleNodeConfig<'a> {
    here: String,
    here_source_id: u16,
    there: String,
    there_source_id: u16,
    there_reply_id: u16,
    timeout_secs: u64,
    icmp_sync_pps: u32,
    debug_logs: &'a [&'a str],
    diagnostic_label: Option<&'a str>,
}

fn launch_icmp_middle_node(config: IcmpMiddleNodeConfig<'_>) -> ForwarderSession {
    try_launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: config.here,
        there: config.there,
        here_source_id: Some(config.here_source_id),
        here_reply_id: None,
        there_source_id: Some(config.there_source_id),
        there_reply_id: Some(config.there_reply_id),
        timeout_action: "exit",
        timeout_secs: Some(config.timeout_secs),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(config.icmp_sync_pps),
        debug_logs: config.debug_logs,
        diagnostic_label: config.diagnostic_label,
        icmp_handshake_timeout_secs: None,
    })
    .unwrap_or_else(|err| panic!("{ICMP_MIDDLE_NODE_ERR}:\n{err}"))
}

fn expect_two_way_payload_stats(
    session: &mut ForwarderSession,
    payload_len: usize,
    name: &str,
) -> serde_json::Value {
    expect_session_stats_matching(session, STATS_WAIT_MS, name, |stats| {
        stats["c2u_bytes"].as_u64().expect("missing c2u_bytes") == payload_len as u64
            && stats["u2c_bytes"].as_u64().expect("missing u2c_bytes") == payload_len as u64
            && stats["c2u_pkts"].as_u64().expect("missing c2u_pkts") == 2
            && stats["u2c_pkts"].as_u64().expect("missing u2c_pkts") == 2
    })
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn icmp_sync_mode_forwards_payload_and_tracks_bytes() {
    let handshake_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "icmp_sync_mode_handshake",
    )
    .expect("acquire ICMP DGRAM handshake lock");
    // Single-node kernel-echo topology:
    //   UDP client -> node UDP listener -> ICMP wildcard upstream -> kernel echo
    // The upstream socket negotiates the realized local reply ID with itself via
    // the debug self-handshake path, then forwards only the shimmed user payload
    // back to UDP; sync cadence/control packets must stay internal.
    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: true,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: default_test_icmp_upstream_arg(localhost_ip(Domain::IPV4)),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(QUICK_STATS_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
        debug_logs: &["drops", "handshake", "packet-dump"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to ICMP forwarder (sync cadence)");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout for sync flow");

    client_sock
        .send(ICMP_SYNC_PAYLOAD)
        .expect("send initial payload to start ICMP tunnel handshake");
    let mut buf = [0u8; 2048];
    let n = client_sock
        .recv(&mut buf)
        .expect("recv initial sync reply from ICMP forwarder");
    assert!(n >= 1, "expected at least 1-byte echoed payload, got {}", n);
    assert_eq!(
        &buf[..n],
        ICMP_SYNC_PAYLOAD,
        "expected exact echoed payload"
    );
    drop(handshake_guard);

    let stats = expect_session_stats_json(&mut session, STATS_WAIT_MS, "stats");

    assert_eq!(stats["c2u_pkts"].as_u64().expect("missing c2u_pkts"), 1);
    assert_eq!(
        stats["c2u_bytes"].as_u64().expect("missing c2u_bytes"),
        ICMP_SYNC_PAYLOAD.len() as u64
    );
    assert_eq!(stats["u2c_pkts"].as_u64().expect("missing u2c_pkts"), 1);
    assert_eq!(
        stats["u2c_bytes"].as_u64().expect("missing u2c_bytes"),
        ICMP_SYNC_PAYLOAD.len() as u64
    );
    let (stdout, stderr) = snapshot_forwarder_output(&session).expect("snapshot handshake logs");
    let diagnostics = DiagnosticLogIndex::parse(&stdout, &stderr)
        .unwrap_or_else(|error| panic!("parse handshake diagnostics: {error}\n{stderr}"));
    diagnostics
        .require_single_completed_handshake(ICMP_SYNC_PAYLOAD.len())
        .unwrap_or_else(|error| {
            panic!("first payload handshake invariant failed: {error}\n{stderr}")
        });
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn icmp_sync_cadence_packets_do_not_prevent_timeout_exit() {
    let handshake_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "icmp_sync_cadence_handshake",
    )
    .expect("acquire ICMP DGRAM cadence handshake lock");
    // Same kernel-echo topology as the basic sync test. The first user payload
    // establishes reply-ID negotiation; subsequent empty cadence packets keep
    // the ICMP sync pacer active but must not count as user traffic or reset the
    // idle timeout.
    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: true,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: default_test_icmp_upstream_arg(localhost_ip(Domain::IPV4)),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(2),
        debug_logs: &["drops", "packet-dump"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });
    client_sock
        .connect(session.listen_addr)
        .expect("connect to ICMP forwarder (sync timeout)");

    let payload = ICMP_CADENCE_PAYLOAD;
    client_sock
        .send(payload)
        .expect("send initial payload to start ICMP tunnel handshake");

    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout for sync flow");

    let mut saw_echo = false;
    let mut saw_cadence_as_udp_user_data = false;
    let recv_deadline = Instant::now() + TIMEOUT_SECS;
    while Instant::now() < recv_deadline {
        let mut buf = [0u8; 2048];
        match client_sock.recv(&mut buf) {
            Ok(0) => saw_cadence_as_udp_user_data = true,
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
        !saw_cadence_as_udp_user_data,
        "ICMP cadence/control traffic must not be surfaced as UDP user payload"
    );

    let exit_deadline = Instant::now() + TIMEOUT_SECS + MAX_WAIT_SECS;
    let status = loop {
        match session.try_status() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= exit_deadline {
                    panic!("forwarder did not exit on timeout while cadence packets were active");
                }
                std::thread::sleep(TEST_RETRY_INTERVAL);
            }
            Err(e) => panic!("wait error: {e}"),
        }
    };

    assert!(status.success, "forwarder did not exit cleanly: {status}");
    drop(handshake_guard);

    let stats = expect_session_stats_json(&mut session, STATS_WAIT_MS, "stats after timeout");
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
    let (_stdout, stderr) = snapshot_forwarder_output(&session).expect("snapshot cadence logs");
    assert!(
        stderr.contains("\"disposition\":\"consume-cadence\""),
        "{stderr}"
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn zero_len_udp_client_payload_round_trips_over_icmp() {
    let handshake_guard = acquire_icmp_dgram_session_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "zero_len_udp_over_icmp_handshake",
    )
    .expect("acquire zero-length ICMP DGRAM handshake lock");
    // Zero-length UDP data is encoded as a shimmed ICMP user packet, not as an
    // empty cadence packet. The self-handshake still negotiates the local reply
    // ID before the zero-length user payload is delivered back to UDP.
    let client_sock = bind_ipv4_client();
    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: true,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: default_test_icmp_upstream_arg(localhost_ip(Domain::IPV4)),
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
        debug_logs: &["drops", "handshake"],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
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
    drop(handshake_guard);

    let stats = expect_session_stats_json(&mut session, STATS_WAIT_MS, "stats");
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
    let (stdout, stderr) = snapshot_forwarder_output(&session).expect("snapshot handshake logs");
    let diagnostics = DiagnosticLogIndex::parse(&stdout, &stderr).unwrap_or_else(|error| {
        panic!("parse zero-length handshake diagnostics: {error}\n{stderr}")
    });
    diagnostics
        .require_single_completed_handshake(0)
        .unwrap_or_else(|error| {
            panic!("zero-length first payload handshake invariant failed: {error}\n{stderr}")
        });
}

#[test]
#[ignore = "privileged DGRAM-to-RAW topology runs through the explicit capability runner"]
fn icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node() {
    assert!(
        pkthere_test_support::runtime_capability::dgram_to_bound_raw_icmp_requests(),
        "DGRAM-to-RAW topology requires its runtime platform and privilege capability"
    );
    let _raw_icmp_guard =
        acquire_raw_icmp_lock(Instant::now() + RAW_ICMP_LOCK_WAIT, "icmp_multihop")
            .expect("acquire RAW ICMP multihop lock");

    let client_sock = bind_ipv4_client();
    let udp_up_server = spawn_udp_echo_server(Domain::IPV4).expect(IPV4_UPSTREAM_BIND_ERR);
    let udp_up_addr = udp_up_server.address();

    let localhost_ip = localhost_ip(Domain::IPV4);
    // Three-node raw ICMP bridge:
    //   UDP client -> node1 UDP listener
    //   node1:<generated> -> node2:1101, replies to node1:<generated>
    //   node2:1202      -> node3:1303, replies to node2:1202
    //   node3:1404      -> node2:1202, then node2:1202 -> node1:<generated>
    // The listen/destination ID is the Echo identifier for the current hop;
    // the negotiated reply ID is the destination the peer must use on return.
    let node3_here = render_icmp_arg(localhost_ip, MULTIHOP_NODE3_LISTEN_ID);
    let mut node3 = launch_icmp_endpoint_node(
        node3_here,
        MULTIHOP_NODE3_REPLY_ID,
        udp_up_addr,
        MULTIHOP_NODE_TIMEOUT_SECS,
        DEBUG_TRACE_LOGS,
        Some("node3"),
    );

    let node2_here = render_icmp_arg(localhost_ip, MULTIHOP_NODE2_LISTEN_ID);
    let node2_there = render_icmp_arg(localhost_ip, MULTIHOP_NODE3_LISTEN_ID);
    let mut node2 = launch_icmp_middle_node(IcmpMiddleNodeConfig {
        here: node2_here,
        here_source_id: MULTIHOP_NODE2_REPLY_ID,
        there: node2_there,
        there_source_id: MULTIHOP_NODE2_REPLY_ID,
        there_reply_id: MULTIHOP_NODE2_REPLY_ID,
        timeout_secs: MULTIHOP_NODE_TIMEOUT_SECS,
        icmp_sync_pps: 5,
        debug_logs: DEBUG_TRACE_LOGS,
        diagnostic_label: Some("node2"),
    });

    let mut node1 = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: render_icmp_arg(localhost_ip, MULTIHOP_NODE2_LISTEN_ID),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(MULTIHOP_NODE2_REPLY_ID),
        there_reply_id: Some(MULTIHOP_NODE2_LISTEN_ID),
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: Some(5),
        debug_logs: DEBUG_TRACE_LOGS,
        diagnostic_label: Some("node1"),
        icmp_handshake_timeout_secs: None,
    });
    client_sock
        .connect(node1.listen_addr)
        .expect("connect client to first forwarder");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set client read timeout");

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

    expect_no_echo(&client_sock, &mut buf);

    let stats1_final =
        expect_two_way_payload_stats(&mut node1, payload.len(), "missing final node 1 stats");
    let stats2_final =
        expect_two_way_payload_stats(&mut node2, payload.len(), "missing final node 2 stats");
    let stats3_final =
        expect_two_way_payload_stats(&mut node3, payload.len(), "missing final node 3 stats");

    let node1_worker = worker_flow::locked_worker_flow(&stats1_final);
    let node1_upstream_local =
        worker_flow::worker_str(node1_worker, "upstream_local_filter_canonical");
    let node2_worker = worker_flow::locked_worker_flow(&stats2_final);
    let node3_worker = worker_flow::locked_worker_flow(&stats3_final);
    assert_eq!(node2_worker["client_sock_type"], "RAW");
    assert_eq!(node2_worker["upstream_sock_type"], "RAW");
    assert_eq!(node3_worker["client_sock_type"], "RAW");
    let node2_listen = render_canonical_ip_id(localhost_ip, MULTIHOP_NODE2_LISTEN_ID);
    let node2_reply = render_canonical_ip_id(localhost_ip, MULTIHOP_NODE2_REPLY_ID);
    let node3_listen = render_canonical_ip_id(localhost_ip, MULTIHOP_NODE3_LISTEN_ID);
    let node3_reply = render_canonical_ip_id(localhost_ip, MULTIHOP_NODE3_REPLY_ID);
    worker_flow::assert_flow_tuple(
        node2_worker,
        "listener_flow_inbound",
        &node2_reply,
        &node2_listen,
    );
    worker_flow::assert_flow_tuple(
        node2_worker,
        "listener_flow_outbound",
        &node2_reply,
        node1_upstream_local,
    );
    assert_eq!(
        worker_flow::worker_str(node2_worker, "upstream_remote_filter_canonical"),
        node3_listen
    );
    assert_eq!(
        worker_flow::worker_str(node2_worker, "upstream_local_filter_canonical"),
        node2_reply
    );
    worker_flow::assert_flow_tuple(
        node3_worker,
        "listener_flow_inbound",
        &node2_reply,
        &node3_listen,
    );
    worker_flow::assert_flow_tuple(
        node3_worker,
        "listener_flow_outbound",
        &node3_reply,
        &node2_reply,
    );
}

#[test]
#[ignore = "privileged pure-RAW topology runs through the explicit capability runner"]
fn test_raw_icmp_independent_ids() {
    assert!(
        pkthere_test_support::runtime_capability::raw_to_bound_raw_icmp_requests(),
        "pure-RAW topology requires its runtime platform and privilege capability"
    );
    let _raw_icmp_guard = acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_icmp_independent_ids",
    )
    .expect("acquire RAW ICMP independent-ID lock");

    let client_sock = bind_ipv4_client();
    let udp_up_server = spawn_udp_echo_server(Domain::IPV4).expect(IPV4_UPSTREAM_BIND_ERR);
    let udp_up_addr = udp_up_server.address();

    let local_ip = localhost_ip(Domain::IPV4);
    let client_source_id: u16 = 40000;
    let client_reply_id: u16 = 40001;
    let server_listen_id: u16 = 9999;
    let server_source_id: u16 = 7777;

    // One logical ICMP datagram connection with four distinct endpoint IDs:
    //   client:40000 -> server:9999  (source ID -> destination/listen ID)
    //   server:7777  -> client:40001 (source ID -> negotiated reply ID)
    // Source IDs identify the sender on every shimmed packet and drive flow
    // locking; reply IDs are only negotiated by session-control frames and then
    // used as the destination ID for reverse traffic.
    let mut node_b = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: render_icmp_arg(local_ip, server_listen_id),
        there: format!("UDP:{udp_up_addr}"),
        here_source_id: Some(server_source_id),
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: DEBUG_TRACE_LOGS,
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    let mut node_a = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: render_icmp_arg(local_ip, server_listen_id),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(client_source_id),
        there_reply_id: Some(client_reply_id),
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: DEBUG_TRACE_LOGS,
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(node_a.listen_addr)
        .expect("connect client to A");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set client read timeout");
    let payload = INDEPENDENT_IDS_PAYLOAD;
    client_sock.send(payload).expect("send payload");

    let mut buf = [0u8; 2048];
    let n = client_sock.recv(&mut buf).unwrap_or_else(|error| {
        panic!(
            "recv reply over ICMP connection with 4 disjoint IDs: {error}\n{}\n{}",
            node_a.diagnostic_snapshot(100),
            node_b.diagnostic_snapshot(100)
        )
    });
    assert_eq!(&buf[..n], payload);

    let stats_a = expect_session_stats_matching(
        &mut node_a,
        STATS_WAIT_MS,
        "did not see stats for node A",
        |s| s["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 1,
    );
    let stats_b = expect_session_stats_matching(
        &mut node_b,
        STATS_WAIT_MS,
        "did not see stats for node B",
        |s| s["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 1,
    );

    let client_source = render_canonical_ip_id(local_ip, client_source_id);
    let client_reply = render_canonical_ip_id(local_ip, client_reply_id);
    let server_listen = render_canonical_ip_id(local_ip, server_listen_id);
    let server_source = render_canonical_ip_id(local_ip, server_source_id);

    let worker_a = worker_flow::locked_worker_flow(&stats_a);
    assert_eq!(
        worker_flow::worker_str(worker_a, "upstream_local_filter_canonical"),
        client_reply
    );
    assert_eq!(
        worker_flow::worker_str(worker_a, "upstream_remote_filter_canonical"),
        server_listen
    );
    worker_flow::assert_flow_tuple(
        worker_a,
        "upstream_flow_outbound",
        &client_source,
        &server_listen,
    );
    worker_flow::assert_flow_tuple(
        worker_a,
        "upstream_flow_inbound",
        &server_source,
        &client_reply,
    );

    let worker_b = worker_flow::locked_worker_flow(&stats_b);
    assert_eq!(
        worker_flow::worker_str(worker_b, "listen_local_filter_canonical"),
        server_listen
    );
    worker_flow::assert_flow_tuple(
        worker_b,
        "listener_flow_inbound",
        &client_source,
        &server_listen,
    );
    worker_flow::assert_flow_tuple(
        worker_b,
        "listener_flow_outbound",
        &server_source,
        &client_reply,
    );
}

#[test]
#[ignore = "privileged pure-RAW topology runs through the explicit capability runner"]
fn raw_icmp_locked_flow_rejects_wrong_source_id() {
    assert!(
        pkthere_test_support::runtime_capability::raw_to_bound_raw_icmp_requests(),
        "pure-RAW topology requires its runtime platform and privilege capability"
    );
    let _raw_icmp_guard = acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "raw_icmp_wrong_source_ip",
    )
    .expect("acquire RAW ICMP wrong-source lock");
    const WRONG_SOURCE_TEST_TIMEOUT_SECS: u64 = MULTIHOP_NODE_TIMEOUT_SECS + 5;

    let client_legit = bind_ipv4_client();
    let client_stray = bind_ipv4_client();
    let udp_up_server = spawn_udp_echo_server(Domain::IPV4).expect(IPV4_UPSTREAM_BIND_ERR);
    let udp_up_addr = udp_up_server.address();
    let local_ip = localhost_ip(Domain::IPV4);

    // Wrong-source topology:
    //   legit:1111 -> target:4141, target replies to legit:1111
    //   stray:2222 -> target:4141, target would reply to stray:2222
    // The first legit packet locks target's ICMP listener flow by source ID
    // 1111. A later packet with the same destination ID but source ID 2222 must
    // be rejected by admission even though the raw listener is unconnected.
    let mut node_target = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: true,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: render_icmp_arg(local_ip, WRONG_PEER_TARGET_PORT_ID),
        there: format!("UDP:{udp_up_addr}"),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(WRONG_SOURCE_TEST_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["drops"],
        diagnostic_label: Some("target"),
        icmp_handshake_timeout_secs: None,
    });

    // node_legit forwards UDP -> ICMP target ID 4141, source/reply ID 1111.
    let node_legit = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: render_icmp_arg(local_ip, WRONG_PEER_TARGET_PORT_ID),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(WRONG_PEER_LEGIT_PORT_ID),
        there_reply_id: Some(WRONG_PEER_LEGIT_PORT_ID),
        timeout_action: "exit",
        timeout_secs: Some(WRONG_SOURCE_TEST_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: Some("legit"),
        icmp_handshake_timeout_secs: None,
    });

    // node_stray forwards UDP -> ICMP target ID 4141, source/reply ID 2222.
    let node_stray = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: render_icmp_arg(local_ip, WRONG_PEER_TARGET_PORT_ID),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(WRONG_PEER_STRAY_PORT_ID),
        there_reply_id: Some(WRONG_PEER_STRAY_PORT_ID),
        timeout_action: "exit",
        timeout_secs: Some(WRONG_SOURCE_TEST_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: Some("stray"),
        icmp_handshake_timeout_secs: None,
    });

    client_legit
        .connect(node_legit.listen_addr)
        .expect("connect legit client");
    client_stray
        .connect(node_stray.listen_addr)
        .expect("connect stray client");

    let mut buf = [0u8; 2048];

    // 1. Establish lock on node_target with legit client (ID 1111)
    let n = recv_legitimate_echo_with_retry(
        &client_legit,
        LEGIT_PAYLOAD_1,
        &mut buf,
        "legit",
        "echo 1",
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error}\nnode target:\n{}\nnode legit:\n{}",
            node_target.diagnostic_snapshot(80),
            node_legit.diagnostic_snapshot(80)
        )
    });
    assert_eq!(&buf[..n], LEGIT_PAYLOAD_1);

    wait_for_locked_client(&mut node_target, MAX_WAIT_SECS).expect("node_target lock");

    // 2. Stray client sends from ID 2222; must be rejected by node_target.
    client_stray.send(ICMP_STRAY_PAYLOAD).expect("send stray");
    expect_no_echo(&client_stray, &mut buf);

    // Explicitly verify the drop log for node_target
    let (stdout, stderr) = snapshot_forwarder_output(&node_target).expect("snapshot output");
    let all_output = format!("{}\n{}", stdout, stderr);
    let stray_addr = localhost_addr(Domain::IPV4, WRONG_PEER_STRAY_PORT_ID);
    let legacy_drop = format!("dropping packet from unexpected client peer {}", stray_addr);
    let source_id_drop = format!(
        "dropping ICMP packet from client peer {} because source endpoint ID mismatches the locked flow",
        stray_addr
    );
    assert!(
        all_output.contains(&source_id_drop) || all_output.contains(&legacy_drop),
        "node_target should have logged a packet drop for the stray client {}",
        stray_addr
    );

    // 3. Legit client still works.
    let n = recv_legitimate_echo_with_retry(
        &client_legit,
        LEGIT_PAYLOAD_2,
        &mut buf,
        "legit",
        "echo 2",
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error}\nnode target:\n{}\nnode legit:\n{}",
            node_target.diagnostic_snapshot(80),
            node_legit.diagnostic_snapshot(80)
        )
    });
    assert_eq!(&buf[..n], LEGIT_PAYLOAD_2);

    // 4. Verify both legitimate payloads were admitted. The retry helper may
    // produce additional legitimate admissions before Windows delivers the
    // corresponding RAW replies; the stray source is verified by its drop log.
    let stats = expect_session_stats_matching(
        &mut node_target,
        STATS_WAIT_MS,
        "node_target final stats",
        |s| s["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 2,
    );
    assert!(stats["c2u_pkts"].as_u64().expect("c2u_pkts") >= 2);
}
