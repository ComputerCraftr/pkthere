#[cfg(any(target_os = "linux", target_os = "android"))]
use pkthere_test_support::fixtures::MULTI_WORKER_CANDIDATE_PREFIX;
use pkthere_test_support::fixtures::{
    MULTI_WORKER_FOLLOWUP_PAYLOAD, MULTI_WORKER_SHARED_PAYLOAD, MULTI_WORKER_TIMEOUT_SECS,
};
use pkthere_test_support::forwarder::{
    ForwarderConfig, ForwarderSession, launch_forwarder_with_extra_args,
};
use pkthere_test_support::network::{
    UdpEchoServer, bind_udp_client, default_test_icmp_upstream_arg, localhost_addr,
    spawn_udp_multi_peer_echo_server, udp_listen_arg,
};
use pkthere_test_support::runtime_asserts::{
    expect_session_stats_matching, recv_legitimate_echo_with_retry,
};
use pkthere_test_support::timing::{CHILD_CLEANUP_WAIT, MAX_WAIT_SECS};
#[cfg(any(target_os = "linux", target_os = "android"))]
use pkthere_test_support::timing::{CLIENT_WAIT_MS, TEST_POLL_INTERVAL};
use pkthere_wire::SupportedProtocol;
use socket2::Domain;
use std::collections::HashSet;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::ErrorKind;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::net::{SocketAddr, UdpSocket};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::thread;
use std::time::Instant;

const WORKER_PAIRS: usize = 3;
#[cfg(any(target_os = "linux", target_os = "android"))]
const FLOW_CANDIDATES: usize = 64;

#[test]
fn shared_flow_publishes_one_udp_flow_to_all_worker_pairs_ipv4_and_ipv6() {
    for family in [Domain::IPV4, Domain::IPV6] {
        run_shared_flow_case(family, SupportedProtocol::UDP);
    }
}

#[test]
#[cfg(any(target_os = "linux", target_os = "android"))]
fn single_flow_distributes_distinct_udp_flows_across_all_worker_pairs_ipv4_and_ipv6() {
    for family in [Domain::IPV4, Domain::IPV6] {
        run_single_flow_case(family, SupportedProtocol::UDP);
    }
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn shared_flow_shares_icmp_handshake_state_across_worker_pairs() {
    run_shared_flow_case(Domain::IPV4, SupportedProtocol::ICMP);
}

fn run_shared_flow_case(family: Domain, proto: SupportedProtocol) {
    let client = bind_udp_client(family).expect("bind shared-flow client");
    let client_addr = client.local_addr().expect("shared-flow client address");
    let (mut session, _upstream_echo) = launch_worker_forwarder(family, proto, "shared-flow");
    client
        .connect(session.listen_addr)
        .expect("connect shared-flow client");

    let mut buf = [0u8; 2048];
    for payload in [MULTI_WORKER_SHARED_PAYLOAD, MULTI_WORKER_FOLLOWUP_PAYLOAD] {
        client.send(payload).expect("send shared-flow payload");
        recv_legitimate_echo_with_retry(
            &client,
            payload,
            &mut buf,
            &format!("shared-flow {family:?} {}", proto.to_str()),
            "shared-flow echo",
        )
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    }

    let stats = expect_session_stats_matching(
        &mut session,
        MAX_WAIT_SECS,
        "shared-flow workers did not publish one shared lock",
        |stats| {
            stats["locked_worker_pairs"].as_u64() == Some(WORKER_PAIRS as u64)
                && stats["c2u_pkts"].as_u64() == Some(2)
                && stats["u2c_pkts"].as_u64() == Some(2)
        },
    );
    let flows = strict_worker_flows(&stats);
    assert_worker_slots(flows);
    assert_eq!(flows.len(), WORKER_PAIRS);
    assert!(
        flows
            .iter()
            .all(|flow| flow["locked"].as_bool() == Some(true)),
        "shared-flow did not expose the lock through every worker pair: {stats}"
    );
    let expected_key = client_addr.to_string();
    let keys = flow_keys(flows);
    assert_eq!(keys, HashSet::from([expected_key.as_str()]));
    for flow in flows {
        let outbound = flow["listener_flow_outbound"]
            .as_str()
            .expect("shared listener outbound tuple");
        assert!(
            outbound.ends_with(&format!(" -> {client_addr}")),
            "shared worker published the wrong client tuple: {outbound}"
        );
    }
    finish_worker_forwarder(session, "shared-flow forwarder");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_single_flow_case(family: Domain, proto: SupportedProtocol) {
    let (mut session, _upstream_echo) = launch_worker_forwarder(family, proto, "single-flow");
    let mut candidates = make_flow_candidates(family, session.listen_addr);
    for candidate in &candidates {
        candidate
            .socket
            .send(&candidate.payload)
            .expect("send single-flow candidate");
    }

    let active = collect_candidate_replies(&mut candidates, WORKER_PAIRS, &session);
    assert_eq!(
        active.len(),
        WORKER_PAIRS,
        "single-flow should accept exactly one flow per worker pair\n{}",
        session.diagnostic_snapshot(60)
    );

    for index in &active {
        let candidate = &candidates[*index];
        candidate
            .socket
            .set_nonblocking(false)
            .expect("restore active client blocking mode");
        candidate
            .socket
            .set_read_timeout(Some(CLIENT_WAIT_MS))
            .expect("restore active client timeout");
        candidate
            .socket
            .send(MULTI_WORKER_FOLLOWUP_PAYLOAD)
            .expect("send single-flow follow-up");
        let mut buf = [0u8; 2048];
        recv_legitimate_echo_with_retry(
            &candidate.socket,
            MULTI_WORKER_FOLLOWUP_PAYLOAD,
            &mut buf,
            &format!("single-flow {family:?} {}", proto.to_str()),
            "single-flow follow-up echo",
        )
        .unwrap_or_else(|error| panic!("{error}\n{}", session.diagnostic_snapshot(80)));
    }

    let expected_packets = (WORKER_PAIRS * 2) as u64;
    let stats = expect_session_stats_matching(
        &mut session,
        MAX_WAIT_SECS,
        "single-flow workers did not retain independent locks",
        |stats| {
            stats["locked_worker_pairs"].as_u64() == Some(WORKER_PAIRS as u64)
                && stats["c2u_pkts"].as_u64() == Some(expected_packets)
                && stats["u2c_pkts"].as_u64() == Some(expected_packets)
        },
    );
    let flows = strict_worker_flows(&stats);
    assert_worker_slots(flows);
    assert_eq!(flows.len(), WORKER_PAIRS);
    assert!(
        flows
            .iter()
            .all(|flow| flow["locked"].as_bool() == Some(true)),
        "single-flow did not lock every worker pair: {stats}"
    );
    assert_eq!(
        flow_keys(flows).len(),
        WORKER_PAIRS,
        "single-flow worker pairs must retain distinct flow state: {stats}"
    );
    let active_addrs = active
        .iter()
        .map(|index| candidates[*index].local_addr.to_string())
        .collect::<HashSet<_>>();
    assert_eq!(
        flow_keys(flows),
        active_addrs.iter().map(String::as_str).collect()
    );
    finish_worker_forwarder(session, "single-flow forwarder");
}

fn finish_worker_forwarder(mut session: ForwarderSession, context: &str) {
    if let Err(error) = session.terminate(Instant::now() + CHILD_CLEANUP_WAIT) {
        panic!(
            "failed to terminate and reap {context}: {error}\n{}",
            session.diagnostic_snapshot(80)
        );
    }
}

fn launch_worker_forwarder(
    family: Domain,
    proto: SupportedProtocol,
    worker_flow_mode: &str,
) -> (ForwarderSession, Option<UdpEchoServer>) {
    let (there, upstream_echo) = if proto == SupportedProtocol::ICMP {
        (
            default_test_icmp_upstream_arg(localhost_addr(family, 0).ip()),
            None,
        )
    } else {
        let server = spawn_udp_multi_peer_echo_server(family).expect("spawn multi-peer UDP echo");
        (format!("UDP:{}", server.address()), Some(server))
    };
    let extra_args = vec![
        "--workers".to_string(),
        WORKER_PAIRS.to_string(),
        "--worker-flow-mode".to_string(),
        worker_flow_mode.to_string(),
    ];
    let session = launch_forwarder_with_extra_args(
        ForwarderConfig {
            debug_client_unconnected: worker_flow_mode == "single-flow",
            debug_upstream_unconnected: false,
            debug_icmp_kernel_echo_self_handshake: proto == SupportedProtocol::ICMP,
            debug_force_raw_icmp_wildcard_upstream: false,
            here: udp_listen_arg(localhost_addr(family, 0)),
            there,
            here_source_id: None,
            here_reply_id: None,
            there_source_id: None,
            there_reply_id: None,
            timeout_action: "exit",
            timeout_secs: Some(MULTI_WORKER_TIMEOUT_SECS),
            max_payload: None,
            fast_stats: true,
            stats_interval_mins: None,
            icmp_sync_pps: None,
            debug_logs: &["drops", "handshake", "handles"],
            diagnostic_label: Some("multi-worker forwarder"),
            icmp_handshake_timeout_secs: None,
        },
        &extra_args,
    );
    (session, upstream_echo)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct FlowCandidate {
    socket: UdpSocket,
    local_addr: SocketAddr,
    payload: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn make_flow_candidates(family: Domain, destination: SocketAddr) -> Vec<FlowCandidate> {
    (0..FLOW_CANDIDATES)
        .map(|index| {
            let socket = bind_udp_client(family).expect("bind single-flow candidate");
            socket
                .connect(destination)
                .expect("connect single-flow candidate");
            socket
                .set_nonblocking(true)
                .expect("set single-flow candidate nonblocking");
            let local_addr = socket.local_addr().expect("candidate local address");
            let mut payload = MULTI_WORKER_CANDIDATE_PREFIX.to_vec();
            payload.extend_from_slice(index.to_string().as_bytes());
            FlowCandidate {
                socket,
                local_addr,
                payload,
            }
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn collect_candidate_replies(
    candidates: &mut [FlowCandidate],
    expected: usize,
    session: &ForwarderSession,
) -> Vec<usize> {
    let deadline = Instant::now() + MAX_WAIT_SECS;
    let mut active = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && active.len() < expected {
        for (index, candidate) in candidates.iter().enumerate() {
            if active.contains(&index) {
                continue;
            }
            match candidate.socket.recv(&mut buf) {
                Ok(n) => {
                    assert_eq!(
                        &buf[..n],
                        candidate.payload,
                        "candidate received another flow's payload\n{}",
                        session.diagnostic_snapshot(40)
                    );
                    active.push(index);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => panic!(
                    "receive single-flow candidate reply: {error}\n{}",
                    session.diagnostic_snapshot(40)
                ),
            }
        }
        thread::sleep(TEST_POLL_INTERVAL);
    }
    active
}

fn strict_worker_flows(stats: &serde_json::Value) -> &[serde_json::Value] {
    stats["worker_flows"]
        .as_array()
        .expect("stats worker_flows array")
}

fn assert_worker_slots(flows: &[serde_json::Value]) {
    let listener_slots = flows
        .iter()
        .map(|flow| {
            flow["listen_socket_evidence"]["socket_slot"]
                .as_u64()
                .expect("listener socket slot")
        })
        .collect::<HashSet<_>>();
    let upstream_slots = flows
        .iter()
        .map(|flow| {
            flow["upstream_socket_evidence"]["socket_slot"]
                .as_u64()
                .expect("upstream socket slot")
        })
        .collect::<HashSet<_>>();
    let expected = (0..WORKER_PAIRS as u64).collect::<HashSet<_>>();
    assert_eq!(listener_slots, expected);
    assert_eq!(upstream_slots, expected);
}

fn flow_keys(flows: &[serde_json::Value]) -> HashSet<&str> {
    flows
        .iter()
        .map(|flow| flow["flow_key"].as_str().expect("locked worker flow key"))
        .collect()
}
