use pkthere_test_support::authority_evidence::require_complete_worker_authority_evidence;
use pkthere_test_support::forwarder::{
    ForwarderConfig, launch_forwarder, launch_forwarder_with_extra_args,
};
use pkthere_test_support::matrix::spawn_upstream_echo_or_skip;
use pkthere_test_support::network::{
    bind_udp_client, default_test_icmp_upstream_arg, localhost_addr,
    spawn_udp_multi_peer_echo_server, udp_listen_arg,
};
use pkthere_test_support::runtime_asserts::{
    expect_session_stats_json, expect_session_stats_matching,
};
use pkthere_test_support::timing::{
    DISTRIBUTED_STRESS_DURATION, DISTRIBUTED_STRESS_IDLE_TIMEOUT, MAX_WAIT_SECS,
    RETRY_RECV_WAIT_MS, STATS_WAIT_MS, STRESS_DRAIN_WAIT, STRESS_FORWARDER_IDLE_TIMEOUT,
    STRESS_SEND_PAUSE, STRESS_STALL_KEEPALIVE_INTERVAL, STRESS_STALL_POLL_INTERVAL,
    STRESS_TEST_DURATION, TIMEOUT_SECS,
};
use pkthere_wire::SupportedProtocol;

use socket2::Domain;
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

const STRESS_SEND_BURST_PACKETS: u64 = 8;
const STRESS_MAX_IN_FLIGHT_PACKETS: u64 = 32;
const DISTRIBUTED_STRESS_CANDIDATES: usize = 128;
const DISTRIBUTED_STRESS_MAX_LOAD_RATIO: u64 = 4;
const DISTRIBUTED_STRESS_WORKER_PAIRS: usize = 8;

fn stress_send_burst(sent: u64, received: u64, now: Instant, next_keepalive: Instant) -> u64 {
    let in_flight = sent.saturating_sub(received);
    let available = STRESS_MAX_IN_FLIGHT_PACKETS.saturating_sub(in_flight);
    if available == 0 {
        u64::from(now >= next_keepalive)
    } else {
        available.min(STRESS_SEND_BURST_PACKETS)
    }
}

#[test]
#[ignore = "long-running release stress owner; invoked exactly by native release-stress CI"]
fn stress_test_ipv4() {
    for &proto in pkthere_test_support::runtime_capability::enabled_forward_protocols() {
        stress_test_ipv4_case(proto);
    }
}

#[test]
#[ignore = "Alpine authority-audit owner for sustained multi-socket UDP worker distribution"]
fn stress_multi_worker_distributed_udp_ipv4() {
    stress_multi_worker_distributed_ipv4(SupportedProtocol::UDP);
}

#[test]
#[ignore = "Alpine authority-audit owner for sustained multi-socket ICMP worker distribution"]
fn stress_multi_worker_distributed_icmp_ipv4() {
    stress_multi_worker_distributed_ipv4(SupportedProtocol::ICMP);
}

fn stress_multi_worker_distributed_ipv4(protocol: SupportedProtocol) {
    let distribution =
        pkthere_socket_policy::listener_worker_socket_policy(DISTRIBUTED_STRESS_WORKER_PAIRS, true);
    assert!(
        distribution.supports_requested_distribution(),
        "the explicitly selected distributed stress owner requires policy-authorized kernel flow affinity"
    );
    if protocol == SupportedProtocol::ICMP {
        assert!(
            pkthere_test_support::runtime_capability::icmp_dgram_echo(),
            "Linux Alpine must provide the policy-authorized ICMP-DGRAM echo path"
        );
    }
    let (there, _upstream) = match protocol {
        SupportedProtocol::UDP => {
            let upstream =
                spawn_udp_multi_peer_echo_server(Domain::IPV4).expect("spawn distributed UDP echo");
            (format!("UDP:{}", upstream.address()), Some(upstream))
        }
        SupportedProtocol::ICMP => (
            default_test_icmp_upstream_arg(localhost_addr(Domain::IPV4, 0).ip()),
            None,
        ),
    };
    let protocol_name = protocol.to_str();
    let extra_args = vec![
        "--workers".to_string(),
        DISTRIBUTED_STRESS_WORKER_PAIRS.to_string(),
        "--worker-flow-mode".to_string(),
        "single-flow".to_string(),
    ];
    let mut session = launch_forwarder_with_extra_args(
        ForwarderConfig {
            debug_client_unconnected: false,
            debug_upstream_unconnected: false,
            debug_icmp_kernel_echo_self_handshake: protocol == SupportedProtocol::ICMP,
            debug_force_raw_icmp_wildcard_upstream: false,
            here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
            there,
            here_source_id: None,
            here_reply_id: None,
            there_source_id: None,
            there_reply_id: None,
            timeout_action: "exit",
            timeout_secs: Some(DISTRIBUTED_STRESS_IDLE_TIMEOUT.as_secs()),
            max_payload: None,
            fast_stats: true,
            stats_interval_mins: Some(1),
            icmp_sync_pps: None,
            debug_logs: &[],
            diagnostic_label: Some(match protocol {
                SupportedProtocol::UDP => "distributed UDP authority stress",
                SupportedProtocol::ICMP => "distributed ICMP authority stress",
            }),
            icmp_handshake_timeout_secs: None,
        },
        &extra_args,
    );

    let candidates = (0..DISTRIBUTED_STRESS_CANDIDATES)
        .map(|index| {
            let socket = bind_udp_client(Domain::IPV4).expect("bind distributed client");
            socket
                .connect(session.listen_addr)
                .expect("connect distributed client");
            socket
                .set_nonblocking(true)
                .expect("set distributed client nonblocking");
            let payload =
                format!("distributed-{protocol_name}-authority-stress-{index}").into_bytes();
            socket.send(&payload).expect("send distribution candidate");
            (socket, payload)
        })
        .collect::<Vec<_>>();
    let discovery_deadline = Instant::now() + MAX_WAIT_SECS;
    let mut active = Vec::new();
    let mut buffer = [0_u8; 256];
    while Instant::now() < discovery_deadline && active.len() < DISTRIBUTED_STRESS_WORKER_PAIRS {
        for (index, (socket, payload)) in candidates.iter().enumerate() {
            if active.contains(&index) {
                continue;
            }
            match socket.recv(&mut buffer) {
                Ok(length) => {
                    assert_eq!(&buffer[..length], payload);
                    active.push(index);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionRefused
                    ) => {}
                Err(error) => panic!("distributed candidate receive failed: {error}"),
            }
        }
        thread::sleep(STRESS_STALL_POLL_INTERVAL);
    }
    assert_eq!(
        active.len(),
        DISTRIBUTED_STRESS_WORKER_PAIRS,
        "{protocol_name} kernel distribution did not activate every worker socket\n{}",
        session.diagnostic_snapshot(80)
    );

    let stress_deadline = Instant::now() + DISTRIBUTED_STRESS_DURATION;
    let active = active.into_iter().collect::<HashSet<_>>();
    let workers = candidates
        .into_iter()
        .enumerate()
        .filter(|(index, _)| active.contains(index))
        .map(|(_, (socket, payload))| {
            thread::spawn(move || -> io::Result<(String, u64)> {
                let flow_key = socket.local_addr()?.to_string();
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(RETRY_RECV_WAIT_MS))?;
                let mut replies = 0_u64;
                let mut reply = [0_u8; 256];
                while Instant::now() < stress_deadline {
                    socket.send(&payload)?;
                    match socket.recv(&mut reply) {
                        Ok(length) => {
                            if reply[..length] != payload {
                                return Err(io::Error::other(
                                    "distributed worker received another flow's payload",
                                ));
                            }
                            replies = replies.saturating_add(1);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok((flow_key, replies))
            })
        })
        .collect::<Vec<_>>();
    let live_stats = expect_session_stats_matching(
        &mut session,
        STATS_WAIT_MS,
        "distributed stress did not publish all live worker locks",
        |stats| {
            stats["locked_worker_pairs"].as_u64() == Some(DISTRIBUTED_STRESS_WORKER_PAIRS as u64)
        },
    );
    let mut total_replies = 0_u64;
    let mut loaded_flow_keys = HashSet::new();
    let mut worker_packet_counts = Vec::with_capacity(DISTRIBUTED_STRESS_WORKER_PAIRS);
    for worker in workers {
        let worker_result = worker
            .join()
            .expect("distributed stress client thread panicked");
        let (flow_key, replies) = worker_result.unwrap_or_else(|error| {
            panic!(
                "distributed {protocol_name} stress client failed: {error}\n{}",
                session.diagnostic_snapshot(120)
            )
        });
        assert!(
            replies >= 100,
            "distributed {protocol_name} worker flow {flow_key} was not kept under load: {replies} replies"
        );
        assert!(
            loaded_flow_keys.insert(flow_key.clone()),
            "distributed stress selected one flow more than once"
        );
        worker_packet_counts.push((flow_key, replies));
        total_replies = total_replies.saturating_add(replies);
    }
    assert_eq!(loaded_flow_keys.len(), DISTRIBUTED_STRESS_WORKER_PAIRS);
    assert!(
        total_replies >= (DISTRIBUTED_STRESS_WORKER_PAIRS as u64) * 100,
        "distributed {protocol_name} stress forwarded too few replies: {total_replies}"
    );
    let min_packets = worker_packet_counts
        .iter()
        .map(|(_, packets)| *packets)
        .min()
        .expect("distributed stress requires worker packet counts");
    let max_packets = worker_packet_counts
        .iter()
        .map(|(_, packets)| *packets)
        .max()
        .expect("distributed stress requires worker packet counts");
    assert!(
        max_packets <= min_packets.saturating_mul(DISTRIBUTED_STRESS_MAX_LOAD_RATIO),
        "distributed {protocol_name} worker load exceeded the {DISTRIBUTED_STRESS_MAX_LOAD_RATIO}:1 sanity bound: {worker_packet_counts:?}"
    );

    session
        .wait_for_exit_success(DISTRIBUTED_STRESS_IDLE_TIMEOUT + MAX_WAIT_SECS)
        .expect("distributed stress forwarder exit");
    let audit_output = session.output_snapshot();
    require_complete_worker_authority_evidence(
        &audit_output.stderr_lossy(),
        DISTRIBUTED_STRESS_WORKER_PAIRS,
        DISTRIBUTED_STRESS_MAX_LOAD_RATIO,
    )
    .unwrap_or_else(|error| {
        panic!(
            "distributed {protocol_name} authority evidence failed: {error}\n{}",
            session.diagnostic_snapshot(100)
        )
    });
    let stats = expect_session_stats_json(
        &mut session,
        STATS_WAIT_MS,
        "distributed stress omitted final stats",
    );
    let flows = live_stats["worker_flows"]
        .as_array()
        .expect("distributed stress worker flow array");
    let listener_slots = flows
        .iter()
        .map(|flow| {
            flow["listen_socket_evidence"]["socket_slot"]
                .as_u64()
                .expect("distributed listener socket slot")
        })
        .collect::<HashSet<_>>();
    let upstream_slots = flows
        .iter()
        .map(|flow| {
            flow["upstream_socket_evidence"]["socket_slot"]
                .as_u64()
                .expect("distributed upstream socket slot")
        })
        .collect::<HashSet<_>>();
    let expected_slots = (0..DISTRIBUTED_STRESS_WORKER_PAIRS as u64).collect::<HashSet<_>>();
    assert_eq!(listener_slots, expected_slots);
    assert_eq!(upstream_slots, expected_slots);
    let published_flow_keys = flows
        .iter()
        .map(|flow| {
            flow["flow_key"]
                .as_str()
                .expect("distributed worker flow key")
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        published_flow_keys,
        loaded_flow_keys.iter().map(String::as_str).collect(),
        "every loaded client must map to one independently locked worker flow"
    );
    assert!(
        stats["invariant_failures"]
            .as_u64()
            .is_none_or(|value| value == 0),
        "distributed {protocol_name} authority stress recorded an invariant failure: {stats}"
    );
}

fn stress_test_ipv4_case(proto: &str) {
    let client_sock = bind_udp_client(Domain::IPV4).expect("IPv4 loopback not available");

    let Some((there_arg, _up_addr, _upstream_echo)) =
        spawn_upstream_echo_or_skip(Domain::IPV4, proto)
    else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: proto.eq_ignore_ascii_case("icmp"),
        debug_force_raw_icmp_wildcard_upstream: false,
        here: udp_listen_arg(localhost_addr(Domain::IPV4, 0)),
        there: there_arg,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(STRESS_FORWARDER_IDLE_TIMEOUT.as_secs()),
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: Some(1),
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: Some(STRESS_FORWARDER_IDLE_TIMEOUT.as_secs()),
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (IPv4)");

    let payload = vec![255u8; 1400];
    client_sock
        .send(&payload)
        .expect("send to forwarder (IPv4)");

    let send_deadline = Instant::now() + STRESS_TEST_DURATION;
    let receive_deadline = send_deadline + STRESS_DRAIN_WAIT;
    let mut sent = 1u64;
    let received = Arc::new(AtomicU64::new(0));
    let mut next_stall_keepalive = Instant::now() + STRESS_STALL_KEEPALIVE_INTERVAL;

    let recv_sock = client_sock.try_clone().expect("clone recv socket");
    recv_sock
        .set_read_timeout(Some(RETRY_RECV_WAIT_MS))
        .expect("set bounded stress receive timeout");
    let receive_count = Arc::clone(&received);
    let recv_thr = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 65535];
        while Instant::now() < receive_deadline {
            match recv_sock.recv(&mut buf) {
                Ok(_) => {
                    receive_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    let kind = e.kind();
                    if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    });

    let mut send_error = None;
    while Instant::now() < send_deadline {
        let now = Instant::now();
        let burst = stress_send_burst(
            sent,
            received.load(Ordering::Relaxed),
            now,
            next_stall_keepalive,
        );
        if burst == 0 {
            thread::sleep(STRESS_STALL_POLL_INTERVAL);
            continue;
        }
        for _ in 0..burst {
            if let Err(error) = client_sock.send(&payload) {
                send_error = Some(error);
                break;
            }
            sent += 1;
        }
        if send_error.is_some() {
            break;
        }
        next_stall_keepalive = now + STRESS_STALL_KEEPALIVE_INTERVAL;
        thread::sleep(STRESS_SEND_PAUSE);
    }

    let receive_result = recv_thr.join().expect("join recv thread");
    if send_error.is_some() || receive_result.is_err() {
        panic!(
            "{proto} stress socket failure: send_error={send_error:?} receive_error={:?}\n{}",
            receive_result.err(),
            session.diagnostic_snapshot(80)
        );
    }
    let rcvd = received.load(Ordering::Relaxed);
    let rcvd_pct = if sent == 0 {
        0.0
    } else {
        (rcvd as f64) * 100.0 / (sent as f64)
    };

    session
        .wait_for_exit_success(STRESS_FORWARDER_IDLE_TIMEOUT + MAX_WAIT_SECS)
        .expect("stress forwarder exit");

    let stats = expect_session_stats_json(
        &mut session,
        STATS_WAIT_MS,
        &format!("did not see stats JSON line within {:?}", STATS_WAIT_MS),
    );
    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap();
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap();
    let c2u_bytes = stats["c2u_bytes"].as_u64().unwrap();
    let u2c_bytes = stats["u2c_bytes"].as_u64().unwrap();
    assert_eq!(c2u_bytes, c2u_pkts * (payload.len() as u64));
    assert_eq!(u2c_bytes, u2c_pkts * (payload.len() as u64));
    eprintln!("{proto} stress summary: sent={sent} received={rcvd} c2u={c2u_pkts} u2c={u2c_pkts}");

    assert!(
        u2c_pkts >= rcvd,
        "u2c_pkts too low: u2c_pkts={u2c_pkts} rcvd={rcvd} rcvd_pct={rcvd_pct:.2}% stats={}",
        stats
    );

    let min_pct = if proto.eq_ignore_ascii_case("icmp") {
        #[cfg(not(windows))]
        {
            15.0
        }
        #[cfg(windows)]
        {
            5.0
        }
    } else {
        60.0
    };
    let c2u_pct = if sent == 0 {
        0.0
    } else {
        (c2u_pkts as f64) * 100.0 / (sent as f64)
    };
    assert!(
        c2u_pct >= min_pct,
        "c2u_pkts too low: sent={sent} c2u_pkts={c2u_pkts} c2u_pct={c2u_pct:.2}% min={min_pct}% stats={}",
        stats
    );
    assert!(
        rcvd_pct >= min_pct,
        "rcvd ratio too low: sent={sent} rcvd={rcvd} rcvd_pct={rcvd_pct:.2}% min={min_pct}% stats={}",
        stats
    );
}

#[test]
fn stress_sender_keeps_an_active_flow_alive_after_a_dropped_reply() {
    let now = Instant::now();
    let sent = STRESS_MAX_IN_FLIGHT_PACKETS;
    let received = 0_u64;
    assert_eq!(
        stress_send_burst(sent, received, now, now + STRESS_STALL_KEEPALIVE_INTERVAL),
        0,
        "a saturated response window must remain throttled before its keepalive is due"
    );
    assert_eq!(
        stress_send_burst(sent, received, now, now),
        1,
        "a dropped reply must not permanently stop input and trigger an idle timeout"
    );
    assert!(
        STRESS_STALL_KEEPALIVE_INTERVAL < TIMEOUT_SECS,
        "the saturated-window keepalive must precede the stress forwarder's idle timeout"
    );
}
