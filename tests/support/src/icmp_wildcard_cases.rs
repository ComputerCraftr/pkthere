use crate::fixtures::{MULTIHOP_NODE_TIMEOUT_SECS, localhost_ip};
use crate::forwarder::{ForwarderConfig, launch_forwarder};
use crate::matrix::{ALL_CONNECT_MODES, IPV4_ONLY_FAMILIES, bind_client_or_skip, run_matrix_cases};
use crate::network::{localhost_addr, render_canonical_ip_id, render_icmp_arg, udp_listen_arg};
use crate::raw_icmp::acquire_raw_icmp_lock;
use crate::runtime_asserts::{expect_session_stats_matching, recv_legitimate_echo_with_retry};
use crate::timing::RAW_ICMP_LOCK_WAIT;
use crate::timing::{CLIENT_WAIT_MS, STATS_WAIT_MS};
use crate::worker_flow;
use socket2::Domain;

const DEBUG_TRACE_LOGS: &[&str] = &["packets", "drops", "handles"];

#[test]
#[ignore = "privileged RAW wildcard topology runs through the explicit capability runner"]
fn raw_icmp_wildcard_upstream_locks_on_localhost() {
    assert!(
        crate::runtime_capability::raw_icmp_enabled(),
        "RAW wildcard topology requires PKTHERE_ALLOW_RAW_ICMP=1"
    );
    let _raw_icmp_guard = acquire_raw_icmp_lock(
        std::time::Instant::now() + RAW_ICMP_LOCK_WAIT,
        "icmp_wildcard_case",
    )
    .expect("acquire RAW ICMP lock");
    run_matrix_cases(
        &IPV4_ONLY_FAMILIES,
        &["icmp"],
        &ALL_CONNECT_MODES,
        &[false],
        |case| {
            run_raw_icmp_wildcard_listener_case(
                case.family,
                case.debug_client_unconnected,
                case.debug_upstream_unconnected,
            );
        },
    );
}

fn run_raw_icmp_wildcard_listener_case(
    family: Domain,
    debug_client_unconnected: bool,
    debug_upstream_unconnected: bool,
) {
    let Some(client_sock) = bind_client_or_skip(family) else {
        return;
    };
    let local_ip = localhost_ip(family);

    // Debug RAW wildcard topology:
    //   UDP client -> node_a UDP listener
    //   node_a:<selected> -> node_a:<selected> through RAW ICMP
    // The debug override keeps RAW transport so localhost packet capture reaches
    // the pkthere listener path, but intentionally models DGRAM no-disjoint
    // semantics: the selected source ID and negotiated reply/destination ID are
    // the same concrete nonzero endpoint.
    let mut node_a = launch_forwarder(ForwarderConfig {
        debug_client_unconnected,
        debug_upstream_unconnected,
        debug_icmp_kernel_echo_self_handshake: true,
        debug_force_raw_icmp_wildcard_upstream: true,
        here: udp_listen_arg(localhost_addr(family, 0)),
        there: render_icmp_arg(local_ip, 0),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(0),
        there_reply_id: Some(0),
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

    let stats_a_prelock = expect_session_stats_matching(
        &mut node_a,
        STATS_WAIT_MS,
        "did not see debug RAW wildcard upstream select a concrete ID",
        |s| {
            s["worker_flows"]
                .as_array()
                .and_then(|flows| flows.first())
                .and_then(|worker| worker["upstream_local_filter_canonical"].as_str())
                .is_some_and(|addr| addr != render_canonical_ip_id(local_ip, 0))
        },
    );
    let worker_a_prelock = stats_a_prelock["worker_flows"]
        .as_array()
        .and_then(|flows| flows.first())
        .expect("worker flow entry");
    assert_eq!(
        worker_flow::worker_str(worker_a_prelock, "upstream_sock_type"),
        "RAW"
    );
    let upstream_local =
        worker_flow::worker_str(worker_a_prelock, "upstream_local_filter_canonical").to_string();
    let upstream_remote =
        worker_flow::worker_str(worker_a_prelock, "upstream_remote_filter_canonical").to_string();
    assert_eq!(
        upstream_local, upstream_remote,
        "debug RAW wildcard upstream should model DGRAM no-disjoint IDs before traffic"
    );
    let upstream_id = upstream_local
        .rsplit_once(':')
        .expect("canonical endpoint contains id")
        .1
        .parse::<u16>()
        .expect("canonical endpoint id is numeric");

    client_sock
        .connect(node_a.listen_addr)
        .expect("connect client to A");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set client read timeout");

    let payload = format!(
        "wildcard-icmp-lock-{family:?}-{debug_client_unconnected}-{debug_upstream_unconnected}"
    );
    let mut buf = [0u8; 2048];
    let n = recv_legitimate_echo_with_retry(
        &client_sock,
        payload.as_bytes(),
        &mut buf,
        "wildcard RAW",
        "echo",
    )
    .unwrap_or_else(|error| {
        panic!(
            "{error}\nnode diagnostics:\n{}",
            node_a.diagnostic_snapshot(100)
        )
    });
    assert_eq!(&buf[..n], payload.as_bytes());

    let stats_a = expect_session_stats_matching(
        &mut node_a,
        STATS_WAIT_MS,
        "did not see wildcard upstream stats",
        |s| {
            s["c2u_pkts"].as_u64().expect("missing c2u_pkts") >= 1
                && s["u2c_pkts"].as_u64().expect("missing u2c_pkts") >= 1
        },
    );
    let worker_a = worker_flow::locked_worker_flow(&stats_a);
    assert_eq!(
        worker_flow::worker_str(worker_a, "upstream_sock_type"),
        "RAW"
    );
    let upstream_local = worker_flow::worker_str(worker_a, "upstream_local_filter_canonical");
    let upstream_remote = worker_flow::worker_str(worker_a, "upstream_remote_filter_canonical");
    assert_eq!(
        upstream_local, upstream_remote,
        "debug RAW wildcard upstream should model DGRAM no-disjoint IDs"
    );
    assert_ne!(upstream_local, render_canonical_ip_id(local_ip, 0));
    worker_flow::assert_flow_tuple(
        worker_a,
        "upstream_flow_inbound",
        upstream_remote,
        upstream_local,
    );
    worker_flow::assert_flow_tuple(
        worker_a,
        "upstream_flow_outbound",
        upstream_local,
        upstream_remote,
    );
    assert_eq!(
        worker_flow::worker_str(worker_a, "upstream_local_filter_canonical"),
        render_canonical_ip_id(local_ip, upstream_id)
    );
}
