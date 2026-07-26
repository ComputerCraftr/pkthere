use crate::{
    CLIENT_WAIT_MS, Domain, ForwarderConfig, LEGIT_PAYLOAD_1, STATS_WAIT_MS, bind_udp_client,
    expect_session_stats_matching, launch_forwarder, localhost_addr, random_unprivileged_port,
    recv_legitimate_echo_with_retry, render_canonical_ip_id, spawn_echo_or_skip, udp_listen_arg,
    worker_flow,
};

#[test]
fn udp_upstream_explicit_source_port_is_bound_from_cli() {
    let family = Domain::IPV4;
    let client = bind_udp_client(family).expect("client bind");
    let (up_addr, _upstream_echo) =
        spawn_echo_or_skip(family).expect("IPv4 UDP echo server is required");
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
        timeout_secs: None,
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
            worker_flow::find_locked_worker_flow(stats).is_some_and(|worker| {
                worker["upstream_local_filter"]
                    .as_str()
                    .is_some_and(|addr| addr == render_canonical_ip_id(up_addr.ip(), source_port))
            })
        },
    );
    let worker = worker_flow::locked_worker_flow(&stats);
    assert_eq!(
        worker_flow::worker_str(worker, "upstream_local_filter"),
        render_canonical_ip_id(up_addr.ip(), source_port)
    );
}
