use pkthere_test_support::forwarder::{ForwarderConfig, launch_forwarder};
use pkthere_test_support::matrix::spawn_upstream_echo_or_skip;
use pkthere_test_support::network::{bind_udp_client, localhost_addr, udp_listen_arg};
use pkthere_test_support::runtime_asserts::expect_session_stats_json;
use pkthere_test_support::timing::{
    MAX_WAIT_SECS, STATS_WAIT_MS, STRESS_SEND_PAUSE, STRESS_TEST_DURATION,
};

use socket2::Domain;
use std::io;
use std::thread;
use std::time::Instant;

#[test]
#[ignore = "long-running release stress owner; invoked exactly by native release-stress CI"]
fn stress_test_ipv4() {
    for &proto in pkthere_test_support::runtime_capability::enabled_forward_protocols() {
        stress_test_ipv4_case(proto);
    }
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
        timeout_secs: None,
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: Some(1),
        icmp_sync_pps: None,
        debug_logs: &[],
        diagnostic_label: None,
        icmp_handshake_timeout_secs: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (IPv4)");

    let payload = vec![255u8; 1400];
    client_sock
        .send(&payload)
        .expect("send to forwarder (IPv4)");

    let end = Instant::now() + STRESS_TEST_DURATION;
    let mut sent = 0u64;

    let recv_sock = client_sock.try_clone().expect("clone recv socket");
    let recv_thr = thread::spawn(move || {
        let mut rcvd = 0u64;
        let mut buf = [0u8; 65535];
        while Instant::now() < end {
            match recv_sock.recv(&mut buf) {
                Ok(_) => rcvd += 1,
                Err(e) => {
                    let kind = e.kind();
                    if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                        continue;
                    }
                    panic!("recv from forwarder (IPv4): {e}");
                }
            }
        }
        rcvd
    });

    while Instant::now() < end {
        for _ in 0..64 {
            client_sock
                .send(&payload)
                .expect("send to forwarder (IPv4)");
            sent += 1;
        }
        thread::sleep(STRESS_SEND_PAUSE);
    }

    let rcvd = recv_thr.join().expect("join recv thread");
    let rcvd_pct = if sent == 0 {
        0.0
    } else {
        (rcvd as f64) * 100.0 / (sent as f64)
    };

    session
        .wait_for_exit_success(MAX_WAIT_SECS)
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
