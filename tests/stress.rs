#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/orchestrator.rs"]
mod orchestrator;

use crate::core::{JSON_WAIT_MS, MAX_WAIT_SECS, SUPPORTED_PROTOCOLS, wait_for_stats_json_from};
use crate::orchestrator::{
    ForwarderConfig, IpFamily, SocketMode, bind_udp_client, launch_forwarder,
    random_unprivileged_port, spawn_udp_echo_server, wait_for_child_exit_success,
};

use std::io;
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn stress_test_ipv4_all() {
    let _ = IpFamily::V6;
    let _ = SocketMode::Unconnected;
    for &proto in SUPPORTED_PROTOCOLS {
        stress_test_ipv4(proto);
    }
}

fn stress_test_ipv4(proto: &str) {
    let client_sock = bind_udp_client(IpFamily::V4).expect("IPv4 loopback not available");

    let up_addr = if !proto.eq_ignore_ascii_case("icmp") {
        spawn_udp_echo_server(IpFamily::V4)
            .expect("IPv4 echo server could not bind")
            .0
    } else {
        let ident = random_unprivileged_port(IpFamily::V4).expect("random ICMP identifier");
        format!("127.0.0.1:{ident}")
            .parse::<SocketAddr>()
            .expect("IPv4 socket address could not be parsed")
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: SocketMode::Connected,
        here: "UDP:127.0.0.1:0".to_string(),
        there: format!("{proto}:{up_addr}"),
        timeout_action: "exit",
        timeout_secs: None,
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: Some(1),
        icmp_sync_pps: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (IPv4)");

    let payload = vec![255u8; 1400];
    client_sock
        .send(&payload)
        .expect("send to forwarder (IPv4)");

    let end = Instant::now() + Duration::from_secs(20);
    let mut sent = 0u64;

    let recv_sock = client_sock.try_clone().expect("clone recv socket");
    let recv_thr = thread::spawn(move || {
        let mut rcvd = 0u64;
        let mut buf = [0u8; 65535];
        while Instant::now() < end {
            match recv_sock.recv(&mut buf) {
                Ok(_) => rcvd += 1,
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => panic!("recv from forwarder (IPv4): {e}"),
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
        thread::sleep(Duration::from_micros(50));
    }

    let rcvd = recv_thr.join().expect("join recv thread");
    let rcvd_pct = if sent == 0 {
        0.0
    } else {
        (rcvd as f64) * 100.0 / (sent as f64)
    };

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
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
        40.0
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
