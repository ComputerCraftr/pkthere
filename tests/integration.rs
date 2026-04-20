#[path = "common/app_bin.rs"]
mod app_bin;
#[path = "common/core.rs"]
mod core;
#[path = "common/matrix.rs"]
mod matrix;
#[path = "common/orchestrator.rs"]
mod orchestrator;
#[path = "common/runtime_asserts.rs"]
mod runtime_asserts;

use crate::core::{
    IpFamily, JSON_WAIT_MS, MAX_WAIT_SECS, SUPPORTED_PROTOCOLS, bind_udp_client,
    random_unprivileged_port, spawn_udp_echo_server, wait_for_stats_json_from,
};
use crate::matrix::{
    IPV4_ONLY_FAMILIES, MatrixCase, SOCKET_MODES, bind_client_or_skip, run_matrix_cases,
    spawn_echo_or_skip,
};
use crate::orchestrator::{ForwarderConfig, launch_forwarder, wait_for_child_exit_success};
use crate::runtime_asserts::{
    CLIENT_WAIT_MS, json_addr, send_until_locked, wait_for_locked_client_from,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::runtime_asserts::{expect_no_echo, wait_for_stats_matching};

use std::io::ErrorKind;
use std::thread;
use std::time::Duration;

#[test]
fn enforce_max_payload_all() {
    for (family, max_payload, recv_buf_len) in [
        (IpFamily::V4, 548usize, 2048usize),
        (IpFamily::V6, 1232usize, 4096usize),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            run_enforce_max_payload(case, max_payload, recv_buf_len);
        });
    }
}

fn run_enforce_max_payload(case: MatrixCase<'_>, max_payload: usize, recv_buf_len: usize) {
    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let Some((up_addr, _up_thread)) = spawn_echo_or_skip(case.family) else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: format!("{}:{up_addr}", case.proto),
        timeout_action: "exit",
        max_payload: Some(max_payload),
        fast_stats: false,
        stats_interval_mins: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (max payload)");

    let ok = vec![255u8; max_payload];
    client_sock.send(&ok).expect("send max payload");
    let mut buf = vec![0u8; recv_buf_len];
    let _ = client_sock
        .recv(&mut buf)
        .expect("recv from forwarder (max payload)");

    let over = vec![255u8; max_payload + 1];
    client_sock.send(&over).expect("send oversize payload");
    client_sock
        .set_read_timeout(Some(CLIENT_WAIT_MS))
        .expect("set read timeout");
    assert!(
        client_sock.recv(&mut buf).is_err(),
        "oversize payload should be dropped"
    );

    wait_for_child_exit_success(&mut session.child, MAX_WAIT_SECS);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    assert_eq!(stats["c2u_drops_oversize"].as_u64().unwrap_or(0), 1);
}

#[test]
fn single_client_forwarding_all() {
    for (family, payload) in [
        (IpFamily::V4, b"hello-through-forwarder".as_slice()),
        (IpFamily::V6, b"hello-through-forwarder-v6".as_slice()),
    ] {
        run_matrix_cases(&[family], SUPPORTED_PROTOCOLS, &SOCKET_MODES, |case| {
            run_single_client_forwarding(case, payload);
        });
    }
}

fn run_single_client_forwarding(case: MatrixCase<'_>, payload: &[u8]) {
    const COUNT: usize = 5;

    let Some(client_sock) = bind_client_or_skip(case.family) else {
        return;
    };
    let client_local = client_sock.local_addr().expect("client local addr");
    let Some((up_addr, _up_thread)) = spawn_echo_or_skip(case.family) else {
        return;
    };

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: case.family.listen_arg().to_string(),
        there: format!("{}:{up_addr}", case.proto),
        timeout_action: "exit",
        max_payload: None,
        fast_stats: false,
        stats_interval_mins: None,
    });

    client_sock
        .connect(session.listen_addr)
        .expect("connect to forwarder (single client)");

    for _ in 0..COUNT {
        client_sock
            .send(payload)
            .expect("send to forwarder (single client)");
        let mut buf = [0u8; 2048];
        let n = client_sock
            .recv(&mut buf)
            .expect("recv from forwarder (single client)");
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

    let stats_client = json_addr(&stats["client_addr"]).expect("parse stats client_addr");
    assert_eq!(stats_client, client_local, "stats client_addr mismatch");
    let stats_upstream = json_addr(&stats["upstream_addr"]).expect("parse stats upstream_addr");
    assert_eq!(stats_upstream, up_addr, "stats upstream_addr mismatch");

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
fn relock_after_timeout_drop_all() {
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
    let up_addr = spawn_udp_echo_server(IpFamily::V4)
        .expect("IPv4 echo server could not bind")
        .0;
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:127.0.0.1:{here_port}"),
        there: format!("{}:{up_addr}", case.proto),
        timeout_action: "drop",
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
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
    let n = got.expect("did not receive echo from forwarder after re-lock");
    assert_eq!(&buf[..n], payload_b);

    let stats = wait_for_stats_json_from(&mut session.out, JSON_WAIT_MS).expect(&format!(
        "did not see stats JSON line within {:?}",
        JSON_WAIT_MS
    ));
    let _ = session.child.kill();

    let stats_client = json_addr(&stats["client_addr"]).expect("parse stats client_addr");
    assert_eq!(
        stats_client, client_b_local,
        "forwarder did not relock to client B"
    );

    let c2u_pkts = stats["c2u_pkts"].as_u64().unwrap_or(0);
    let u2c_pkts = stats["u2c_pkts"].as_u64().unwrap_or(0);
    assert!(c2u_pkts >= 2 && u2c_pkts >= 2);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn timeout_drop_relocks_after_forward_errors_udp() {
    run_matrix_cases(&IPV4_ONLY_FAMILIES, &["UDP"], &SOCKET_MODES, |case| {
        timeout_drop_relocks_after_forward_errors_udp_case(case);
    });
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn timeout_drop_relocks_after_forward_errors_udp_case(case: MatrixCase<'_>) {
    let client_a = bind_udp_client(IpFamily::V4).expect("client_a IPv4 loopback not available");
    let client_b = bind_udp_client(IpFamily::V4).expect("client_b IPv4 loopback not available");
    let dead_upstream_port = random_unprivileged_port(IpFamily::V4).expect("dead upstream port");
    let here_port = random_unprivileged_port(IpFamily::V4).expect("ephemeral listen port");

    let mut session = launch_forwarder(ForwarderConfig {
        mode: case.mode,
        here: format!("UDP:127.0.0.1:{here_port}"),
        there: format!("UDP:127.0.0.1:{dead_upstream_port}"),
        timeout_action: "drop",
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
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
        json_addr(&stats["client_addr"]).expect("stats client addr"),
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
