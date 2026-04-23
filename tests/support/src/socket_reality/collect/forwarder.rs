use crate::fixtures::{
    INDEPENDENT_IDS_PAYLOAD, MULTIHOP_NODE_TIMEOUT_SECS, REALITY_RELOCK_TIMEOUT_SECS, localhost_ip,
};
use crate::forwarder::{
    ForwarderConfig, ForwarderSession, launch_forwarder, launch_forwarder_with_extra_args,
};
use crate::matrix::bind_client_or_skip;
use crate::network::{localhost_addr, render_icmp_arg, spawn_udp_echo_server, udp_listen_arg};
use crate::runtime_asserts::wait_for_session_stats_matching;
use crate::socket_reality::case::RealityCase;
use crate::socket_reality::evidence::{
    CallResult, ClientReceiveEvidence, ExitStatusEvidence, ForwarderEvidence,
    ForwarderLifecycleEvidence, ForwarderProcessEvidence,
};
use crate::socket_reality::witness::{
    ClientSendObservation, UdpWitness, client_send_observation, probe_payload,
};
use crate::timing::{
    CLIENT_WAIT_MS, DRAIN_WAIT_MS, MAX_WAIT_SECS, RETRY_RECV_WAIT_MS, STATS_WAIT_MS,
    TEST_RETRY_INTERVAL,
};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const CLIENT_SOURCE_ID: u16 = 40000;
const CLIENT_REPLY_ID: u16 = 40001;
const SERVER_LISTEN_ID: u16 = 9999;
const SERVER_SOURCE_ID: u16 = 7777;
const NEGATIVE_WINDOW: Duration = DRAIN_WAIT_MS;
static NEXT_LIFECYCLE_FILE: AtomicU64 = AtomicU64::new(1);

pub fn collect_raw_four_id(case: &RealityCase) -> io::Result<ForwarderEvidence> {
    if case.domain != Domain::IPV4
        || case.protocol != SupportedProtocol::ICMP
        || case.socket_type != Type::RAW
        || case.connected
    {
        return Err(io::Error::other(format!(
            "RAW four-ID collector does not support case {case:?}"
        )));
    }

    let client = bind_client_or_skip(Domain::IPV4)
        .ok_or_else(|| io::Error::other("IPv4 UDP client bind unavailable"))?;
    let echo_server = spawn_udp_echo_server(Domain::IPV4)?;
    let udp_upstream = echo_server.address();
    let local_ip = localhost_ip(Domain::IPV4);

    let node_b_here = render_icmp_arg(local_ip, SERVER_LISTEN_ID);
    let node_b_there = format!("UDP:{udp_upstream}");
    let mut node_b = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: node_b_here.clone(),
        there: node_b_there.clone(),
        here_source_id: Some(SERVER_SOURCE_ID),
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "drops", "handles", "handshake"],
        diagnostic_label: Some("socket-reality-raw-b"),
        icmp_handshake_timeout_secs: None,
    });

    let node_a_here = udp_listen_arg(localhost_addr(Domain::IPV4, 0));
    let node_a_there = render_icmp_arg(local_ip, SERVER_LISTEN_ID);
    let mut node_a = launch_forwarder(ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here: node_a_here.clone(),
        there: node_a_there.clone(),
        here_source_id: None,
        here_reply_id: None,
        there_source_id: Some(CLIENT_SOURCE_ID),
        there_reply_id: Some(CLIENT_REPLY_ID),
        timeout_action: "exit",
        timeout_secs: Some(MULTIHOP_NODE_TIMEOUT_SECS),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "drops", "handles", "handshake"],
        diagnostic_label: Some("socket-reality-raw-a"),
        icmp_handshake_timeout_secs: None,
    });

    client.connect(node_a.listen_addr)?;
    let client_received = collect_four_id_client_reply(&client)?;

    let node_a_arguments = node_a.command_arguments().to_vec();
    let node_b_arguments = node_b.command_arguments().to_vec();
    let process_a = capture_process(&mut node_a, "node-a", node_a_arguments)?;
    let process_b = capture_process(&mut node_b, "node-b", node_b_arguments)?;

    Ok(ForwarderEvidence {
        processes: vec![process_a, process_b],
        client_sent: INDEPENDENT_IDS_PAYLOAD.to_vec(),
        client_received,
    })
}

fn collect_four_id_client_reply(client: &UdpSocket) -> io::Result<CallResult<Vec<u8>>> {
    client.set_read_timeout(Some(RETRY_RECV_WAIT_MS))?;
    let deadline = Instant::now() + CLIENT_WAIT_MS;
    loop {
        client.send(INDEPENDENT_IDS_PAYLOAD)?;
        let mut received = vec![0u8; 2048];
        match client.recv(&mut received) {
            Ok(length) => {
                received.truncate(length);
                return Ok(CallResult::Ok(received));
            }
            Err(_) if Instant::now() < deadline => {
                thread::sleep(TEST_RETRY_INTERVAL);
            }
            Err(error) => return Ok(CallResult::OsError((&error).into())),
        }
    }
}

pub fn collect_lifecycle(case: &RealityCase) -> io::Result<ForwarderLifecycleEvidence> {
    match case.operation {
        crate::socket_reality::case::RealityOperation::UpstreamReconnect => {
            collect_upstream_reconnect(case)
        }
        crate::socket_reality::case::RealityOperation::ListenerRelock => {
            collect_listener_relock(case)
        }
        crate::socket_reality::case::RealityOperation::ListenerRebind => {
            collect_listener_rebind(case)
        }
        _ => Err(io::Error::other(format!(
            "lifecycle collector does not execute {case:?}"
        ))),
    }
}

fn collect_upstream_reconnect(case: &RealityCase) -> io::Result<ForwarderLifecycleEvidence> {
    require_udp_lifecycle(case, SocketRole::Upstream)?;
    let witness_a = UdpWitness::spawn("target-a", localhost_addr(case.domain, 0))?;
    let target_domain = case
        .target_domain
        .ok_or_else(|| io::Error::other("upstream lifecycle case omitted target domain"))?;
    let witness_b = UdpWitness::spawn("target-b", localhost_addr(target_domain, 0))?;
    let resolver_path = resolver_path();
    write_resolver_revision(&resolver_path, 1, None, Some(witness_a.local_addr()))?;
    let extra = resolver_args(&resolver_path, "upstream");
    let mut config = udp_forwarder_config(
        format!("UDP:{}", localhost_addr(case.domain, 0)),
        format!("UDP:{}", witness_a.local_addr()),
        10,
    );
    config.debug_upstream_unconnected = !case.connected;
    let mut session = launch_forwarder_with_extra_args(config, &extra);
    let client = configured_client(session.listen_addr)?;
    let started = Instant::now();
    let mut sends = Vec::new();
    let mut receives = Vec::new();
    send_probe_until_reply(
        &client,
        session.listen_addr,
        1,
        1,
        started,
        &mut sends,
        &mut receives,
    );
    write_resolver_revision(&resolver_path, 2, None, Some(witness_b.local_addr()))?;
    wait_for_resolver_revision(&mut session, 2)?;
    wait_for_worker_refresh_after_revision(&mut session, 2, "c2u")?;
    send_probe_until_reply(
        &client,
        session.listen_addr,
        2,
        2,
        started,
        &mut sends,
        &mut receives,
    );
    thread::sleep(NEGATIVE_WINDOW);
    let command_arguments = session.command_arguments().to_vec();
    let process = capture_process(&mut session, "lifecycle-forwarder", command_arguments)?;
    fs::remove_file(&resolver_path).ok();
    let mut observations = witness_a.observations();
    observations.extend(witness_b.observations());
    Ok(ForwarderLifecycleEvidence {
        process,
        client_sends: sends,
        client_receives: receives,
        endpoint_observations: observations,
        negative_observation_window: NEGATIVE_WINDOW,
    })
}

fn collect_listener_rebind(case: &RealityCase) -> io::Result<ForwarderLifecycleEvidence> {
    require_udp_lifecycle(case, SocketRole::Listener)?;
    let upstream = UdpWitness::spawn("upstream", ipv4(127, 0, 0, 1, 0))?;
    let target_domain = case
        .target_domain
        .ok_or_else(|| io::Error::other("listener lifecycle case omitted target domain"))?;
    let listen_a = localhost_addr(Domain::IPV4, reserve_port(localhost_addr(Domain::IPV4, 0))?);
    let listen_b = distinct_loopback_addr(target_domain, listen_a.port())?;
    let resolver_path = resolver_path();
    write_resolver_revision(&resolver_path, 1, Some(listen_a), None)?;
    let extra = resolver_args(&resolver_path, "listen");
    let mut session = launch_forwarder_with_extra_args(
        udp_forwarder_config(
            format!("UDP:{listen_a}"),
            format!("UDP:{}", upstream.local_addr()),
            10,
        ),
        &extra,
    );
    let client_a = configured_unconnected_client(Domain::IPV4)?;
    let client_b = configured_unconnected_client(target_domain)?;
    let started = Instant::now();
    let mut sends = Vec::new();
    let mut receives = Vec::new();
    send_probe_until_reply(
        &client_a,
        listen_a,
        11,
        1,
        started,
        &mut sends,
        &mut receives,
    );
    write_resolver_revision(&resolver_path, 2, Some(listen_b), None)?;
    wait_for_resolver_revision(&mut session, 2)?;
    wait_for_worker_refresh_after_revision(&mut session, 2, "c2u")?;
    send_probe_until_reply(
        &client_b,
        listen_b,
        12,
        2,
        started,
        &mut sends,
        &mut receives,
    );
    send_probe_without_reply(&client_a, listen_a, 13, 3, started, &mut sends);
    thread::sleep(NEGATIVE_WINDOW);
    let command_arguments = session.command_arguments().to_vec();
    let process = capture_process(&mut session, "lifecycle-forwarder", command_arguments)?;
    fs::remove_file(&resolver_path).ok();
    Ok(ForwarderLifecycleEvidence {
        process,
        client_sends: sends,
        client_receives: receives,
        endpoint_observations: upstream.observations(),
        negative_observation_window: NEGATIVE_WINDOW,
    })
}

fn collect_listener_relock(case: &RealityCase) -> io::Result<ForwarderLifecycleEvidence> {
    require_udp_lifecycle(case, SocketRole::Listener)?;
    let upstream = UdpWitness::spawn("upstream", localhost_addr(case.domain, 0))?;
    let mut config = udp_forwarder_config(
        format!("UDP:{}", localhost_addr(case.domain, 0)),
        format!("UDP:{}", upstream.local_addr()),
        REALITY_RELOCK_TIMEOUT_SECS,
    );
    config.debug_client_unconnected = !case.connected;
    let mut session = launch_forwarder(config);
    let client_a = configured_unconnected_client(case.domain)?;
    let client_b = configured_unconnected_client(case.domain)?;
    let started = Instant::now();
    let mut sends = Vec::new();
    let mut receives = Vec::new();
    send_probe_until_reply(
        &client_a,
        session.listen_addr,
        21,
        1,
        started,
        &mut sends,
        &mut receives,
    );
    send_probe_without_reply(&client_b, session.listen_addr, 22, 2, started, &mut sends);
    wait_for_log(&mut session, "watchdog publish disconnect")?;
    send_probe_until_reply(
        &client_b,
        session.listen_addr,
        23,
        3,
        started,
        &mut sends,
        &mut receives,
    );
    let client_b_key = client_b.local_addr()?.to_string();
    let stats = wait_for_session_stats_matching(&mut session, STATS_WAIT_MS, |stats| {
        stats["worker_flows"].as_array().is_some_and(|flows| {
            flows.iter().any(|flow| {
                flow["locked"].as_bool() == Some(true)
                    && flow["flow_key"].as_str() == Some(client_b_key.as_str())
            })
        })
    });
    if !stats.matched {
        return Err(io::Error::other(format!(
            "listener relock did not publish client B stats\n{}",
            stats.failure_details()
        )));
    }
    thread::sleep(NEGATIVE_WINDOW);
    let command_arguments = session.command_arguments().to_vec();
    let process = capture_process(&mut session, "lifecycle-forwarder", command_arguments)?;
    Ok(ForwarderLifecycleEvidence {
        process,
        client_sends: sends,
        client_receives: receives,
        endpoint_observations: upstream.observations(),
        negative_observation_window: NEGATIVE_WINDOW,
    })
}

fn udp_forwarder_config(
    here: String,
    there: String,
    timeout_secs: u64,
) -> ForwarderConfig<'static> {
    ForwarderConfig {
        debug_client_unconnected: false,
        debug_upstream_unconnected: false,
        debug_icmp_kernel_echo_self_handshake: false,
        debug_force_raw_icmp_wildcard_upstream: false,
        here,
        there,
        here_source_id: None,
        here_reply_id: None,
        there_source_id: None,
        there_reply_id: None,
        timeout_action: "drop",
        timeout_secs: Some(timeout_secs),
        max_payload: None,
        fast_stats: true,
        stats_interval_mins: None,
        icmp_sync_pps: None,
        debug_logs: &["packet-dump", "drops", "handles"],
        diagnostic_label: Some("socket-reality-lifecycle"),
        icmp_handshake_timeout_secs: None,
    }
}

fn require_udp_lifecycle(case: &RealityCase, role: SocketRole) -> io::Result<()> {
    if matches!(case.domain, Domain::IPV4 | Domain::IPV6)
        && matches!(
            case.target_domain,
            Some(domain) if domain == Domain::IPV4 || domain == Domain::IPV6
        )
        && case.protocol == SupportedProtocol::UDP
        && case.socket_type == Type::DGRAM
        && case.policy_role == role
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "unsupported lifecycle case {case:?}"
        )))
    }
}

fn configured_client(destination: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if destination.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = configured_unconnected_client(domain)?;
    socket.connect(destination)?;
    Ok(socket)
}

fn configured_unconnected_client(domain: Domain) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(localhost_addr(domain, 0))?;
    socket.set_read_timeout(Some(RETRY_RECV_WAIT_MS))?;
    Ok(socket)
}

fn send_probe(
    socket: &UdpSocket,
    destination: SocketAddr,
    probe_id: u64,
    sequence: u64,
    started: Instant,
    sends: &mut Vec<ClientSendObservation>,
    receives: &mut Vec<ClientReceiveEvidence>,
) {
    let payload = probe_payload(probe_id);
    let source = socket.local_addr().expect("client getsockname");
    let result = if socket.peer_addr().ok() == Some(destination) {
        socket.send(&payload)
    } else {
        socket.send_to(&payload, destination)
    };
    result.expect("send lifecycle probe");
    sends.push(client_send_observation(
        sequence,
        source,
        destination,
        probe_id,
        &payload,
        started.elapsed(),
    ));
    let mut reply = vec![0u8; 2048];
    let result = match socket.recv(&mut reply) {
        Ok(length) => {
            reply.truncate(length);
            CallResult::Ok(reply)
        }
        Err(error) => CallResult::OsError((&error).into()),
    };
    receives.push(ClientReceiveEvidence {
        probe_id,
        payload: result,
    });
}

fn send_probe_until_reply(
    socket: &UdpSocket,
    destination: SocketAddr,
    probe_id: u64,
    sequence: u64,
    started: Instant,
    sends: &mut Vec<ClientSendObservation>,
    receives: &mut Vec<ClientReceiveEvidence>,
) {
    let deadline = Instant::now() + CLIENT_WAIT_MS;
    let mut attempt = 0;
    while Instant::now() < deadline {
        send_probe(
            socket,
            destination,
            probe_id,
            sequence.saturating_add(attempt),
            started,
            sends,
            receives,
        );
        if receives.last().is_some_and(|receive| {
            receive.probe_id == probe_id && receive.payload.as_ok().is_some()
        }) {
            return;
        }
        attempt = attempt.saturating_add(1);
        thread::sleep(TEST_RETRY_INTERVAL);
    }
}

fn send_probe_without_reply(
    socket: &UdpSocket,
    destination: SocketAddr,
    probe_id: u64,
    sequence: u64,
    started: Instant,
    sends: &mut Vec<ClientSendObservation>,
) {
    let payload = probe_payload(probe_id);
    if socket.peer_addr().ok() == Some(destination) {
        socket.send(&payload)
    } else {
        socket.send_to(&payload, destination)
    }
    .expect("send negative lifecycle probe");
    sends.push(client_send_observation(
        sequence,
        socket.local_addr().expect("client getsockname"),
        destination,
        probe_id,
        &payload,
        started.elapsed(),
    ));
}

fn resolver_args(path: &Path, mode: &str) -> Vec<String> {
    vec![
        "--reresolve-secs".to_owned(),
        "1".to_owned(),
        "--reresolve-mode".to_owned(),
        mode.to_owned(),
        "--debug-reresolve-address-file".to_owned(),
        path.display().to_string(),
    ]
}

fn resolver_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pkthere-reality-resolver-{}-{}.json",
        std::process::id(),
        NEXT_LIFECYCLE_FILE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_resolver_revision(
    path: &Path,
    revision: u64,
    listen_addr: Option<SocketAddr>,
    upstream_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut object = serde_json::Map::new();
    object.insert("revision".to_owned(), revision.into());
    if let Some(addr) = listen_addr {
        object.insert("listen_addr".to_owned(), addr.to_string().into());
    }
    if let Some(addr) = upstream_addr {
        object.insert("upstream_addr".to_owned(), addr.to_string().into());
    }
    fs::write(&temporary, serde_json::Value::Object(object).to_string())?;
    replace_file(&temporary, path)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wait_for_resolver_revision(session: &mut ForwarderSession, revision: u64) -> io::Result<()> {
    let needle = format!("\"revision\":{revision}");
    wait_for_output(session, |stderr| {
        stderr.contains("resolver-evidence")
            && stderr.contains(&needle)
            && stderr.contains("\"application_result\":\"applied\"")
    })
}

fn wait_for_worker_refresh_after_revision(
    session: &mut ForwarderSession,
    revision: u64,
    direction: &str,
) -> io::Result<()> {
    let revision_needle = format!("\"revision\":{revision}");
    let refresh_needle = format!("[{direction}] refresh_handles_and_cache");
    wait_for_output(session, |stderr| {
        stderr
            .find(&revision_needle)
            .is_some_and(|revision_at| stderr[revision_at..].contains(&refresh_needle))
    })
}

fn wait_for_log(session: &mut ForwarderSession, needle: &str) -> io::Result<()> {
    wait_for_output(session, |stderr| stderr.contains(needle))
}

fn wait_for_output(
    session: &mut ForwarderSession,
    predicate: impl Fn(&str) -> bool,
) -> io::Result<()> {
    session
        .wait_for_output(
            Instant::now() + MAX_WAIT_SECS,
            "socket-reality lifecycle evidence",
            |output| predicate(&output.stderr_lossy()),
        )
        .map(|_| ())
}

fn reserve_port(bind: SocketAddr) -> io::Result<u16> {
    let socket = UdpSocket::bind(bind)?;
    Ok(socket.local_addr()?.port())
}

const fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

fn distinct_loopback_addr(domain: Domain, other_port: u16) -> io::Result<SocketAddr> {
    loop {
        let port = reserve_port(localhost_addr(domain, 0))?;
        if port != other_port {
            return Ok(localhost_addr(domain, port));
        }
    }
}

fn capture_process(
    session: &mut ForwarderSession,
    label: &str,
    command_arguments: Vec<String>,
) -> io::Result<ForwarderProcessEvidence> {
    let completed = session.terminate(
        Instant::now()
            + crate::timing::CHILD_TERMINATION_GRACE
            + crate::timing::CHILD_FORCED_REAP_WAIT,
    )?;
    let status = Some(ExitStatusEvidence::from(completed.exit.clone()));
    let stdout = completed.output.stdout_lossy();
    let stderr = completed.output.stderr_lossy();
    Ok(ForwarderProcessEvidence {
        label: label.to_string(),
        command_arguments,
        stdout,
        stderr,
        exit_status: status,
    })
}

#[cfg(test)]
mod tests {
    use super::{resolver_path, write_resolver_revision};
    use serde_json::Value;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn resolver_writer_atomically_replaces_complete_revisions() {
        let path = resolver_path();
        write_resolver_revision(
            &path,
            1,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12002)),
            None,
        )
        .expect("write first revision");
        write_resolver_revision(
            &path,
            2,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12003)),
            None,
        )
        .expect("replace with second revision");

        let value: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read revision"))
            .expect("complete JSON");
        assert_eq!(value["revision"], 2);
        assert_eq!(value["listen_addr"], "127.0.0.1:12003");
        fs::remove_file(path).expect("remove resolver fixture");
    }
}
