use super::direct::{
    InstrumentedSocket, RAW_DISJOINT_SOURCE_ID, RAW_PROBE_SESSION_ID, REUSE_PORT_FLOWS,
    REUSE_PORT_RECEIVERS,
};
use super::icmp_dgram::{
    EchoReplyExpectation, ICMP_SEQUENCE, build_correlated_echo, next_nonce,
    observe as observe_icmp_dgram,
};
use crate::socket_reality::case::{
    ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation, RealitySocketPath,
};
use crate::socket_reality::evidence::{
    DirectSocketEvidence, IcmpDgramCollectionOutcome, IcmpDgramEvidence,
    ListenerOwnerReplacementEvidence, ProbeSocketId, RawReceiveEvidence, ReusePortFanoutEvidence,
};
use crate::timing::{SOCKET_REALITY_RECEIVE_WAIT, SOCKET_WITNESS_WAIT, TEST_POLL_INTERVAL};
use pkthere_socket_policy::{
    IcmpChecksumMode, SocketCreationPath, listener_socket_setup_policy,
    listener_worker_socket_policy,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::checksum::checksum16_header_parts;
use pkthere_wire::packet_headers::{ICMP_TUNNEL_SESSION_ID_LEN, SHIM_IS_DATA};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Instant;

pub fn collect_icmp_dgram(case: &RealityCase) -> io::Result<IcmpDgramEvidence> {
    require_case(case, SupportedProtocol::ICMP, Type::DGRAM, true)?;
    let requested_id = match case.operation {
        RealityOperation::IcmpDgramReceiveId => 0,
        RealityOperation::IcmpDgramFixedId => ICMP_DGRAM_FIXED_ID,
        operation => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported ICMP DGRAM reality operation {operation:?}"),
            ));
        }
    };
    let socket_id = ProbeSocketId(1);
    let mut socket = match InstrumentedSocket::create(socket_id, case.socket_create_spec()) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(IcmpDgramEvidence {
                direct: DirectSocketEvidence {
                    sockets: vec![create],
                },
                socket: socket_id,
                outcome: IcmpDgramCollectionOutcome::NotAttempted,
                zero_checksum_sequence: None,
                zero_checksum_outcome: None,
            });
        }
    };

    let local = loopback(case.domain);
    socket.getsockname();
    if !socket.bind(SocketAddr::new(local, requested_id)) {
        return Ok(IcmpDgramEvidence {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
            outcome: IcmpDgramCollectionOutcome::NotAttempted,
            zero_checksum_sequence: None,
            zero_checksum_outcome: None,
        });
    }
    socket.getsockname();
    if !socket.connect(SocketAddr::new(local, requested_id)) {
        return Ok(IcmpDgramEvidence {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
            outcome: IcmpDgramCollectionOutcome::NotAttempted,
            zero_checksum_sequence: None,
            zero_checksum_outcome: None,
        });
    }
    let realized_addr = socket.getsockname();
    if !socket.set_read_timeout(SOCKET_REALITY_RECEIVE_WAIT) {
        return Ok(IcmpDgramEvidence {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
            outcome: IcmpDgramCollectionOutcome::NotAttempted,
            zero_checksum_sequence: None,
            zero_checksum_outcome: None,
        });
    }
    let kernel_reported_echo_id = realized_addr.map_or(0, |address| address.port());
    let requested_echo_id = if requested_id != 0 || kernel_reported_echo_id == 0 {
        ICMP_DGRAM_FIXED_ID
    } else {
        0
    };
    let payload_nonce = next_nonce(case.domain);
    let packet = build_correlated_echo(
        case.domain,
        requested_echo_id,
        ICMP_SEQUENCE,
        &payload_nonce,
        crate::socket_reality::case::icmp_dgram_probe_checksum_mode(case.domain),
    );
    socket.send(&packet);
    let post_send_addr = socket.getsockname();
    let realized_echo_id = post_send_addr
        .or(realized_addr)
        .map(|address| address.port())
        .filter(|identifier| *identifier != 0)
        .or(Some(requested_echo_id));
    let Some(realized_echo_id) = realized_echo_id else {
        return Ok(IcmpDgramEvidence {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
            outcome: IcmpDgramCollectionOutcome::NotAttempted,
            zero_checksum_sequence: None,
            zero_checksum_outcome: None,
        });
    };
    let expectation = EchoReplyExpectation {
        peer: local,
        realized_echo_id,
        sequence: ICMP_SEQUENCE,
        payload_nonce,
    };
    let outcome = collect_icmp_dgram_probe(&mut socket, case.domain, expectation);
    let (zero_checksum_sequence, zero_checksum_outcome) =
        if case.domain == Domain::IPV4 && case.operation == RealityOperation::IcmpDgramReceiveId {
            let payload_nonce = next_nonce(case.domain);
            let sequence = ICMP_SEQUENCE.wrapping_add(1);
            let packet = build_correlated_echo(
                case.domain,
                requested_echo_id,
                sequence,
                &payload_nonce,
                IcmpChecksumMode::KernelComputed,
            );
            socket.send(&packet);
            (
                Some(sequence),
                Some(collect_icmp_dgram_probe(
                    &mut socket,
                    case.domain,
                    EchoReplyExpectation {
                        peer: local,
                        realized_echo_id,
                        sequence,
                        payload_nonce,
                    },
                )),
            )
        } else {
            (None, None)
        };

    Ok(IcmpDgramEvidence {
        direct: DirectSocketEvidence {
            sockets: vec![socket.finish()],
        },
        socket: socket_id,
        outcome,
        zero_checksum_sequence,
        zero_checksum_outcome,
    })
}

pub(super) fn collect_icmp_dgram_probe(
    socket: &mut InstrumentedSocket,
    domain: Domain,
    expectation: EchoReplyExpectation,
) -> IcmpDgramCollectionOutcome {
    let deadline = Instant::now() + SOCKET_REALITY_RECEIVE_WAIT;
    let mut observed_noise_packets = 0;
    while let Some(received) = socket.recv_from_observed(2048) {
        if let Some(outcome) =
            observe_icmp_dgram(domain, &received, expectation, &mut observed_noise_packets)
        {
            return outcome;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if !socket.set_read_timeout(remaining) {
            break;
        }
    }
    IcmpDgramCollectionOutcome::ReceiveEnded
}

pub fn collect_reuse_port_fanout(case: &RealityCase) -> io::Result<ReusePortFanoutEvidence> {
    require_case(case, SupportedProtocol::UDP, Type::DGRAM, false)?;
    let setup = listener_socket_setup_policy(
        listener_worker_socket_policy(REUSE_PORT_RECEIVERS, true),
        SocketCreationPath::Datagram,
    );
    let mut receivers = Vec::with_capacity(REUSE_PORT_RECEIVERS);
    let mut target = SocketAddr::new(loopback(case.domain), 0);
    let create = case.socket_create_spec();
    for _ in 0..REUSE_PORT_RECEIVERS {
        let socket = match Socket::new(create.domain, create.socket_type, create.protocol) {
            Ok(socket) => socket,
            Err(error) => return Ok(reuse_port_error(receivers.len(), error)),
        };
        if setup.worker.reuse_address
            && let Err(error) = socket.set_reuse_address(true)
        {
            return Ok(reuse_port_error(receivers.len(), error));
        }
        #[cfg(unix)]
        if setup.worker.reuse_port
            && let Err(error) = socket.set_reuse_port(true)
        {
            return Ok(reuse_port_error(receivers.len(), error));
        }
        #[cfg(not(unix))]
        if setup.worker.reuse_port {
            return Ok(reuse_port_error(
                receivers.len(),
                io::Error::other("policy requested SO_REUSEPORT on a non-Unix target"),
            ));
        }
        if !setup.bind_requested_address {
            return Ok(reuse_port_error(
                receivers.len(),
                io::Error::other("listener setup policy omitted bind"),
            ));
        }
        if let Err(error) = socket.bind(&SockAddr::from(target)) {
            return Ok(reuse_port_error(receivers.len(), error));
        }
        if receivers.is_empty() {
            target = socket
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("reuse-port getsockname was not INET"))?;
        }
        socket.set_nonblocking(true)?;
        receivers.push(UdpSocket::from(socket));
    }

    for flow_index in 0..REUSE_PORT_FLOWS {
        let sender = UdpSocket::bind(SocketAddr::new(loopback(case.domain), 0))?;
        sender.connect(target)?;
        sender.send(&flow_index.to_be_bytes())?;
    }

    let mut received_flow_counts = vec![0; receivers.len()];
    let mut buffer = [0u8; 64];
    let deadline = Instant::now() + SOCKET_WITNESS_WAIT;
    while Instant::now() < deadline && received_flow_counts.iter().sum::<usize>() < REUSE_PORT_FLOWS
    {
        for (index, receiver) in receivers.iter().enumerate() {
            loop {
                match receiver.recv(&mut buffer) {
                    Ok(_) => received_flow_counts[index] += 1,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Ok(ReusePortFanoutEvidence {
                            receiver_count: REUSE_PORT_RECEIVERS,
                            successful_bind_count: receivers.len(),
                            sent_flow_count: REUSE_PORT_FLOWS,
                            received_flow_counts,
                            error: Some(error.to_string()),
                        });
                    }
                }
            }
        }
        thread::sleep(TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Ok(ReusePortFanoutEvidence {
        receiver_count: REUSE_PORT_RECEIVERS,
        successful_bind_count: receivers.len(),
        sent_flow_count: REUSE_PORT_FLOWS,
        received_flow_counts,
        error: None,
    })
}

pub fn collect_listener_owner_replacement(
    case: &RealityCase,
) -> io::Result<ListenerOwnerReplacementEvidence> {
    match try_collect_listener_owner_replacement(case) {
        Ok(evidence) => Ok(evidence),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::AddrInUse | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(ListenerOwnerReplacementEvidence {
                receiver_count: REUSE_PORT_RECEIVERS,
                successful_initial_bind_count: 0,
                bound_addr: None,
                initial_owner_peer: None,
                initial_owner_received: false,
                initial_sibling_received: false,
                replacement_bind_succeeded: false,
                replacement_addr: None,
                relock_owner_peer: None,
                relock_owner_received: false,
                unsupported: Some((&error).into()),
                error: None,
            })
        }
        Err(error) => Err(error),
    }
}

pub(super) fn try_collect_listener_owner_replacement(
    case: &RealityCase,
) -> io::Result<ListenerOwnerReplacementEvidence> {
    require_case(case, SupportedProtocol::UDP, Type::DGRAM, false)?;
    let setup = listener_socket_setup_policy(
        listener_worker_socket_policy(REUSE_PORT_RECEIVERS, false),
        SocketCreationPath::Datagram,
    );
    let mut receivers = Vec::with_capacity(REUSE_PORT_RECEIVERS);
    let mut target = SocketAddr::new(loopback(case.domain), 0);
    for _ in 0..REUSE_PORT_RECEIVERS {
        let socket = Socket::new(case.domain, Type::DGRAM, Some(Protocol::UDP))?;
        if setup.worker.reuse_address {
            socket.set_reuse_address(true)?;
        }
        #[cfg(unix)]
        if setup.worker.reuse_port {
            socket.set_reuse_port(true)?;
        }
        #[cfg(not(unix))]
        if setup.worker.reuse_port {
            return Err(io::Error::other(
                "listener replacement policy requested SO_REUSEPORT on a non-Unix target",
            ));
        }
        socket.bind(&SockAddr::from(target))?;
        if receivers.is_empty() {
            target = socket
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("replacement getsockname was not INET"))?;
        }
        socket.set_nonblocking(true)?;
        receivers.push(UdpSocket::from(socket));
    }

    let client_a = UdpSocket::bind(SocketAddr::new(loopback(case.domain), 0))?;
    let client_a_addr = client_a.local_addr()?;
    receivers[0].connect(client_a_addr)?;
    let initial_owner_peer = receivers[0].peer_addr().ok();
    client_a.send_to(b"owner-a", target)?;
    let initial_receivers =
        receive_matching_receivers(&receivers, b"owner-a", Instant::now() + SOCKET_WITNESS_WAIT)?;
    let initial_owner_received = initial_receivers.contains(&0);
    let initial_sibling_received = initial_receivers.iter().any(|index| *index != 0);

    let replacement_socket = Socket::new(case.domain, Type::DGRAM, Some(Protocol::UDP))?;
    if setup.worker.reuse_address {
        replacement_socket.set_reuse_address(true)?;
    }
    #[cfg(unix)]
    if setup.worker.reuse_port {
        replacement_socket.set_reuse_port(true)?;
    }
    replacement_socket.bind(&SockAddr::from(target))?;
    replacement_socket.set_nonblocking(true)?;
    let replacement = UdpSocket::from(replacement_socket);
    let replacement_addr = replacement.local_addr()?;

    receivers.remove(0);
    receivers.push(replacement);

    let client_b = UdpSocket::bind(SocketAddr::new(loopback(case.domain), 0))?;
    let client_b_addr = client_b.local_addr()?;
    client_b.send_to(b"owner-b-select", target)?;
    let selected = receive_matching_receivers(
        &receivers,
        b"owner-b-select",
        Instant::now() + SOCKET_WITNESS_WAIT,
    )?
    .into_iter()
    .next();
    let mut relock_owner_peer = None;
    let mut relock_owner_received = false;
    if let Some(index) = selected {
        receivers[index].connect(client_b_addr)?;
        relock_owner_peer = receivers[index].peer_addr().ok();
        client_b.send_to(b"owner-b-connected", target)?;
        relock_owner_received = receive_matching_receivers(
            &receivers,
            b"owner-b-connected",
            Instant::now() + SOCKET_WITNESS_WAIT,
        )?
        .contains(&index);
    }

    Ok(ListenerOwnerReplacementEvidence {
        receiver_count: REUSE_PORT_RECEIVERS,
        successful_initial_bind_count: REUSE_PORT_RECEIVERS,
        bound_addr: Some(target),
        initial_owner_peer,
        initial_owner_received,
        initial_sibling_received,
        replacement_bind_succeeded: true,
        replacement_addr: Some(replacement_addr),
        relock_owner_peer,
        relock_owner_received,
        unsupported: None,
        error: None,
    })
}

pub(super) fn receive_matching_receivers(
    receivers: &[UdpSocket],
    expected: &[u8],
    deadline: Instant,
) -> io::Result<Vec<usize>> {
    let mut matched = Vec::new();
    let mut buffer = [0u8; 64];
    while Instant::now() < deadline && matched.is_empty() {
        for (index, receiver) in receivers.iter().enumerate() {
            loop {
                match receiver.recv(&mut buffer) {
                    Ok(length) if &buffer[..length] == expected => {
                        if !matched.contains(&index) {
                            matched.push(index);
                        }
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        if matched.is_empty() {
            thread::sleep(
                TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    Ok(matched)
}

pub(super) fn reuse_port_error(
    successful_bind_count: usize,
    error: io::Error,
) -> ReusePortFanoutEvidence {
    ReusePortFanoutEvidence {
        receiver_count: REUSE_PORT_RECEIVERS,
        successful_bind_count,
        sent_flow_count: REUSE_PORT_FLOWS,
        received_flow_counts: vec![0; successful_bind_count],
        error: Some(error.to_string()),
    }
}

pub fn collect_raw_receive(case: &RealityCase) -> io::Result<RawReceiveEvidence> {
    require_case(case, SupportedProtocol::ICMP, Type::RAW, false)?;
    let socket_id = ProbeSocketId(1);
    let mut socket = match InstrumentedSocket::create(socket_id, case.socket_create_spec()) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(RawReceiveEvidence::Direct {
                direct: DirectSocketEvidence {
                    sockets: vec![create],
                },
                socket: socket_id,
            });
        }
    };

    let local = loopback(case.domain);
    socket.getsockname();
    socket.bind(SocketAddr::new(local, 0));
    socket.getsockname();
    if case.domain == Domain::IPV4 {
        socket.get_header_included_v4();
    }
    if !socket.set_read_timeout(SOCKET_REALITY_RECEIVE_WAIT) {
        return Ok(RawReceiveEvidence::Direct {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
        });
    }
    let packet = build_disjoint_echo(
        case.domain,
        RAW_DISJOINT_SOURCE_ID,
        ICMP_DGRAM_FIXED_ID,
        ICMP_SEQUENCE,
        crate::socket_reality::case::icmp_dgram_probe_checksum_mode(case.domain),
    );
    socket.send_to(&packet, SocketAddr::new(local, 0));
    socket.recv_from(4096);

    Ok(RawReceiveEvidence::Direct {
        direct: DirectSocketEvidence {
            sockets: vec![socket.finish()],
        },
        socket: socket_id,
    })
}

pub(super) fn require_case(
    case: &RealityCase,
    protocol: SupportedProtocol,
    socket_type: Type,
    connected: bool,
) -> io::Result<()> {
    let path_supported = if socket_type == Type::DGRAM {
        case.socket_path == RealitySocketPath::Datagram
    } else {
        case.socket_path == RealitySocketPath::RawIcmp
    };
    if case.protocol == protocol
        && case.socket_type == socket_type
        && case.connection_scenario.direct_connected() == Some(connected)
        && path_supported
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "collector does not support case {case:?}"
        )))
    }
}

pub(super) fn loopback(domain: Domain) -> IpAddr {
    if domain == Domain::IPV4 {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }
}

pub(super) fn build_echo_with_payload(
    domain: Domain,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    checksum_mode: IcmpChecksumMode,
) -> Vec<u8> {
    let mut header = [
        if domain == Domain::IPV4 { 8 } else { 128 },
        0,
        0,
        0,
        (identifier >> 8) as u8,
        identifier as u8,
        (sequence >> 8) as u8,
        sequence as u8,
    ];
    if checksum_mode == IcmpChecksumMode::ApplicationComputed {
        assert_eq!(
            domain,
            Domain::IPV4,
            "application-computed ICMP reality checksum requires IPv4"
        );
        let checksum = checksum16_header_parts(&header, &[], payload);
        header[2] = (checksum >> 8) as u8;
        header[3] = checksum as u8;
    }
    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(payload);
    packet
}

pub(super) fn build_disjoint_echo(
    domain: Domain,
    source_id: u16,
    destination_id: u16,
    sequence: u16,
    checksum_mode: IcmpChecksumMode,
) -> Vec<u8> {
    assert_ne!(source_id, destination_id);
    let mut payload = Vec::with_capacity(3 + ICMP_TUNNEL_SESSION_ID_LEN);
    payload.extend_from_slice(&[SHIM_IS_DATA, (source_id >> 8) as u8, source_id as u8]);
    payload.extend_from_slice(&RAW_PROBE_SESSION_ID.to_be_bytes());
    build_echo_with_payload(domain, destination_id, sequence, &payload, checksum_mode)
}
