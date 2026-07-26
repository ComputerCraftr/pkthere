use super::direct_icmp::{loopback, require_case};
use super::receive_buffer::ProbeReceiveBuffer;
use crate::socket_reality::case::{
    ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation, RealitySocketPath, SocketCreateSpec,
};
use crate::socket_reality::evidence::{
    CallResult, ConnectedFilterEvidence, DatagramBindShape, DatagramDisconnectAttempt,
    DatagramDisconnectEvidence, DatagramQueueIsolationEvidence, DatagramReceiveEvidence,
    DirectSocketEvidence, OrderedSocketCall, ProbeSocketEvidence, ProbeSocketId, ReceiveApi,
    ReceiveEvidence, SocketCall, SocketCreateEvidence, SocketDisconnectAttempt,
    SocketDisconnectEvidence,
};
use crate::timing::{
    DRAIN_WAIT_MS, SOCKET_DISCONNECT_OBSERVATION_WAIT, SOCKET_REALITY_RECEIVE_WAIT,
    TEST_POLL_INTERVAL,
};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

pub(super) const PROBE_PAYLOAD: &[u8] = b"pkthere-socket-reality";
pub(super) const RAW_DISJOINT_SOURCE_ID: u16 = 0x5222;
pub(super) const RAW_PROBE_SESSION_ID: u64 = 0x706b_7468_6572_6503;
pub(super) const REUSE_PORT_RECEIVERS: usize = 3;
pub(super) const REUSE_PORT_FLOWS: usize = 64;
pub(super) const DISCONNECT_ATTEMPTS: usize = 8;

pub(super) fn route_probe_bind_before_connect_required(domain: Domain) -> io::Result<bool> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    Ok(socket.local_addr().is_err())
}

pub(super) fn datagram_evidence(
    receiver: ProbeSocketId,
    sender: ProbeSocketId,
    sockets: Vec<ProbeSocketEvidence>,
) -> DatagramReceiveEvidence {
    DatagramReceiveEvidence {
        direct: DirectSocketEvidence { sockets },
        receiver,
        sender,
    }
}

pub(super) fn connected_evidence(
    receiver: ProbeSocketId,
    accepted_peer: ProbeSocketId,
    rejected_peer: ProbeSocketId,
    sockets: Vec<ProbeSocketEvidence>,
) -> ConnectedFilterEvidence {
    ConnectedFilterEvidence {
        direct: DirectSocketEvidence { sockets },
        receiver,
        accepted_peer,
        rejected_peer,
    }
}

pub(super) struct InstrumentedSocket {
    socket: Socket,
    evidence: ProbeSocketEvidence,
    next_sequence: u64,
}

impl InstrumentedSocket {
    pub(super) fn create(
        socket_id: ProbeSocketId,
        spec: SocketCreateSpec,
    ) -> Result<Self, ProbeSocketEvidence> {
        match Socket::new(spec.domain, spec.socket_type, spec.protocol) {
            Ok(socket) => Ok(Self {
                socket,
                evidence: ProbeSocketEvidence {
                    create: SocketCreateEvidence {
                        socket_id,
                        domain: spec.domain,
                        socket_type: spec.socket_type,
                        protocol: spec.protocol,
                        result: CallResult::Ok(()),
                    },
                    calls: Vec::new(),
                },
                next_sequence: 1,
            }),
            Err(error) => Err(ProbeSocketEvidence {
                create: SocketCreateEvidence {
                    socket_id,
                    domain: spec.domain,
                    socket_type: spec.socket_type,
                    protocol: spec.protocol,
                    result: CallResult::OsError((&error).into()),
                },
                calls: Vec::new(),
            }),
        }
    }

    fn record(&mut self, call: SocketCall) {
        self.evidence.calls.push(OrderedSocketCall {
            sequence: self.next_sequence,
            call,
        });
        self.next_sequence += 1;
    }

    pub(super) fn bind(&mut self, requested: SocketAddr) -> bool {
        let result = CallResult::from_io(self.socket.bind(&SockAddr::from(requested)));
        let ok = result.is_ok();
        self.record(SocketCall::Bind { requested, result });
        ok
    }

    pub(super) fn connect(&mut self, target: SocketAddr) -> bool {
        let result = CallResult::from_io(self.socket.connect(&SockAddr::from(target)));
        let ok = result.is_ok();
        self.record(SocketCall::Connect { target, result });
        ok
    }

    pub(super) fn getsockname(&mut self) -> Option<SocketAddr> {
        let result = CallResult::from_io(self.socket.local_addr().and_then(|address| {
            address
                .as_socket()
                .ok_or_else(|| io::Error::other("getsockname returned a non-INET address"))
        }));
        let address = result.as_ok().copied();
        self.record(SocketCall::GetSockName { result });
        address
    }

    pub(super) fn set_read_timeout(&mut self, timeout: Duration) -> bool {
        let result = CallResult::from_io(self.socket.set_read_timeout(Some(timeout)));
        let ok = result.is_ok();
        self.record(SocketCall::SetReadTimeout {
            milliseconds: timeout
                .as_millis()
                .try_into()
                .expect("socket-reality timeout must fit in u64 milliseconds"),
            result,
        });
        ok
    }

    pub(super) fn set_reuse_address(&mut self) -> bool {
        let result = CallResult::from_io(self.socket.set_reuse_address(true));
        let ok = result.is_ok();
        self.record(SocketCall::SetReuseAddress { result });
        ok
    }

    pub(super) fn set_reuse_port(&mut self) -> bool {
        #[cfg(unix)]
        let result = CallResult::from_io(self.socket.set_reuse_port(true));
        #[cfg(not(unix))]
        let result = CallResult::from_io(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_REUSEPORT is unavailable on this platform",
        )));
        let ok = result.is_ok();
        self.record(SocketCall::SetReusePort { result });
        ok
    }

    pub(super) fn get_header_included_v4(&mut self) -> Option<bool> {
        let result = CallResult::from_io(self.socket.header_included_v4());
        let value = result.as_ok().copied();
        self.record(SocketCall::GetHeaderIncludedV4 { result });
        value
    }

    pub(super) fn send(&mut self, bytes: &[u8]) {
        let result = CallResult::from_io(self.socket.send(bytes));
        self.record(SocketCall::Send {
            destination: None,
            bytes: bytes.to_vec(),
            result,
        });
    }

    pub(super) fn send_to(&mut self, bytes: &[u8], destination: SocketAddr) {
        let result = CallResult::from_io(self.socket.send_to(bytes, &SockAddr::from(destination)));
        self.record(SocketCall::Send {
            destination: Some(destination),
            bytes: bytes.to_vec(),
            result,
        });
    }

    fn recv(&mut self, capacity: usize) {
        let mut buffer = ProbeReceiveBuffer::with_capacity(capacity);
        let result = match buffer.recv(&self.socket) {
            Ok(bytes) => CallResult::Ok(ReceiveEvidence {
                bytes,
                source: None,
            }),
            Err(error) => CallResult::OsError((&error).into()),
        };
        self.record(SocketCall::Receive {
            api: ReceiveApi::Recv,
            result,
        });
    }

    pub(super) fn recv_from(&mut self, capacity: usize) {
        self.recv_from_observed(capacity);
    }

    pub(super) fn recv_from_observed(&mut self, capacity: usize) -> Option<ReceiveEvidence> {
        let mut buffer = ProbeReceiveBuffer::with_capacity(capacity);
        let result = match buffer.recv_from(&self.socket) {
            Ok((bytes, source)) => CallResult::Ok(ReceiveEvidence {
                bytes,
                source: source.as_socket(),
            }),
            Err(error) => CallResult::OsError((&error).into()),
        };
        self.record(SocketCall::Receive {
            api: ReceiveApi::RecvFrom,
            result,
        });
        match &self
            .evidence
            .calls
            .last()
            .expect("receive-from call was just recorded")
            .call
        {
            SocketCall::Receive {
                result: CallResult::Ok(receive),
                ..
            } => Some(receive.clone()),
            _ => None,
        }
    }

    pub(super) fn finish(self) -> ProbeSocketEvidence {
        self.evidence
    }
}

pub fn collect_udp_datagram(case: &RealityCase) -> io::Result<DatagramReceiveEvidence> {
    require_case(case, SupportedProtocol::UDP, Type::DGRAM, false)?;
    let receiver_id = ProbeSocketId(1);
    let sender_id = ProbeSocketId(2);
    let spec = case.socket_create_spec();
    let mut receiver = match InstrumentedSocket::create(receiver_id, spec) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(datagram_evidence(receiver_id, sender_id, vec![create]));
        }
    };
    let mut sender = match InstrumentedSocket::create(sender_id, spec) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(datagram_evidence(
                receiver_id,
                sender_id,
                vec![receiver.finish(), create],
            ));
        }
    };
    let local = loopback(case.domain);

    if !receiver.bind(SocketAddr::new(local, 0)) {
        return Ok(datagram_evidence(
            receiver_id,
            sender_id,
            vec![receiver.finish(), sender.finish()],
        ));
    }
    let Some(receiver_addr) = receiver.getsockname() else {
        return Ok(datagram_evidence(
            receiver_id,
            sender_id,
            vec![receiver.finish(), sender.finish()],
        ));
    };
    if !sender.bind(SocketAddr::new(local, 0)) {
        return Ok(datagram_evidence(
            receiver_id,
            sender_id,
            vec![receiver.finish(), sender.finish()],
        ));
    }
    sender.getsockname();
    if !sender.connect(receiver_addr) {
        return Ok(datagram_evidence(
            receiver_id,
            sender_id,
            vec![receiver.finish(), sender.finish()],
        ));
    }
    sender.getsockname();
    if !receiver.set_read_timeout(SOCKET_REALITY_RECEIVE_WAIT) {
        return Ok(datagram_evidence(
            receiver_id,
            sender_id,
            vec![receiver.finish(), sender.finish()],
        ));
    }
    sender.send(PROBE_PAYLOAD);
    receiver.recv_from(2048);

    Ok(datagram_evidence(
        receiver_id,
        sender_id,
        vec![receiver.finish(), sender.finish()],
    ))
}

pub fn collect_udp_disconnect(case: &RealityCase) -> io::Result<DatagramDisconnectEvidence> {
    require_case(case, SupportedProtocol::UDP, Type::DGRAM, true)?;
    let local = loopback(case.domain);
    let wildcard = match case.domain {
        Domain::IPV6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let mut attempts = Vec::with_capacity(DISCONNECT_ATTEMPTS * 4);
    for (bind_shape, bind_ip, fixed_port) in [
        (DatagramBindShape::ConcreteEphemeralPort, local, false),
        (DatagramBindShape::WildcardEphemeralPort, wildcard, false),
        (DatagramBindShape::ConcreteFixedPort, local, true),
        (DatagramBindShape::WildcardFixedPort, wildcard, true),
    ] {
        for _ in 0..DISCONNECT_ATTEMPTS {
            let subject = create_bound_disconnect_subject(case.domain, local, bind_ip, fixed_port)?;
            subject.set_nonblocking(true)?;
            let subject = UdpSocket::from(subject);
            let bound_before = subject.local_addr()?;
            let original_destination = SocketAddr::new(local, bound_before.port());

            let peer_a = UdpSocket::bind(SocketAddr::new(local, 0))?;
            let peer_b = UdpSocket::bind(SocketAddr::new(local, 0))?;
            peer_b.set_nonblocking(true)?;
            subject.connect(peer_a.local_addr()?)?;
            let connected_local = subject.local_addr()?;

            let disconnect_result = CallResult::from_io(super::disconnect_platform::disconnect(
                &subject,
                case.domain,
            ));
            let peer_after_disconnect = CallResult::from_io(observe_peer(&subject));
            let local_after_disconnect = CallResult::from_io(subject.local_addr());

            peer_b.send_to(PROBE_PAYLOAD, original_destination)?;
            let receive_after_disconnect = CallResult::from_io(receive_udp_until(
                &subject,
                SOCKET_DISCONNECT_OBSERVATION_WAIT,
            ));

            let peer_b_addr = peer_b.local_addr()?;
            let reconnect_result = CallResult::from_io(subject.connect(peer_b_addr));
            let peer_after_reconnect = CallResult::from_io(subject.peer_addr());
            let local_after_reconnect = CallResult::from_io(subject.local_addr());
            let peer_received_after_reconnect =
                CallResult::from_io(subject.send(PROBE_PAYLOAD).and_then(|_| {
                    receive_bytes_until(&peer_b, SOCKET_DISCONNECT_OBSERVATION_WAIT)
                }));
            let queue_isolation = CallResult::from_io(collect_udp_queue_isolation(
                case.domain,
                local,
                bind_ip,
                fixed_port,
            ));

            attempts.push(DatagramDisconnectAttempt {
                bind_shape,
                bound_before,
                original_destination,
                connected_local,
                new_peer: peer_b_addr,
                disconnect_result,
                peer_after_disconnect,
                local_after_disconnect,
                receive_after_disconnect,
                reconnect_result,
                peer_after_reconnect,
                local_after_reconnect,
                peer_received_after_reconnect,
                queue_isolation,
            });
        }
    }
    Ok(DatagramDisconnectEvidence {
        sent_bytes: PROBE_PAYLOAD.to_vec(),
        attempts,
    })
}

pub(super) fn collect_udp_queue_isolation(
    domain: Domain,
    local: IpAddr,
    bind_ip: IpAddr,
    fixed_port: bool,
) -> io::Result<DatagramQueueIsolationEvidence> {
    const QUEUED_BEFORE: &[u8] = b"pkthere-queued-before-disconnect";
    const QUEUED_CLOSED: &[u8] = b"pkthere-queued-while-gate-closed";
    const FRESH_AFTER: &[u8] = b"pkthere-fresh-after-reconnect";
    const MAX_OBSERVED_DATAGRAMS: usize = 8;

    let subject = create_bound_disconnect_subject(domain, local, bind_ip, fixed_port)?;
    subject.set_nonblocking(true)?;
    let subject = UdpSocket::from(subject);
    let bound = subject.local_addr()?;
    let destination = SocketAddr::new(local, bound.port());
    let peer_a = UdpSocket::bind(SocketAddr::new(local, 0))?;
    let peer_b = UdpSocket::bind(SocketAddr::new(local, 0))?;

    subject.connect(peer_a.local_addr()?)?;
    peer_a.send_to(QUEUED_BEFORE, destination)?;
    await_udp_peek(&subject, QUEUED_BEFORE, SOCKET_DISCONNECT_OBSERVATION_WAIT)?;
    let disconnect_error = super::disconnect_platform::disconnect(&subject, domain).err();
    if observe_peer(&subject)?.is_some() {
        return Err(match disconnect_error {
            Some(error) => error,
            None => io::Error::other("queue-isolation disconnect left the socket connected"),
        });
    }
    peer_b.send_to(QUEUED_CLOSED, destination)?;
    subject.connect(peer_b.local_addr()?)?;
    peer_b.send_to(FRESH_AFTER, destination)?;

    let deadline = Instant::now() + SOCKET_DISCONNECT_OBSERVATION_WAIT;
    let mut received = Vec::new();
    let mut buffer = [0_u8; 64];
    while Instant::now() < deadline && received.len() < MAX_OBSERVED_DATAGRAMS {
        match subject.recv_from(&mut buffer) {
            Ok((length, source)) => received.push(ReceiveEvidence {
                bytes: buffer[..length].to_vec(),
                source: Some(source),
            }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if received.iter().any(|packet| packet.bytes == FRESH_AFTER) {
                    break;
                }
                thread::sleep(
                    TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }

    Ok(DatagramQueueIsolationEvidence {
        queued_before_disconnect: QUEUED_BEFORE.to_vec(),
        queued_while_gate_closed: QUEUED_CLOSED.to_vec(),
        fresh_after_reconnect: FRESH_AFTER.to_vec(),
        received_after_reconnect: received,
    })
}

fn await_udp_peek(socket: &UdpSocket, expected: &[u8], wait: Duration) -> io::Result<()> {
    let deadline = Instant::now() + wait;
    let mut buffer = [0_u8; 64];
    loop {
        match socket.peek_from(&mut buffer) {
            Ok((length, _)) if buffer[..length] == *expected => return Ok(()),
            Ok(_) => {
                return Err(io::Error::other(
                    "queue-isolation precondition observed an unexpected datagram",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "queue-isolation precondition did not become readable",
                    ));
                }
                thread::sleep(
                    TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn create_bound_disconnect_subject(
    domain: Domain,
    local: IpAddr,
    bind_ip: IpAddr,
    fixed_port: bool,
) -> io::Result<Socket> {
    const FIXED_PORT_BIND_ATTEMPTS: usize = 8;
    for attempt in 0..FIXED_PORT_BIND_ATTEMPTS {
        let requested_port = if fixed_port {
            reserve_udp_port(domain, local)?
        } else {
            0
        };
        let subject = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        match subject.bind(&SockAddr::from(SocketAddr::new(bind_ip, requested_port))) {
            Ok(()) => return Ok(subject),
            Err(error)
                if fixed_port
                    && error.kind() == io::ErrorKind::AddrInUse
                    && attempt + 1 < FIXED_PORT_BIND_ATTEMPTS => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "fixed-port disconnect probe exhausted its bounded bind retries",
    ))
}

pub(super) fn reserve_udp_port(domain: Domain, local: IpAddr) -> io::Result<u16> {
    let reservation = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    reservation.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
    reservation
        .local_addr()?
        .as_socket()
        .map(|address| address.port())
        .ok_or_else(|| io::Error::other("UDP port reservation returned a non-INET address"))
}

pub(super) fn observe_peer(socket: &UdpSocket) -> io::Result<Option<SocketAddr>> {
    match socket.peer_addr() {
        Ok(peer) => Ok(Some(peer)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn receive_udp_until(socket: &UdpSocket, wait: Duration) -> io::Result<ReceiveEvidence> {
    let mut buffer = [0_u8; 64];
    let deadline = Instant::now() + wait;
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                return Ok(ReceiveEvidence {
                    bytes: buffer[..length].to_vec(),
                    source: Some(source),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "disconnect receive observation timed out",
                    ));
                }
                thread::sleep(
                    TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn receive_bytes_until(socket: &UdpSocket, wait: Duration) -> io::Result<Vec<u8>> {
    receive_udp_until(socket, wait).map(|received| received.bytes)
}

pub fn collect_socket_disconnect(case: &RealityCase) -> io::Result<SocketDisconnectEvidence> {
    if case.operation != RealityOperation::SocketDisconnect
        || case.connection_scenario.direct_connected() != Some(true)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket disconnect evidence requires a direct-connected disconnect case",
        ));
    }
    let attempt = (|| {
        let spec = case.socket_create_spec();
        let socket = Socket::new(spec.domain, spec.socket_type, spec.protocol)?;
        socket.set_nonblocking(true)?;
        let local = loopback(case.domain);
        socket.bind(&SockAddr::from(SocketAddr::new(local, 0)))?;
        let bound_before = CallResult::from_io(
            socket
                .local_addr()
                .and_then(|address| inet_socket_addr(address, "disconnect bound address")),
        );
        let post_bind_setup = if case.socket_path == RealitySocketPath::WindowsProtocolZeroCapture {
            CallResult::from_io(super::disconnect_platform::configure_protocol_zero_capture(
                &socket,
            ))
        } else {
            CallResult::Ok(())
        };
        let peer_id = match (case.protocol, case.socket_type) {
            (SupportedProtocol::UDP, Type::DGRAM) => UdpSocket::bind(SocketAddr::new(local, 0))?
                .local_addr()?
                .port(),
            (SupportedProtocol::ICMP, Type::DGRAM) => ICMP_DGRAM_FIXED_ID,
            (SupportedProtocol::ICMP, Type::RAW) => 0,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "disconnect probe does not support this protocol/socket type",
                ));
            }
        };
        let peer = SocketAddr::new(local, peer_id);
        socket.connect(&SockAddr::from(peer))?;
        let connected_local = CallResult::from_io(
            socket
                .local_addr()
                .and_then(|address| inet_socket_addr(address, "disconnect connected address")),
        );
        let peer_before = CallResult::from_io(observe_socket_peer(&socket));
        let disconnect_result =
            CallResult::from_io(super::disconnect_platform::disconnect(&socket, case.domain));
        let peer_after_disconnect = CallResult::from_io(observe_socket_peer(&socket));
        let local_after_disconnect = CallResult::from_io(socket.local_addr().and_then(|address| {
            inet_socket_addr(address, "disconnect postcondition local address")
        }));
        let reconnect_result = CallResult::from_io(socket.connect(&SockAddr::from(peer)));
        let peer_after_reconnect = CallResult::from_io(observe_socket_peer(&socket));
        let local_after_reconnect = CallResult::from_io(
            socket
                .local_addr()
                .and_then(|address| inet_socket_addr(address, "disconnect reconnect address")),
        );
        Ok(SocketDisconnectAttempt {
            bound_before,
            post_bind_setup,
            connected_local,
            peer_before,
            disconnect_result,
            peer_after_disconnect,
            local_after_disconnect,
            reconnect_result,
            peer_after_reconnect,
            local_after_reconnect,
        })
    })();
    Ok(SocketDisconnectEvidence {
        attempt: CallResult::from_io(attempt),
    })
}

pub(super) fn inet_socket_addr(address: SockAddr, context: &str) -> io::Result<SocketAddr> {
    address
        .as_socket()
        .ok_or_else(|| io::Error::other(format!("{context} is not an INET socket address")))
}

pub(super) fn observe_socket_peer(socket: &Socket) -> io::Result<Option<SocketAddr>> {
    match socket.peer_addr() {
        Ok(address) => address
            .as_socket()
            .map(Some)
            .ok_or_else(|| io::Error::other("peer address is not an INET socket address")),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub fn collect_udp_connected_filter(case: &RealityCase) -> io::Result<ConnectedFilterEvidence> {
    require_case(case, SupportedProtocol::UDP, Type::DGRAM, true)?;
    let receiver_id = ProbeSocketId(1);
    let accepted_id = ProbeSocketId(2);
    let rejected_id = ProbeSocketId(3);
    let spec = case.socket_create_spec();
    let mut receiver = match InstrumentedSocket::create(receiver_id, spec) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(connected_evidence(
                receiver_id,
                accepted_id,
                rejected_id,
                vec![create],
            ));
        }
    };
    let mut accepted = match InstrumentedSocket::create(accepted_id, spec) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(connected_evidence(
                receiver_id,
                accepted_id,
                rejected_id,
                vec![receiver.finish(), create],
            ));
        }
    };
    let mut rejected = match InstrumentedSocket::create(rejected_id, spec) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(connected_evidence(
                receiver_id,
                accepted_id,
                rejected_id,
                vec![receiver.finish(), accepted.finish(), create],
            ));
        }
    };
    let local = loopback(case.domain);

    if !receiver.bind(SocketAddr::new(local, 0)) {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    }
    let Some(receiver_addr) = receiver.getsockname() else {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    };
    if !accepted.bind(SocketAddr::new(local, 0)) {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    }
    let Some(accepted_addr) = accepted.getsockname() else {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    };
    if !rejected.bind(SocketAddr::new(local, 0)) {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    }
    rejected.getsockname();
    if !receiver.set_read_timeout(DRAIN_WAIT_MS) {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    }

    if case.policy_role == SocketRole::Listener {
        rejected.send_to(PROBE_PAYLOAD, receiver_addr);
        if !receiver.connect(accepted_addr) {
            return Ok(connected_evidence(
                receiver_id,
                accepted_id,
                rejected_id,
                vec![receiver.finish(), accepted.finish(), rejected.finish()],
            ));
        }
        receiver.recv_from(2048);
    } else {
        if !receiver.connect(accepted_addr) {
            return Ok(connected_evidence(
                receiver_id,
                accepted_id,
                rejected_id,
                vec![receiver.finish(), accepted.finish(), rejected.finish()],
            ));
        }
        rejected.send_to(PROBE_PAYLOAD, receiver_addr);
        receiver.recv(2048);
    }

    if !receiver.set_read_timeout(SOCKET_REALITY_RECEIVE_WAIT) {
        return Ok(connected_evidence(
            receiver_id,
            accepted_id,
            rejected_id,
            vec![receiver.finish(), accepted.finish(), rejected.finish()],
        ));
    }
    accepted.send_to(PROBE_PAYLOAD, receiver_addr);
    match case.policy_role {
        SocketRole::Listener => receiver.recv_from(2048),
        SocketRole::Upstream => receiver.recv(2048),
    }

    Ok(connected_evidence(
        receiver_id,
        accepted_id,
        rejected_id,
        vec![receiver.finish(), accepted.finish(), rejected.finish()],
    ))
}
