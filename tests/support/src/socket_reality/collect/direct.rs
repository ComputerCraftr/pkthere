use crate::socket_reality::case::{
    ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation, RealitySocketPath, SocketCreateSpec,
};
use crate::socket_reality::evidence::{
    CallResult, ConnectedFilterEvidence, DatagramReceiveEvidence, DirectSocketEvidence,
    IcmpDgramEvidence, OrderedSocketCall, ProbeSocketEvidence, ProbeSocketId, RawReceiveEvidence,
    ReceiveApi, ReceiveEvidence, ReusePortFanoutEvidence, SocketCall, SocketCreateEvidence,
};
use crate::timing::{
    DRAIN_WAIT_MS, SOCKET_REALITY_RECEIVE_WAIT, SOCKET_WITNESS_WAIT, TEST_POLL_INTERVAL,
};
use pkthere_socket_policy::{
    SocketCreationPath, SocketRole, listener_socket_setup_policy, listener_worker_socket_policy,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::checksum::checksum16_header_parts;
use pkthere_wire::packet_headers::{SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

const PROBE_PAYLOAD: &[u8] = b"pkthere-socket-reality";
const ICMP_SEQUENCE: u16 = 0x51a7;
const RAW_DISJOINT_SOURCE_ID: u16 = 0x5222;
const REUSE_PORT_RECEIVERS: usize = 3;
const REUSE_PORT_FLOWS: usize = 64;

struct InstrumentedSocket {
    socket: Socket,
    evidence: ProbeSocketEvidence,
    next_sequence: u64,
}

impl InstrumentedSocket {
    fn create(
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

    fn bind(&mut self, requested: SocketAddr) -> bool {
        let result = CallResult::from_io(self.socket.bind(&SockAddr::from(requested)));
        let ok = result.is_ok();
        self.record(SocketCall::Bind { requested, result });
        ok
    }

    fn connect(&mut self, target: SocketAddr) -> bool {
        let result = CallResult::from_io(self.socket.connect(&SockAddr::from(target)));
        let ok = result.is_ok();
        self.record(SocketCall::Connect { target, result });
        ok
    }

    fn getsockname(&mut self) -> Option<SocketAddr> {
        let result = CallResult::from_io(self.socket.local_addr().and_then(|address| {
            address
                .as_socket()
                .ok_or_else(|| io::Error::other("getsockname returned a non-INET address"))
        }));
        let address = result.as_ok().copied();
        self.record(SocketCall::GetSockName { result });
        address
    }

    fn set_read_timeout(&mut self, timeout: Duration) -> bool {
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

    fn send(&mut self, bytes: &[u8]) {
        let result = CallResult::from_io(self.socket.send(bytes));
        self.record(SocketCall::Send {
            destination: None,
            bytes: bytes.to_vec(),
            result,
        });
    }

    fn send_to(&mut self, bytes: &[u8], destination: SocketAddr) {
        let result = CallResult::from_io(self.socket.send_to(bytes, &SockAddr::from(destination)));
        self.record(SocketCall::Send {
            destination: Some(destination),
            bytes: bytes.to_vec(),
            result,
        });
    }

    fn recv(&mut self, capacity: usize) {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); capacity];
        let result = match self.socket.recv(&mut buffer) {
            Ok(length) => CallResult::Ok(ReceiveEvidence {
                bytes: initialized_prefix(&buffer, length),
                source: None,
            }),
            Err(error) => CallResult::OsError((&error).into()),
        };
        self.record(SocketCall::Receive {
            api: ReceiveApi::Recv,
            result,
        });
    }

    fn recv_from(&mut self, capacity: usize) {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); capacity];
        let result = match self.socket.recv_from(&mut buffer) {
            Ok((length, source)) => CallResult::Ok(ReceiveEvidence {
                bytes: initialized_prefix(&buffer, length),
                source: source.as_socket(),
            }),
            Err(error) => CallResult::OsError((&error).into()),
        };
        self.record(SocketCall::Receive {
            api: ReceiveApi::RecvFrom,
            result,
        });
    }

    fn finish(self) -> ProbeSocketEvidence {
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
    let packet = build_echo(case.domain, ICMP_DGRAM_FIXED_ID, ICMP_SEQUENCE);
    let mut socket = match InstrumentedSocket::create(socket_id, case.socket_create_spec()) {
        Ok(socket) => socket,
        Err(create) => {
            return Ok(IcmpDgramEvidence {
                direct: DirectSocketEvidence {
                    sockets: vec![create],
                },
                socket: socket_id,
            });
        }
    };

    let local = loopback(case.domain);
    socket.getsockname();
    socket.bind(SocketAddr::new(local, requested_id));
    socket.getsockname();
    socket.connect(SocketAddr::new(local, requested_id));
    socket.getsockname();
    if !socket.set_read_timeout(SOCKET_REALITY_RECEIVE_WAIT) {
        return Ok(IcmpDgramEvidence {
            direct: DirectSocketEvidence {
                sockets: vec![socket.finish()],
            },
            socket: socket_id,
        });
    }
    socket.send(&packet);
    socket.getsockname();
    socket.recv(2048);

    Ok(IcmpDgramEvidence {
        direct: DirectSocketEvidence {
            sockets: vec![socket.finish()],
        },
        socket: socket_id,
    })
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

fn reuse_port_error(successful_bind_count: usize, error: io::Error) -> ReusePortFanoutEvidence {
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

fn require_case(
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
        && case.connected == connected
        && path_supported
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "collector does not support case {case:?}"
        )))
    }
}

fn initialized_prefix(buffer: &[MaybeUninit<u8>], length: usize) -> Vec<u8> {
    // socket2 guarantees the first `length` elements were initialized by recv.
    unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length) }.to_vec()
}

fn loopback(domain: Domain) -> IpAddr {
    if domain == Domain::IPV4 {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }
}

fn build_echo(domain: Domain, identifier: u16, sequence: u16) -> Vec<u8> {
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
    let payload = [SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER];
    if domain == Domain::IPV4 {
        let checksum = checksum16_header_parts(&header, &[], &payload);
        header[2] = (checksum >> 8) as u8;
        header[3] = checksum as u8;
    }
    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&payload);
    packet
}

fn build_disjoint_echo(
    domain: Domain,
    source_id: u16,
    destination_id: u16,
    sequence: u16,
) -> Vec<u8> {
    assert_ne!(source_id, destination_id);
    let mut packet = build_echo(domain, destination_id, sequence);
    packet.truncate(8);
    packet.extend_from_slice(&[SHIM_IS_DATA, (source_id >> 8) as u8, source_id as u8]);
    if domain == Domain::IPV4 {
        packet[2] = 0;
        packet[3] = 0;
        let header: &[u8; 8] = packet[..8]
            .try_into()
            .expect("RAW Echo header has fixed length");
        let checksum = checksum16_header_parts(header, &[], &packet[8..]);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = checksum as u8;
    }
    packet
}

fn datagram_evidence(
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

fn connected_evidence(
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

#[cfg(test)]
mod tests {
    use super::collect_udp_connected_filter;
    use crate::socket_reality::case::{RealityCase, RealityOperation, RealitySocketPath};
    use crate::socket_reality::evidence::SocketCall;
    use crate::timing::{DRAIN_WAIT_MS, SOCKET_REALITY_RECEIVE_WAIT};
    use pkthere_socket_policy::SocketRole;
    use pkthere_wire::SupportedProtocol;
    use socket2::{Domain, Type};

    #[test]
    fn connected_udp_positive_receive_has_its_own_deadline() {
        for policy_role in [SocketRole::Listener, SocketRole::Upstream] {
            let case = RealityCase {
                domain: Domain::IPV4,
                target_domain: None,
                protocol: SupportedProtocol::UDP,
                socket_type: Type::DGRAM,
                socket_path: RealitySocketPath::Datagram,
                policy_role,
                connected: true,
                operation: RealityOperation::ConnectedPeerFiltering,
            };
            let evidence = collect_udp_connected_filter(&case)
                .unwrap_or_else(|error| panic!("collect {policy_role:?} evidence: {error}"));
            let receiver = evidence
                .direct
                .socket(evidence.receiver)
                .expect("receiver evidence");
            let timeouts = receiver
                .calls
                .iter()
                .filter_map(|call| match call.call {
                    SocketCall::SetReadTimeout { milliseconds, .. } => Some(milliseconds),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                timeouts,
                [
                    DRAIN_WAIT_MS.as_millis() as u64,
                    SOCKET_REALITY_RECEIVE_WAIT.as_millis() as u64,
                ],
                "{policy_role:?} positive receive inherited its negative-filter timeout"
            );
        }
    }
}
