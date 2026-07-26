use super::direct::InstrumentedSocket;
use super::direct_icmp::loopback;
use super::icmp_dgram::{
    EchoReplyExpectation, ICMP_SEQUENCE, build_correlated_echo, next_nonce,
    observe as observe_icmp_dgram,
};
use crate::socket_reality::case::{ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation};
use crate::socket_reality::evidence::{
    DirectSocketEvidence, IcmpDgramCollectionOutcome, IcmpDgramSharedIdEvidence, ProbeSocketId,
};
use crate::timing::{SOCKET_REALITY_RECEIVE_WAIT, TEST_POLL_INTERVAL};
use pkthere_wire::SupportedProtocol;
use socket2::Type;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

const SHARED_SOCKET_COUNT: usize = 2;

pub(super) fn collect(case: &RealityCase) -> io::Result<IcmpDgramSharedIdEvidence> {
    require_case(case)?;
    let socket_ids = (1..=SHARED_SOCKET_COUNT)
        .map(|index| ProbeSocketId(u32::try_from(index).expect("socket index fits u32")))
        .collect::<Vec<_>>();
    let mut sockets = Vec::with_capacity(socket_ids.len());
    for socket_id in &socket_ids {
        match InstrumentedSocket::create(*socket_id, case.socket_create_spec()) {
            Ok(mut socket) => {
                if !socket.set_reuse_address() || !socket.set_reuse_port() {
                    sockets.push(socket);
                    return Ok(evidence(socket_ids, sockets, Vec::new()));
                }
                sockets.push(socket);
            }
            Err(create) => {
                let mut recorded = sockets
                    .into_iter()
                    .map(InstrumentedSocket::finish)
                    .collect::<Vec<_>>();
                recorded.push(create);
                return Ok(IcmpDgramSharedIdEvidence {
                    direct: DirectSocketEvidence { sockets: recorded },
                    sockets: socket_ids,
                    outcomes: Vec::new(),
                });
            }
        }
    }

    let local = loopback(case.domain);
    let endpoint = SocketAddr::new(local, ICMP_DGRAM_FIXED_ID);
    for socket in &mut sockets {
        if !socket.bind(endpoint) || !socket.connect(endpoint) {
            return Ok(evidence(socket_ids, sockets, Vec::new()));
        }
        socket.getsockname();
        if !socket.set_read_timeout(TEST_POLL_INTERVAL) {
            return Ok(evidence(socket_ids, sockets, Vec::new()));
        }
    }

    let expectations = sockets
        .iter_mut()
        .enumerate()
        .map(|(index, socket)| {
            let sequence = ICMP_SEQUENCE
                .checked_add(u16::try_from(index).expect("socket index fits u16"))
                .expect("shared probe sequence range");
            let payload_nonce = next_nonce(case.domain);
            socket.send(&build_correlated_echo(
                case.domain,
                ICMP_DGRAM_FIXED_ID,
                sequence,
                &payload_nonce,
                crate::socket_reality::case::icmp_dgram_probe_checksum_mode(case.domain),
            ));
            EchoReplyExpectation {
                peer: local,
                realized_echo_id: ICMP_DGRAM_FIXED_ID,
                sequence,
                payload_nonce,
            }
        })
        .collect::<Vec<_>>();

    let deadline = Instant::now() + SOCKET_REALITY_RECEIVE_WAIT;
    let mut outcomes = vec![IcmpDgramCollectionOutcome::ReceiveEnded; expectations.len()];
    let mut complete = vec![false; expectations.len()];
    let mut noise = vec![0; expectations.len()];
    while complete.iter().any(|observed| !observed) && Instant::now() < deadline {
        for socket in &mut sockets {
            let Some(received) = socket.recv_from_observed(2048) else {
                continue;
            };
            for (index, expectation) in expectations.iter().copied().enumerate() {
                if complete[index] {
                    continue;
                }
                if let Some(outcome) =
                    observe_icmp_dgram(case.domain, &received, expectation, &mut noise[index])
                {
                    complete[index] = matches!(outcome, IcmpDgramCollectionOutcome::ReplyObserved);
                    outcomes[index] = outcome;
                }
            }
        }
    }
    Ok(evidence(socket_ids, sockets, outcomes))
}

fn evidence(
    socket_ids: Vec<ProbeSocketId>,
    sockets: Vec<InstrumentedSocket>,
    outcomes: Vec<IcmpDgramCollectionOutcome>,
) -> IcmpDgramSharedIdEvidence {
    IcmpDgramSharedIdEvidence {
        direct: DirectSocketEvidence {
            sockets: sockets
                .into_iter()
                .map(InstrumentedSocket::finish)
                .collect(),
        },
        sockets: socket_ids,
        outcomes,
    }
}

fn require_case(case: &RealityCase) -> io::Result<()> {
    if case.operation == RealityOperation::IcmpDgramSharedId
        && case.protocol == SupportedProtocol::ICMP
        && case.socket_type == Type::DGRAM
        && case.connection_scenario
            == crate::socket_reality::case::ConnectionScenario::DirectConnected
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shared ICMP DGRAM collector received an invalid case",
        ))
    }
}
