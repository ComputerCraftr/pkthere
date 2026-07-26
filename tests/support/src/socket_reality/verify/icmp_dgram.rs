use super::implementation::{
    error, last_getsockname, parse_icmp_transport, parse_received_icmp, require_create_dimensions,
    require_socket, successful_receives, successful_sends, verify_sent_icmp_transport_checksum,
};
use super::model::{DerivedFacts, VerificationError};
use crate::socket_reality::case::{ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation};
use crate::socket_reality::evidence::{
    IcmpDgramCollectionOutcome, IcmpDgramEvidence, IcmpDgramSharedIdEvidence, ProbeSocketEvidence,
    ReceiveApi, ReceiveEvidence, SocketCall,
};
use pkthere_socket_policy::{
    IcmpChecksumMode, IcmpSocketIdCapability, PeerSourceRequirement, ReceiveSyscall,
    ResolvedSocketPolicy, upstream_socket_bind_policy, upstream_worker_socket_policy,
};
use socket2::Domain;

pub(super) fn verify(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &IcmpDgramEvidence,
) -> Result<DerivedFacts, VerificationError> {
    let socket = require_socket(&evidence.direct, evidence.socket)?;
    require_create_dimensions(socket, requested)?;
    let requested_bind_id = match requested.operation {
        RealityOperation::IcmpDgramReceiveId => 0,
        RealityOperation::IcmpDgramFixedId => ICMP_DGRAM_FIXED_ID,
        _ => return Err(error("invalid ICMP DGRAM reality operation")),
    };
    if !socket.create.result.is_ok() {
        return Err(error(
            "production policy permits ICMP DGRAM but socket creation failed",
        ));
    }
    require_reply_outcome(evidence.outcome)?;
    let connected = socket
        .calls
        .iter()
        .any(|event| matches!(&event.call, SocketCall::Connect { result, .. } if result.is_ok()));
    if !connected {
        return Err(error(
            "ICMP DGRAM receive evidence has no successful connect lifecycle event",
        ));
    }
    let bound_id = socket
        .calls
        .iter()
        .find_map(|event| match &event.call {
            SocketCall::Bind { requested, result } if result.is_ok() => Some(requested.port()),
            _ => None,
        })
        .ok_or_else(|| error("ICMP DGRAM receive evidence has no successful bind event"))?;
    if bound_id != requested_bind_id {
        return Err(error(format!(
            "ICMP DGRAM bound requested ID {bound_id}, expected {requested_bind_id}"
        )));
    }
    let production_bind = upstream_socket_bind_policy(policy, requested_bind_id, requested_bind_id);
    if !production_bind.bind_before_connect || production_bind.kernel_id != bound_id {
        return Err(error(format!(
            "production ICMP DGRAM bind policy {:?} differs from independently observed bind ID {bound_id}",
            production_bind
        )));
    }
    let connected_id = socket
        .calls
        .iter()
        .find_map(|event| match &event.call {
            SocketCall::Connect { target, result } if result.is_ok() => Some(target.port()),
            _ => None,
        })
        .expect("successful connect was checked above");
    if connected_id != requested_bind_id {
        return Err(error(format!(
            "ICMP DGRAM connected to ID {connected_id}, expected {requested_bind_id}"
        )));
    }

    let kernel_reported_echo_id = last_getsockname(socket)?.port();
    let sent = successful_sends(socket)
        .next()
        .ok_or_else(|| error("ICMP DGRAM produced no successful send evidence"))?;
    if policy.receive_syscall(true) != ReceiveSyscall::Recv {
        return Err(error(
            "production connected ICMP DGRAM policy does not select optimized recv",
        ));
    }

    let sent_parsed = parse_icmp_transport(requested.domain, sent);
    let sent_icmp = sent_parsed
        .icmp
        .ok_or_else(|| error("ICMP DGRAM send bytes did not contain a valid Echo header"))?;
    let sent_extent = sent_parsed
        .declared_extent(sent)
        .ok_or_else(|| error("ICMP DGRAM request has no valid declared packet extent"))?;
    if sent_extent.packet != (0..sent.len()) {
        return Err(error(
            "ICMP DGRAM request declared extent does not equal the sent packet extent",
        ));
    }
    verify_sent_icmp_transport_checksum(
        crate::socket_reality::case::icmp_dgram_probe_checksum_mode(requested.domain),
        requested.domain,
        sent,
    )?;
    let sent_nonce = sent
        .get(sent_extent.payload.clone())
        .ok_or_else(|| error("ICMP DGRAM request payload nonce is outside the packet"))?;
    if sent_nonce.len() != 16 {
        return Err(error(format!(
            "ICMP DGRAM request payload nonce is {} bytes, expected 16",
            sent_nonce.len()
        )));
    }
    let (received, parsed, received_extent) = successful_receives(socket)
        .find_map(|received| {
            let parsed = parse_received_icmp(requested.domain, policy, &received.1.bytes).ok()?;
            let icmp = parsed.icmp?;
            let extent = parsed
                .declared_extent_with_ipv4_length(&received.1.bytes, policy.ipv4_receive_length)?;
            let nonce = received.1.bytes.get(extent.payload.clone())?;
            (!icmp.is_req && icmp.seq == sent_icmp.seq && nonce == sent_nonce)
                .then_some((received, parsed, extent))
        })
        .ok_or_else(|| error("ICMP DGRAM produced no correlated Echo Reply evidence"))?;
    if received.0 != ReceiveApi::RecvFrom {
        return Err(error(
            "ICMP DGRAM correlation probe did not preserve recv_from source metadata",
        ));
    }
    let icmp = parsed
        .icmp
        .expect("correlated receive was selected from a parsed ICMP Echo");
    if received_extent.packet != (0..received.1.bytes.len()) {
        return Err(error(
            "ICMP DGRAM reply declared extent does not equal the captured packet extent",
        ));
    }
    let received_nonce = received
        .1
        .bytes
        .get(received_extent.payload.clone())
        .ok_or_else(|| error("ICMP DGRAM reply payload nonce is outside the packet"))?;
    if received_nonce != sent_nonce {
        return Err(error(
            "ICMP DGRAM reply payload nonce differs from the sent probe nonce",
        ));
    }
    if icmp.is_req {
        return Err(error(
            "ICMP DGRAM correlated receive is a reflected Echo Request, not an Echo Reply",
        ));
    }
    if sent_icmp.seq != icmp.seq {
        return Err(error(format!(
            "ICMP DGRAM response sequence {} differs from sent sequence {}",
            icmp.seq, sent_icmp.seq
        )));
    }
    verify_zero_checksum_capability(requested, policy, evidence, socket)?;

    let expected_peer = socket
        .calls
        .iter()
        .find_map(|event| match &event.call {
            SocketCall::Connect { target, result } if result.is_ok() => Some(target.ip()),
            _ => None,
        })
        .ok_or_else(|| error("ICMP DGRAM evidence omitted its connected peer"))?;
    let reply_source = received
        .1
        .source
        .ok_or_else(|| error("ICMP DGRAM reply omitted recv_from source metadata"))?;
    if reply_source.ip() != expected_peer {
        return Err(error(format!(
            "ICMP DGRAM reply source {} differs from expected peer {expected_peer}",
            reply_source.ip()
        )));
    }
    if parsed
        .source_ip()
        .is_some_and(|packet_source| packet_source != expected_peer)
    {
        return Err(error(
            "ICMP DGRAM reply packet source differs from the expected peer",
        ));
    }
    if policy.evidence_policy(true).peer_source != PeerSourceRequirement::ConnectedKernel {
        return Err(error(
            "ICMP DGRAM layout/source policy disagrees with measured evidence",
        ));
    }

    let requested_echo_id = sent_icmp.identity.destination_id;
    let realized_echo_id = realized_echo_id(
        policy,
        requested_bind_id,
        requested_echo_id,
        kernel_reported_echo_id,
    )?;
    if icmp.identity.destination_id != realized_echo_id {
        return Err(error(format!(
            "wire Echo ID {} differs from realized DGRAM Echo ID {}",
            icmp.identity.destination_id, realized_echo_id
        )));
    }
    verify_reflected_request_identity(
        socket,
        received.1,
        ReflectedRequestExpectation {
            domain: requested.domain,
            policy,
            expected_peer,
            realized_echo_id,
            sequence: sent_icmp.seq,
            payload_nonce: sent_nonce,
        },
    )?;
    Ok(DerivedFacts::IcmpDgram {
        requested_bind_id,
        requested_echo_id,
        kernel_reported_echo_id,
        realized_echo_id,
        wire_observed_echo_id: icmp.identity.destination_id,
        sequence: icmp.seq,
        byte_count: received.1.bytes.len(),
    })
}

fn verify_zero_checksum_capability(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &IcmpDgramEvidence,
    socket: &ProbeSocketEvidence,
) -> Result<(), VerificationError> {
    if requested.domain != Domain::IPV4
        || requested.operation != RealityOperation::IcmpDgramReceiveId
    {
        if evidence.zero_checksum_sequence.is_some() || evidence.zero_checksum_outcome.is_some() {
            return Err(error(
                "zero-checksum capability evidence appeared outside its authoritative IPv4 row",
            ));
        }
        return Ok(());
    }
    let outcome = evidence
        .zero_checksum_outcome
        .ok_or_else(|| error("IPv4 ICMP DGRAM evidence omitted the zero-checksum probe"))?;
    let sequence = evidence
        .zero_checksum_sequence
        .ok_or_else(|| error("IPv4 ICMP DGRAM evidence omitted the zero-checksum sequence"))?;
    let zero_send = successful_sends(socket)
        .find(|packet| {
            parse_icmp_transport(requested.domain, packet)
                .icmp
                .is_some_and(|icmp| icmp.seq == sequence)
        })
        .ok_or_else(|| error("zero-checksum outcome has no matching sent probe"))?;
    verify_sent_icmp_transport_checksum(
        IcmpChecksumMode::KernelComputed,
        requested.domain,
        zero_send,
    )?;
    match policy.send_policy.icmp_checksum {
        IcmpChecksumMode::KernelComputed => require_reply_outcome(outcome),
        IcmpChecksumMode::ApplicationComputed
            if outcome == IcmpDgramCollectionOutcome::ReplyObserved =>
        {
            Err(error(
                "kernel accepted a zero-checksum ICMP DGRAM probe but policy requires application checksum calculation",
            ))
        }
        IcmpChecksumMode::ApplicationComputed => Ok(()),
    }
}

pub(super) fn verify_shared_id(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &IcmpDgramSharedIdEvidence,
) -> Result<DerivedFacts, VerificationError> {
    if !upstream_worker_socket_policy(
        2,
        false,
        pkthere_wire::SupportedProtocol::ICMP,
        socket2::Type::DGRAM,
        requested.domain,
    )
    .shares_icmp_identity()
    {
        return Err(VerificationError {
            kind: super::model::VerificationErrorKind::PolicyCapabilityContradiction,
            message: "shared ICMP DGRAM evidence executed where policy marks it unsupported"
                .to_owned(),
        });
    }
    if evidence.sockets.len() != 2 || evidence.outcomes.len() != evidence.sockets.len() {
        return Err(error(
            "shared ICMP DGRAM evidence must contain two sockets and two probe outcomes",
        ));
    }
    for outcome in &evidence.outcomes {
        require_reply_outcome(*outcome)?;
    }

    let mut sent_probes = Vec::with_capacity(evidence.sockets.len());
    for socket_id in &evidence.sockets {
        let socket = require_socket(&evidence.direct, *socket_id)?;
        require_create_dimensions(socket, requested)?;
        if !socket.create.result.is_ok() {
            return Err(error("shared ICMP DGRAM socket creation failed"));
        }
        for option in ["SO_REUSEADDR", "SO_REUSEPORT"] {
            let configured = socket
                .calls
                .iter()
                .any(|event| match (&event.call, option) {
                    (SocketCall::SetReuseAddress { result }, "SO_REUSEADDR")
                    | (SocketCall::SetReusePort { result }, "SO_REUSEPORT") => result.is_ok(),
                    _ => false,
                });
            if !configured {
                return Err(error(format!(
                    "shared ICMP DGRAM socket omitted successful {option}"
                )));
            }
        }
        let bound = socket.calls.iter().any(|event| {
            matches!(
                &event.call,
                SocketCall::Bind { requested, result }
                    if result.is_ok() && requested.port() == ICMP_DGRAM_FIXED_ID
            )
        });
        let connected = socket.calls.iter().any(|event| {
            matches!(
                &event.call,
                SocketCall::Connect { target, result }
                    if result.is_ok() && target.port() == ICMP_DGRAM_FIXED_ID
            )
        });
        if !bound || !connected {
            return Err(error(
                "shared ICMP DGRAM socket did not bind and connect the shared fixed ID",
            ));
        }
        let sent = successful_sends(socket)
            .next()
            .ok_or_else(|| error("shared ICMP DGRAM socket produced no successful probe send"))?;
        verify_sent_icmp_transport_checksum(
            crate::socket_reality::case::icmp_dgram_probe_checksum_mode(requested.domain),
            requested.domain,
            sent,
        )?;
        let parsed = parse_icmp_transport(requested.domain, sent);
        let icmp = parsed
            .icmp
            .ok_or_else(|| error("shared ICMP DGRAM probe omitted an Echo header"))?;
        let extent = parsed
            .declared_extent(sent)
            .ok_or_else(|| error("shared ICMP DGRAM probe has no exact declared extent"))?;
        let payload = sent
            .get(extent.payload)
            .ok_or_else(|| error("shared ICMP DGRAM probe payload is outside its extent"))?;
        if icmp.identity.destination_id != ICMP_DGRAM_FIXED_ID {
            return Err(error("shared ICMP DGRAM probe used the wrong Echo ID"));
        }
        sent_probes.push((icmp.seq, payload.to_vec()));
    }

    let received = evidence
        .sockets
        .iter()
        .filter_map(|socket_id| evidence.direct.socket(*socket_id))
        .flat_map(successful_receives)
        .collect::<Vec<_>>();
    let mut correlated_reply_count = 0;
    for (sequence, payload) in &sent_probes {
        let matched = received.iter().any(|(_, receive)| {
            let Ok(parsed) = parse_received_icmp(requested.domain, policy, &receive.bytes) else {
                return false;
            };
            let Some(icmp) = parsed.icmp else {
                return false;
            };
            let Some(extent) =
                parsed.declared_extent_with_ipv4_length(&receive.bytes, policy.ipv4_receive_length)
            else {
                return false;
            };
            !icmp.is_req
                && icmp.seq == *sequence
                && icmp.identity.destination_id == ICMP_DGRAM_FIXED_ID
                && receive.bytes.get(extent.payload) == Some(payload.as_slice())
        });
        if !matched {
            return Err(error(format!(
                "shared ICMP DGRAM group omitted correlated reply for sequence {sequence}"
            )));
        }
        correlated_reply_count += 1;
    }

    Ok(DerivedFacts::IcmpDgramSharedId {
        socket_count: evidence.sockets.len(),
        shared_echo_id: ICMP_DGRAM_FIXED_ID,
        correlated_reply_count,
    })
}

fn require_reply_outcome(outcome: IcmpDgramCollectionOutcome) -> Result<(), VerificationError> {
    match outcome {
        IcmpDgramCollectionOutcome::ReplyObserved => Ok(()),
        IcmpDgramCollectionOutcome::NoiseLimitExceeded {
            limit,
            observed_noise_packets,
        } => Err(error(format!(
            "ICMP DGRAM reply correlation exceeded the {limit}-packet noise limit \
             after observing {observed_noise_packets} noise packets"
        ))),
        IcmpDgramCollectionOutcome::NotAttempted => {
            Err(error("ICMP DGRAM reply correlation was not attempted"))
        }
        IcmpDgramCollectionOutcome::ReceiveEnded => Err(error(
            "ICMP DGRAM receive ended before a correlated Echo Reply was observed",
        )),
    }
}

fn realized_echo_id(
    policy: ResolvedSocketPolicy,
    requested_bind_id: u16,
    requested_echo_id: u16,
    kernel_reported_echo_id: u16,
) -> Result<u16, VerificationError> {
    let id_policy = policy
        .icmp
        .ok_or_else(|| error("ICMP DGRAM policy omitted ICMP ID capability"))?;
    if id_policy.id_capability == IcmpSocketIdCapability::DisjointIds {
        return Err(error(
            "ICMP DGRAM production policy incorrectly advertises disjoint receive IDs",
        ));
    }
    if requested_bind_id != 0 {
        if !id_policy.fixed_ids_honored {
            return Err(error(
                "production policy does not advertise fixed ICMP DGRAM ID preservation",
            ));
        }
        if requested_echo_id != requested_bind_id {
            return Err(error(format!(
                "fixed ICMP DGRAM requested Echo ID {requested_echo_id} differs from bind ID \
                 {requested_bind_id}"
            )));
        }
        if kernel_reported_echo_id != 0 && kernel_reported_echo_id != requested_bind_id {
            return Err(error(format!(
                "fixed ICMP DGRAM requested ID {requested_bind_id} was reported by the kernel as \
                 {kernel_reported_echo_id}"
            )));
        }
        return Ok(requested_bind_id);
    }
    if id_policy.id_capability == IcmpSocketIdCapability::KernelAssignedCollapsedId {
        if requested_echo_id != 0 {
            return Err(error(format!(
                "kernel-assigned wildcard ICMP DGRAM probe requested Echo ID {requested_echo_id}, \
                 expected 0"
            )));
        }
        if kernel_reported_echo_id == 0 {
            return Err(error(
                "kernel-assigned wildcard ICMP DGRAM probe reported no realized Echo ID",
            ));
        }
        return Ok(kernel_reported_echo_id);
    }
    if !id_policy.fixed_ids_honored {
        return Err(error(
            "fixed-collapse wildcard ICMP DGRAM policy cannot honor its generated Echo ID",
        ));
    }
    if requested_echo_id == 0 {
        return Err(error(
            "fixed-collapse wildcard ICMP DGRAM probe did not request a nonzero Echo ID",
        ));
    }
    if kernel_reported_echo_id != 0 && kernel_reported_echo_id != requested_echo_id {
        return Err(error(format!(
            "fixed-collapse wildcard Echo ID {requested_echo_id} conflicts with kernel ID \
             {kernel_reported_echo_id}"
        )));
    }
    Ok(requested_echo_id)
}

struct ReflectedRequestExpectation<'a> {
    domain: Domain,
    policy: ResolvedSocketPolicy,
    expected_peer: std::net::IpAddr,
    realized_echo_id: u16,
    sequence: u16,
    payload_nonce: &'a [u8],
}

fn verify_reflected_request_identity(
    socket: &ProbeSocketEvidence,
    reply: &ReceiveEvidence,
    expectation: ReflectedRequestExpectation<'_>,
) -> Result<(), VerificationError> {
    for (_, receive) in successful_receives(socket) {
        if std::ptr::eq(receive, reply) {
            continue;
        }
        let Ok(parsed) =
            parse_received_icmp(expectation.domain, expectation.policy, &receive.bytes)
        else {
            continue;
        };
        let Some(icmp) = parsed.icmp else {
            continue;
        };
        let Some(extent) = parsed.declared_extent_with_ipv4_length(
            &receive.bytes,
            expectation.policy.ipv4_receive_length,
        ) else {
            continue;
        };
        if !icmp.is_req
            || icmp.seq != expectation.sequence
            || receive.bytes.get(extent.payload.clone()) != Some(expectation.payload_nonce)
        {
            continue;
        }
        if extent.packet != (0..receive.bytes.len()) {
            return Err(error(
                "reflected ICMP DGRAM request has an invalid declared packet extent",
            ));
        }
        let reflected_source = receive
            .source
            .ok_or_else(|| error("reflected ICMP DGRAM request omitted source metadata"))?;
        if reflected_source.ip() != expectation.expected_peer
            || parsed
                .source_ip()
                .is_some_and(|packet_source| packet_source != expectation.expected_peer)
        {
            return Err(error(
                "reflected ICMP DGRAM request source differs from the expected peer",
            ));
        }
        if icmp.identity.destination_id != expectation.realized_echo_id {
            return Err(error(format!(
                "reflected Echo Request ID {} differs from realized/reply Echo ID {}",
                icmp.identity.destination_id, expectation.realized_echo_id
            )));
        }
    }
    Ok(())
}
