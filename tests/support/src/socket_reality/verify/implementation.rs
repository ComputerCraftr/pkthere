use super::model::{
    DerivedFacts, RawIdObservation, VerificationError, VerificationErrorKind, VerifiedReality,
};
use super::raw::verify_forwarder_kernel_evidence;
use crate::packet_diagnostics::{DiagnosticLogIndex, TraceKey, trace_key};
use crate::socket_reality::case::{ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation};
use crate::socket_reality::evidence::{
    CallResult, ConnectedFilterEvidence, DatagramReceiveEvidence, DirectSocketEvidence,
    ForwarderEvidence, IcmpDgramEvidence, ProbeSocketEvidence, ProbeSocketId, RawReceiveEvidence,
    RealityEvidence, ReceiveApi, ReceiveEvidence, SocketCall,
};
use pkthere_socket_policy::{
    IcmpKernelIdPolicy, IcmpPolicyIntent, IcmpSocketIdCapability, PeerSourceRequirement,
    ReceiveSyscall, ResolvedSocketPolicy, SocketEvidenceKey, SocketRole, TimeoutAction,
    resolve_socket_policy_with_icmp_intent, socket_post_bind_policy,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::{
    self, IpVersion, ParsedPacketHeaders, ReceiveHeaderMode, select_receive_parser,
};
use serde_json::Value;
use socket2::{Domain, Type};
use std::net::SocketAddr;

pub fn verify(
    requested: RealityCase,
    evidence: &RealityEvidence,
) -> Result<VerifiedReality, VerificationError> {
    require_case_contract(requested)?;
    let timeout_action = if requested.operation == RealityOperation::ListenerRelock {
        TimeoutAction::Drop
    } else {
        TimeoutAction::Exit
    };
    let debug_unconnected = matches!(
        requested.operation,
        RealityOperation::UpstreamReconnect | RealityOperation::ListenerRelock
    ) && !requested.connected;
    let policy = resolve_socket_policy_with_icmp_intent(
        requested.policy_role,
        requested.protocol,
        requested.socket_type,
        timeout_action,
        debug_unconnected,
        requested.domain,
        IcmpPolicyIntent::default(),
    );
    let creation_policy = super::creation::verify_creation_policy(requested, policy)?;
    let facts = match (requested.operation, evidence) {
        (RealityOperation::DatagramReceiveEvidence, RealityEvidence::DatagramReceive(evidence)) => {
            verify_datagram(requested, policy, evidence)?
        }
        (RealityOperation::ConnectedPeerFiltering, RealityEvidence::ConnectedFilter(evidence)) => {
            verify_connected_filter(requested, policy, evidence)?
        }
        (
            RealityOperation::IcmpDgramReceiveId | RealityOperation::IcmpDgramFixedId,
            RealityEvidence::IcmpDgram(evidence),
        ) => verify_icmp_dgram(requested, policy, evidence)?,
        (RealityOperation::ReusePortFanout, RealityEvidence::ReusePortFanout(evidence)) => {
            super::reuse_port::verify_reuse_port_fanout(evidence)?
        }
        (RealityOperation::RawReceiveEvidence, RealityEvidence::RawReceive(evidence)) => {
            verify_raw_receive(requested, policy, evidence)?
        }
        (RealityOperation::RawFourIdForwarding, RealityEvidence::RawFourId(evidence)) => {
            verify_raw_four_id(requested, policy, evidence)?
        }
        (
            RealityOperation::UpstreamReconnect
            | RealityOperation::ListenerRelock
            | RealityOperation::ListenerRebind,
            RealityEvidence::Lifecycle(evidence),
        ) => super::lifecycle::verify_lifecycle(requested, policy, evidence)?,
        _ => {
            return Err(error(format!(
                "evidence variant does not execute requested operation {:?}",
                requested.operation
            )));
        }
    };
    Ok(VerifiedReality {
        requested,
        creation_policy,
        policy,
        facts,
    })
}

fn verify_datagram(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &DatagramReceiveEvidence,
) -> Result<DerivedFacts, VerificationError> {
    require_direct_dimensions(
        &evidence.direct,
        requested,
        &[evidence.receiver, evidence.sender],
    )?;
    let receiver = require_socket(&evidence.direct, evidence.receiver)?;
    let sender = require_socket(&evidence.direct, evidence.sender)?;
    let receiver_addr = last_getsockname(receiver)?;
    let sender_addr = last_getsockname(sender)?;
    let sender_target = sender
        .calls
        .iter()
        .find_map(|event| match &event.call {
            SocketCall::Connect { target, result } if result.is_ok() => Some(*target),
            _ => None,
        })
        .ok_or_else(|| error("UDP sender has no successful connect evidence"))?;
    if sender_target != receiver_addr {
        return Err(error(format!(
            "UDP sender connected to {sender_target}, but receiver getsockname reports {receiver_addr}"
        )));
    }
    let received = successful_receives(receiver)
        .next_back()
        .ok_or_else(|| error("UDP receiver produced no successful receive"))?;
    let sent = successful_sends(sender)
        .next_back()
        .ok_or_else(|| error("UDP sender produced no successful send"))?;
    if received.0 != ReceiveApi::RecvFrom {
        return Err(error("unconnected UDP probe did not use recv_from"));
    }
    let source = received
        .1
        .source
        .ok_or_else(|| error("UDP recv_from omitted source metadata"))?;
    if source != sender_addr {
        return Err(error(format!(
            "UDP source metadata {source} does not match sender getsockname {sender_addr}"
        )));
    }
    if received.1.bytes != sent {
        return Err(error("UDP receive bytes differ from sent probe payload"));
    }
    let parsed = packet_headers::parse_udp_datagram_payload(&received.1.bytes);
    if parsed.src_ip.is_some() || parsed.dst_ip.is_some() || parsed.udp.is_some() {
        return Err(error(
            "UDP DGRAM receive unexpectedly contained IP or UDP headers",
        ));
    }
    if policy.receive_header != ReceiveHeaderMode::PayloadOnly
        || policy.evidence_policy(false).peer_source != PeerSourceRequirement::SourceMetadata
        || policy.receive_syscall(false) != ReceiveSyscall::RecvFrom
    {
        return Err(error(
            "production UDP receive policy disagrees with measured payload/source metadata",
        ));
    }
    Ok(DerivedFacts::Datagram {
        receiver: receiver_addr,
        sender: sender_addr,
        source_metadata: source,
        byte_count: received.1.bytes.len(),
    })
}

fn verify_connected_filter(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &ConnectedFilterEvidence,
) -> Result<DerivedFacts, VerificationError> {
    require_direct_dimensions(
        &evidence.direct,
        requested,
        &[
            evidence.receiver,
            evidence.accepted_peer,
            evidence.rejected_peer,
        ],
    )?;
    let receiver = require_socket(&evidence.direct, evidence.receiver)?;
    let connects = receiver
        .calls
        .iter()
        .filter(|event| matches!(&event.call, SocketCall::Connect { result, .. } if result.is_ok()))
        .count();
    if connects != 1 {
        return Err(error(format!(
            "connected filter probe recorded {connects} successful connects"
        )));
    }
    let mut receive_calls = receiver.calls.iter().filter_map(|event| match &event.call {
        SocketCall::Receive { api, result } => Some((*api, result)),
        _ => None,
    });
    let first = receive_calls.next();
    let second = receive_calls.next();
    if first.is_none() || second.is_none() || receive_calls.next().is_some() {
        return Err(error("connected filter probe must record two receives"));
    }
    let first = first.expect("checked first receive");
    let second = second.expect("checked second receive");
    let rejected_peer_filtered = matches!(first.1, CallResult::OsError(_));
    let rejected = require_socket(&evidence.direct, evidence.rejected_peer)?;
    let rejected_payload = successful_sends(rejected)
        .next_back()
        .ok_or_else(|| error("rejected UDP peer produced no successful send"))?;
    let rejected_addr = last_getsockname(rejected)?;
    let queued_wrong_peer_source_visible = matches!(
        first,
        (ReceiveApi::RecvFrom, CallResult::Ok(receive))
            if receive.source == Some(rejected_addr) && receive.bytes == rejected_payload
    );
    let accepted = require_socket(&evidence.direct, evidence.accepted_peer)?;
    let accepted_payload = successful_sends(accepted)
        .next_back()
        .ok_or_else(|| error("accepted UDP peer produced no successful send"))?;
    let accepted_addr = last_getsockname(accepted)?;
    let accepted_peer_delivered = match requested.policy_role {
        SocketRole::Listener => matches!(
            second,
            (ReceiveApi::RecvFrom, CallResult::Ok(receive))
                if receive.source == Some(accepted_addr) && receive.bytes == accepted_payload
        ),
        SocketRole::Upstream => matches!(
            second,
            (ReceiveApi::Recv, CallResult::Ok(receive))
                if receive.source.is_none() && receive.bytes == accepted_payload
        ),
    };
    match requested.policy_role {
        SocketRole::Listener => {
            if (!rejected_peer_filtered && !queued_wrong_peer_source_visible)
                || !accepted_peer_delivered
            {
                return Err(error(
                    "connected UDP listener neither filtered nor exposed the pre-connect queued wrong peer",
                ));
            }
            if policy.evidence_policy(true).peer_source != PeerSourceRequirement::SourceMetadata
                || policy.receive_syscall(true) != ReceiveSyscall::RecvFrom
            {
                return Err(error(
                    "production listener policy does not preserve queued source evidence with recv_from",
                ));
            }
        }
        SocketRole::Upstream => {
            if !rejected_peer_filtered
                || queued_wrong_peer_source_visible
                || !accepted_peer_delivered
            {
                return Err(error(
                    "connected UDP upstream did not kernel-filter the wrong peer and deliver the connected peer",
                ));
            }
            if policy.evidence_policy(true).peer_source != PeerSourceRequirement::ConnectedKernel
                || policy.receive_syscall(true) != ReceiveSyscall::Recv
            {
                return Err(error(
                    "production upstream policy does not use connected-kernel evidence with recv",
                ));
            }
        }
    }
    Ok(DerivedFacts::ConnectedFilter {
        rejected_peer_filtered,
        queued_wrong_peer_source_visible,
        accepted_peer_delivered,
    })
}

fn verify_icmp_dgram(
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
    let kernel_addr = last_getsockname(socket)?;
    let received = successful_receives(socket)
        .next_back()
        .ok_or_else(|| error("ICMP DGRAM produced no receive evidence"))?;
    let sent = successful_sends(socket)
        .next_back()
        .ok_or_else(|| error("ICMP DGRAM produced no successful send evidence"))?;
    if received.0 != ReceiveApi::Recv || policy.receive_syscall(true) != ReceiveSyscall::Recv {
        return Err(error("connected ICMP DGRAM probe did not use recv"));
    }
    let parsed = parse_received_icmp(requested.domain, policy.receive_header, &received.1.bytes);
    let icmp = parsed
        .icmp
        .ok_or_else(|| error("ICMP DGRAM receive bytes did not contain a valid Echo header"))?;
    let sent_icmp = parse_icmp_transport(requested.domain, sent)
        .icmp
        .ok_or_else(|| error("ICMP DGRAM send bytes did not contain a valid Echo header"))?;
    if sent_icmp.seq != icmp.seq {
        return Err(error(format!(
            "ICMP DGRAM response sequence {} differs from sent sequence {}",
            icmp.seq, sent_icmp.seq
        )));
    }
    if policy.evidence_policy(true).peer_source != PeerSourceRequirement::ConnectedKernel {
        return Err(error(
            "ICMP DGRAM layout/source policy disagrees with measured evidence",
        ));
    }
    let id_policy = policy
        .icmp
        .ok_or_else(|| error("ICMP DGRAM policy omitted ICMP ID capability"))?;
    if id_policy.id_capability == IcmpSocketIdCapability::DisjointIds {
        return Err(error(
            "ICMP DGRAM production policy incorrectly advertises disjoint receive IDs",
        ));
    }
    let expected_receive_id = if requested_bind_id != 0 {
        if !id_policy.fixed_ids_honored {
            return Err(error(
                "production policy does not advertise fixed ICMP DGRAM ID preservation",
            ));
        }
        requested_bind_id
    } else if kernel_addr.port() != 0 {
        kernel_addr.port()
    } else if id_policy.fixed_ids_honored {
        sent_icmp.identity.destination_id
    } else {
        return Err(error(
            "ICMP DGRAM getsockname exposed no receive ID and policy cannot preserve a fixed ID",
        ));
    };
    if icmp.identity.destination_id != expected_receive_id {
        return Err(error(format!(
            "wire Echo ID {} differs from effective DGRAM receive ID {}",
            icmp.identity.destination_id, expected_receive_id
        )));
    }
    Ok(DerivedFacts::IcmpDgram {
        requested_bind_id,
        requested_echo_id: sent_icmp.identity.destination_id,
        kernel_receive_id: kernel_addr.port(),
        observed_echo_id: icmp.identity.destination_id,
        sequence: icmp.seq,
        byte_count: received.1.bytes.len(),
    })
}

fn verify_raw_receive(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &RawReceiveEvidence,
) -> Result<DerivedFacts, VerificationError> {
    let icmp_policy = policy
        .icmp
        .ok_or_else(|| error("RAW policy omitted ICMP policy"))?;
    if icmp_policy.kernel_id_policy != IcmpKernelIdPolicy::IgnoreGetsocknameProtocol {
        return Err(error(
            "production RAW policy does not explicitly distrust getsockname Echo IDs",
        ));
    }
    if !icmp_policy.can_honor_disjoint_ids() {
        return Err(error(
            "production RAW policy does not advertise disjoint IDs",
        ));
    }
    match evidence {
        RawReceiveEvidence::Direct { direct, socket } => {
            let socket = require_socket(direct, *socket)?;
            require_create_dimensions(socket, requested)?;
            if !socket.create.result.is_ok() {
                return Err(error(
                    "RAW direct evidence unavailable and no production-forwarder fallback supplied",
                ));
            }
            let bound_to_zero = socket.calls.iter().any(|event| {
                matches!(
                    &event.call,
                    SocketCall::Bind { requested, result }
                        if requested.port() == 0 && result.is_ok()
                )
            });
            if !bound_to_zero {
                return Err(error(
                    "RAW direct evidence did not preserve a successful bind request with ID 0",
                ));
            }
            let sent = successful_sends(socket)
                .next_back()
                .ok_or_else(|| error("RAW direct evidence has no successful send"))?;
            let sent_icmp = parse_icmp_transport(requested.domain, sent)
                .icmp
                .ok_or_else(|| error("RAW send evidence omitted a valid Echo header"))?;
            let requested_source_id = sent_icmp
                .identity
                .source_id
                .ok_or_else(|| error("RAW send evidence omitted an explicit logical source ID"))?;
            let requested_echo_id = sent_icmp.identity.destination_id;
            if requested_source_id == requested_echo_id {
                return Err(error(
                    "RAW send evidence did not exercise disjoint logical IDs",
                ));
            }
            let kernel_addr = last_getsockname(socket)?;
            let received = successful_receives(socket)
                .next_back()
                .ok_or_else(|| error("RAW socket produced no receive evidence"))?;
            if received.0 != ReceiveApi::RecvFrom
                || policy.receive_syscall(false) != ReceiveSyscall::RecvFrom
            {
                return Err(error("unconnected RAW probe did not use recv_from"));
            }
            let parsed =
                parse_received_icmp(requested.domain, policy.receive_header, &received.1.bytes);
            let icmp = parsed
                .icmp
                .ok_or_else(|| error("RAW receive bytes did not contain a valid Echo header"))?;
            if requested_echo_id != icmp.identity.destination_id {
                return Err(error(format!(
                    "RAW wire Echo ID {} differs from sent ID {}",
                    icmp.identity.destination_id, requested_echo_id
                )));
            }
            if icmp.identity.source_id != Some(requested_source_id) {
                return Err(error(format!(
                    "RAW logical source ID {:?} differs from sent ID {}",
                    icmp.identity.source_id, requested_source_id
                )));
            }
            let ip_header_present = parsed.src_ip.is_some();
            let source_metadata_present = received.1.source.is_some();
            verify_raw_source_policy(policy, ip_header_present, source_metadata_present)?;
            Ok(DerivedFacts::RawReceive {
                kernel_addr,
                observed_source_id: requested_source_id,
                observed_echo_id: icmp.identity.destination_id,
                ip_header_present,
                source_metadata_present,
                id_observation: classify_raw(
                    Some(kernel_addr.port()),
                    Some(icmp.identity.destination_id),
                ),
            })
        }
        RawReceiveEvidence::ProductionForwarder(evidence) => {
            let observed = verify_forwarder_kernel_evidence(
                evidence,
                requested.domain,
                requested.policy_role,
            )?;
            Ok(DerivedFacts::RawReceive {
                kernel_addr: observed.kernel_addr,
                observed_source_id: observed.source_id,
                observed_echo_id: observed.echo_id,
                ip_header_present: observed.ip_header_present,
                source_metadata_present: observed.source_metadata_present,
                id_observation: classify_raw(
                    Some(observed.kernel_addr.port()),
                    Some(observed.echo_id),
                ),
            })
        }
    }
}

fn verify_raw_four_id(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &ForwarderEvidence,
) -> Result<DerivedFacts, VerificationError> {
    let icmp = policy
        .icmp
        .ok_or_else(|| error("RAW four-ID policy omitted ICMP policy"))?;
    if !icmp.can_honor_disjoint_ids() {
        return Err(error(
            "production RAW policy does not advertise disjoint IDs",
        ));
    }
    if icmp.kernel_id_policy != IcmpKernelIdPolicy::IgnoreGetsocknameProtocol {
        return Err(error(
            "production RAW four-ID policy trusts getsockname Echo IDs",
        ));
    }
    let post_bind = socket_post_bind_policy(requested.socket_path);
    if requested.socket_path
        == crate::socket_reality::case::RealitySocketPath::WindowsProtocolZeroCapture
        && (!post_bind.enable_windows_rcvall || !post_bind.set_ipv4_header_included)
    {
        return Err(error(
            "protocol-zero RAW forwarding lacks required post-bind capture setup policy",
        ));
    }
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        let observed = verify_forwarder_kernel_evidence(evidence, requested.domain, role)?;
        if post_bind.enable_windows_rcvall && !observed.ip_header_present {
            return Err(error(format!(
                "{role:?} protocol-zero capture produced no IPv4 header evidence"
            )));
        }
        verify_raw_source_policy(
            policy,
            observed.ip_header_present,
            observed.source_metadata_present,
        )?;
    }
    let received = evidence
        .client_received
        .as_ok()
        .ok_or_else(|| error("RAW four-ID client did not receive a reply"))?;
    if received != &evidence.client_sent {
        return Err(error("RAW four-ID forwarding changed the client payload"));
    }
    let node_a = process(evidence, "node-a")?;
    let node_b = process(evidence, "node-b")?;
    let client_source_id = argument_u16(&node_a.command_arguments, "--there-source-id")?;
    let client_reply_id = argument_u16(&node_a.command_arguments, "--there-reply-id")?;
    let server_source_id = argument_u16(&node_b.command_arguments, "--here-source-id")?;
    let server_destination_id = endpoint_id(&node_b.command_arguments, "--here")?;

    let node_b_diagnostics = diagnostic_index(node_b)?;
    let client_to_server =
        require_same_packet_ids(&node_b_diagnostics, client_source_id, server_destination_id)?;
    require_complete_trace(&node_b_diagnostics, &client_to_server)?;
    let node_a_diagnostics = diagnostic_index(node_a)?;
    let server_to_client =
        require_same_packet_ids(&node_a_diagnostics, server_source_id, client_reply_id)?;
    require_complete_trace(&node_a_diagnostics, &server_to_client)?;

    let mut keys = Vec::new();
    for process in [node_a, node_b] {
        let diagnostics = diagnostic_index(process)?;
        for dump in diagnostics.packets() {
            let Some(value) = dump.value.pointer("/socket/evidence_key") else {
                continue;
            };
            let key = parse_evidence_key(value)?;
            let kernel_addr = dump
                .value
                .pointer("/socket/local_kernel_addr")
                .and_then(Value::as_str)
                .ok_or_else(|| error("packet dump omitted local_kernel_addr"))?;
            let matching = diagnostics.socket_evidence().any(|line| {
                line.value.get("key") == Some(value)
                    && line.value.get("getsockname").and_then(Value::as_str) == Some(kernel_addr)
            });
            if !matching {
                return Err(error(
                    "packet dump kernel address lacks same-generation socket evidence",
                ));
            }
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err(error("RAW four-ID logs contained no socket evidence keys"));
    }
    keys.sort_by_key(|key| {
        (
            key.process_id,
            key.socket_slot,
            key.generation,
            role_rank(key.role),
        )
    });
    keys.dedup();
    Ok(DerivedFacts::RawFourId {
        client_source_id,
        server_destination_id,
        server_source_id,
        client_reply_id,
        evidence_keys: keys,
    })
}

fn require_case_contract(case: RealityCase) -> Result<(), VerificationError> {
    let valid = match case.operation {
        RealityOperation::DatagramReceiveEvidence => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && !case.connected
        }
        RealityOperation::ConnectedPeerFiltering => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.connected
        }
        RealityOperation::IcmpDgramReceiveId | RealityOperation::IcmpDgramFixedId => {
            case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Upstream
                && case.connected
        }
        RealityOperation::ReusePortFanout => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && !case.connected
        }
        RealityOperation::RawReceiveEvidence => {
            case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::RAW
                && !case.connected
        }
        RealityOperation::RawFourIdForwarding => {
            case.domain == Domain::IPV4
                && case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::RAW
                && case.policy_role == SocketRole::Upstream
                && !case.connected
        }
        RealityOperation::UpstreamReconnect => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Upstream
                && case.target_domain.is_some()
        }
        RealityOperation::ListenerRelock => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && case.target_domain == Some(case.domain)
        }
        RealityOperation::ListenerRebind => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && !case.connected
                && case.target_domain.is_some()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(error(format!(
            "requested case has an invalid dimension combination: {case:?}"
        )))
    }
}

fn require_direct_dimensions(
    evidence: &DirectSocketEvidence,
    requested: RealityCase,
    socket_ids: &[ProbeSocketId],
) -> Result<(), VerificationError> {
    for socket_id in socket_ids {
        require_create_dimensions(require_socket(evidence, *socket_id)?, requested)?;
    }
    Ok(())
}

fn require_create_dimensions(
    socket: &ProbeSocketEvidence,
    requested: RealityCase,
) -> Result<(), VerificationError> {
    let create = &socket.create;
    for (index, call) in socket.calls.iter().enumerate() {
        let expected = u64::try_from(index + 1).expect("socket call index fits u64");
        if call.sequence != expected {
            return Err(error(format!(
                "socket {:?} event order jumps from expected {expected} to {}",
                create.socket_id, call.sequence
            )));
        }
    }
    let expected = requested.socket_create_spec();
    if create.domain != expected.domain
        || create.socket_type != expected.socket_type
        || create.protocol != expected.protocol
    {
        return Err(error(format!(
            "recorded socket creation {:?}/{:?}/{:?} does not match requested {:?}/{:?}/{:?}",
            create.domain,
            create.socket_type,
            create.protocol,
            expected.domain,
            expected.socket_type,
            expected.protocol
        )));
    }
    Ok(())
}

fn require_socket(
    evidence: &DirectSocketEvidence,
    id: ProbeSocketId,
) -> Result<&ProbeSocketEvidence, VerificationError> {
    evidence
        .socket(id)
        .ok_or_else(|| error(format!("direct evidence omitted probe socket {id:?}")))
}

fn last_getsockname(socket: &ProbeSocketEvidence) -> Result<SocketAddr, VerificationError> {
    socket
        .calls
        .iter()
        .rev()
        .find_map(|event| match &event.call {
            SocketCall::GetSockName {
                result: CallResult::Ok(address),
            } => Some(*address),
            _ => None,
        })
        .ok_or_else(|| error("socket has no successful getsockname evidence"))
}

fn successful_receives(
    socket: &ProbeSocketEvidence,
) -> impl DoubleEndedIterator<Item = (ReceiveApi, &ReceiveEvidence)> {
    socket.calls.iter().filter_map(|event| match &event.call {
        SocketCall::Receive {
            api,
            result: CallResult::Ok(receive),
        } => Some((*api, receive)),
        _ => None,
    })
}

fn successful_sends(socket: &ProbeSocketEvidence) -> impl DoubleEndedIterator<Item = &[u8]> {
    socket.calls.iter().filter_map(|event| match &event.call {
        SocketCall::Send {
            bytes,
            result: CallResult::Ok(length),
            ..
        } if *length == bytes.len() => Some(bytes.as_slice()),
        _ => None,
    })
}

fn parse_icmp_transport(domain: Domain, bytes: &[u8]) -> ParsedPacketHeaders {
    if domain == Domain::IPV4 {
        packet_headers::parse_icmp_v4_transport(bytes)
    } else {
        packet_headers::parse_icmp_v6_transport(bytes)
    }
}

fn parse_received_icmp(
    domain: Domain,
    receive_header: ReceiveHeaderMode,
    bytes: &[u8],
) -> ParsedPacketHeaders {
    let version = if domain == Domain::IPV4 {
        IpVersion::V4
    } else if domain == Domain::IPV6 {
        IpVersion::V6
    } else {
        panic!("unsupported direct-probe domain: {domain:?}");
    };
    select_receive_parser(SupportedProtocol::ICMP, version, receive_header)
        .expect("production policy must select a strict ICMP parser")
        .parse(bytes)
}

fn verify_raw_source_policy(
    policy: ResolvedSocketPolicy,
    ip_header_present: bool,
    source_metadata_present: bool,
) -> Result<(), VerificationError> {
    let matches = match policy.evidence_policy(false).peer_source {
        PeerSourceRequirement::RawPacketHeader => ip_header_present,
        PeerSourceRequirement::SourceMetadata => source_metadata_present,
        PeerSourceRequirement::ConnectedKernel => false,
    };
    if matches {
        Ok(())
    } else {
        Err(error(
            "RAW source evidence does not satisfy production receive policy",
        ))
    }
}

fn classify_raw(kernel_id: Option<u16>, wire_id: Option<u16>) -> RawIdObservation {
    match (kernel_id, wire_id) {
        (Some(kernel), Some(wire)) if kernel == wire => {
            RawIdObservation::EqualObservedButNotProofOfTrust
        }
        (Some(_), Some(_)) => RawIdObservation::MismatchObserved,
        _ => RawIdObservation::EvidenceUnavailable,
    }
}

fn process<'a>(
    evidence: &'a ForwarderEvidence,
    label: &str,
) -> Result<&'a crate::socket_reality::evidence::ForwarderProcessEvidence, VerificationError> {
    evidence
        .processes
        .iter()
        .find(|process| process.label == label)
        .ok_or_else(|| error(format!("forwarder evidence omitted {label}")))
}

fn diagnostic_index(
    process: &crate::socket_reality::evidence::ForwarderProcessEvidence,
) -> Result<DiagnosticLogIndex, VerificationError> {
    DiagnosticLogIndex::parse(&process.stdout, &process.stderr)
        .map_err(|message| error(format!("{} diagnostics: {message}", process.label)))
}

fn argument_u16(arguments: &[String], flag: &str) -> Result<u16, VerificationError> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == flag)
        .and_then(|pair| pair[1].parse().ok())
        .ok_or_else(|| error(format!("forwarder arguments omitted {flag}")))
}

fn endpoint_id(arguments: &[String], flag: &str) -> Result<u16, VerificationError> {
    let endpoint = arguments
        .windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| error(format!("forwarder arguments omitted {flag}")))?;
    endpoint
        .rsplit_once(':')
        .and_then(|(_, id)| id.parse().ok())
        .ok_or_else(|| error(format!("invalid endpoint argument {endpoint}")))
}

pub(super) fn require_same_packet_ids(
    diagnostics: &DiagnosticLogIndex,
    source_id: u16,
    destination_id: u16,
) -> Result<TraceKey, VerificationError> {
    let found = diagnostics.packets().find_map(|dump| {
        let matches = dump.value.get("stage").and_then(Value::as_str) == Some("admission")
            && dump
                .value
                .pointer("/admission/result")
                .and_then(Value::as_str)
                == Some("accepted")
            && dump
                .value
                .pointer("/parse/headers/icmp/logical_source_id")
                .and_then(Value::as_u64)
                == Some(u64::from(source_id))
            && dump
                .value
                .pointer("/parse/headers/icmp/logical_destination_id")
                .and_then(Value::as_u64)
                == Some(u64::from(destination_id));
        matches.then(|| trace_key(&dump.value)).flatten()
    });
    found.ok_or_else(|| {
        error(format!(
            "no single admitted packet observed ICMP IDs {source_id} -> {destination_id}"
        ))
    })
}

fn require_complete_trace(
    diagnostics: &DiagnosticLogIndex,
    key: &TraceKey,
) -> Result<(), VerificationError> {
    let grouped = diagnostics.trace_stages();
    let stages = grouped
        .get(key)
        .ok_or_else(|| error("admitted packet has no correlated trace stages"))?;
    if stages.received.len() != 1 || stages.admission.len() != 1 || stages.disposition.len() != 1 {
        return Err(error(format!(
            "packet trace {key:?} is incomplete or non-terminal"
        )));
    }
    if !(stages.received[0].sequence < stages.admission[0].sequence
        && stages.admission[0].sequence < stages.disposition[0].sequence)
    {
        return Err(error(format!(
            "packet trace {key:?} stages are out of order"
        )));
    }
    Ok(())
}

pub(super) fn parse_evidence_key(value: &Value) -> Result<SocketEvidenceKey, VerificationError> {
    let role = match value.get("role").and_then(Value::as_str) {
        Some("listener") => SocketRole::Listener,
        Some("upstream") => SocketRole::Upstream,
        other => return Err(error(format!("invalid socket evidence role {other:?}"))),
    };
    let domain = match value.get("domain").and_then(Value::as_str) {
        Some("ipv4") => Domain::IPV4,
        Some("ipv6") => Domain::IPV6,
        other => return Err(error(format!("invalid socket evidence domain {other:?}"))),
    };
    Ok(SocketEvidenceKey {
        process_id: value
            .get("process_id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
            .ok_or_else(|| error("socket evidence key omitted process_id"))?,
        role,
        domain,
        socket_slot: value
            .get("socket_slot")
            .and_then(Value::as_u64)
            .and_then(|slot| u32::try_from(slot).ok())
            .ok_or_else(|| error("socket evidence key omitted socket_slot"))?,
        generation: value
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| error("socket evidence key omitted generation"))?,
    })
}

fn role_rank(role: SocketRole) -> u8 {
    u8::from(role == SocketRole::Upstream)
}

pub(super) fn error(message: impl Into<String>) -> VerificationError {
    VerificationError {
        kind: VerificationErrorKind::EvidenceMismatch,
        message: message.into(),
    }
}
