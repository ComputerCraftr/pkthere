use super::diagnostic::{role_name, socket_type_name};
use pkthere_socket_policy::{
    CapabilityEvidence, IcmpChecksumMode, IcmpKernelIdPolicy, IcmpSocketIdCapability,
    IcmpWildcardIdPolicy, IpHeaderMode, Ipv6DestinationScopeEvidence, ListenerLockLifecycle,
    PeerSourceRequirement, PeerVerification, ProtocolIdRequirement, ReceiveCaptureScope,
    ReceiveSyscall, ResolvedIcmpSocketPolicy, ResolvedSocketPolicy, SocketReresolveMode,
};
use pkthere_wire::packet_headers::{Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use serde_json::{Value, json};

pub(super) fn policy_snapshot(policy: ResolvedSocketPolicy) -> Value {
    let (disconnect_status, disconnect_capability) = match policy.disconnect.evidence {
        CapabilityEvidence::Measured { capability, .. } => ("measured", Some(capability)),
        CapabilityEvidence::Unsupported(_) => ("unsupported", None),
        CapabilityEvidence::Unverified(_) => ("unverified", None),
    };
    json!({
        "creation_path": format!("{:?}", policy.creation_path),
        "receive_capture_scope": receive_capture_scope(policy.receive_capture_scope),
        "peer_verification": peer_verification(policy.peer_verification),
        "listener_lifecycle": policy.listener_lifecycle.map(ListenerLockLifecycle::wire_name),
        "reuse": {
            "startup_peer_mode": policy.reuse.startup_peer_mode.wire_name(),
            "reresolve_mode": reresolve_mode(policy.reuse.reresolve_mode),
        },
        "disconnect": {
            "evidence_status": disconnect_status,
            "fingerprint": {
                "platform": format!("{:?}", policy.disconnect.fingerprint.platform),
                "family": format!("{:?}", policy.disconnect.fingerprint.family),
                "protocol": format!("{:?}", policy.disconnect.fingerprint.protocol),
                "socket_type": socket_type_name(policy.disconnect.fingerprint.socket_type),
                "role": role_name(policy.disconnect.fingerprint.role),
                "creation_path": format!("{:?}", policy.disconnect.fingerprint.creation_path),
                "bind_shape": format!("{:?}", policy.disconnect.fingerprint.bind_shape),
                "reuse_address": policy.disconnect.fingerprint.reuse_address,
                "reuse_port": policy.disconnect.fingerprint.reuse_port,
                "v6_only": policy.disconnect.fingerprint.v6_only,
                "receive_header":
                    receive_header_mode(policy.disconnect.fingerprint.receive_header),
                "protocol_zero_capture":
                    policy.disconnect.fingerprint.protocol_zero_capture,
                "bound_interface":
                    policy.disconnect.fingerprint.bound_interface.map(|value| format!("{value:?}")),
                "connected_peer_mode":
                    peer_verification(policy.disconnect.fingerprint.connected_peer_mode),
            },
            "association_clear_supported":
                disconnect_capability.map(|value| value.association_clear_supported),
            "exact_local_bind_preserved":
                disconnect_capability.map(|value| value.exact_local_bind_preserved),
            "reconnect_after_disconnect_supported":
                disconnect_capability.map(|value| value.reconnect_after_disconnect_supported),
            "peer_inspection_supported":
                disconnect_capability.map(|value| value.peer_inspection_supported),
            "stale_receive_queue_isolated":
                disconnect_capability.map(|value| value.stale_receive_queue_isolated),
        },
        "icmp": policy.icmp.map(icmp_policy),
        "send_policy": {
            "icmp_checksum": checksum_mode(policy.send_policy.icmp_checksum),
            "ip_header": ip_header_mode(policy.send_policy.ip_header),
        },
        "receive_header": receive_header_mode(policy.receive_header),
        "ipv6_destination_scope":
            ipv6_destination_scope(policy.ipv6_destination_scope),
        "ipv4_receive_length": ipv4_receive_length(policy.ipv4_receive_length),
        "receive_syscall": {
            "connected": receive_syscall(policy.receive_syscall.connected),
            "unconnected": receive_syscall(policy.receive_syscall.unconnected),
        },
        "receive_evidence": {
            "connected": {
                "peer_source": peer_source(policy.receive_evidence.connected.peer_source),
                "protocol_id":
                    protocol_id(policy.receive_evidence.connected.protocol_id),
            },
            "unconnected": {
                "peer_source": peer_source(policy.receive_evidence.unconnected.peer_source),
                "protocol_id":
                    protocol_id(policy.receive_evidence.unconnected.protocol_id),
            },
        },
    })
}

pub(super) fn bind_preservation_json(
    capability: pkthere_socket_policy::DatagramBindPreservation,
) -> Value {
    json!({
        "exact_local_bind_preserved": capability.exact_local_bind_preserved,
        "local_port_preserved": capability.local_port_preserved,
        "original_destination_receive_supported":
            capability.original_destination_receive_supported,
    })
}

const fn ipv6_destination_scope(scope: Ipv6DestinationScopeEvidence) -> &'static str {
    match scope {
        Ipv6DestinationScopeEvidence::NotApplicable => "not-applicable",
        Ipv6DestinationScopeEvidence::ExactBoundEndpoint => "exact-bound-endpoint",
    }
}

const fn receive_capture_scope(scope: ReceiveCaptureScope) -> &'static str {
    match scope {
        ReceiveCaptureScope::ProtocolFiltered => "protocol-filtered",
        ReceiveCaptureScope::InterfaceIpv4 => "interface-ipv4",
    }
}

const fn peer_verification(verification: PeerVerification) -> &'static str {
    match verification {
        PeerVerification::RequirePeerAddr => "exact-peer-address",
        PeerVerification::RequirePeerNetworkAddress => "peer-network-address",
        PeerVerification::ConnectSuccess => "connect-success",
    }
}

const fn ipv4_receive_length(encoding: Ipv4PacketLengthEncoding) -> &'static str {
    match encoding {
        Ipv4PacketLengthEncoding::NetworkTotal => "network-total",
        Ipv4PacketLengthEncoding::DarwinHostPayload => "darwin-host-payload",
    }
}

const fn receive_syscall(syscall: ReceiveSyscall) -> &'static str {
    match syscall {
        ReceiveSyscall::Recv => "recv",
        ReceiveSyscall::RecvFrom => "recv_from",
    }
}

fn icmp_policy(policy: ResolvedIcmpSocketPolicy) -> Value {
    json!({
        "role": role_name(policy.role),
        "socket_type": socket_type_name(policy.socket_type),
        "id_capability": id_capability(policy.id_capability),
        "kernel_id_policy": kernel_id_policy(policy.kernel_id_policy),
        "wildcard_id_policy": wildcard_id_policy(policy.wildcard_id_policy),
        "fixed_ids_honored": policy.fixed_ids_honored,
        "raw_packet_admission": policy.raw_packet_admission,
        "allow_debug_kernel_echo_self_handshake":
            policy.allow_debug_kernel_echo_self_handshake,
    })
}

const fn reresolve_mode(mode: SocketReresolveMode) -> &'static str {
    match mode {
        SocketReresolveMode::ReconnectInPlace => "reconnect-in-place",
        SocketReresolveMode::ReplaceSocket => "replace-socket",
        SocketReresolveMode::MetadataOnlyWhenUnconnected => "metadata-only-when-unconnected",
        SocketReresolveMode::ProcessExitOnly => "process-exit-only",
    }
}

const fn checksum_mode(mode: IcmpChecksumMode) -> &'static str {
    match mode {
        IcmpChecksumMode::ApplicationComputed => "application-computed",
        IcmpChecksumMode::KernelComputed => "kernel-computed",
    }
}

const fn ip_header_mode(mode: IpHeaderMode) -> &'static str {
    match mode {
        IpHeaderMode::PayloadOnly => "payload-only",
        IpHeaderMode::Ipv4HeaderIncluded => "ipv4-header-included",
    }
}

const fn receive_header_mode(mode: ReceiveHeaderMode) -> &'static str {
    match mode {
        ReceiveHeaderMode::PayloadOnly => "payload-only",
        ReceiveHeaderMode::TransportHeaderOnly => "transport-header-only",
        ReceiveHeaderMode::IpHeaderIncluded => "ip-header-included",
    }
}

const fn peer_source(requirement: PeerSourceRequirement) -> &'static str {
    match requirement {
        PeerSourceRequirement::ConnectedKernel => "connected-kernel",
        PeerSourceRequirement::SourceMetadata => "source-metadata",
        PeerSourceRequirement::RawPacketHeader => "raw-packet-header",
    }
}

const fn protocol_id(requirement: ProtocolIdRequirement) -> &'static str {
    match requirement {
        ProtocolIdRequirement::None => "none",
        ProtocolIdRequirement::ParsedTransportIdentifier => "parsed-transport-identifier",
    }
}

const fn id_capability(capability: IcmpSocketIdCapability) -> &'static str {
    match capability {
        IcmpSocketIdCapability::DisjointIds => "disjoint-ids",
        IcmpSocketIdCapability::KernelAssignedCollapsedId => "kernel-assigned-collapsed-id",
        IcmpSocketIdCapability::FixedCollapsedId => "fixed-collapsed-id",
    }
}

const fn kernel_id_policy(policy: IcmpKernelIdPolicy) -> &'static str {
    match policy {
        IcmpKernelIdPolicy::TrustedGetsockname => "trusted-getsockname",
        IcmpKernelIdPolicy::DeferredKernelAssigned => "deferred-kernel-assigned",
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol => "ignore-getsockname-protocol",
    }
}

const fn wildcard_id_policy(policy: IcmpWildcardIdPolicy) -> &'static str {
    match policy {
        IcmpWildcardIdPolicy::UseKernelAssignedCollapsedId => "use-kernel-assigned-collapsed-id",
        IcmpWildcardIdPolicy::GenerateFixedCollapsedId => "generate-fixed-collapsed-id",
        IcmpWildcardIdPolicy::GenerateDisjointIds => "generate-disjoint-ids",
    }
}
