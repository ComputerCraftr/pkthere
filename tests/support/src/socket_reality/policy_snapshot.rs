use super::names::{role_name, socket_type_name};
use pkthere_socket_policy::{
    IcmpChecksumMode, IcmpKernelIdPolicy, IcmpSocketIdCapability, IcmpWildcardIdPolicy,
    IpHeaderMode, LockedPeerMode, PeerSourceRequirement, ProtocolIdRequirement, ReceiveSyscall,
    ResolvedIcmpSocketPolicy, ResolvedSocketPolicy, SocketReresolveMode, StartupPeerMode,
    TimeoutClearMode,
};
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use serde_json::{Value, json};

pub(super) fn policy_snapshot(policy: ResolvedSocketPolicy) -> Value {
    json!({
        "reuse": {
            "startup_peer_mode": startup_mode(policy.reuse.startup_peer_mode),
            "locked_peer_mode": locked_mode(policy.reuse.locked_peer_mode),
            "reresolve_mode": reresolve_mode(policy.reuse.reresolve_mode),
            "timeout_clear_mode": timeout_clear_mode(policy.reuse.timeout_clear_mode),
        },
        "datagram_disconnect": {
            "disconnect_call_supported":
                policy.datagram_disconnect.disconnect_call_supported,
            "reconnect_after_disconnect_supported":
                policy.datagram_disconnect.reconnect_after_disconnect_supported,
            "listener_original_bind_receive_after_disconnect_supported":
                policy.datagram_disconnect
                    .listener_original_bind_receive_after_disconnect_supported,
        },
        "icmp": policy.icmp.map(icmp_policy),
        "send_policy": {
            "icmp_checksum": checksum_mode(policy.send_policy.icmp_checksum),
            "ip_header": ip_header_mode(policy.send_policy.ip_header),
        },
        "receive_header": receive_header_mode(policy.receive_header),
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

const fn startup_mode(mode: StartupPeerMode) -> &'static str {
    match mode {
        StartupPeerMode::Connected => "connected",
        StartupPeerMode::Unconnected => "unconnected",
    }
}

const fn locked_mode(mode: LockedPeerMode) -> &'static str {
    match mode {
        LockedPeerMode::ConnectAfterLock => "connect-after-lock",
        LockedPeerMode::StayUnconnected => "stay-unconnected",
    }
}

const fn reresolve_mode(mode: SocketReresolveMode) -> &'static str {
    match mode {
        SocketReresolveMode::ReconnectInPlace => "reconnect-in-place",
        SocketReresolveMode::ReplaceSocket => "replace-socket",
        SocketReresolveMode::MetadataOnlyWhenUnconnected => "metadata-only-when-unconnected",
    }
}

const fn timeout_clear_mode(mode: TimeoutClearMode) -> &'static str {
    match mode {
        TimeoutClearMode::DisconnectSocket => "disconnect-socket",
        TimeoutClearMode::ProcessExit => "process-exit",
        TimeoutClearMode::NoConnectedState => "no-connected-state",
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
