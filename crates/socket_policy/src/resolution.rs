use crate::{
    DisconnectBindShape, DisconnectRealityKey, IcmpChecksumMode, IcmpKernelIdPolicy,
    IcmpSocketIdCapability, IcmpWildcardIdPolicy, InterfaceBindingKind, IpHeaderMode,
    Ipv6DestinationScopeEvidence, ListenerLockLifecycle, ListenerWorkerSocketPolicy,
    PeerSourceRequirement, ProtocolIdRequirement, ReceiveCaptureScope, ReceiveEvidencePolicy,
    ReceiveSyscall, ResolvedDisconnectContract, ResolvedIcmpSocketPolicy, ResolvedReceiveEvidence,
    ResolvedReceiveSyscall, ResolvedSocketPolicy, SocketCreationPath, SocketPlatform,
    SocketReresolveMode, SocketRole, SocketSendPolicy, StartupPeerMode, TimeoutAction,
    current_icmp_platform_capabilities, icmp_platform_capabilities, listener_lifecycle,
    listener_worker_socket_policy, raw_icmp_creation_path, resolution_api,
    resolve_peer_verification, socket_disconnect_evidence,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use socket2::{Domain, Type};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcmpPolicyIntent {
    pub disable_disjoint_ids: bool,
    pub allow_debug_kernel_echo_self_handshake: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolPolicyIntent {
    Udp,
    Icmp(IcmpPolicyIntent),
}

impl ProtocolPolicyIntent {
    #[inline]
    pub(crate) const fn protocol(self) -> SupportedProtocol {
        match self {
            Self::Udp => SupportedProtocol::UDP,
            Self::Icmp(_) => SupportedProtocol::ICMP,
        }
    }

    #[inline]
    const fn icmp(self) -> Option<IcmpPolicyIntent> {
        match self {
            Self::Udp => None,
            Self::Icmp(intent) => Some(intent),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPathContext {
    pub family: Domain,
    pub creation_path: SocketCreationPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPolicyContext {
    pub path: SocketPathContext,
    pub lifecycle: SocketLifecycleContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketLifecycleContext {
    pub bind_shape: DisconnectBindShape,
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub v6_only: Option<bool>,
    pub bound_interface: Option<InterfaceBindingKind>,
}

impl SocketLifecycleContext {
    #[inline]
    pub const fn direct_default() -> Self {
        Self {
            bind_shape: DisconnectBindShape::ConcreteEphemeral,
            reuse_address: false,
            reuse_port: false,
            v6_only: None,
            bound_interface: None,
        }
    }

    #[inline]
    pub fn for_requested_bind(
        requested: std::net::SocketAddr,
        reuse_address: bool,
        reuse_port: bool,
    ) -> Self {
        let wildcard = requested.ip().is_unspecified();
        let fixed = requested.port() != 0;
        let bind_shape = match (wildcard, fixed) {
            (false, false) => DisconnectBindShape::ConcreteEphemeral,
            (false, true) => DisconnectBindShape::ConcreteFixed,
            (true, false) => DisconnectBindShape::WildcardEphemeral,
            (true, true) => DisconnectBindShape::WildcardFixed,
        };
        Self {
            bind_shape,
            reuse_address,
            reuse_port,
            v6_only: None,
            bound_interface: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketReuseCapability {
    pub startup_peer_mode: StartupPeerMode,
    pub reresolve_mode: SocketReresolveMode,
}

impl SocketReuseCapability {
    #[inline]
    pub const fn starts_connected(self) -> bool {
        matches!(self.startup_peer_mode, StartupPeerMode::Connected)
    }

    #[inline]
    pub const fn reconnects_in_place(self) -> bool {
        matches!(self.reresolve_mode, SocketReresolveMode::ReconnectInPlace)
    }
}

pub(crate) struct SocketPolicyRequest {
    pub(crate) role: SocketRole,
    pub(crate) protocol_intent: ProtocolPolicyIntent,
    pub(crate) sock_type: Type,
    pub(crate) timeout_act: TimeoutAction,
    pub(crate) debug_unconnected: bool,
    pub(crate) family: Domain,
    pub(crate) creation_path: SocketCreationPath,
    pub(crate) lifecycle: SocketLifecycleContext,
    pub(crate) listener_worker_policy: Option<ListenerWorkerSocketPolicy>,
}

pub(crate) fn resolve_socket_policy(request: SocketPolicyRequest) -> ResolvedSocketPolicy {
    let SocketPolicyRequest {
        role,
        protocol_intent,
        sock_type,
        timeout_act,
        debug_unconnected,
        family,
        creation_path,
        lifecycle,
        listener_worker_policy,
    } = request;
    let proto = protocol_intent.protocol();
    let receive_header = resolve_receive_header_mode(proto, sock_type, family);
    let peer_verification = resolve_peer_verification(proto, sock_type);
    let disconnect_key = DisconnectRealityKey {
        platform: SocketPlatform::current(),
        family,
        protocol: proto,
        socket_type: sock_type,
        role,
        creation_path,
        bind_shape: lifecycle.bind_shape,
        reuse_address: lifecycle.reuse_address,
        reuse_port: lifecycle.reuse_port,
        v6_only: lifecycle.v6_only,
        receive_header,
        protocol_zero_capture: creation_path == SocketCreationPath::WindowsProtocolZeroCapture,
        bound_interface: lifecycle.bound_interface,
        connected_peer_mode: peer_verification,
    };
    let disconnect = ResolvedDisconnectContract {
        fingerprint: disconnect_key,
        evidence: socket_disconnect_evidence(disconnect_key),
    };
    let listener_lifecycle = match role {
        SocketRole::Listener => Some(listener_lifecycle::listener_lock_lifecycle_with_contract(
            proto,
            sock_type,
            timeout_act,
            debug_unconnected,
            family,
            listener_worker_policy.unwrap_or_else(|| listener_worker_socket_policy(1, false)),
            disconnect,
        )),
        SocketRole::Upstream => None,
    };
    let reuse = match listener_lifecycle {
        Some(lifecycle) => listener_reuse_capability_for_lifecycle(lifecycle),
        None => {
            resolution_api::upstream_reuse_capability_from_contract(debug_unconnected, disconnect)
        }
    };
    let icmp = protocol_intent
        .icmp()
        .map(|intent| resolve_icmp_socket_policy_with_intent(role, sock_type, intent));
    let send_policy = resolve_socket_send_policy(proto, sock_type, family, creation_path);
    let receive_evidence = resolve_receive_evidence_policy(role, proto, sock_type, receive_header);
    let receive_syscall = resolve_receive_syscall(role, proto);
    ResolvedSocketPolicy {
        creation_path,
        receive_capture_scope: if creation_path == SocketCreationPath::WindowsProtocolZeroCapture {
            ReceiveCaptureScope::InterfaceIpv4
        } else {
            ReceiveCaptureScope::ProtocolFiltered
        },
        peer_verification,
        reuse,
        listener_lifecycle,
        disconnect,
        icmp,
        send_policy,
        receive_header,
        ipv4_receive_length: current_icmp_platform_capabilities().ipv4_receive_length,
        receive_evidence,
        receive_syscall,
        ipv6_destination_scope: if family == Domain::IPV6 {
            Ipv6DestinationScopeEvidence::ExactBoundEndpoint
        } else {
            Ipv6DestinationScopeEvidence::NotApplicable
        },
    }
}

pub(crate) fn inferred_socket_creation_path(
    proto: SupportedProtocol,
    sock_type: Type,
    family: Domain,
) -> SocketCreationPath {
    if sock_type == Type::DGRAM {
        SocketCreationPath::Datagram
    } else if proto == SupportedProtocol::ICMP {
        raw_icmp_creation_path(family)
    } else {
        SocketCreationPath::RawIcmp
    }
}

fn resolve_receive_syscall(role: SocketRole, proto: SupportedProtocol) -> ResolvedReceiveSyscall {
    ResolvedReceiveSyscall {
        connected: if role == SocketRole::Listener && proto == SupportedProtocol::UDP {
            ReceiveSyscall::RecvFrom
        } else {
            ReceiveSyscall::Recv
        },
        unconnected: ReceiveSyscall::RecvFrom,
    }
}

fn resolve_receive_evidence_policy(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    receive_header: ReceiveHeaderMode,
) -> ResolvedReceiveEvidence {
    let get_policy = |connected: bool| {
        let peer_source = if connected
            && role == SocketRole::Listener
            && proto == SupportedProtocol::UDP
        {
            PeerSourceRequirement::SourceMetadata
        } else if connected {
            if sock_type == Type::RAW && receive_header == ReceiveHeaderMode::IpHeaderIncluded {
                PeerSourceRequirement::RawPacketHeader
            } else {
                PeerSourceRequirement::ConnectedKernel
            }
        } else if sock_type == Type::RAW && receive_header == ReceiveHeaderMode::IpHeaderIncluded {
            PeerSourceRequirement::RawPacketHeader
        } else {
            PeerSourceRequirement::SourceMetadata
        };

        let protocol_id = if proto == SupportedProtocol::ICMP {
            ProtocolIdRequirement::ParsedTransportIdentifier
        } else {
            ProtocolIdRequirement::None
        };

        ReceiveEvidencePolicy {
            peer_source,
            protocol_id,
        }
    };

    ResolvedReceiveEvidence {
        connected: get_policy(true),
        unconnected: get_policy(false),
    }
}

pub(crate) fn resolve_receive_header_mode(
    proto: SupportedProtocol,
    sock_type: Type,
    family: Domain,
) -> ReceiveHeaderMode {
    resolve_receive_header_mode_for_platform(SocketPlatform::current(), proto, sock_type, family)
}

pub(crate) fn resolve_receive_header_mode_for_platform(
    platform: SocketPlatform,
    proto: SupportedProtocol,
    sock_type: Type,
    family: Domain,
) -> ReceiveHeaderMode {
    match (proto, sock_type, family) {
        (SupportedProtocol::UDP, Type::DGRAM, _) => ReceiveHeaderMode::PayloadOnly,
        (SupportedProtocol::ICMP, Type::DGRAM, Domain::IPV4) => {
            icmp_platform_capabilities(platform).icmp_v4_dgram_receive_header
        }
        (SupportedProtocol::ICMP, Type::DGRAM, _) => ReceiveHeaderMode::TransportHeaderOnly,
        (SupportedProtocol::ICMP, Type::RAW, Domain::IPV4) => ReceiveHeaderMode::IpHeaderIncluded,
        (SupportedProtocol::ICMP, Type::RAW, Domain::IPV6) => {
            ReceiveHeaderMode::TransportHeaderOnly
        }
        _ => ReceiveHeaderMode::IpHeaderIncluded,
    }
}

fn resolve_socket_send_policy(
    proto: SupportedProtocol,
    sock_type: Type,
    family: Domain,
    creation_path: SocketCreationPath,
) -> SocketSendPolicy {
    let platform = current_icmp_platform_capabilities();
    let icmp_checksum = if proto == SupportedProtocol::ICMP
        && (family == Domain::IPV6
            || (sock_type == Type::DGRAM
                && family == Domain::IPV4
                && platform.kernel_computed_dgram_checksum))
    {
        IcmpChecksumMode::KernelComputed
    } else {
        IcmpChecksumMode::ApplicationComputed
    };

    if creation_path == SocketCreationPath::WindowsProtocolZeroCapture {
        SocketSendPolicy {
            icmp_checksum,
            ip_header: IpHeaderMode::Ipv4HeaderIncluded,
        }
    } else {
        SocketSendPolicy {
            icmp_checksum,
            ip_header: IpHeaderMode::PayloadOnly,
        }
    }
}

#[inline]
pub fn resolve_icmp_socket_policy_with_intent(
    role: SocketRole,
    socket_type: Type,
    intent: IcmpPolicyIntent,
) -> ResolvedIcmpSocketPolicy {
    let is_raw = socket_type == Type::RAW;
    let id_capability =
        if intent.disable_disjoint_ids || intent.allow_debug_kernel_echo_self_handshake {
            IcmpSocketIdCapability::FixedCollapsedId
        } else if is_raw {
            IcmpSocketIdCapability::DisjointIds
        } else if current_icmp_platform_capabilities().kernel_assigned_dgram_ids {
            IcmpSocketIdCapability::KernelAssignedCollapsedId
        } else {
            IcmpSocketIdCapability::FixedCollapsedId
        };
    let kernel_id_policy = if is_raw {
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol
    } else if matches!(
        id_capability,
        IcmpSocketIdCapability::KernelAssignedCollapsedId
    ) {
        IcmpKernelIdPolicy::DeferredKernelAssigned
    } else {
        IcmpKernelIdPolicy::TrustedGetsockname
    };
    let wildcard_id_policy = match id_capability {
        IcmpSocketIdCapability::DisjointIds => IcmpWildcardIdPolicy::GenerateDisjointIds,
        IcmpSocketIdCapability::KernelAssignedCollapsedId => {
            IcmpWildcardIdPolicy::UseKernelAssignedCollapsedId
        }
        IcmpSocketIdCapability::FixedCollapsedId => IcmpWildcardIdPolicy::GenerateFixedCollapsedId,
    };
    ResolvedIcmpSocketPolicy {
        role,
        socket_type,
        id_capability,
        kernel_id_policy,
        wildcard_id_policy,
        fixed_ids_honored: is_raw || current_icmp_platform_capabilities().fixed_dgram_ids_honored,
        raw_packet_admission: is_raw,
        allow_debug_kernel_echo_self_handshake: intent.allow_debug_kernel_echo_self_handshake,
    }
}

fn listener_reuse_capability_for_lifecycle(
    lifecycle: ListenerLockLifecycle,
) -> SocketReuseCapability {
    SocketReuseCapability {
        startup_peer_mode: StartupPeerMode::Unconnected,
        reresolve_mode: listener_lifecycle::listener_reresolve_mode(lifecycle),
    }
}
