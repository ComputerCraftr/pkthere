mod platform;

pub use platform::{
    IcmpPlatformCapabilities, SocketPlatform, current_icmp_platform_capabilities,
    icmp_platform_capabilities,
};

use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use socket2::{Domain, Protocol, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Drop,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketRole {
    Listener,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketCreationPath {
    Datagram,
    RawIcmp,
    WindowsProtocolZeroCapture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketCreateSpec {
    pub domain: Domain,
    pub socket_type: Type,
    pub protocol: Option<Protocol>,
    pub path: SocketCreationPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketCreationPolicy {
    pub primary: SocketCreateSpec,
    /// Used only when creating `primary` fails. Bind, connect, and setup
    /// failures must remain visible rather than silently changing socket mode.
    pub create_fallback: Option<SocketCreateSpec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPostBindPolicy {
    pub enable_windows_rcvall: bool,
    pub set_ipv4_header_included: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerSocketSetupPolicy {
    pub worker: ListenerWorkerSocketPolicy,
    pub bind_requested_address: bool,
    pub post_bind: SocketPostBindPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketEvidenceKey {
    pub process_id: u32,
    pub role: SocketRole,
    pub domain: Domain,
    pub socket_slot: u32,
    pub generation: u64,
}

impl SocketEvidenceKey {
    pub fn initial(role: SocketRole, socket_slot: u32, addr: std::net::SocketAddr) -> Self {
        Self {
            process_id: std::process::id(),
            role,
            domain: Domain::for_address(addr),
            socket_slot,
            generation: 1,
        }
    }

    pub fn replacement(self, addr: std::net::SocketAddr) -> Self {
        Self {
            domain: Domain::for_address(addr),
            generation: self.generation.saturating_add(1),
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPeerMode {
    Connected,
    Unconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockedPeerMode {
    ConnectAfterLock,
    StayUnconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketReresolveMode {
    ReconnectInPlace,
    ReplaceSocket,
    MetadataOnlyWhenUnconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutClearMode {
    DisconnectSocket,
    ProcessExit,
    NoConnectedState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpSocketIdCapability {
    DisjointIds,
    KernelAssignedCollapsedId,
    FixedCollapsedId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKernelIdPolicy {
    TrustedGetsockname,
    DeferredKernelAssigned,
    IgnoreGetsocknameProtocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpWildcardIdPolicy {
    UseKernelAssignedCollapsedId,
    GenerateFixedCollapsedId,
    GenerateDisjointIds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpChecksumMode {
    ApplicationComputed,
    KernelComputed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpHeaderMode {
    PayloadOnly,
    Ipv4HeaderIncluded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSourceRequirement {
    ConnectedKernel,
    SourceMetadata,
    RawPacketHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolIdRequirement {
    None,
    ParsedTransportIdentifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveSyscall {
    Recv,
    RecvFrom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedReceiveSyscall {
    pub connected: ReceiveSyscall,
    pub unconnected: ReceiveSyscall,
}

impl ResolvedReceiveSyscall {
    #[inline]
    pub const fn policy(&self, connected: bool) -> ReceiveSyscall {
        if connected {
            self.connected
        } else {
            self.unconnected
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveEvidencePolicy {
    pub peer_source: PeerSourceRequirement,
    pub protocol_id: ProtocolIdRequirement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedReceiveEvidence {
    pub connected: ReceiveEvidencePolicy,
    pub unconnected: ReceiveEvidencePolicy,
}

impl ResolvedReceiveEvidence {
    #[inline]
    pub const fn policy(&self, connected: bool) -> ReceiveEvidencePolicy {
        if connected {
            self.connected
        } else {
            self.unconnected
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketSendPolicy {
    pub icmp_checksum: IcmpChecksumMode,
    pub ip_header: IpHeaderMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedIcmpSocketPolicy {
    pub role: SocketRole,
    pub socket_type: Type,
    pub id_capability: IcmpSocketIdCapability,
    pub kernel_id_policy: IcmpKernelIdPolicy,
    pub wildcard_id_policy: IcmpWildcardIdPolicy,
    pub fixed_ids_honored: bool,
    pub raw_packet_admission: bool,
    pub allow_debug_kernel_echo_self_handshake: bool,
}

impl ResolvedIcmpSocketPolicy {
    #[inline]
    pub const fn requires_raw_packet_admission(self) -> bool {
        self.raw_packet_admission
    }

    #[inline]
    pub const fn can_honor_disjoint_ids(self) -> bool {
        matches!(self.id_capability, IcmpSocketIdCapability::DisjointIds)
    }

    #[inline]
    pub const fn trusts_kernel_local_id(self) -> bool {
        !matches!(
            self.kernel_id_policy,
            IcmpKernelIdPolicy::IgnoreGetsocknameProtocol
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSocketPolicy {
    pub reuse: SocketReuseCapability,
    pub datagram_disconnect: DatagramDisconnectCapability,
    pub icmp: Option<ResolvedIcmpSocketPolicy>,
    pub send_policy: SocketSendPolicy,
    pub receive_header: ReceiveHeaderMode,
    pub receive_evidence: ResolvedReceiveEvidence,
    pub receive_syscall: ResolvedReceiveSyscall,
}

pub fn socket_create_spec(
    path: SocketCreationPath,
    proto: SupportedProtocol,
    domain: Domain,
) -> SocketCreateSpec {
    let (socket_type, protocol) = match path {
        SocketCreationPath::Datagram => (
            Type::DGRAM,
            Some(match proto {
                SupportedProtocol::UDP => Protocol::UDP,
                SupportedProtocol::ICMP if domain == Domain::IPV4 => Protocol::ICMPV4,
                SupportedProtocol::ICMP if domain == Domain::IPV6 => Protocol::ICMPV6,
                SupportedProtocol::ICMP => unreachable!("unsupported ICMP socket domain"),
            }),
        ),
        SocketCreationPath::RawIcmp => (
            Type::RAW,
            Some(if domain == Domain::IPV6 {
                Protocol::ICMPV6
            } else {
                Protocol::ICMPV4
            }),
        ),
        SocketCreationPath::WindowsProtocolZeroCapture => {
            debug_assert_eq!(domain, Domain::IPV4);
            (Type::RAW, Some(Protocol::from(0)))
        }
    };
    SocketCreateSpec {
        domain,
        socket_type,
        protocol,
        path,
    }
}

fn raw_icmp_creation_path(domain: Domain) -> SocketCreationPath {
    if current_icmp_platform_capabilities().windows_ipv4_protocol_zero_raw && domain == Domain::IPV4
    {
        SocketCreationPath::WindowsProtocolZeroCapture
    } else {
        SocketCreationPath::RawIcmp
    }
}

pub fn listener_socket_creation_policy(
    proto: SupportedProtocol,
    domain: Domain,
) -> SocketCreationPolicy {
    let path = if proto == SupportedProtocol::ICMP {
        raw_icmp_creation_path(domain)
    } else {
        SocketCreationPath::Datagram
    };
    SocketCreationPolicy {
        primary: socket_create_spec(path, proto, domain),
        create_fallback: None,
    }
}

pub fn upstream_socket_creation_policy(
    proto: SupportedProtocol,
    domain: Domain,
    requested_remote_id: u16,
    requested_local_id: u16,
    force_raw_wildcard: bool,
) -> SocketCreationPolicy {
    let raw = socket_create_spec(raw_icmp_creation_path(domain), proto, domain);
    if proto != SupportedProtocol::ICMP {
        return SocketCreationPolicy {
            primary: socket_create_spec(SocketCreationPath::Datagram, proto, domain),
            create_fallback: None,
        };
    }

    let disjoint_fixed_ids = requested_remote_id != 0
        && requested_local_id != 0
        && requested_remote_id != requested_local_id;
    let dgram_eligible = !force_raw_wildcard
        && !disjoint_fixed_ids
        && current_icmp_platform_capabilities().datagram_echo_sockets;
    if !dgram_eligible {
        return SocketCreationPolicy {
            primary: raw,
            create_fallback: None,
        };
    }
    SocketCreationPolicy {
        primary: socket_create_spec(SocketCreationPath::Datagram, proto, domain),
        create_fallback: Some(raw),
    }
}

pub fn upstream_pre_connect_bind_id(
    proto: SupportedProtocol,
    socket_type: Type,
    planned_local_id: u16,
    requested_local_id: u16,
) -> Option<u16> {
    let bind_id = if matches!(proto, SupportedProtocol::ICMP) && socket_type == Type::DGRAM {
        planned_local_id
    } else if matches!(proto, SupportedProtocol::UDP) {
        requested_local_id
    } else {
        0
    };
    if bind_id == 0 { None } else { Some(bind_id) }
}

pub const fn socket_post_bind_policy(path: SocketCreationPath) -> SocketPostBindPolicy {
    let windows_protocol_zero = matches!(path, SocketCreationPath::WindowsProtocolZeroCapture);
    SocketPostBindPolicy {
        enable_windows_rcvall: windows_protocol_zero,
        set_ipv4_header_included: windows_protocol_zero,
    }
}

pub const fn listener_socket_setup_policy(
    worker: ListenerWorkerSocketPolicy,
    path: SocketCreationPath,
) -> ListenerSocketSetupPolicy {
    ListenerSocketSetupPolicy {
        worker,
        bind_requested_address: true,
        post_bind: socket_post_bind_policy(path),
    }
}

impl ResolvedSocketPolicy {
    #[inline]
    pub const fn evidence_policy(&self, connected: bool) -> ReceiveEvidencePolicy {
        self.receive_evidence.policy(connected)
    }

    #[inline]
    pub const fn receive_syscall(&self, connected: bool) -> ReceiveSyscall {
        self.receive_syscall.policy(connected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerWorkerDistribution {
    SingleSocket,
    SharedState,
    KernelFlowAffinity,
    UnsupportedSeparateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerWorkerSocketPolicy {
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub distribution: ListenerWorkerDistribution,
}

impl ListenerWorkerSocketPolicy {
    #[inline]
    pub const fn supports_requested_distribution(self) -> bool {
        !matches!(
            self.distribution,
            ListenerWorkerDistribution::UnsupportedSeparateState
        )
    }
}

#[inline]
pub const fn listener_worker_socket_policy(
    worker_count: usize,
    separate_flow_state: bool,
) -> ListenerWorkerSocketPolicy {
    if worker_count <= 1 {
        return ListenerWorkerSocketPolicy {
            reuse_address: false,
            reuse_port: false,
            distribution: ListenerWorkerDistribution::SingleSocket,
        };
    }

    let reuse_port = cfg!(unix);
    let distribution = if !separate_flow_state {
        ListenerWorkerDistribution::SharedState
    } else if cfg!(any(target_os = "linux", target_os = "android")) {
        ListenerWorkerDistribution::KernelFlowAffinity
    } else {
        ListenerWorkerDistribution::UnsupportedSeparateState
    };
    ListenerWorkerSocketPolicy {
        reuse_address: true,
        reuse_port,
        distribution,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcmpPolicyIntent {
    pub disable_disjoint_ids: bool,
    pub allow_debug_kernel_echo_self_handshake: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketReuseCapability {
    pub startup_peer_mode: StartupPeerMode,
    pub locked_peer_mode: LockedPeerMode,
    pub reresolve_mode: SocketReresolveMode,
    pub timeout_clear_mode: TimeoutClearMode,
}

impl SocketReuseCapability {
    #[inline]
    pub const fn starts_connected(self) -> bool {
        matches!(self.startup_peer_mode, StartupPeerMode::Connected)
    }

    #[inline]
    pub const fn connects_after_lock(self) -> bool {
        matches!(self.locked_peer_mode, LockedPeerMode::ConnectAfterLock)
    }

    #[inline]
    pub const fn reconnects_in_place(self) -> bool {
        matches!(self.reresolve_mode, SocketReresolveMode::ReconnectInPlace)
    }
}

#[inline]
pub fn resolve_socket_policy_with_icmp_intent(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    icmp_intent: IcmpPolicyIntent,
) -> ResolvedSocketPolicy {
    let reuse = socket_reuse_capability_for_family(
        role,
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
        family,
    );
    let icmp = (proto == SupportedProtocol::ICMP)
        .then(|| resolve_icmp_socket_policy_with_intent(role, sock_type, icmp_intent));
    let send_policy = resolve_socket_send_policy(proto, sock_type, family);
    let receive_header = resolve_receive_header_mode(proto, sock_type, family);
    let receive_evidence = resolve_receive_evidence_policy(role, proto, sock_type, receive_header);
    let receive_syscall = resolve_receive_syscall(role, proto);
    ResolvedSocketPolicy {
        reuse,
        datagram_disconnect: datagram_disconnect_capability(proto, family),
        icmp,
        send_policy,
        receive_header,
        receive_evidence,
        receive_syscall,
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

fn resolve_receive_header_mode(
    proto: SupportedProtocol,
    sock_type: Type,
    family: Domain,
) -> ReceiveHeaderMode {
    match (proto, sock_type, family) {
        (SupportedProtocol::UDP, Type::DGRAM, _) => ReceiveHeaderMode::PayloadOnly,
        (SupportedProtocol::ICMP, Type::DGRAM, Domain::IPV4)
            if cfg!(any(target_os = "macos", target_os = "ios")) =>
        {
            ReceiveHeaderMode::IpHeaderIncluded
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
) -> SocketSendPolicy {
    let icmp_checksum = if proto == SupportedProtocol::ICMP
        && sock_type == Type::DGRAM
        && family == Domain::IPV4
        && cfg!(any(target_os = "linux", target_os = "android"))
    {
        IcmpChecksumMode::KernelComputed
    } else {
        IcmpChecksumMode::ApplicationComputed
    };

    if cfg!(windows)
        && proto == SupportedProtocol::ICMP
        && sock_type == Type::RAW
        && family == Domain::IPV4
    {
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
        } else if cfg!(any(target_os = "linux", target_os = "android")) {
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
        fixed_ids_honored: is_raw
            || cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos"
            )),
        raw_packet_admission: is_raw,
        allow_debug_kernel_echo_self_handshake: intent.allow_debug_kernel_echo_self_handshake,
    }
}

#[inline]
pub fn socket_reuse_capability_for_family(
    role: SocketRole,
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> SocketReuseCapability {
    match role {
        SocketRole::Listener => {
            listener_reuse_capability(proto, sock_type, timeout_act, debug_unconnected, family)
        }
        SocketRole::Upstream => {
            upstream_reuse_capability(proto, sock_type, debug_unconnected, family)
        }
    }
}

fn listener_reuse_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> SocketReuseCapability {
    let relock =
        listener_relock_capability(proto, sock_type, timeout_act, debug_unconnected, family);
    SocketReuseCapability {
        startup_peer_mode: StartupPeerMode::Unconnected,
        locked_peer_mode: relock.locked_peer_mode,
        reresolve_mode: relock.reresolve_mode(),
        timeout_clear_mode: relock.timeout_clear_mode,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamReresolveCapability {
    datagram_disconnect: Option<DatagramDisconnectCapability>,
    reresolve_mode: SocketReresolveMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerRelockCapability {
    datagram_disconnect: Option<DatagramDisconnectCapability>,
    can_lock_connected: bool,
    pub locked_peer_mode: LockedPeerMode,
    pub timeout_clear_mode: TimeoutClearMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramDisconnectCapability {
    pub disconnect_call_supported: bool,
    pub reconnect_after_disconnect_supported: bool,
    pub listener_original_bind_receive_after_disconnect_supported: bool,
}

impl UpstreamReresolveCapability {
    pub const fn can_disconnect(self) -> bool {
        matches!(
            self.datagram_disconnect,
            Some(capability) if capability.disconnect_call_supported
        )
    }

    pub const fn can_reconnect_to_new_target(self) -> bool {
        matches!(
            self.datagram_disconnect,
            Some(capability) if capability.reconnect_after_disconnect_supported
        )
    }

    pub const fn reresolve_mode(self) -> SocketReresolveMode {
        self.reresolve_mode
    }
}

impl ListenerRelockCapability {
    pub const fn can_lock_connected(self) -> bool {
        self.can_lock_connected
    }

    pub const fn can_disconnect_lock(self) -> bool {
        self.can_lock_connected
            && matches!(
                self.datagram_disconnect,
                Some(capability) if capability.disconnect_call_supported
            )
    }

    pub const fn can_receive_on_original_bind_after_disconnect(self) -> bool {
        matches!(
            self.datagram_disconnect,
            Some(capability) if capability.listener_original_bind_receive_after_disconnect_supported
        )
    }

    pub const fn can_relock_to_new_peer(self) -> bool {
        self.can_lock_connected() && self.can_disconnect_lock()
    }

    pub const fn reresolve_mode(self) -> SocketReresolveMode {
        if matches!(self.locked_peer_mode, LockedPeerMode::ConnectAfterLock) {
            SocketReresolveMode::ReconnectInPlace
        } else {
            SocketReresolveMode::ReplaceSocket
        }
    }
}

#[inline]
pub fn upstream_reresolve_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    debug_unconnected: bool,
    family: Domain,
) -> UpstreamReresolveCapability {
    let windows_raw_capture =
        cfg!(windows) && proto == SupportedProtocol::ICMP && sock_type == Type::RAW;
    let datagram = sock_type == Type::DGRAM && !debug_unconnected;
    let datagram_disconnect = datagram_disconnect_capability(proto, family);
    let reresolve_mode = if debug_unconnected || windows_raw_capture {
        SocketReresolveMode::MetadataOnlyWhenUnconnected
    } else if sock_type == Type::RAW
        || datagram && !datagram_disconnect.reconnect_after_disconnect_supported
    {
        SocketReresolveMode::ReplaceSocket
    } else {
        SocketReresolveMode::ReconnectInPlace
    };
    UpstreamReresolveCapability {
        datagram_disconnect: datagram.then_some(datagram_disconnect),
        reresolve_mode,
    }
}

#[inline]
pub fn listener_relock_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
) -> ListenerRelockCapability {
    if debug_unconnected || proto == SupportedProtocol::ICMP || sock_type == Type::RAW {
        return ListenerRelockCapability {
            datagram_disconnect: None,
            can_lock_connected: false,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        };
    }

    let datagram = proto == SupportedProtocol::UDP && sock_type == Type::DGRAM;
    let dgram_cap = datagram_disconnect_capability(proto, family);
    let can_receive =
        datagram && dgram_cap.listener_original_bind_receive_after_disconnect_supported;
    let can_disconnect_lock = datagram && dgram_cap.disconnect_call_supported;
    let can_lock_connected = datagram;
    let can_relock_to_new_peer = can_lock_connected && can_disconnect_lock;
    let can_clear_lock_by_disconnect = can_relock_to_new_peer && can_receive;
    ListenerRelockCapability {
        datagram_disconnect: datagram.then_some(dgram_cap),
        can_lock_connected,
        locked_peer_mode: if timeout_act == TimeoutAction::Exit || can_clear_lock_by_disconnect {
            LockedPeerMode::ConnectAfterLock
        } else {
            LockedPeerMode::StayUnconnected
        },
        timeout_clear_mode: if timeout_act == TimeoutAction::Exit {
            TimeoutClearMode::ProcessExit
        } else if can_clear_lock_by_disconnect {
            TimeoutClearMode::DisconnectSocket
        } else {
            TimeoutClearMode::NoConnectedState
        },
    }
}

#[inline]
pub fn datagram_disconnect_capability(
    proto: SupportedProtocol,
    family: Domain,
) -> DatagramDisconnectCapability {
    let supported = match proto {
        SupportedProtocol::UDP => cfg!(any(unix, windows)),
        SupportedProtocol::ICMP => cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos"
        )),
    };
    let listener_original_bind_receive_after_disconnect_supported = supported
        && !(cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd"
        )) || cfg!(any(target_os = "macos", target_os = "ios")) && family == Domain::IPV6);

    let reconnect_after_disconnect_supported =
        supported && !(cfg!(any(target_os = "macos", target_os = "ios")) && family == Domain::IPV6);
    DatagramDisconnectCapability {
        disconnect_call_supported: supported,
        reconnect_after_disconnect_supported,
        listener_original_bind_receive_after_disconnect_supported,
    }
}

fn upstream_reuse_capability(
    proto: SupportedProtocol,
    sock_type: Type,
    debug_unconnected: bool,
    family: Domain,
) -> SocketReuseCapability {
    match upstream_reresolve_capability(proto, sock_type, debug_unconnected, family)
        .reresolve_mode()
    {
        SocketReresolveMode::MetadataOnlyWhenUnconnected => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Unconnected,
            locked_peer_mode: LockedPeerMode::StayUnconnected,
            reresolve_mode: SocketReresolveMode::MetadataOnlyWhenUnconnected,
            timeout_clear_mode: TimeoutClearMode::NoConnectedState,
        },
        SocketReresolveMode::ReplaceSocket => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReplaceSocket,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        },
        SocketReresolveMode::ReconnectInPlace => SocketReuseCapability {
            startup_peer_mode: StartupPeerMode::Connected,
            locked_peer_mode: LockedPeerMode::ConnectAfterLock,
            reresolve_mode: SocketReresolveMode::ReconnectInPlace,
            timeout_clear_mode: TimeoutClearMode::ProcessExit,
        },
    }
}

#[cfg(test)]
mod tests;
