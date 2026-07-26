use crate::{ListenerWorkerSocketPolicy, ResolvedDisconnectContract, SocketReuseCapability};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::{Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;

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
pub enum PeerVerification {
    RequirePeerAddr,
    RequirePeerNetworkAddress,
    ConnectSuccess,
}

impl PeerVerification {
    /// Validate the kernel peer observation required by the selected socket
    /// path. `ConnectSuccess` is used only after the connect syscall itself
    /// succeeded; ICMP datagram kernels need not preserve the requested Echo
    /// identifier in `getpeername`.
    pub fn accepts_observation(
        self,
        expected: Option<SocketAddr>,
        observed: Option<SocketAddr>,
    ) -> bool {
        match (expected, self) {
            (None, _) => observed.is_none(),
            (Some(expected), Self::RequirePeerAddr) => observed == Some(expected),
            (Some(expected), Self::RequirePeerNetworkAddress) => {
                observed.is_some_and(|observed| observed.ip() == expected.ip())
            }
            (Some(_), Self::ConnectSuccess) => true,
        }
    }
}

pub(crate) const fn resolve_peer_verification(
    protocol: SupportedProtocol,
    socket_type: Type,
) -> PeerVerification {
    match (protocol, socket_type) {
        (SupportedProtocol::ICMP, Type::DGRAM) => PeerVerification::ConnectSuccess,
        (SupportedProtocol::ICMP, Type::RAW) => PeerVerification::RequirePeerNetworkAddress,
        _ => PeerVerification::RequirePeerAddr,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketCreateSpec {
    pub domain: Domain,
    pub socket_type: Type,
    pub protocol: Option<Protocol>,
    pub path: SocketCreationPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketCreationPlan {
    pub primary: SocketCreateSpec,
    pub fallback: Option<SocketFallbackPolicy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketFallbackPolicy {
    pub from: SocketCreateSpec,
    pub to: SocketCreateSpec,
    pub eligible_failures: &'static [SocketCreationFailureClass],
}

impl SocketFallbackPolicy {
    #[inline]
    pub const fn permits(self, failure: SocketCreationFailureClass) -> bool {
        let mut index = 0;
        while index < self.eligible_failures.len() {
            if self.eligible_failures[index] as u8 == failure as u8 {
                return true;
            }
            index += 1;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketCreationFailureClass {
    UnsupportedCandidate,
    UnavailableInCurrentExecutionDomain,
    PermissionDenied,
    TransientInterrupted,
    ResourceExhausted,
    InvalidSpecification,
    Unexpected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketPostBindPolicy {
    pub capture: SocketCaptureAction,
    pub ipv4_header: Ipv4HeaderAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketCaptureAction {
    Disabled,
    WindowsReceiveAllIp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4HeaderAction {
    KernelManaged,
    ApplicationIncluded,
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

    pub fn replacement(
        self,
        addr: std::net::SocketAddr,
    ) -> Result<Self, EvidenceGenerationExhausted> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(EvidenceGenerationExhausted {
                generation: self.generation,
            })?;
        Ok(Self {
            domain: Domain::for_address(addr),
            generation,
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceGenerationExhausted {
    pub generation: u64,
}

impl std::fmt::Display for EvidenceGenerationExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "socket evidence generation {} is exhausted",
            self.generation
        )
    }
}

impl std::error::Error for EvidenceGenerationExhausted {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPeerMode {
    Connected,
    Unconnected,
}

impl StartupPeerMode {
    #[inline]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Unconnected => "unconnected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketReresolveMode {
    ReconnectInPlace,
    ReplaceSocket,
    MetadataOnlyWhenUnconnected,
    ProcessExitOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerClearStrategy {
    DisconnectToOriginalBind,
    ReplaceOwnerSameBind,
    ProcessExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerLockLifecycle {
    StayUnconnected,
    StayUnconnectedReplaceOnClear,
    Connected { clear: ListenerClearStrategy },
}

impl ListenerLockLifecycle {
    #[inline]
    pub const fn connects_after_lock(self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    #[inline]
    pub const fn replaces_on_clear(self) -> bool {
        matches!(
            self,
            Self::StayUnconnectedReplaceOnClear
                | Self::Connected {
                    clear: ListenerClearStrategy::ReplaceOwnerSameBind,
                }
        )
    }

    #[inline]
    pub const fn clear_strategy(self) -> Option<ListenerClearStrategy> {
        match self {
            Self::StayUnconnected => None,
            Self::StayUnconnectedReplaceOnClear => {
                Some(ListenerClearStrategy::ReplaceOwnerSameBind)
            }
            Self::Connected { clear } => Some(clear),
        }
    }

    #[inline]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::StayUnconnected => "stay-unconnected",
            Self::StayUnconnectedReplaceOnClear => "unconnected-replace-on-clear",
            Self::Connected {
                clear: ListenerClearStrategy::DisconnectToOriginalBind,
            } => "connected-disconnect-to-original-bind",
            Self::Connected {
                clear: ListenerClearStrategy::ReplaceOwnerSameBind,
            } => "connected-replace-owner-same-bind",
            Self::Connected {
                clear: ListenerClearStrategy::ProcessExit,
            } => "connected-process-exit",
        }
    }
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
pub enum ReceiveCaptureScope {
    ProtocolFiltered,
    InterfaceIpv4,
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

/// Authoritative source for an IPv6 destination interface scope.
///
/// Packet-info collection is not currently selected by any production socket
/// path. A link-local destination is therefore admissible only when the
/// requested filter and realized kernel bind provide the same concrete scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6DestinationScopeEvidence {
    NotApplicable,
    ExactBoundEndpoint,
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

    /// Returns the socket-local protocol identifier only when the resolved
    /// socket policy makes `getsockname` authoritative for that identifier.
    ///
    /// RAW ICMP kernels may report the IP protocol number in the socket port
    /// field. Keeping that interpretation here prevents endpoint construction
    /// and upstream ID selection from inventing separate trust rules.
    #[inline]
    pub const fn trusted_kernel_local_id(self, reported_id: u16) -> Option<u16> {
        if self.trusts_kernel_local_id() && reported_id != 0 {
            Some(reported_id)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSocketPolicy {
    pub creation_path: SocketCreationPath,
    pub receive_capture_scope: ReceiveCaptureScope,
    pub peer_verification: PeerVerification,
    pub reuse: SocketReuseCapability,
    pub listener_lifecycle: Option<ListenerLockLifecycle>,
    pub disconnect: ResolvedDisconnectContract,
    pub icmp: Option<ResolvedIcmpSocketPolicy>,
    pub send_policy: SocketSendPolicy,
    pub receive_header: ReceiveHeaderMode,
    pub ipv4_receive_length: Ipv4PacketLengthEncoding,
    pub receive_evidence: ResolvedReceiveEvidence,
    pub receive_syscall: ResolvedReceiveSyscall,
    pub ipv6_destination_scope: Ipv6DestinationScopeEvidence,
}
