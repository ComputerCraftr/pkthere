use crate::{
    Ipv4HeaderAction, ListenerSocketSetupPolicy, ReceiveEvidencePolicy, ReceiveSyscall,
    ResolvedSocketPolicy, SocketCaptureAction, SocketCreateSpec, SocketCreationFailureClass,
    SocketCreationPath, SocketCreationPlan, SocketFallbackPolicy, SocketPlatform,
    SocketPostBindPolicy,
};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Protocol, Type};

const ICMP_DGRAM_FALLBACK_FAILURES: &[SocketCreationFailureClass] =
    &[SocketCreationFailureClass::UnsupportedCandidate];

pub fn socket_create_spec(
    path: SocketCreationPath,
    proto: SupportedProtocol,
    domain: Domain,
) -> SocketCreateSpec {
    let (socket_type, protocol) = match path {
        SocketCreationPath::Datagram => (
            Type::DGRAM,
            match proto {
                SupportedProtocol::UDP => Some(Protocol::UDP),
                SupportedProtocol::ICMP if domain == Domain::IPV4 => Some(Protocol::ICMPV4),
                SupportedProtocol::ICMP if domain == Domain::IPV6 => Some(Protocol::ICMPV6),
                SupportedProtocol::ICMP => None,
            },
        ),
        SocketCreationPath::RawIcmp => (
            Type::RAW,
            if domain == Domain::IPV4 {
                Some(Protocol::ICMPV4)
            } else if domain == Domain::IPV6 {
                Some(Protocol::ICMPV6)
            } else {
                None
            },
        ),
        SocketCreationPath::WindowsProtocolZeroCapture => (
            Type::RAW,
            (domain == Domain::IPV4).then(|| Protocol::from(0)),
        ),
    };
    SocketCreateSpec {
        domain,
        socket_type,
        protocol,
        path,
    }
}

pub(crate) fn raw_icmp_creation_path(domain: Domain) -> SocketCreationPath {
    if SocketPlatform::current() == SocketPlatform::Windows && domain == Domain::IPV4 {
        SocketCreationPath::WindowsProtocolZeroCapture
    } else {
        SocketCreationPath::RawIcmp
    }
}

pub fn listener_socket_creation_policy(
    proto: SupportedProtocol,
    domain: Domain,
) -> SocketCreationPlan {
    let path = if proto == SupportedProtocol::ICMP {
        raw_icmp_creation_path(domain)
    } else {
        SocketCreationPath::Datagram
    };
    SocketCreationPlan {
        primary: socket_create_spec(path, proto, domain),
        fallback: None,
    }
}

pub fn upstream_socket_creation_policy(
    proto: SupportedProtocol,
    domain: Domain,
    requested_remote_id: u16,
    requested_local_id: u16,
    force_raw_wildcard: bool,
) -> SocketCreationPlan {
    let raw = socket_create_spec(raw_icmp_creation_path(domain), proto, domain);
    if proto != SupportedProtocol::ICMP {
        return SocketCreationPlan {
            primary: socket_create_spec(SocketCreationPath::Datagram, proto, domain),
            fallback: None,
        };
    }

    let disjoint_fixed_ids = requested_remote_id != 0
        && requested_local_id != 0
        && requested_remote_id != requested_local_id;
    let dgram_eligible = !force_raw_wildcard && !disjoint_fixed_ids;
    if !dgram_eligible {
        return SocketCreationPlan {
            primary: raw,
            fallback: None,
        };
    }
    let datagram = socket_create_spec(SocketCreationPath::Datagram, proto, domain);
    SocketCreationPlan {
        primary: datagram,
        fallback: Some(SocketFallbackPolicy {
            from: datagram,
            to: raw,
            eligible_failures: ICMP_DGRAM_FALLBACK_FAILURES,
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamSocketBindPolicy {
    pub kernel_id: u16,
    pub bind_before_connect: bool,
    pub address: UpstreamBindAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerSocketBindPolicy {
    pub kernel_id: u16,
}

/// Resolve the sockaddr identity independently from the logical packet ID.
/// RAW and protocol-zero sockets bind only their layer-3 address; ICMP Echo
/// identifiers remain packet-admission authority.
pub const fn listener_socket_bind_policy(
    path: SocketCreationPath,
    requested_id: u16,
) -> ListenerSocketBindPolicy {
    ListenerSocketBindPolicy {
        kernel_id: match path {
            SocketCreationPath::Datagram => requested_id,
            SocketCreationPath::RawIcmp | SocketCreationPath::WindowsProtocolZeroCapture => 0,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamBindAddress {
    Wildcard,
    RouteSelected,
}

/// Resolve the kernel bind identity from the selected socket policy.
///
/// ICMP DGRAM binds use the already-planned ping-socket identity. A zero
/// planned identity is authoritative for reality-backed kernel assignment.
/// RAW ICMP identifiers remain packet-admission metadata and never become a
/// sockaddr bind port. UDP binds use the requested local port.
pub fn upstream_socket_bind_policy(
    policy: ResolvedSocketPolicy,
    planned_local_id: u16,
    requested_local_id: u16,
) -> UpstreamSocketBindPolicy {
    let lifecycle_address = if policy.reuse.starts_connected() {
        UpstreamBindAddress::Wildcard
    } else {
        UpstreamBindAddress::RouteSelected
    };
    let (kernel_id, bind_before_connect, address) = match policy.icmp {
        // Reality probes exercise an explicit bind for both fixed and
        // wildcard ping-socket IDs. Keep production on that exact path.
        Some(icmp) if icmp.socket_type == Type::DGRAM => {
            (planned_local_id, true, lifecycle_address)
        }
        Some(_) if policy.creation_path == SocketCreationPath::WindowsProtocolZeroCapture => {
            // SIO_RCVALL requires an explicit interface bind before it is
            // enabled. This remains true when the RAW L3 socket subsequently
            // connects to its peer.
            (0, true, UpstreamBindAddress::RouteSelected)
        }
        Some(_) => (0, false, lifecycle_address),
        None => (
            requested_local_id,
            requested_local_id != 0,
            lifecycle_address,
        ),
    };
    UpstreamSocketBindPolicy {
        kernel_id,
        bind_before_connect,
        address,
    }
}

pub const fn socket_post_bind_policy(path: SocketCreationPath) -> SocketPostBindPolicy {
    let windows_protocol_zero = matches!(path, SocketCreationPath::WindowsProtocolZeroCapture);
    SocketPostBindPolicy {
        capture: if windows_protocol_zero {
            SocketCaptureAction::WindowsReceiveAllIp
        } else {
            SocketCaptureAction::Disabled
        },
        ipv4_header: if windows_protocol_zero {
            Ipv4HeaderAction::ApplicationIncluded
        } else {
            Ipv4HeaderAction::KernelManaged
        },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReusePortAction {
    Disabled,
    Enable,
    Unsupported,
}

#[inline]
pub const fn reuse_port_action(requested: bool) -> ReusePortAction {
    reuse_port_action_for(SocketPlatform::current(), requested)
}

#[inline]
pub const fn reuse_port_action_for(platform: SocketPlatform, requested: bool) -> ReusePortAction {
    if !requested {
        return ReusePortAction::Disabled;
    }
    match platform {
        SocketPlatform::Linux
        | SocketPlatform::Android
        | SocketPlatform::Macos
        | SocketPlatform::Ios
        | SocketPlatform::Freebsd => ReusePortAction::Enable,
        SocketPlatform::Windows | SocketPlatform::Other => ReusePortAction::Unsupported,
    }
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
    listener_worker_socket_policy_for(SocketPlatform::current(), worker_count, separate_flow_state)
}

pub(crate) const fn listener_worker_socket_policy_for(
    platform: SocketPlatform,
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

    let reuse_port = matches!(
        reuse_port_action_for(platform, true),
        ReusePortAction::Enable
    );
    let distribution = if !separate_flow_state {
        ListenerWorkerDistribution::SharedState
    } else if matches!(platform, SocketPlatform::Linux | SocketPlatform::Android) {
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
