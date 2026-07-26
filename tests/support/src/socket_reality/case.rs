use pkthere_socket_policy::{IcmpChecksumMode, SocketRole};
pub use pkthere_socket_policy::{SocketCreateSpec, SocketCreationPath as RealitySocketPath};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

pub const ICMP_DGRAM_FIXED_ID: u16 = 0x6111;

/// Checksum shape used by the independent ICMP DGRAM correlation fixture.
pub(crate) fn icmp_dgram_probe_checksum_mode(domain: Domain) -> IcmpChecksumMode {
    if domain == Domain::IPV4 {
        IcmpChecksumMode::ApplicationComputed
    } else {
        IcmpChecksumMode::KernelComputed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionScenario {
    DirectUnconnected,
    DirectConnected,
    ProductionPolicy,
    ForcedUnconnectedDebug,
}

impl ConnectionScenario {
    pub const fn direct_connected(self) -> Option<bool> {
        match self {
            Self::DirectUnconnected => Some(false),
            Self::DirectConnected => Some(true),
            Self::ProductionPolicy | Self::ForcedUnconnectedDebug => None,
        }
    }

    pub const fn debug_force_unconnected(self) -> bool {
        matches!(self, Self::ForcedUnconnectedDebug)
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DirectUnconnected => "direct-unconnected",
            Self::DirectConnected => "direct-connected",
            Self::ProductionPolicy => "production-policy",
            Self::ForcedUnconnectedDebug => "forced-unconnected-debug",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealityOperation {
    DatagramReceiveEvidence,
    DatagramDisconnect,
    SocketDisconnect,
    ConnectedPeerFiltering,
    IcmpDgramReceiveId,
    IcmpDgramFixedId,
    IcmpDgramSharedId,
    RawReceiveEvidence,
    RawFourIdForwarding,
    UpstreamReconnect,
    ListenerRelock,
    ListenerRebind,
    ListenerOwnerReplacement,
    ReusePortFanout,
}

impl RealityOperation {
    pub const ALL: [Self; 14] = [
        Self::DatagramReceiveEvidence,
        Self::DatagramDisconnect,
        Self::SocketDisconnect,
        Self::ConnectedPeerFiltering,
        Self::IcmpDgramReceiveId,
        Self::IcmpDgramFixedId,
        Self::IcmpDgramSharedId,
        Self::RawReceiveEvidence,
        Self::RawFourIdForwarding,
        Self::UpstreamReconnect,
        Self::ListenerRelock,
        Self::ListenerRebind,
        Self::ListenerOwnerReplacement,
        Self::ReusePortFanout,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DatagramReceiveEvidence => "datagram-receive-evidence",
            Self::DatagramDisconnect => "datagram-disconnect",
            Self::SocketDisconnect => "socket-disconnect",
            Self::ConnectedPeerFiltering => "connected-peer-filtering",
            Self::IcmpDgramReceiveId => "icmp-dgram-receive-id",
            Self::IcmpDgramFixedId => "icmp-dgram-fixed-id",
            Self::IcmpDgramSharedId => "icmp-dgram-shared-id",
            Self::RawReceiveEvidence => "raw-receive-evidence",
            Self::RawFourIdForwarding => "raw-four-id-forwarding",
            Self::UpstreamReconnect => "upstream-reconnect",
            Self::ListenerRelock => "listener-relock",
            Self::ListenerRebind => "listener-rebind",
            Self::ListenerOwnerReplacement => "listener-owner-replacement",
            Self::ReusePortFanout => "reuse-port-fanout",
        }
    }

    pub const fn uses_forwarder_lifecycle(self) -> bool {
        matches!(
            self,
            Self::UpstreamReconnect | Self::ListenerRelock | Self::ListenerRebind
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealityCase {
    pub domain: Domain,
    pub target_domain: Option<Domain>,
    pub protocol: SupportedProtocol,
    pub socket_type: Type,
    pub socket_path: RealitySocketPath,
    pub policy_role: SocketRole,
    pub connection_scenario: ConnectionScenario,
    pub operation: RealityOperation,
}

impl RealityCase {
    pub fn socket_create_spec(self) -> SocketCreateSpec {
        pkthere_socket_policy::socket_create_spec(self.socket_path, self.protocol, self.domain)
    }
}
