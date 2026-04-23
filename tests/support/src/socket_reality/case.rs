use pkthere_socket_policy::SocketRole;
pub use pkthere_socket_policy::{SocketCreateSpec, SocketCreationPath as RealitySocketPath};
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

pub const ICMP_DGRAM_FIXED_ID: u16 = 0x6111;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RealityOperation {
    DatagramReceiveEvidence,
    ConnectedPeerFiltering,
    IcmpDgramReceiveId,
    IcmpDgramFixedId,
    RawReceiveEvidence,
    RawFourIdForwarding,
    UpstreamReconnect,
    ListenerRelock,
    ListenerRebind,
    ReusePortFanout,
}

impl RealityOperation {
    pub const ALL: [Self; 10] = [
        Self::DatagramReceiveEvidence,
        Self::ConnectedPeerFiltering,
        Self::IcmpDgramReceiveId,
        Self::IcmpDgramFixedId,
        Self::RawReceiveEvidence,
        Self::RawFourIdForwarding,
        Self::UpstreamReconnect,
        Self::ListenerRelock,
        Self::ListenerRebind,
        Self::ReusePortFanout,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DatagramReceiveEvidence => "datagram-receive-evidence",
            Self::ConnectedPeerFiltering => "connected-peer-filtering",
            Self::IcmpDgramReceiveId => "icmp-dgram-receive-id",
            Self::IcmpDgramFixedId => "icmp-dgram-fixed-id",
            Self::RawReceiveEvidence => "raw-receive-evidence",
            Self::RawFourIdForwarding => "raw-four-id-forwarding",
            Self::UpstreamReconnect => "upstream-reconnect",
            Self::ListenerRelock => "listener-relock",
            Self::ListenerRebind => "listener-rebind",
            Self::ReusePortFanout => "reuse-port-fanout",
        }
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
    pub connected: bool,
    pub operation: RealityOperation,
}

impl RealityCase {
    pub fn socket_create_spec(self) -> SocketCreateSpec {
        pkthere_socket_policy::socket_create_spec(self.socket_path, self.protocol, self.domain)
    }
}
