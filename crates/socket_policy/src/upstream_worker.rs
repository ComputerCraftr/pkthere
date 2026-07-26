use super::{
    ReusePortAction, SocketPlatform, SupportedProtocol, icmp_platform_capabilities,
    reuse_port_action_for,
};
use socket2::{Domain, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedIcmpIdentityRealityKey {
    pub platform: SocketPlatform,
    pub family: Domain,
    pub socket_type: Type,
}

#[inline]
pub fn shared_icmp_identity_supported(key: SharedIcmpIdentityRealityKey) -> bool {
    matches!(key.family, Domain::IPV4 | Domain::IPV6)
        && key.socket_type == Type::DGRAM
        && icmp_platform_capabilities(key.platform).shared_dgram_echo_id
        && matches!(
            reuse_port_action_for(key.platform, true),
            ReusePortAction::Enable
        )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamWorkerDistribution {
    #[default]
    PerWorkerIdentity,
    SharedIcmpIdentity,
    UnsupportedSharedIcmpIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamWorkerSocketPolicy {
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub distribution: UpstreamWorkerDistribution,
}

impl Default for UpstreamWorkerSocketPolicy {
    fn default() -> Self {
        Self {
            reuse_address: false,
            reuse_port: false,
            distribution: UpstreamWorkerDistribution::PerWorkerIdentity,
        }
    }
}

impl UpstreamWorkerSocketPolicy {
    #[inline]
    pub const fn shares_icmp_identity(self) -> bool {
        matches!(
            self.distribution,
            UpstreamWorkerDistribution::SharedIcmpIdentity
        )
    }

    #[inline]
    pub const fn supports_requested_distribution(self) -> bool {
        !matches!(
            self.distribution,
            UpstreamWorkerDistribution::UnsupportedSharedIcmpIdentity
        )
    }
}

#[inline]
pub fn upstream_worker_socket_policy(
    worker_count: usize,
    separate_flow_state: bool,
    protocol: SupportedProtocol,
    socket_type: Type,
    family: Domain,
) -> UpstreamWorkerSocketPolicy {
    if worker_count <= 1
        || separate_flow_state
        || !matches!(protocol, SupportedProtocol::ICMP)
        || socket_type != Type::DGRAM
    {
        return UpstreamWorkerSocketPolicy {
            reuse_address: false,
            reuse_port: false,
            distribution: UpstreamWorkerDistribution::PerWorkerIdentity,
        };
    }

    if shared_icmp_identity_supported(SharedIcmpIdentityRealityKey {
        platform: SocketPlatform::current(),
        family,
        socket_type,
    }) {
        UpstreamWorkerSocketPolicy {
            reuse_address: true,
            reuse_port: true,
            distribution: UpstreamWorkerDistribution::SharedIcmpIdentity,
        }
    } else {
        UpstreamWorkerSocketPolicy {
            reuse_address: false,
            reuse_port: false,
            distribution: UpstreamWorkerDistribution::UnsupportedSharedIcmpIdentity,
        }
    }
}
