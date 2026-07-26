use pkthere_wire::packet_headers::{IpVersion, Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use socket2::Domain;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedSocketDomain(pub Domain);

impl fmt::Display for UnsupportedSocketDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported socket domain: {:?}", self.0)
    }
}

impl std::error::Error for UnsupportedSocketDomain {}

pub fn ip_version_for_domain(domain: Domain) -> Result<IpVersion, UnsupportedSocketDomain> {
    if domain == Domain::IPV4 {
        Ok(IpVersion::V4)
    } else if domain == Domain::IPV6 {
        Ok(IpVersion::V6)
    } else {
        Err(UnsupportedSocketDomain(domain))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPlatform {
    Linux,
    Android,
    Macos,
    Ios,
    Windows,
    Freebsd,
    Other,
}

impl SocketPlatform {
    pub fn from_target_os(target_os: &str) -> Self {
        match target_os {
            "linux" => Self::Linux,
            "android" => Self::Android,
            "macos" => Self::Macos,
            "ios" => Self::Ios,
            "windows" => Self::Windows,
            "freebsd" => Self::Freebsd,
            _ => Self::Other,
        }
    }

    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }
        #[cfg(target_os = "android")]
        {
            return Self::Android;
        }
        #[cfg(target_os = "macos")]
        {
            return Self::Macos;
        }
        #[cfg(target_os = "ios")]
        {
            return Self::Ios;
        }
        #[cfg(windows)]
        {
            return Self::Windows;
        }
        #[cfg(target_os = "freebsd")]
        {
            return Self::Freebsd;
        }
        #[allow(unreachable_code)]
        Self::Other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpPlatformCapabilities {
    pub shared_dgram_echo_id: bool,
    pub kernel_assigned_dgram_ids: bool,
    pub kernel_computed_dgram_checksum: bool,
    pub fixed_dgram_ids_honored: bool,
    /// A DGRAM Echo Request reaches a separately bound RAW loopback socket.
    pub dgram_to_bound_raw_loopback: bool,
    /// A RAW Echo Request is routed to a separately bound RAW loopback socket.
    ///
    /// This is intentionally distinct from privileged RAW socket support and
    /// Windows protocol-zero capture. Protocol-zero capture observes interface
    /// traffic globally and cannot provide the isolated bound-socket topology
    /// required by pure-RAW multi-forwarder tests.
    pub raw_to_bound_raw_loopback: bool,
    pub icmp_v4_dgram_receive_header: ReceiveHeaderMode,
    pub ipv4_receive_length: Ipv4PacketLengthEncoding,
}

pub const fn icmp_platform_capabilities(platform: SocketPlatform) -> IcmpPlatformCapabilities {
    IcmpPlatformCapabilities {
        shared_dgram_echo_id: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android | SocketPlatform::Macos
        ),
        kernel_assigned_dgram_ids: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android
        ),
        kernel_computed_dgram_checksum: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android
        ),
        fixed_dgram_ids_honored: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android | SocketPlatform::Macos
        ),
        dgram_to_bound_raw_loopback: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android
        ),
        raw_to_bound_raw_loopback: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android
        ),
        icmp_v4_dgram_receive_header: if matches!(
            platform,
            SocketPlatform::Macos | SocketPlatform::Ios
        ) {
            ReceiveHeaderMode::IpHeaderIncluded
        } else {
            ReceiveHeaderMode::TransportHeaderOnly
        },
        ipv4_receive_length: if matches!(platform, SocketPlatform::Macos | SocketPlatform::Ios) {
            Ipv4PacketLengthEncoding::DarwinHostPayload
        } else {
            Ipv4PacketLengthEncoding::NetworkTotal
        },
    }
}

pub const fn current_icmp_platform_capabilities() -> IcmpPlatformCapabilities {
    icmp_platform_capabilities(SocketPlatform::current())
}
