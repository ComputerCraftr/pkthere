#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPlatform {
    Linux,
    Android,
    Macos,
    Ios,
    Windows,
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
            _ => Self::Other,
        }
    }

    pub fn current() -> Self {
        Self::from_target_os(std::env::consts::OS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpPlatformCapabilities {
    pub datagram_echo_sockets: bool,
    pub windows_ipv4_protocol_zero_raw: bool,
    pub dgram_to_bound_raw_loopback: bool,
    pub raw_to_bound_raw_loopback: bool,
}

pub const fn icmp_platform_capabilities(platform: SocketPlatform) -> IcmpPlatformCapabilities {
    let datagram_echo_sockets = matches!(
        platform,
        SocketPlatform::Linux | SocketPlatform::Android | SocketPlatform::Macos
    );
    IcmpPlatformCapabilities {
        datagram_echo_sockets,
        windows_ipv4_protocol_zero_raw: matches!(platform, SocketPlatform::Windows),
        dgram_to_bound_raw_loopback: matches!(
            platform,
            SocketPlatform::Linux | SocketPlatform::Android
        ),
        raw_to_bound_raw_loopback: !matches!(platform, SocketPlatform::Macos | SocketPlatform::Ios),
    }
}

pub fn current_icmp_platform_capabilities() -> IcmpPlatformCapabilities {
    icmp_platform_capabilities(SocketPlatform::current())
}
