use crate::app_bin::find_app_bin;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::Command;

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::Duration;

#[path = "../../build_support/icmp_probe.rs"]
mod icmp_probe;

pub fn require_raw_icmp_supported() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if linux_binary_has_raw_capability() {
            return Ok(());
        }
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        if setuid_binary_has_raw_capability() {
            return Ok(());
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        if fallback_binary_has_raw_capability() {
            return Ok(());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "raw ICMP test support unavailable (requires cap_net_raw, setuid root, or Administrator)",
    ))
}

static KERNEL_ECHO_SUPPORT: OnceLock<io::Result<()>> = OnceLock::new();

pub fn require_kernel_echo_reply_supported() -> io::Result<()> {
    KERNEL_ECHO_SUPPORT
        .get_or_init(icmp_probe::probe_kernel_icmp_echo)
        .as_ref()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

pub fn require_bound_raw_icmp_loopback_request_delivery(
    ip: Ipv4Addr,
    ident: u16,
) -> io::Result<()> {
    match icmp_probe::probe_bound_raw_icmp_loopback_request_delivery(
        ip,
        ident,
        Duration::from_millis(750),
    ) {
        Ok(icmp_probe::RawLoopbackProbeResult::EchoRequest) => Ok(()),
        Ok(icmp_probe::RawLoopbackProbeResult::OnlyEchoReply) => Err(io::Error::other(format!(
            "requested-bound RAW ICMP listener on {ip}:{ident} observed only reflected Echo Replies; this host does not deliver the Echo Request stream required by the raw loopback multihop test"
        ))),
        Ok(icmp_probe::RawLoopbackProbeResult::NoMatchingIcmp) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "requested-bound RAW ICMP listener on {ip}:{ident} did not observe a matching Echo Request before the probe deadline"
            ),
        )),
        Err(err) => Err(io::Error::new(
            err.kind(),
            format!("requested-bound RAW ICMP loopback probe failed for {ip}:{ident}: {err}"),
        )),
    }
}

pub fn platform_supports_dgram_icmp() -> bool {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok()
}

pub fn platform_requires_raw_privilege_for_any_icmp() -> bool {
    !platform_supports_dgram_icmp()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_binary_has_raw_capability() -> bool {
    let Some(bin) = find_app_bin() else {
        return false;
    };

    let output = Command::new("getcap").arg(&bin).output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    stdout.contains("cap_net_raw")
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn setuid_binary_has_raw_capability() -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(bin) = find_app_bin() else {
        return false;
    };

    if let Ok(meta) = std::fs::metadata(&bin) {
        // uid 0 means owned by root; 0o4000 is the setuid bit
        return meta.uid() == 0 && (meta.mode() & 0o4000) != 0;
    }
    false
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn fallback_binary_has_raw_capability() -> bool {
    // If we can open a raw ICMP socket in the test runner, the spawned binary can too.
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn linux_binary_has_raw_capability() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn platform_dgram_support_check_returns_bool_without_panicking() {
        super::platform_supports_dgram_icmp();
    }

    #[test]
    fn platform_raw_requirement_check_returns_bool_without_panicking() {
        super::platform_requires_raw_privilege_for_any_icmp();
    }
}
