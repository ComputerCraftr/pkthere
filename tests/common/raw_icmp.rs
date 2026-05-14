use crate::app_bin::find_app_bin;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::Command;

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::sync::OnceLock;

#[path = "../../build_support/icmp_probe.rs"]
mod icmp_probe;

pub fn require_raw_icmp_supported() -> io::Result<()> {
    let has_raw_binary_capability = {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            linux_binary_has_raw_capability()
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
            setuid_binary_has_raw_capability()
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
            fallback_binary_has_raw_capability()
        }
    };

    if !has_raw_binary_capability {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw ICMP test support unavailable (requires cap_net_raw, setuid root, or Administrator)",
        ));
    }

    RAW_ICMP_CAPABILITY
        .get_or_init(icmp_probe::probe_raw_icmp_capability)
        .as_ref()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

static RAW_ICMP_CAPABILITY: OnceLock<io::Result<()>> = OnceLock::new();

static KERNEL_ECHO_SUPPORT: OnceLock<io::Result<()>> = OnceLock::new();

pub fn require_kernel_echo_reply_supported() -> io::Result<()> {
    KERNEL_ECHO_SUPPORT
        .get_or_init(icmp_probe::probe_kernel_icmp_echo)
        .as_ref()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

pub fn platform_supports_dgram_icmp() -> bool {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok()
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
    fn raw_icmp_capability_probe_reports_result_without_panicking() {
        let _ = super::icmp_probe::probe_raw_icmp_capability();
    }
}
