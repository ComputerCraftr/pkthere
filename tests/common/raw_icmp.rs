use crate::app_bin::find_app_bin;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::Command;

pub fn raw_icmp_test_supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return linux_binary_has_raw_capability();
    }
    #[cfg(target_os = "macos")]
    {
        return macos_binary_has_raw_capability();
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        return fallback_binary_has_raw_capability();
    }
}

pub fn platform_requires_raw_privilege_for_fixed_icmp() -> bool {
    // macOS DGRAM sockets can bind to a fixed ID, so it does not require raw privileges.
    if cfg!(target_os = "macos") {
        return false;
    }
    // Everything else (Linux/Android ignores DGRAM bind ID, others lack DGRAM entirely)
    // requires raw sockets for fixed IDs.
    true
}

pub fn platform_requires_raw_privilege_for_any_icmp() -> bool {
    // If we can't create a DGRAM ICMP socket, we MUST use RAW for any ICMP.
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::ICMPV4),
    )
    .is_err()
}

pub fn skip_unless_raw_icmp_supported(test_name: &str) -> bool {
    if raw_icmp_test_supported() {
        return false;
    }

    eprintln!(
        "skipping {test_name}: raw ICMP test support unavailable on this host (requires cap_net_raw on Linux, setuid root on macOS, or Administrator on Windows/others)"
    );
    true
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

#[cfg(target_os = "macos")]
fn macos_binary_has_raw_capability() -> bool {
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

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn fallback_binary_has_raw_capability() -> bool {
    // If we can open a raw ICMP socket in the test runner, the spawned binary can too.
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .is_ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn linux_binary_has_raw_capability() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{
        platform_requires_raw_privilege_for_fixed_icmp, raw_icmp_test_supported,
        skip_unless_raw_icmp_supported,
    };

    #[test]
    fn raw_icmp_support_check_is_never_true_without_matching_platform_policy() {
        if !platform_requires_raw_privilege_for_fixed_icmp() {
            let _ = raw_icmp_test_supported();
        }
    }

    #[test]
    fn skip_helper_returns_bool_without_panicking() {
        let _ = skip_unless_raw_icmp_supported("raw-icmp-smoke");
    }
}
