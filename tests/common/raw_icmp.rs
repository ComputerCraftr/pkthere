use crate::app_bin::find_app_bin;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::Command;

pub fn raw_icmp_test_supported() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return linux_binary_has_raw_capability();
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
        return setuid_binary_has_raw_capability();
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
        return fallback_binary_has_raw_capability();
    }
}

pub fn platform_supports_dgram_icmp() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::ICMPV4),
    )
    .is_ok()
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

pub fn kernel_echo_reply_supported() -> bool {
    // Try to send an ICMP Echo Request to localhost and wait for a reply.
    // This ensures the kernel actually responds to pings, which is required for some tests.
    let sock = if platform_supports_dgram_icmp() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::ICMPV4),
        )
    } else {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
    };

    let Ok(sock) = sock else {
        return false;
    };

    let bind_sa = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ));
    if sock.bind(&bind_sa.into()).is_err() {
        return false;
    }

    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(500)));

    // ICMP Echo Request: type 8, code 0, checksum 0 (for now), id 0, seq 0
    let mut request = [
        8u8, 0, 0, 0, // type, code, checksum
        0, 0, 0, 0, // id, seq
        b'p', b'k', b't', b'h', b'e', b'r', b'e', // payload
    ];

    // Simple RFC1071 checksum calculation
    let mut sum = 0u32;
    let (chunks, remainder) = request.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    let checksum = !(sum as u16);
    let checksum_bytes = checksum.to_be_bytes();
    request[2] = checksum_bytes[0];
    request[3] = checksum_bytes[1];

    let dest = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ));

    if sock.send_to(&request, &dest.into()).is_err() {
        return false;
    }

    let mut recv_buf = [std::mem::MaybeUninit::uninit(); 2048];
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_millis(500) {
        match sock.recv(&mut recv_buf) {
            Ok(n) => {
                if n < 8 {
                    continue;
                }
                // Safety: recv returned Ok(n), so at least n bytes are initialized.
                let buf = unsafe {
                    &*(&recv_buf[..n] as *const [std::mem::MaybeUninit<u8>] as *const [u8])
                };

                // Detect if the packet starts with an IPv4 or IPv6 header.
                // RAW sockets typically return the IP header, while DGRAM sockets do not.
                let mut icmp_start = 0;
                let version = buf[0] >> 4;
                if version == 4 {
                    let ihl = (buf[0] & 0x0f) as usize * 4;
                    if n >= ihl + 8 {
                        icmp_start = ihl;
                    }
                } else if version == 6 {
                    // IPv6 header is a fixed 40 bytes.
                    if n >= 40 + 8 {
                        icmp_start = 40;
                    }
                }

                // ICMP Echo Reply: Type 0 (v4) or 129 (v6), Code 0
                let icmp_type = buf[icmp_start];
                let icmp_code = buf[icmp_start + 1];
                if (icmp_type == 0 || icmp_type == 129) && icmp_code == 0 {
                    return true;
                }
            }
            Err(_) => break,
        }
    }

    false
}

pub fn skip_unless_kernel_echo_supported(test_name: &str) -> bool {
    if kernel_echo_reply_supported() {
        return false;
    }

    eprintln!(
        "skipping {test_name}: kernel does not provide ICMP echo replies on localhost or ICMP socket support unavailable"
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
        kernel_echo_reply_supported, raw_icmp_test_supported, skip_unless_kernel_echo_supported,
        skip_unless_raw_icmp_supported,
    };

    #[test]
    fn raw_icmp_support_check_returns_bool_without_panicking() {
        let _ = raw_icmp_test_supported();
    }

    #[test]
    fn skip_helper_returns_bool_without_panicking() {
        let _ = skip_unless_raw_icmp_supported("raw-icmp-smoke");
    }

    #[test]
    fn kernel_echo_check_returns_bool_without_panicking() {
        let _ = kernel_echo_reply_supported();
    }

    #[test]
    fn kernel_echo_skip_helper_returns_bool_without_panicking() {
        let _ = skip_unless_kernel_echo_supported("kernel-echo-smoke");
    }

    #[test]
    fn platform_dgram_support_check_returns_bool_without_panicking() {
        let _ = super::platform_supports_dgram_icmp();
    }
}
