use crate::cli::SupportedProtocol;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Create a socket (UDP datagram or ICMP) bound to `bind_addr`.
/// Returns the socket and the actual local SocketAddr after bind (for ICMP
/// datagram sockets the kernel may assign an identifier/port). When ICMP is
/// requested, `force_raw_icmp` can be used to skip the datagram attempt (needed
/// for listeners that must see incoming Echo Requests).
pub fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    read_timeout_ms: u64,
    reuseaddr: bool,
    force_raw_icmp: bool,
) -> io::Result<(Socket, SocketAddr)> {
    // Raw ICMP: use well-known protocol numbers (see IANA)
    // IPv4 ICMP = 1, IPv6 ICMP = 58; same on Unix and Windows.
    let (domain, icmp_proto) = match bind_addr {
        SocketAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        _ => (Domain::IPV4, Protocol::ICMPV4),
    };

    let sock = match proto {
        SupportedProtocol::ICMP => {
            // Linux kernels expose SOCK_DGRAM ping sockets when ping_group_range
            // permits it; fall back to raw sockets elsewhere.
            make_icmp_socket(domain, icmp_proto, force_raw_icmp)?
        }
        _ => Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
    };

    if reuseaddr {
        sock.set_reuse_address(true)?;
        // Best effort: only some platforms support SO_REUSEPORT.
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
    }

    // Best-effort bigger buffers
    sock.set_recv_buffer_size(1 << 20)?;
    sock.set_send_buffer_size(1 << 20)?;

    // Bind
    let bind_sa = SockAddr::from(bind_addr);
    sock.bind(&bind_sa)?;

    // Read timeout
    sock.set_read_timeout(if read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(read_timeout_ms))
    })?;

    let actual_local = if force_raw_icmp {
        bind_addr
    } else {
        sock.local_addr()?.as_socket().unwrap_or(bind_addr)
    };

    Ok((sock, actual_local))
}

fn make_icmp_socket(domain: Domain, proto: Protocol, force_raw: bool) -> io::Result<Socket> {
    if force_raw {
        return Socket::new(domain, Type::RAW, Some(proto));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        // Linux/Android/macOS expose ping sockets as SOCK_DGRAM that enforce ICMP checksum
        // and avoid raw socket privileges. Prefer that path, but gracefully fall back to
        // SOCK_RAW if the kernel denies access or the feature is disabled.
        match Socket::new(domain, Type::DGRAM, Some(proto)) {
            Ok(sock) => Ok(sock),
            Err(err) => {
                log_warn!(
                    "ICMP datagram sockets unavailable on {:?} ({err}); falling back to raw sockets",
                    domain
                );
                Socket::new(domain, Type::RAW, Some(proto))
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        // Other OSes do not expose ping sockets via SOCK_DGRAM; raw sockets are the
        // only option for sending ICMP Echo traffic.
        Socket::new(domain, Type::RAW, Some(proto))
    }
}

/// Create and connect a socket suitable for forwarding data to `dest`.
pub fn make_upstream_socket_for(
    dest: SocketAddr,
    proto: SupportedProtocol,
) -> io::Result<(Socket, SocketAddr)> {
    let local_port = if proto == SupportedProtocol::ICMP {
        dest.port()
    } else {
        0
    };
    let bind_addr = match dest {
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_port),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port),
    };

    let (sock, _) = make_socket(bind_addr, proto, 1000, false, false)?;

    let dest_sa = SockAddr::from(dest);
    sock.connect(&dest_sa)?;
    let actual_dest = sock.peer_addr()?.as_socket().unwrap_or(bind_addr);

    Ok((sock, actual_dest))
}

#[inline]
pub fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    // Fast path: direct SocketAddr parse (no DNS, no allocations).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // Fallback: resolve host:port or [IPv6]:port via DNS.
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No address resolved"))
}

#[inline]
pub const fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => false,
        _ => true,
    }
}

/// Disconnect a connected UDP socket so it returns to wildcard receive state.
///
/// macOS/*BSD man page: datagram sockets may dissolve the association by
/// connecting to an invalid address (NULL or AF_UNSPEC). The error
/// EAFNOSUPPORT may be harmlessly returned; consider it success.
#[cfg(unix)]
pub fn disconnect_socket(sock: &Socket) -> io::Result<()> {
    let fd = sock.as_raw_fd();

    // --- macOS / iOS / *BSD: AF_UNSPEC is sufficient. ---
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        // sockaddr WITH sa_len on these platforms
        let addr = libc::sockaddr {
            sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                addr.sa_len as libc::socklen_t,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
            // macOS/*BSD man page: harmless when disconnecting UDP
            return Ok(());
        }
        return Err(err);
    }

    // --- Linux/Android: AF_UNSPEC is the standard way; no sa_len field. ---
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    {
        let addr = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
}

/// Windows: disconnect a UDP socket by connecting to INADDR_ANY/IN6ADDR_ANY and port 0.
#[cfg(windows)]
pub fn disconnect_socket(sock: &Socket) -> io::Result<()> {
    let local = sock.local_addr()?;
    let any_std = match local.as_socket() {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    // Winsock treats connect(INADDR_ANY/IN6ADDR_ANY:0) as clearing the UDP peer
    let any = SockAddr::from(any_std);
    sock.connect(&any)
}

/// Fallback: not supported on this platform.
#[cfg(all(not(unix), not(windows)))]
pub fn disconnect_socket(_sock: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Function disconnect_socket is not supported on this OS",
    ))
}
