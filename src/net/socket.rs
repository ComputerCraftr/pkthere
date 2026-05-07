use crate::cli::{SupportedProtocol, TimeoutAction};
use crate::net::checksum::checksum16;
use crate::net::icmp_support::{
    choose_upstream_icmp_ids, listener_requires_raw, upstream_requires_raw,
};
use crate::net::params::CanonicalAddr;
use crate::net::socket_policy::{SocketReuseCapability, SocketRole, socket_reuse_capability};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::Duration;

const CADENCE_PROBE_SEQ: u16 = 0;

/// Create a socket (UDP datagram or ICMP) bound to `bind_addr`.
/// Returns the socket and the actual local SocketAddr after bind (for ICMP
/// datagram sockets the kernel may assign an identifier/port). When ICMP is
/// requested, `force_raw_icmp` can be used to skip the datagram attempt (needed
/// for listeners that must see incoming Echo Requests).
pub(crate) fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    read_timeout_ms: u64,
    reuseport: bool,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
) -> io::Result<(
    Socket,
    CanonicalAddr,
    CanonicalAddr,
    Type,
    SocketReuseCapability,
)> {
    // Raw ICMP: use well-known protocol numbers (see IANA)
    // IPv4 ICMP = 1, IPv6 ICMP = 58; same on Unix and Windows.
    let (domain, icmp_proto) = match bind_addr {
        SocketAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        _ => (Domain::IPV4, Protocol::ICMPV4),
    };

    let is_icmp = proto == SupportedProtocol::ICMP;
    let force_raw = is_icmp && listener_requires_raw(proto);

    // Create socket
    let (sock, sock_type) = match proto {
        SupportedProtocol::ICMP => {
            // Linux kernels expose SOCK_DGRAM ping sockets when ping_group_range
            // permits it; fall back to raw sockets elsewhere.
            let (s, t) = make_icmp_socket(domain, icmp_proto, force_raw)?;
            (s, t)
        }
        _ => (
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
            Type::DGRAM,
        ),
    };

    if reuseport {
        sock.set_reuse_address(true)?;
        // Best effort: only some platforms support SO_REUSEPORT.
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
    }

    let capability = socket_reuse_capability(
        SocketRole::Listener,
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
    );
    let should_bind_wildcard = capability.binds_wildcard();

    // Best-effort bigger buffers
    let _ = sock.set_recv_buffer_size(1 << 20);
    let _ = sock.set_send_buffer_size(1 << 20);

    // Read timeout
    sock.set_read_timeout(if read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(read_timeout_ms))
    })?;

    // Bind
    let bind_sa = SockAddr::from(if should_bind_wildcard {
        match domain {
            Domain::IPV6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), bind_addr.port()),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind_addr.port()),
        }
    } else {
        bind_addr
    });
    sock.bind(&bind_sa)?;

    let kernel_local = CanonicalAddr::from_socket_addr(
        sock.local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("No socket resolved from getsockname"))?,
    );
    let logical_local = if bind_addr.port() == 0 {
        CanonicalAddr::new(bind_addr, kernel_local.id)
    } else {
        CanonicalAddr::from_socket_addr(bind_addr)
    };

    Ok((sock, logical_local, kernel_local, sock_type, capability))
}

fn make_icmp_socket(
    domain: Domain,
    proto: Protocol,
    force_raw: bool,
) -> io::Result<(Socket, Type)> {
    if force_raw {
        return Ok((Socket::new(domain, Type::RAW, Some(proto))?, Type::RAW));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        // Linux/Android/macOS expose ping sockets as SOCK_DGRAM that enforce ICMP checksum
        // and avoid raw socket privileges. Prefer that path, but gracefully fall back to
        // SOCK_RAW if the kernel denies access or the feature is disabled.
        match Socket::new(domain, Type::DGRAM, Some(proto)) {
            Ok(sock) => Ok((sock, Type::DGRAM)),
            Err(err) => {
                log_warn!(
                    "ICMP datagram sockets unavailable on {:?} ({err}); falling back to raw sockets",
                    domain
                );
                Ok((Socket::new(domain, Type::RAW, Some(proto))?, Type::RAW))
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        // Other OSes do not expose ping sockets via SOCK_DGRAM; raw sockets are the
        // only option for sending ICMP Echo traffic.
        Ok((Socket::new(domain, Type::RAW, Some(proto))?, Type::RAW))
    }
}

fn build_empty_cadence_probe_packet(dest: SocketAddr, remote_id: u16) -> [u8; 8] {
    let mut hdr = [0u8; 8];
    let idb = remote_id.to_be_bytes();
    let sqb = CADENCE_PROBE_SEQ.to_be_bytes();
    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];

    if dest.is_ipv6() {
        hdr[0] = 128;
        hdr[2] = 0;
        hdr[3] = 0;
    } else {
        hdr[0] = 8;
        let cksum = checksum16(&hdr, &[]).to_be_bytes();
        hdr[2] = cksum[0];
        hdr[3] = cksum[1];
    }

    hdr
}

fn learn_concrete_local_addr_via_cadence_probe(
    sock: &Socket,
    dest: CanonicalAddr,
) -> io::Result<SocketAddr> {
    let packet = build_empty_cadence_probe_packet(dest.addr, dest.id);
    let dest_sa = dest.as_sock_addr();
    sock.send_to(&packet, &dest_sa)?;
    sock.local_addr()?.as_socket().ok_or_else(|| {
        io::Error::other("No socket resolved from getsockname after RAW ICMP cadence probe")
    })
}

/// Create and connect a socket suitable for forwarding data to `dest`.
pub(crate) fn make_upstream_socket_for(
    dest: CanonicalAddr,
    proto: SupportedProtocol,
    req_local_id: u16,
    reuse_remote_id: bool,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    debug_handles: bool,
) -> io::Result<(
    Socket,
    CanonicalAddr,
    CanonicalAddr,
    CanonicalAddr,
    Type,
    SocketReuseCapability,
)> {
    let (domain, proto_id) = match dest.addr {
        SocketAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        _ => (Domain::IPV4, Protocol::ICMPV4),
    };

    let is_icmp = proto == SupportedProtocol::ICMP;
    let force_raw = is_icmp && upstream_requires_raw(proto, dest.id);

    // Create socket
    let (sock, sock_type) = if is_icmp {
        if force_raw {
            (Socket::new(domain, Type::RAW, Some(proto_id))?, Type::RAW)
        } else {
            match Socket::new(domain, Type::DGRAM, Some(proto_id)) {
                Ok(s) => (s, Type::DGRAM),
                Err(_) => (Socket::new(domain, Type::RAW, Some(proto_id))?, Type::RAW),
            }
        }
    } else {
        (
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
            Type::DGRAM,
        )
    };

    // Pre-generate remote ID if wildcard
    let mut remote_id = dest.id;
    let mut local_id = req_local_id;

    if is_icmp {
        let (l, r) = choose_upstream_icmp_ids(
            local_id,
            remote_id,
            0, // actual_local_port not known yet
            reuse_remote_id,
            sock_type == Type::RAW,
            debug_handles,
        );
        local_id = l;
        remote_id = r;
    }

    let mut final_dest = CanonicalAddr::new(dest.addr, remote_id);
    let capability = socket_reuse_capability(
        SocketRole::Upstream,
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
    );
    let should_connect = capability.starts_connected();

    // Best-effort bigger buffers
    let _ = sock.set_recv_buffer_size(1 << 20);
    let _ = sock.set_send_buffer_size(1 << 20);

    // Read timeout
    let read_timeout = Duration::from_millis(1000);
    sock.set_read_timeout(Some(read_timeout))?;
    sock.set_write_timeout(Some(read_timeout))?;

    if should_connect {
        // Connect
        let dest_sa = final_dest.as_sock_addr();
        sock.connect(&dest_sa)?;
    } else {
        // Bind to get a local address/port assigned for unconnected paths.
        // Without this, send_to/recv_from sockets can retain port 0 until the
        // first outbound send, which breaks stats identity, admission checks,
        // and debug tests that inject traffic at the published local address.
        let any_addr = match domain {
            Domain::IPV6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_id),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_id),
        };
        sock.bind(&SockAddr::from(any_addr))?;
    }

    let actual_local_sa = if is_icmp && sock_type == Type::RAW && !should_connect {
        let learned = learn_concrete_local_addr_via_cadence_probe(&sock, final_dest)?;
        if learned.ip().is_unspecified() {
            log_warn!(
                "RAW ICMP cadence probe did not yield a concrete local address; retaining {} for upstream local identity",
                learned
            );
        }
        learned
    } else {
        sock.local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("No socket resolved from getsockname"))?
    };

    // After connect, the kernel definitively assigns the local ICMP ID (on most platforms).
    let final_local_port = actual_local_sa.port();

    let (assigned_local_id, assigned_remote_id) = if is_icmp {
        // Re-run with the actual assigned local port.
        // On macOS DGRAM, the kernel might have forced the local port to match the remote port.
        // On Linux DGRAM, the kernel assigns a random local port, which forces BOTH local and remote IDs.
        choose_upstream_icmp_ids(
            local_id,
            remote_id,
            final_local_port,
            reuse_remote_id,
            sock_type == Type::RAW,
            debug_handles,
        )
    } else {
        (final_local_port, final_dest.id)
    };

    let local = CanonicalAddr::new(actual_local_sa, assigned_local_id);
    let local_kernel = CanonicalAddr::from_socket_addr(actual_local_sa);
    final_dest.id = assigned_remote_id;
    Ok((sock, local, final_dest, local_kernel, sock_type, capability))
}

#[inline]
pub(crate) fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    // Fast path: direct SocketAddr parse (no DNS, no allocations).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // Fallback: resolve host:port or [IPv6]:port via DNS.
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::other("No address resolved"))
}

#[inline]
pub(crate) const fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    !matches!(
        (a, b),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

/// Disconnect a connected UDP socket so it returns to wildcard receive state.
///
/// macOS/*BSD man page: datagram sockets may dissolve the association by
/// connecting to an invalid address (NULL or AF_UNSPEC). The error
/// EAFNOSUPPORT may be harmlessly returned; consider it success.
#[cfg(unix)]
pub(crate) fn disconnect_socket(sock: &Socket) -> io::Result<()> {
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
        let rc = connect_with_raw_sockaddr(fd, &addr, addr.sa_len as libc::socklen_t);
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
            // macOS/*BSD man page: harmless when disconnecting UDP
            Ok(())
        } else {
            Err(err)
        }
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
        let rc = connect_with_raw_sockaddr(
            fd,
            &addr,
            std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
        );
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
fn connect_with_raw_sockaddr(
    fd: std::os::fd::RawFd,
    addr: &libc::sockaddr,
    len: libc::socklen_t,
) -> libc::c_int {
    unsafe { libc::connect(fd, addr as *const libc::sockaddr, len) }
}

/// Windows: disconnect a UDP socket by connecting to INADDR_ANY/IN6ADDR_ANY and port 0.
#[cfg(windows)]
pub(crate) fn disconnect_socket(sock: &Socket) -> io::Result<()> {
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
pub(crate) fn disconnect_socket(_sock: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Function disconnect_socket is not supported on this OS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TimeoutAction::Drop;
    use crate::net::socket_policy::{SocketRole, socket_reuse_capability};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_make_upstream_socket_local_id_assigned() {
        // Use a loopback UDP address as destination to avoid privilege issues
        // while still testing the port/ID assignment logic on platforms where
        // ICMP datagram sockets are not the default connected path.
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        let (dest, proto) = (
            CanonicalAddr::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)),
            SupportedProtocol::UDP,
        );

        // Use ID 0 for ICMP to trigger dynamic local/remote ID assignment where
        // ICMP datagram sockets are the normal connected upstream path.
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        let (dest, proto) = (
            CanonicalAddr::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            SupportedProtocol::ICMP,
        );

        let (sock, local, remote, _local_kernel, sock_type, connected_policy) =
            make_upstream_socket_for(dest, proto, 0, false, Drop, false, false)
                .expect("make_upstream_socket_for failed");

        assert_ne!(remote.id, 0, "Remote canonical ID should be nonzero");
        assert_ne!(local.id, 0, "Local canonical ID should be assigned");
        assert_eq!(
            sock_type,
            Type::DGRAM,
            "Upstream socket type should be DGRAM"
        );
        let policy = socket_reuse_capability(SocketRole::Upstream, proto, sock_type, Drop, false);
        assert_eq!(connected_policy, policy);
        #[cfg(target_os = "macos")]
        assert_eq!(sock.local_addr().unwrap().as_socket().unwrap().port(), 0);
        #[cfg(not(any(target_os = "macos")))]
        assert_eq!(
            sock.local_addr().unwrap().as_socket().unwrap().port(),
            local.id
        );
    }

    #[test]
    fn connected_udp_upstream_local_identity_is_concrete_immediately() {
        let dest =
            CanonicalAddr::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
        let (_sock, local, _remote, _local_kernel, sock_type, connected) =
            make_upstream_socket_for(dest, SupportedProtocol::UDP, 0, false, Drop, false, false)
                .expect("connected udp upstream socket");
        assert_eq!(sock_type, Type::DGRAM);
        assert!(connected.starts_connected());
        assert!(
            !local.addr.ip().is_unspecified(),
            "Connected UDP upstream local identity should be concrete immediately"
        );
    }

    #[test]
    fn udp_listener_reports_logical_and_kernel_identity() {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (_sock, logical, kernel, sock_type, capability) = make_socket(
            listen_addr,
            SupportedProtocol::UDP,
            1000,
            false,
            Drop,
            false,
        )
        .expect("udp listener socket");

        assert_eq!(sock_type, Type::DGRAM);
        assert!(!capability.binds_wildcard());
        assert_eq!(logical, kernel);
        assert!(!logical.addr.ip().is_unspecified());
        assert_ne!(logical.id, 0);
    }

    #[test]
    fn upstream_connectedness_matches_platform_policy() {
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        let protocols = vec![SupportedProtocol::UDP];

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        let protocols = vec![SupportedProtocol::UDP, SupportedProtocol::ICMP];

        for proto in protocols {
            let dest = match proto {
                SupportedProtocol::UDP => CanonicalAddr::from_socket_addr(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    9,
                )),
                SupportedProtocol::ICMP => CanonicalAddr::from_socket_addr(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    0,
                )),
            };

            let (_sock, _local, _remote, _local_kernel, sock_type, connected_policy) =
                make_upstream_socket_for(dest, proto, 0, false, Drop, false, false)
                    .expect("upstream socket");
            let policy =
                socket_reuse_capability(SocketRole::Upstream, proto, sock_type, Drop, false);
            assert_eq!(
                connected_policy, policy,
                "proto={:?} sock_type={:?} connected mismatch",
                proto, sock_type
            );
        }
    }

    #[test]
    fn debug_unconnected_forces_otherwise_connected_upstream_unconnected() {
        let dest =
            CanonicalAddr::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9));
        let (_sock, _local, _remote, _local_kernel, _sock_type, connected) =
            make_upstream_socket_for(dest, SupportedProtocol::UDP, 0, false, Drop, true, false)
                .expect("debug unconnected upstream socket");
        assert!(!connected.starts_connected());
    }

    #[test]
    fn debug_unconnected_upstream_binds_a_concrete_local_port() {
        let probe =
            match std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
                Ok(probe) => probe,
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
                Err(err) => panic!("bind UDP probe socket: {err}"),
            };
        let dest =
            CanonicalAddr::from_socket_addr(probe.local_addr().expect("probe UDP local addr"));
        let (_sock, local, _remote, local_kernel, _sock_type, connected) =
            make_upstream_socket_for(dest, SupportedProtocol::UDP, 0, false, Drop, true, false)
                .expect("debug unconnected upstream socket");
        assert!(!connected.starts_connected());
        assert_ne!(local.addr.port(), 0);
        assert_ne!(local_kernel.addr.port(), 0);
    }

    #[test]
    fn empty_cadence_probe_uses_header_only_echo_shape() {
        let ipv4 = build_empty_cadence_probe_packet(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            2002,
        );
        let ipv6 = build_empty_cadence_probe_packet(
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 9),
            3003,
        );

        assert_eq!(ipv4.len(), 8);
        assert_eq!(ipv4[0], 8);
        assert_eq!(u16::from_be_bytes([ipv4[4], ipv4[5]]), 2002);
        assert_eq!(u16::from_be_bytes([ipv4[6], ipv4[7]]), CADENCE_PROBE_SEQ);
        assert_ne!(u16::from_be_bytes([ipv4[2], ipv4[3]]), 0);

        assert_eq!(ipv6.len(), 8);
        assert_eq!(ipv6[0], 128);
        assert_eq!(u16::from_be_bytes([ipv6[4], ipv6[5]]), 3003);
        assert_eq!(u16::from_be_bytes([ipv6[6], ipv6[7]]), CADENCE_PROBE_SEQ);
    }
}
