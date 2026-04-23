use crate::cli::{SupportedProtocol, TimeoutAction};
use crate::net::icmp_support::choose_upstream_icmp_ids;
use crate::net::params::CanonicalAddr;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ListenerSocketSetupPolicy, ListenerWorkerSocketPolicy,
    ResolvedIcmpSocketPolicy, ResolvedSocketPolicy, SocketCreateSpec, SocketCreationPolicy,
    SocketPostBindPolicy, SocketRole, listener_socket_creation_policy,
    listener_socket_setup_policy, resolve_socket_policy_with_icmp_intent, socket_post_bind_policy,
    upstream_pre_connect_bind_id, upstream_socket_creation_policy,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ListenerEndpointIdentity {
    logical_local: CanonicalAddr,
    kernel_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UpstreamEndpointIdentity {
    local_filter: CanonicalAddr,
    remote_filter: CanonicalAddr,
    local_kernel_addr: SocketAddr,
}

#[inline]
fn effective_kernel_id(
    requested_id: u16,
    kernel_local_sa: SocketAddr,
    icmp_policy: Option<ResolvedIcmpSocketPolicy>,
) -> u16 {
    if icmp_policy
        .is_some_and(|policy| !policy.trusts_kernel_local_id() || kernel_local_sa.port() == 0)
    {
        requested_id
    } else {
        kernel_local_sa.port()
    }
}

fn resolve_listener_endpoint_identity(
    requested_bind: SocketAddr,
    kernel_local_sa: SocketAddr,
    policy: ResolvedSocketPolicy,
) -> ListenerEndpointIdentity {
    let kernel_id = effective_kernel_id(requested_bind.port(), kernel_local_sa, policy.icmp);
    let logical_local = if requested_bind.port() == 0 {
        CanonicalAddr::new(requested_bind, kernel_id)
    } else {
        CanonicalAddr::from_socket_addr(requested_bind)
    };

    ListenerEndpointIdentity {
        logical_local,
        kernel_addr: kernel_local_sa,
    }
}

#[inline]
fn resolve_upstream_pre_socket_ids(
    requested_local_id: u16,
    requested_remote_id: u16,
    policy: ResolvedSocketPolicy,
    debug_handles: bool,
) -> (u16, u16) {
    if let Some(icmp_policy) = policy.icmp {
        let ids = choose_upstream_icmp_ids(
            requested_local_id,
            requested_remote_id,
            0,
            icmp_policy,
            debug_handles,
        );
        (ids.local_id, ids.remote_id)
    } else {
        (requested_local_id, requested_remote_id)
    }
}

fn resolve_upstream_endpoint_identity(
    remote_addr: SocketAddr,
    planned_local_id: u16,
    planned_remote_id: u16,
    actual_local_sa: SocketAddr,
    policy: ResolvedSocketPolicy,
    debug_handles: bool,
) -> UpstreamEndpointIdentity {
    let (local_id, remote_id) = if let Some(icmp_policy) = policy.icmp {
        let ids = choose_upstream_icmp_ids(
            planned_local_id,
            planned_remote_id,
            actual_local_sa.port(),
            icmp_policy,
            debug_handles,
        );
        (ids.local_id, ids.remote_id)
    } else {
        (actual_local_sa.port(), planned_remote_id)
    };
    let local_filter = CanonicalAddr::new(actual_local_sa, local_id);
    let remote_filter = CanonicalAddr::new(remote_addr, remote_id);

    log_debug!(
        debug_handles,
        "[socket_id] upstream identity: remote_sa={:?} planned_local={} planned_remote={} actual_local_sa={:?} policy_icmp={:?} -> logical_local={} logical_remote={}",
        remote_addr,
        planned_local_id,
        planned_remote_id,
        actual_local_sa,
        policy.icmp.is_some(),
        local_filter,
        remote_filter
    );
    UpstreamEndpointIdentity {
        local_filter,
        remote_filter,
        local_kernel_addr: actual_local_sa,
    }
}

#[inline]
fn set_best_effort_socket_buffers(sock: &Socket) {
    // Buffer sizing is an optimization; some platforms cap or reject these values.
    drop(sock.set_recv_buffer_size(1 << 20));
    drop(sock.set_send_buffer_size(1 << 20));
}

#[cfg(windows)]
fn enable_rcvall(sock: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{RCVALL_IPLEVEL, SIO_RCVALL, WSAIoctl};

    let mut bytes_returned = 0;
    let option: u32 = RCVALL_IPLEVEL as u32;

    let res = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as _,
            SIO_RCVALL,
            &option as *const _ as _,
            std::mem::size_of_val(&option) as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };

    if res == 0 {
        Ok(())
    } else {
        use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
        let err = unsafe { WSAGetLastError() };
        Err(io::Error::from_raw_os_error(err))
    }
}

/// Create a socket (UDP datagram or ICMP) bound to `bind_addr`.
/// Returns the socket and the actual local SocketAddr after bind (for ICMP
/// datagram sockets the kernel may assign an identifier/port). Socket type,
/// protocol, fallback, and post-bind setup come from `socket-policy`.
pub(crate) fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    read_timeout_ms: u64,
    worker_socket_policy: ListenerWorkerSocketPolicy,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    allow_debug_kernel_echo_self_handshake: bool,
) -> io::Result<(
    Socket,
    CanonicalAddr,
    SocketAddr,
    Type,
    ResolvedSocketPolicy,
)> {
    let domain = Domain::for_address(bind_addr);
    let creation = listener_socket_creation_policy(proto, domain);
    let (sock, created) = create_socket_from_policy(creation)?;
    let sock_type = created.socket_type;
    let setup = listener_socket_setup_policy(worker_socket_policy, created.path);

    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Listener,
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
        Domain::for_address(bind_addr),
        IcmpPolicyIntent {
            disable_disjoint_ids: false,
            allow_debug_kernel_echo_self_handshake,
        },
    );

    set_best_effort_socket_buffers(&sock);

    // Read timeout
    sock.set_read_timeout(if read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(read_timeout_ms))
    })?;

    apply_listener_socket_setup_policy(&sock, bind_addr, setup)?;

    let kernel_local_sa = sock.local_addr()?.as_socket().ok_or_else(|| {
        io::Error::other("No socket resolved from getsockname during listener setup")
    })?;
    let identity = resolve_listener_endpoint_identity(bind_addr, kernel_local_sa, policy);

    Ok((
        sock,
        identity.logical_local,
        identity.kernel_addr,
        sock_type,
        policy,
    ))
}

fn create_socket_from_policy(
    policy: SocketCreationPolicy,
) -> io::Result<(Socket, SocketCreateSpec)> {
    match Socket::new(
        policy.primary.domain,
        policy.primary.socket_type,
        policy.primary.protocol,
    ) {
        Ok(socket) => Ok((socket, policy.primary)),
        Err(primary_error) => {
            let Some(create_fallback) = policy.create_fallback else {
                return Err(primary_error);
            };
            log_warn!(
                "primary socket creation path {:?} unavailable ({primary_error}); using create fallback {:?}",
                policy.primary.path,
                create_fallback.path
            );
            Socket::new(
                create_fallback.domain,
                create_fallback.socket_type,
                create_fallback.protocol,
            )
            .map(|socket| (socket, create_fallback))
        }
    }
}

fn apply_listener_socket_setup_policy(
    sock: &Socket,
    bind_addr: SocketAddr,
    policy: ListenerSocketSetupPolicy,
) -> io::Result<()> {
    if policy.worker.reuse_address {
        sock.set_reuse_address(true)?;
    }
    #[cfg(unix)]
    if policy.worker.reuse_port {
        sock.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    if policy.worker.reuse_port {
        return Err(io::Error::other(
            "listener policy requested SO_REUSEPORT on an unsupported target",
        ));
    }
    if !policy.bind_requested_address {
        return Err(io::Error::other(
            "listener setup policy omitted its required bind operation",
        ));
    }
    sock.bind(&SockAddr::from(bind_addr))?;
    apply_post_bind_policy(sock, policy.post_bind)
}

fn apply_post_bind_policy(sock: &Socket, policy: SocketPostBindPolicy) -> io::Result<()> {
    if policy.enable_windows_rcvall {
        #[cfg(windows)]
        enable_rcvall(sock)?;
        #[cfg(not(windows))]
        return Err(io::Error::other(
            "socket policy requested Windows SIO_RCVALL on a non-Windows target",
        ));
    }
    if policy.set_ipv4_header_included {
        sock.set_header_included_v4(true)?;
    }
    Ok(())
}

fn resolve_route_local_ip(dest: SocketAddr) -> io::Result<IpAddr> {
    // UDP connect performs a local routing-table lookup without transmitting a
    // datagram. Keep this separate from the unconnected production socket: RAW
    // receive filtering must remain under application policy, and Windows IPv4
    // must know the concrete interface before bind + SIO_RCVALL.
    let domain = Domain::for_address(dest);
    let route_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let mut route_probe_dest = dest;
    if route_probe_dest.port() == 0 {
        // ICMP identifier 0 is valid, but UDP connect(2) rejects destination
        // port 0 on some platforms. This lookup never sends, so use a nonzero
        // placeholder UDP port.
        route_probe_dest.set_port(9);
    }
    route_socket.connect(&SockAddr::from(route_probe_dest))?;
    route_socket
        .local_addr()?
        .as_socket()
        .map(|addr| addr.ip())
        .filter(|ip| !ip.is_unspecified())
        .ok_or_else(|| io::Error::other("route lookup did not yield a concrete local address"))
}

/// Create and connect a socket suitable for forwarding data to `dest`.
#[derive(Clone, Copy)]
pub(crate) struct UpstreamSocketRequest {
    pub(crate) dest: CanonicalAddr,
    pub(crate) proto: SupportedProtocol,
    pub(crate) req_local_id: u16,
    pub(crate) timeout_act: TimeoutAction,
    pub(crate) debug_unconnected: bool,
    pub(crate) force_raw_wildcard_icmp: bool,
    pub(crate) allow_debug_kernel_echo_self_handshake: bool,
    pub(crate) debug_handles: bool,
}

pub(crate) fn make_upstream_socket_for(
    request: UpstreamSocketRequest,
) -> io::Result<(
    Socket,
    CanonicalAddr,
    CanonicalAddr,
    SocketAddr,
    Type,
    ResolvedSocketPolicy,
)> {
    let UpstreamSocketRequest {
        dest,
        proto,
        req_local_id,
        timeout_act,
        debug_unconnected,
        force_raw_wildcard_icmp,
        allow_debug_kernel_echo_self_handshake,
        debug_handles,
    } = request;
    let domain = Domain::for_address(dest.addr);
    let is_icmp = proto == SupportedProtocol::ICMP;
    let force_raw_wildcard =
        is_icmp && force_raw_wildcard_icmp && dest.id == 0 && req_local_id == 0;
    if force_raw_wildcard_icmp && !force_raw_wildcard {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--debug-force-raw-icmp-wildcard-upstream requires upstream ICMP wildcard remote/local ids",
        ));
    }

    let creation =
        upstream_socket_creation_policy(proto, domain, dest.id, req_local_id, force_raw_wildcard);
    let (sock, created) = create_socket_from_policy(creation).map_err(|err| {
        if force_raw_wildcard {
            io::Error::new(
                err.kind(),
                format!(
                    "--debug-force-raw-icmp-wildcard-upstream requires RAW ICMP socket support: {err}"
                ),
            )
        } else {
            err
        }
    })?;
    let sock_type = created.socket_type;

    let policy = resolve_socket_policy_with_icmp_intent(
        SocketRole::Upstream,
        proto,
        sock_type,
        timeout_act,
        debug_unconnected,
        Domain::for_address(dest.addr),
        IcmpPolicyIntent {
            disable_disjoint_ids: force_raw_wildcard || allow_debug_kernel_echo_self_handshake,
            allow_debug_kernel_echo_self_handshake,
        },
    );

    // Resolve any IDs needed before connect/bind. ICMP DGRAM wildcard stays
    // at 0 here so the kernel can assign the concrete ping-socket ID.
    let (planned_local_id, planned_remote_id) =
        resolve_upstream_pre_socket_ids(req_local_id, dest.id, policy, debug_handles);
    let final_dest = CanonicalAddr::new(dest.addr, planned_remote_id);
    let should_connect = policy.reuse.starts_connected();

    set_best_effort_socket_buffers(&sock);

    // Read timeout
    let read_timeout = Duration::from_millis(1000);
    sock.set_read_timeout(Some(read_timeout))?;
    sock.set_write_timeout(Some(read_timeout))?;

    if should_connect {
        if let Some(bind_id) =
            upstream_pre_connect_bind_id(proto, sock_type, planned_local_id, req_local_id)
        {
            let bind_ip = match domain {
                Domain::IPV6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            sock.bind(&SockAddr::from(SocketAddr::new(bind_ip, bind_id)))?;
        }
        // Connect
        let dest_sa = final_dest.as_sock_addr();
        sock.connect(&dest_sa)?;
    } else {
        // Bind to get a local address/port assigned for unconnected paths.
        // Without this, send_to/recv_from sockets can retain port 0 until the
        // first outbound send, which breaks stats identity, admission checks,
        // and debug tests that inject traffic at the published local address.
        let bind_ip = resolve_route_local_ip(dest.addr)?;
        let kernel_bind_id =
            if is_icmp && sock_type == Type::DGRAM && req_local_id == 0 && dest.id == 0 {
                0
            } else {
                planned_local_id
            };
        let bind_addr = match (domain, bind_ip) {
            (Domain::IPV6, IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), kernel_bind_id),
            (_, IpAddr::V4(ip)) => SocketAddr::new(IpAddr::V4(ip), kernel_bind_id),
            _ => return Err(io::Error::other("RAW bind IP family mismatch")),
        };
        sock.bind(&SockAddr::from(bind_addr))?;
    }

    let actual_local_sa = sock
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("No socket resolved from getsockname"))?;

    if !should_connect && actual_local_sa.ip().is_unspecified() {
        return Err(io::Error::other(
            "unconnected upstream socket must have a concrete local IP address for packet admission filtering",
        ));
    }

    apply_post_bind_policy(&sock, socket_post_bind_policy(created.path))?;

    let identity = resolve_upstream_endpoint_identity(
        dest.addr,
        planned_local_id,
        planned_remote_id,
        actual_local_sa,
        policy,
        debug_handles,
    );
    Ok((
        sock,
        identity.local_filter,
        identity.remote_filter,
        identity.local_kernel_addr,
        sock_type,
        policy,
    ))
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
        if matches!(err.raw_os_error(), Some(code) if code == libc::EAFNOSUPPORT) {
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
#[path = "socket_tests.rs"]
mod tests;
