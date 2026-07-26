use crate::cli::{SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::net::icmp_support::choose_upstream_icmp_ids;
use crate::net::managed_socket::ManagedSocket;
use crate::net::managed_socket::realization::{Created, RealizationRequirements, RealizingSocket};
use pkthere_socket_policy::{
    IcmpPolicyIntent, Ipv4HeaderAction, ListenerSocketSetupPolicy, ListenerWorkerSocketPolicy,
    ProtocolPolicyIntent, ResolvedIcmpSocketPolicy, ResolvedSocketPolicy, ReusePortAction,
    SocketCreateSpec, SocketCreationFailureClass, SocketCreationPlan, SocketLifecycleContext,
    SocketPathContext, SocketPolicyContext, SocketPostBindPolicy, SocketRole, UpstreamBindAddress,
    UpstreamSocketBindPolicy, UpstreamWorkerSocketPolicy, listener_socket_bind_policy,
    listener_socket_creation_policy, listener_socket_setup_policy,
    resolve_listener_socket_policy_for_creation_path_with_lifecycle,
    resolve_socket_policy_for_creation_path_with_lifecycle, reuse_port_action,
    socket_post_bind_policy, upstream_socket_bind_policy, upstream_socket_creation_policy,
};
use socket2::{Domain, SockAddr, Socket, Type};

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, ToSocketAddrs};

mod platform;

const MAX_INTERRUPTED_SOCKET_CREATE_ATTEMPTS: u8 = 8;
const SOCKET_CREATION_RETRY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalSocketIdentity {
    logical_filter: LogicalEndpoint,
    kernel_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UpstreamEndpointIdentity {
    local: LocalSocketIdentity,
    remote_filter: LogicalEndpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UpstreamSocketIdentityPlan {
    local_id: u16,
    remote_id: u16,
    bind: UpstreamSocketBindPolicy,
}

fn protocol_policy_intent(
    protocol: SupportedProtocol,
    icmp: IcmpPolicyIntent,
) -> ProtocolPolicyIntent {
    match protocol {
        SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
        SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(icmp),
    }
}

#[inline]
fn effective_kernel_id(
    requested_id: u16,
    kernel_local_sa: SocketAddr,
    icmp_policy: Option<ResolvedIcmpSocketPolicy>,
) -> u16 {
    icmp_policy
        .and_then(|policy| policy.trusted_kernel_local_id(kernel_local_sa.port()))
        .unwrap_or_else(|| {
            if icmp_policy.is_some() {
                requested_id
            } else {
                kernel_local_sa.port()
            }
        })
}

fn resolve_listener_endpoint_identity(
    requested_bind: SocketAddr,
    kernel_local_sa: SocketAddr,
    policy: ResolvedSocketPolicy,
) -> LocalSocketIdentity {
    let kernel_id = effective_kernel_id(requested_bind.port(), kernel_local_sa, policy.icmp);
    let logical_local = if requested_bind.port() == 0 {
        LogicalEndpoint::from_socket_addr_with_id(requested_bind, kernel_id)
    } else {
        LogicalEndpoint::from_socket_addr(requested_bind)
    };

    LocalSocketIdentity {
        logical_filter: logical_local,
        kernel_addr: kernel_local_sa,
    }
}

#[inline]
fn resolve_upstream_socket_identity_plan(
    requested_local_id: u16,
    requested_remote_id: u16,
    policy: ResolvedSocketPolicy,
) -> UpstreamSocketIdentityPlan {
    let (local_id, remote_id) = if let Some(icmp_policy) = policy.icmp {
        let ids = choose_upstream_icmp_ids(requested_local_id, requested_remote_id, 0, icmp_policy);
        (ids.local_id, ids.remote_id)
    } else {
        (requested_local_id, requested_remote_id)
    };
    UpstreamSocketIdentityPlan {
        local_id,
        remote_id,
        bind: upstream_socket_bind_policy(policy, local_id, requested_local_id),
    }
}

fn resolve_upstream_endpoint_identity(
    remote_addr: SocketAddr,
    planned_local_id: u16,
    planned_remote_id: u16,
    actual_local_sa: SocketAddr,
    policy: ResolvedSocketPolicy,
) -> UpstreamEndpointIdentity {
    let (local_id, remote_id) = if let Some(icmp_policy) = policy.icmp {
        let ids = choose_upstream_icmp_ids(
            planned_local_id,
            planned_remote_id,
            actual_local_sa.port(),
            icmp_policy,
        );
        (ids.local_id, ids.remote_id)
    } else {
        (actual_local_sa.port(), planned_remote_id)
    };
    let local_filter = LogicalEndpoint::from_socket_addr_with_id(actual_local_sa, local_id);
    let remote_filter = LogicalEndpoint::from_socket_addr_with_id(remote_addr, remote_id);
    UpstreamEndpointIdentity {
        local: LocalSocketIdentity {
            logical_filter: local_filter,
            kernel_addr: actual_local_sa,
        },
        remote_filter,
    }
}

#[inline]
fn set_best_effort_socket_buffers(sock: &Socket) {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
    // Buffer sizing is an optimization; some platforms cap or reject these values.
    drop(sock.set_recv_buffer_size(1 << 20));
    drop(sock.set_send_buffer_size(1 << 20));
}

fn set_reuse_address(sock: &Socket) -> io::Result<()> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
    sock.set_reuse_address(true)
}

fn set_reuse_port_from_policy(sock: &Socket, requested: bool, role: &str) -> io::Result<()> {
    match reuse_port_action(requested) {
        ReusePortAction::Disabled => Ok(()),
        ReusePortAction::Enable => platform::enable_reuse_port(sock),
        ReusePortAction::Unsupported => Err(io::Error::other(format!(
            "{role} policy requested SO_REUSEPORT on an unsupported target"
        ))),
    }
}

/// Create a socket (UDP datagram or ICMP) bound to `bind_addr`.
/// Returns the socket and the actual local SocketAddr after bind (for ICMP
/// datagram sockets the kernel may assign an identifier/port). Socket type,
/// protocol, fallback, and post-bind setup come from `socket-policy`.
pub(crate) fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    worker_socket_policy: ListenerWorkerSocketPolicy,
    timeout_act: TimeoutAction,
    debug_unconnected: bool,
    allow_debug_kernel_echo_self_handshake: bool,
) -> io::Result<(
    ManagedSocket,
    LogicalEndpoint,
    SocketAddr,
    Type,
    ResolvedSocketPolicy,
)> {
    let domain = Domain::for_address(bind_addr);
    let creation = listener_socket_creation_policy(proto, domain);
    let (realizing, created) = create_socket_from_policy(creation).map_err(io::Error::other)?;
    let sock_type = created.socket_type;
    let setup = listener_socket_setup_policy(worker_socket_policy, created.path);

    let policy = resolve_listener_socket_policy_for_creation_path_with_lifecycle(
        protocol_policy_intent(
            proto,
            IcmpPolicyIntent {
                disable_disjoint_ids: false,
                allow_debug_kernel_echo_self_handshake,
            },
        ),
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPolicyContext {
            path: SocketPathContext {
                family: Domain::for_address(bind_addr),
                creation_path: created.path,
            },
            lifecycle: SocketLifecycleContext::for_requested_bind(
                bind_addr,
                worker_socket_policy.reuse_address,
                worker_socket_policy.reuse_port,
            ),
        },
        worker_socket_policy,
    );

    let kernel_bind_addr = SocketAddr::new(
        bind_addr.ip(),
        listener_socket_bind_policy(created.path, bind_addr.port()).kernel_id,
    );
    let configured = realizing.configure(|sock| {
        set_best_effort_socket_buffers(sock);
        apply_listener_socket_setup_policy(sock, kernel_bind_addr, setup)?;
        let kernel_local_sa = inspect_inet_local_addr(sock, "listener setup")?;
        Ok(RealizationRequirements::unconnected(kernel_local_sa))
    })?;
    let verified = configured.verify(policy)?;
    let kernel_local_sa = verified.required_local_bind();
    let identity = resolve_listener_endpoint_identity(bind_addr, kernel_local_sa, policy);

    Ok((
        verified.into_managed().map_err(io::Error::other)?,
        identity.logical_filter,
        identity.kernel_addr,
        sock_type,
        policy,
    ))
}

fn create_socket_from_policy(
    policy: SocketCreationPlan,
) -> Result<(RealizingSocket<Created>, SocketCreateSpec), SocketCreationError> {
    create_socket_from_policy_using(policy, create_socket)
}

fn create_socket_from_policy_using(
    policy: SocketCreationPlan,
    mut create: impl FnMut(SocketCreateSpec) -> io::Result<Socket>,
) -> Result<(RealizingSocket<Created>, SocketCreateSpec), SocketCreationError> {
    let primary = create_socket_with_retry_using(policy.primary, &mut create)?;
    match primary {
        SocketCreationAttempt::Created(socket) => {
            Ok((RealizingSocket::new(socket, policy.primary), policy.primary))
        }
        SocketCreationAttempt::Failed(primary_error) => {
            let Some(fallback) = policy.fallback else {
                return Err(SocketCreationError::Candidate(primary_error));
            };
            if fallback.from != policy.primary || !fallback.permits(primary_error.class) {
                return Err(SocketCreationError::Candidate(primary_error));
            }
            match create_socket_with_retry_using(fallback.to, &mut create)? {
                SocketCreationAttempt::Created(socket) => {
                    Ok((RealizingSocket::new(socket, fallback.to), fallback.to))
                }
                SocketCreationAttempt::Failed(fallback_error) => {
                    Err(SocketCreationError::CandidatesExhausted {
                        primary: primary_error,
                        fallback: fallback_error,
                    })
                }
            }
        }
    }
}

enum SocketCreationAttempt {
    Created(Socket),
    Failed(SocketCreationFailure),
}

#[derive(Debug)]
struct SocketCreationFailure {
    spec: SocketCreateSpec,
    class: SocketCreationFailureClass,
    attempts: u8,
    source: io::Error,
}

#[derive(Debug)]
enum SocketCreationError {
    Candidate(SocketCreationFailure),
    CandidatesExhausted {
        primary: SocketCreationFailure,
        fallback: SocketCreationFailure,
    },
    RetryDeadlineOverflow,
}

impl fmt::Display for SocketCreationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} failed as {:?} after {} attempt(s), OS code {:?}: {}",
            self.spec,
            self.class,
            self.attempts,
            self.source.raw_os_error(),
            self.source
        )
    }
}

impl fmt::Display for SocketCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(failure) => {
                write!(formatter, "socket candidate creation failed: {failure}")
            }
            Self::CandidatesExhausted { primary, fallback } => write!(
                formatter,
                "socket creation candidates failed; primary {primary}; fallback {fallback}"
            ),
            Self::RetryDeadlineOverflow => {
                formatter.write_str("socket creation retry deadline overflowed")
            }
        }
    }
}

impl std::error::Error for SocketCreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Candidate(failure)
            | Self::CandidatesExhausted {
                primary: failure, ..
            } => Some(&failure.source),
            Self::RetryDeadlineOverflow => None,
        }
    }
}

fn create_socket_with_retry_using(
    spec: SocketCreateSpec,
    mut create: impl FnMut(SocketCreateSpec) -> io::Result<Socket>,
) -> Result<SocketCreationAttempt, SocketCreationError> {
    let deadline = std::time::Instant::now()
        .checked_add(SOCKET_CREATION_RETRY_DEADLINE)
        .ok_or(SocketCreationError::RetryDeadlineOverflow)?;
    let mut attempts = 0_u8;
    loop {
        attempts = attempts
            .checked_add(1)
            .ok_or(SocketCreationError::RetryDeadlineOverflow)?;
        match create(spec) {
            Ok(socket) => return Ok(SocketCreationAttempt::Created(socket)),
            Err(error)
                if classify_creation_error(&error)
                    == SocketCreationFailureClass::TransientInterrupted
                    && attempts < MAX_INTERRUPTED_SOCKET_CREATE_ATTEMPTS
                    && std::time::Instant::now() < deadline => {}
            Err(error) => {
                return Ok(SocketCreationAttempt::Failed(SocketCreationFailure {
                    spec,
                    class: classify_creation_error(&error),
                    attempts,
                    source: error,
                }));
            }
        }
    }
}

fn classify_creation_error(error: &io::Error) -> SocketCreationFailureClass {
    platform::classify_socket_creation_error(error)
}

fn create_socket(spec: SocketCreateSpec) -> io::Result<Socket> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketCreate);
    Socket::new(spec.domain, spec.socket_type, spec.protocol)
}

fn bind_socket(socket: &Socket, address: SocketAddr) -> io::Result<()> {
    let _operation = crate::authority::audited_operation(crate::authority::OperationId::SocketBind);
    socket.bind(&SockAddr::from(address))
}

fn inspect_local_addr(socket: &Socket) -> io::Result<SockAddr> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketLocalInspection);
    socket.local_addr()
}

fn inspect_inet_local_addr(socket: &Socket, stage: &str) -> io::Result<SocketAddr> {
    inspect_local_addr(socket)?.as_socket().ok_or_else(|| {
        io::Error::other(format!(
            "socket exposed a non-INET local address during {stage}"
        ))
    })
}

fn apply_listener_socket_setup_policy(
    sock: &Socket,
    bind_addr: SocketAddr,
    policy: ListenerSocketSetupPolicy,
) -> io::Result<()> {
    if policy.worker.reuse_address {
        set_reuse_address(sock)?;
    }
    set_reuse_port_from_policy(sock, policy.worker.reuse_port, "listener")?;
    if !policy.bind_requested_address {
        return Err(io::Error::other(
            "listener setup policy omitted its required bind operation",
        ));
    }
    bind_socket(sock, bind_addr)?;
    apply_post_bind_policy(sock, policy.post_bind)
}

fn apply_post_bind_policy(sock: &Socket, policy: SocketPostBindPolicy) -> io::Result<()> {
    platform::apply_capture_action(sock, policy.capture)?;
    match policy.ipv4_header {
        Ipv4HeaderAction::KernelManaged => {}
        Ipv4HeaderAction::ApplicationIncluded => {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
            sock.set_header_included_v4(true)?;
        }
    }
    Ok(())
}

fn wildcard_bind_addr(domain: Domain, id: u16) -> SocketAddr {
    if domain == Domain::IPV6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), id)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), id)
    }
}

fn socket_addr_for_domain(domain: Domain, ip: IpAddr, id: u16) -> io::Result<SocketAddr> {
    match (domain, ip) {
        (Domain::IPV6, IpAddr::V6(ip)) => Ok(SocketAddr::new(IpAddr::V6(ip), id)),
        (Domain::IPV4, IpAddr::V4(ip)) => Ok(SocketAddr::new(IpAddr::V4(ip), id)),
        _ => Err(io::Error::other("socket bind IP family mismatch")),
    }
}

fn resolve_route_local_ip(dest: SocketAddr) -> io::Result<IpAddr> {
    // UDP connect performs a local routing-table lookup without transmitting a
    // datagram. Keep this separate from the unconnected production socket: RAW
    // receive filtering must remain under application policy, and Windows IPv4
    // must know the concrete interface before bind + SIO_RCVALL.
    let domain = Domain::for_address(dest);
    let route_spec = pkthere_socket_policy::socket_create_spec(
        pkthere_socket_policy::SocketCreationPath::Datagram,
        SupportedProtocol::UDP,
        domain,
    );
    let route_socket = create_socket(route_spec)?;
    let mut route_probe_dest = dest;
    if route_probe_dest.port() == 0 {
        // ICMP identifier 0 is valid, but UDP connect(2) rejects destination
        // port 0 on some platforms. This lookup never sends, so use a nonzero
        // placeholder UDP port.
        route_probe_dest.set_port(9);
    }
    if inspect_local_addr(&route_socket).is_err() {
        bind_socket(&route_socket, wildcard_bind_addr(domain, 0))?;
        inspect_inet_local_addr(&route_socket, "route-probe bind")?;
    }
    {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::SocketConnect);
        route_socket.connect(&SockAddr::from(route_probe_dest))?;
    }
    let local_ip = inspect_inet_local_addr(&route_socket, "route-probe connect")?.ip();
    if local_ip.is_unspecified() {
        Err(io::Error::other(
            "route lookup did not yield a concrete local address",
        ))
    } else {
        Ok(local_ip)
    }
}

/// Create and connect a socket suitable for forwarding data to `dest`.
#[derive(Clone, Copy)]
pub(crate) struct UpstreamSocketRequest {
    pub(crate) dest: LogicalEndpoint,
    pub(crate) proto: SupportedProtocol,
    pub(crate) req_local_id: u16,
    pub(crate) timeout_act: TimeoutAction,
    pub(crate) debug_unconnected: bool,
    pub(crate) force_raw_wildcard_icmp: bool,
    pub(crate) allow_debug_kernel_echo_self_handshake: bool,
    pub(crate) worker_socket_policy: UpstreamWorkerSocketPolicy,
    pub(crate) authority_identity: Option<(u32, u64, bool)>,
}

/// Fully realized upstream descriptor and the policy-derived identities that
/// must be published with it. Keeping these values together prevents manager
/// initialization and replacement from accidentally mixing metadata from a
/// different socket realization.
pub(crate) struct RealizedUpstreamSocket {
    pub(crate) socket: ManagedSocket,
    pub(crate) local_filter: LogicalEndpoint,
    pub(crate) remote_filter: LogicalEndpoint,
    pub(crate) local_kernel_addr: SocketAddr,
    pub(crate) socket_type: Type,
    pub(crate) policy: ResolvedSocketPolicy,
}

pub(crate) fn make_upstream_socket_for(
    request: UpstreamSocketRequest,
) -> io::Result<RealizedUpstreamSocket> {
    let UpstreamSocketRequest {
        dest,
        proto,
        req_local_id,
        timeout_act,
        debug_unconnected,
        force_raw_wildcard_icmp,
        allow_debug_kernel_echo_self_handshake,
        worker_socket_policy,
        authority_identity,
    } = request;
    let domain = dest.domain();
    let is_icmp = proto == SupportedProtocol::ICMP;
    let force_raw_wildcard =
        is_icmp && force_raw_wildcard_icmp && dest.id() == 0 && req_local_id == 0;
    if force_raw_wildcard_icmp && !force_raw_wildcard {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--debug-force-raw-icmp-wildcard-upstream requires upstream ICMP wildcard remote/local ids",
        ));
    }

    let creation =
        upstream_socket_creation_policy(proto, domain, dest.id(), req_local_id, force_raw_wildcard);
    let (realizing, created) = create_socket_from_policy(creation).map_err(|err| {
        if force_raw_wildcard {
            io::Error::other(format!(
                "--debug-force-raw-icmp-wildcard-upstream requires RAW ICMP socket support: {err}"
            ))
        } else {
            io::Error::other(err)
        }
    })?;
    let sock_type = created.socket_type;

    let icmp_intent = IcmpPolicyIntent {
        disable_disjoint_ids: force_raw_wildcard || allow_debug_kernel_echo_self_handshake,
        allow_debug_kernel_echo_self_handshake,
    };
    let preliminary_policy = resolve_socket_policy_for_creation_path_with_lifecycle(
        SocketRole::Upstream,
        protocol_policy_intent(proto, icmp_intent),
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPolicyContext {
            path: SocketPathContext {
                family: dest.domain(),
                creation_path: created.path,
            },
            lifecycle: SocketLifecycleContext::for_requested_bind(
                wildcard_bind_addr(domain, req_local_id),
                worker_socket_policy.reuse_address,
                worker_socket_policy.reuse_port,
            ),
        },
    );

    // Resolve any IDs needed before connect/bind. ICMP DGRAM wildcard stays
    // at 0 here so the kernel can assign the concrete ping-socket ID.
    let identity_plan =
        resolve_upstream_socket_identity_plan(req_local_id, dest.id(), preliminary_policy);
    let planned_local_id = identity_plan.local_id;
    let planned_remote_id = identity_plan.remote_id;
    let final_dest = dest.with_id(planned_remote_id);
    let preliminary_connect = preliminary_policy.reuse.starts_connected();
    let requested_bind = match identity_plan.bind.address {
        UpstreamBindAddress::RouteSelected => {
            let bind_ip = resolve_route_local_ip(dest.to_socket_addr())?;
            socket_addr_for_domain(domain, bind_ip, identity_plan.bind.kernel_id)?
        }
        UpstreamBindAddress::Wildcard => wildcard_bind_addr(domain, identity_plan.bind.kernel_id),
    };
    let policy = resolve_socket_policy_for_creation_path_with_lifecycle(
        SocketRole::Upstream,
        protocol_policy_intent(proto, icmp_intent),
        sock_type,
        timeout_act,
        debug_unconnected,
        SocketPolicyContext {
            path: SocketPathContext {
                family: dest.domain(),
                creation_path: created.path,
            },
            lifecycle: SocketLifecycleContext::for_requested_bind(
                requested_bind,
                worker_socket_policy.reuse_address,
                worker_socket_policy.reuse_port,
            ),
        },
    );
    let should_connect = policy.reuse.starts_connected();
    if should_connect != preliminary_connect {
        return Err(io::Error::other(
            "exact upstream bind fingerprint changed startup connection policy",
        ));
    }
    let bind_policy = upstream_socket_bind_policy(policy, planned_local_id, req_local_id);
    if bind_policy != identity_plan.bind {
        return Err(io::Error::other(
            "exact upstream socket policy changed the planned kernel bind identity",
        ));
    }

    let final_peer = final_dest.to_socket_addr();
    let configure = |sock: &Socket| {
        set_best_effort_socket_buffers(sock);
        if worker_socket_policy.reuse_address {
            set_reuse_address(sock)?;
        }
        set_reuse_port_from_policy(sock, worker_socket_policy.reuse_port, "upstream worker")?;
        if !should_connect || bind_policy.bind_before_connect {
            bind_socket(sock, requested_bind)?;
        }
        apply_post_bind_policy(sock, socket_post_bind_policy(created.path))?;
        Ok(())
    };
    let configured = if should_connect {
        realizing.configure_connected(final_peer, configure)?
    } else {
        realizing.configure(|sock| {
            configure(sock)?;
            let actual_local = inspect_inet_local_addr(sock, "upstream setup")?;
            Ok(RealizationRequirements::unconnected(actual_local))
        })?
    };
    let verified = configured.verify(policy)?;
    let managed = verified.into_managed().map_err(io::Error::other)?;
    if let Some((socket_slot, generation, unpublished_replacement)) = authority_identity {
        managed
            .bind_authority_identity(
                SocketRole::Upstream,
                socket_slot,
                generation,
                unpublished_replacement,
            )
            .map_err(io::Error::other)?;
    }
    let actual_local_sa = managed
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("No socket resolved from getsockname"))?;

    if !should_connect && actual_local_sa.ip().is_unspecified() {
        return Err(io::Error::other(
            "unconnected upstream socket must have a concrete local IP address for packet admission filtering",
        ));
    }

    let identity = resolve_upstream_endpoint_identity(
        dest.to_socket_addr(),
        planned_local_id,
        planned_remote_id,
        actual_local_sa,
        policy,
    );
    Ok(RealizedUpstreamSocket {
        socket: managed,
        local_filter: identity.local.logical_filter,
        remote_filter: identity.remote_filter,
        local_kernel_addr: identity.local.kernel_addr,
        socket_type: sock_type,
        policy,
    })
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

#[cfg(all(test, not(miri)))]
mod tests;
