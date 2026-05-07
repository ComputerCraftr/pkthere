use crate::cli::{SupportedProtocol, TimeoutAction};
use crate::flow_key::ClientFlowKey;
use crate::net::params::CanonicalAddr;
use crate::net::socket::{
    disconnect_socket, family_changed, make_socket, make_upstream_socket_for, resolve_first,
};
use crate::net::socket_policy::SocketReuseCapability;
use socket2::{SockAddr, Socket, Type};

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};

/// Snapshot of sockets and destination used by worker threads.
pub(crate) struct SocketHandles {
    pub locked_flow: Option<ClientFlowKey>,
    pub client_remote: Option<CanonicalAddr>,
    pub listener_connected: bool,
    pub client_sock: Socket,
    pub listen_sock_type: Type,
    pub upstream_remote_filter: CanonicalAddr,
    pub upstream_local_filter: CanonicalAddr,
    pub upstream_sock_type: Type,
    pub upstream_connected: bool,
    pub upstream_sock: Socket,
    pub version: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct SocketStateSnapshot {
    pub locked_flow: Option<ClientFlowKey>,
    pub client_remote: Option<CanonicalAddr>,
    pub listener_connected: bool,
    pub client_proto: SupportedProtocol,
    pub listen_local_filter: CanonicalAddr,
    pub listen_local_kernel: CanonicalAddr,
    pub listen_sock_type: Type,
    pub listen_capability: SocketReuseCapability,
    pub upstream_remote_filter: CanonicalAddr,
    pub upstream_local_filter: CanonicalAddr,
    pub upstream_local_kernel: CanonicalAddr,
    pub upstream_connected: bool,
    pub upstream_proto: SupportedProtocol,
    pub upstream_sock_type: Type,
    pub upstream_capability: SocketReuseCapability,
}

struct ClientListenState {
    listen_local_filter: CanonicalAddr,
    listen_local_kernel: CanonicalAddr,
    flow: Option<ClientFlowKey>,
    client_remote: Option<CanonicalAddr>,
    listener_connected: bool,
    sock: Socket,
    sock_type: Type,
    capability: SocketReuseCapability,
}

struct UpstreamState {
    upstream_remote_filter: CanonicalAddr,
    upstream_local_filter: CanonicalAddr,
    upstream_local_kernel: CanonicalAddr,
    upstream_connected: bool,
    sock: Socket,
    sock_type: Type,
    capability: SocketReuseCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReresolveAction {
    NoChange,
    UpdateMetadataOnly,
    ReconnectInPlace,
    ReplaceSocket,
}

#[inline]
fn decide_listener_reresolve(
    prev: CanonicalAddr,
    resolved: SocketAddr,
) -> (CanonicalAddr, ReresolveAction) {
    let fresh = prev.with_resolved_ip(resolved);
    if fresh.addr.ip() == prev.addr.ip() {
        (prev, ReresolveAction::NoChange)
    } else {
        (fresh, ReresolveAction::ReplaceSocket)
    }
}

#[inline]
fn decide_upstream_reresolve(
    prev: CanonicalAddr,
    resolved: SocketAddr,
    upstream_connected: bool,
    capability: SocketReuseCapability,
) -> (CanonicalAddr, ReresolveAction) {
    let fresh = prev.with_resolved_ip(resolved);
    if fresh.addr.ip() == prev.addr.ip() {
        return (prev, ReresolveAction::NoChange);
    }
    if family_changed(prev.addr, fresh.addr) {
        return (fresh, ReresolveAction::ReplaceSocket);
    }

    if !upstream_connected {
        if matches!(
            capability.reresolve_mode,
            crate::net::socket_policy::SocketReresolveMode::MetadataOnlyWhenUnconnected
        ) {
            (fresh, ReresolveAction::UpdateMetadataOnly)
        } else {
            (fresh, ReresolveAction::ReplaceSocket)
        }
    } else if capability.reconnects_in_place() {
        (fresh, ReresolveAction::ReconnectInPlace)
    } else {
        (fresh, ReresolveAction::ReplaceSocket)
    }
}

/// Manages both listener and upstream sockets and publishes versioned updates.
///
/// **STRICT LOCK ORDER**:
/// 1. `client_listen`
/// 2. `upstream`
pub(crate) struct SocketManager {
    client_listen: Mutex<ClientListenState>, // cold-path updates only
    listen_target: String,                   // unresolved --here host:port
    listen_proto: SupportedProtocol,         // never changes
    listen_debug_unconnected: bool,
    upstream_state: Mutex<UpstreamState>, // cold-path updates only
    upstream_target: String,              // unresolved --there host:port
    upstream_local_id: u16,
    upstream_proto: SupportedProtocol, // never changes
    upstream_debug_unconnected: bool,
    debug_handles: bool,
    timeout_action: TimeoutAction, // never changes
    version: AtomicU64,            // increments on any change
}

impl SocketManager {
    pub fn new(
        client_sock: Socket,
        listen_local_filter: CanonicalAddr,
        listen_local_kernel: CanonicalAddr,
        listen_sock_type: Type,
        listen_target: String,
        listen_proto: SupportedProtocol,
        listen_capability: SocketReuseCapability,
        listen_debug_unconnected: bool,
        upstream_remote_filter: CanonicalAddr,
        upstream_target: String,
        upstream_local_id: u16,
        upstream_proto: SupportedProtocol,
        upstream_debug_unconnected: bool,
        timeout_act: TimeoutAction,
        debug_handles: bool,
    ) -> io::Result<Self> {
        let (
            sock,
            upstream_local,
            upstream_remote,
            upstream_local_kernel,
            upstream_sock_type,
            upstream_capability,
        ) = make_upstream_socket_for(
            upstream_remote_filter,
            upstream_proto,
            upstream_local_id,
            upstream_local_id == 0,
            timeout_act,
            upstream_debug_unconnected,
            debug_handles,
        )?;
        Ok(Self {
            client_listen: Mutex::new(ClientListenState {
                listen_local_filter,
                listen_local_kernel,
                flow: None,
                client_remote: None,
                listener_connected: listen_capability.starts_connected(),
                sock: client_sock,
                sock_type: listen_sock_type,
                capability: listen_capability,
            }),
            listen_target,
            listen_proto,
            listen_debug_unconnected,
            upstream_state: Mutex::new(UpstreamState {
                upstream_remote_filter: upstream_remote,
                upstream_local_filter: upstream_local,
                upstream_local_kernel,
                upstream_connected: upstream_capability.starts_connected(),
                sock,
                sock_type: upstream_sock_type,
                capability: upstream_capability,
            }),
            upstream_target,
            upstream_local_id,
            upstream_proto,
            upstream_debug_unconnected,
            debug_handles,
            timeout_action: timeout_act,
            version: AtomicU64::new(0),
        })
    }

    /// Current version for lock-free checks in hot paths.
    #[inline]
    pub fn get_version(&self) -> u64 {
        self.version.load(AtomOrdering::Relaxed)
    }

    /// Bump and return the version when `changed` is true; otherwise, return the current version.
    #[inline]
    fn publish_version(&self, changed: bool) -> u64 {
        if changed {
            self.version.fetch_add(1, AtomOrdering::Relaxed) + 1
        } else {
            self.version.load(AtomOrdering::Relaxed)
        }
    }

    /// Whether the listener socket is currently connected to a client.
    #[inline]
    pub fn get_listener_connected(&self) -> bool {
        self.client_listen.lock().unwrap().listener_connected
    }

    /// Update the locked client address/connected state and publish a new version.
    ///
    /// Returns `prev_ver + 1` so callers with a stale cached version stay stale
    /// and will refresh on the next hot-path check, even if other updates raced
    /// and advanced the global version further.
    #[inline]
    pub fn set_listener_remote_connected(
        &self,
        flow: Option<ClientFlowKey>,
        client_remote: Option<CanonicalAddr>,
        listener_connected: bool,
        prev_ver: u64,
    ) -> u64 {
        let mut cl_guard = self.client_listen.lock().unwrap();
        cl_guard.flow = flow;
        cl_guard.client_remote = client_remote;
        cl_guard.listener_connected = listener_connected;
        self.publish_version(true);
        prev_ver + 1
    }

    /// Update the locked client address and connect the listener socket.
    #[inline]
    pub fn set_client_sock_connected(
        &self,
        flow: Option<ClientFlowKey>,
        client_remote: Option<CanonicalAddr>,
        listener_connected: bool,
        client_sa: &SockAddr,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let mut cl_guard = self.client_listen.lock().unwrap();
        cl_guard.flow = flow;
        cl_guard.client_remote = client_remote;
        cl_guard.listener_connected = listener_connected;
        self.publish_version(true);
        if listener_connected {
            cl_guard.sock.connect(client_sa)?;
        }
        Ok(prev_ver + 1)
    }

    /// Update the locked client address and disconnect the listener socket.
    #[inline]
    pub fn set_client_sock_disconnected(
        &self,
        flow: Option<ClientFlowKey>,
        client_remote: Option<CanonicalAddr>,
        listener_connected: bool,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let mut cl_guard = self.client_listen.lock().unwrap();
        cl_guard.flow = flow;
        cl_guard.client_remote = client_remote;
        cl_guard.listener_connected = listener_connected;
        self.publish_version(true);
        if !listener_connected {
            // Use a clone because the original may not be marked as connected.
            disconnect_socket(&cl_guard.sock.try_clone()?)?;
        }
        Ok(prev_ver + 1)
    }

    #[inline]
    pub fn clear_client_lock(&self, prev_ver: u64) -> io::Result<u64> {
        if self.get_listener_connected() {
            self.set_client_sock_disconnected(None, None, false, prev_ver)
        } else {
            Ok(self.set_listener_remote_connected(None, None, false, prev_ver))
        }
    }

    /// Current listener local filter address.
    #[inline]
    pub fn get_listen_addr(&self) -> CanonicalAddr {
        self.client_listen.lock().unwrap().listen_local_filter
    }

    /// Snapshot the current client destination/connected state and protocol.
    #[inline]
    pub fn get_client_dest(&self) -> (Option<ClientFlowKey>, bool, SupportedProtocol) {
        let cl = self.client_listen.lock().unwrap();
        (cl.flow, cl.listener_connected, self.listen_proto)
    }

    /// Snapshot the current upstream destination and protocol.
    #[inline]
    pub fn get_upstream_dest(&self) -> (CanonicalAddr, bool, SupportedProtocol) {
        let up = self.upstream_state.lock().unwrap();
        (
            up.upstream_remote_filter,
            up.upstream_connected,
            self.upstream_proto,
        )
    }

    #[inline]
    pub fn snapshot_state(&self) -> SocketStateSnapshot {
        let cl = self.client_listen.lock().unwrap();
        let up = self.upstream_state.lock().unwrap();
        SocketStateSnapshot {
            locked_flow: cl.flow,
            client_remote: cl.client_remote,
            listener_connected: cl.listener_connected,
            client_proto: self.listen_proto,
            listen_local_filter: cl.listen_local_filter,
            listen_local_kernel: cl.listen_local_kernel,
            listen_sock_type: cl.sock_type,
            listen_capability: cl.capability,
            upstream_remote_filter: up.upstream_remote_filter,
            upstream_local_filter: up.upstream_local_filter,
            upstream_local_kernel: up.upstream_local_kernel,
            upstream_connected: up.upstream_connected,
            upstream_proto: self.upstream_proto,
            upstream_sock_type: up.sock_type,
            upstream_capability: up.capability,
        }
    }

    fn reresolve_upstream(
        &self,
        context: &str,
    ) -> io::Result<(
        Socket,
        CanonicalAddr,
        CanonicalAddr,
        CanonicalAddr,
        Type,
        SocketReuseCapability,
        bool,
    )> {
        let resolved = resolve_first(&self.upstream_target)?;
        let mut up_guard = self.upstream_state.lock().unwrap();
        let prev_addr = up_guard.upstream_remote_filter;
        let prev_local = up_guard.upstream_local_filter;
        let prev_local_kernel = up_guard.upstream_local_kernel;
        let prev_connected = up_guard.upstream_connected;
        let prev_sock_type = up_guard.sock_type;
        let prev_capability = up_guard.capability;
        let (fresh, action) =
            decide_upstream_reresolve(prev_addr, resolved, prev_connected, prev_capability);

        let changed = action != ReresolveAction::NoChange;
        let fam_flip = changed && family_changed(prev_addr.addr, fresh.addr);

        match action {
            ReresolveAction::NoChange => Ok((
                up_guard.sock.try_clone()?,
                prev_addr,
                prev_local,
                prev_local_kernel,
                prev_sock_type,
                prev_capability,
                false,
            )),
            ReresolveAction::UpdateMetadataOnly => {
                log_info!(
                    "{context}: upstream {} (IP changed; metadata updated)",
                    fresh
                );
                up_guard.upstream_remote_filter = fresh;
                Ok((
                    up_guard.sock.try_clone()?,
                    up_guard.upstream_remote_filter,
                    up_guard.upstream_local_filter,
                    up_guard.upstream_local_kernel,
                    up_guard.sock_type,
                    up_guard.capability,
                    true,
                ))
            }
            ReresolveAction::ReconnectInPlace => {
                log_info!(
                    "{context}: upstream {} (IP changed; upstream socket reconnected)",
                    fresh
                );
                if let Err(reconnect_err) = disconnect_socket(&up_guard.sock)
                    .and_then(|_| up_guard.sock.connect(&fresh.as_sock_addr()))
                {
                    log_info!(
                        "{context}: upstream {} reconnect failed ({}); replacing socket",
                        fresh,
                        reconnect_err
                    );
                    let (
                        new_sock,
                        upstream_local_filter,
                        upstream_remote_filter,
                        upstream_local_kernel,
                        new_type,
                        new_capability,
                    ) = make_upstream_socket_for(
                        fresh,
                        self.upstream_proto,
                        self.upstream_local_id,
                        self.upstream_local_id == 0,
                        self.timeout_action,
                        self.upstream_debug_unconnected,
                        self.debug_handles,
                    )?;
                    up_guard.upstream_local_filter = upstream_local_filter;
                    up_guard.upstream_local_kernel = upstream_local_kernel;
                    up_guard.upstream_remote_filter = upstream_remote_filter;
                    up_guard.upstream_connected = new_capability.starts_connected();
                    up_guard.sock = new_sock.try_clone()?;
                    up_guard.sock_type = new_type;
                    return Ok((
                        new_sock,
                        upstream_remote_filter,
                        upstream_local_filter,
                        upstream_local_kernel,
                        new_type,
                        new_capability,
                        true,
                    ));
                }

                up_guard.upstream_remote_filter = fresh;
                up_guard.upstream_connected = true;
                Ok((
                    up_guard.sock.try_clone()?,
                    up_guard.upstream_remote_filter,
                    up_guard.upstream_local_filter,
                    up_guard.upstream_local_kernel,
                    up_guard.sock_type,
                    up_guard.capability,
                    true,
                ))
            }
            ReresolveAction::ReplaceSocket => {
                log_info!(
                    "{context}: upstream {} ({}IP changed; upstream socket swapped)",
                    fresh,
                    if fam_flip { "family and " } else { "" }
                );
                let (
                    new_sock,
                    upstream_local_filter,
                    upstream_remote_filter,
                    upstream_local_kernel,
                    new_type,
                    new_capability,
                ) = make_upstream_socket_for(
                    fresh,
                    self.upstream_proto,
                    self.upstream_local_id,
                    self.upstream_local_id == 0,
                    self.timeout_action,
                    self.upstream_debug_unconnected,
                    self.debug_handles,
                )?;

                up_guard.upstream_local_filter = upstream_local_filter;
                up_guard.upstream_local_kernel = upstream_local_kernel;
                up_guard.upstream_remote_filter = upstream_remote_filter;
                up_guard.upstream_connected = new_capability.starts_connected();
                up_guard.sock = new_sock.try_clone()?;
                up_guard.sock_type = new_type;
                Ok((
                    new_sock,
                    upstream_remote_filter,
                    upstream_local_filter,
                    upstream_local_kernel,
                    new_type,
                    new_capability,
                    true,
                ))
            }
        }
    }

    fn reresolve_listen(
        &self,
        context: &str,
    ) -> io::Result<(
        Socket,
        Option<ClientFlowKey>,
        Option<CanonicalAddr>,
        CanonicalAddr,
        Type,
        SocketReuseCapability,
        bool,
    )> {
        let resolved = resolve_first(&self.listen_target)?;

        let mut cl_guard = self.client_listen.lock().unwrap();
        let prev_listen = cl_guard.listen_local_filter;
        let (fresh, action) = decide_listener_reresolve(prev_listen, resolved);

        match action {
            ReresolveAction::NoChange => Ok((
                cl_guard.sock.try_clone()?,
                cl_guard.flow,
                cl_guard.client_remote,
                cl_guard.listen_local_kernel,
                cl_guard.sock_type,
                cl_guard.capability,
                false,
            )),
            ReresolveAction::ReplaceSocket => {
                log_info!("{context}: listen {} (listener swapped)", fresh);
                let (new_sock, local_canonical, listen_local_kernel, new_type, new_capability) =
                    make_socket(
                        fresh.addr,
                        self.listen_proto,
                        1000,
                        true,
                        self.timeout_action,
                        self.listen_debug_unconnected,
                    )?;

                cl_guard.listen_local_filter = local_canonical;
                cl_guard.listen_local_kernel = listen_local_kernel;
                cl_guard.flow = None;
                cl_guard.client_remote = None;
                cl_guard.listener_connected = new_capability.starts_connected();
                cl_guard.sock = new_sock.try_clone()?;
                cl_guard.sock_type = new_type;
                cl_guard.capability = new_capability;
                Ok((
                    new_sock,
                    None,
                    None,
                    listen_local_kernel,
                    new_type,
                    new_capability,
                    true,
                ))
            }
            _ => unreachable!("listener re-resolve only supports no-op or replacement"),
        }
    }

    /// Re-resolve both ends and publish any changes. When `allow_listen_rebind`
    /// is true, the listening socket may be swapped if the --here DNS changes.
    /// Returns handles and a flag indicating whether the listener changed.
    pub fn reresolve(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
    ) -> io::Result<SocketHandles> {
        if !allow_upstream && !allow_listen_rebind {
            return Ok(self.refresh_handles());
        }

        let (
            client_sock,
            client_flow,
            client_remote,
            _listen_local_kernel,
            listen_sock_type,
            listener_connected,
            _listen_capability,
            listen_changed,
        ) = if allow_listen_rebind {
            let res = self.reresolve_listen(context)?;
            (
                res.0,
                res.1,
                res.2,
                res.3,
                res.4,
                res.5.starts_connected(),
                res.5,
                res.6,
            )
        } else {
            let cl = self.client_listen.lock().unwrap();
            (
                cl.sock.try_clone()?,
                cl.flow,
                cl.client_remote,
                cl.listen_local_kernel,
                cl.sock_type,
                cl.listener_connected,
                cl.capability,
                false,
            )
        };

        let (
            upstream_sock,
            upstream_remote_filter,
            upstream_local_filter,
            _upstream_local_kernel,
            upstream_sock_type,
            upstream_connected,
            _upstream_capability,
            upstream_changed,
        ) = if allow_upstream {
            let res = self.reresolve_upstream(context)?;
            (
                res.0,
                res.1,
                res.2,
                res.3,
                res.4,
                res.5.starts_connected(),
                res.5,
                res.6,
            )
        } else {
            let up = self.upstream_state.lock().unwrap();
            (
                up.sock.try_clone()?,
                up.upstream_remote_filter,
                up.upstream_local_filter,
                up.upstream_local_kernel,
                up.sock_type,
                up.upstream_connected,
                up.capability,
                false,
            )
        };

        let changed_any = listen_changed || upstream_changed;
        let version = self.publish_version(changed_any);

        Ok(SocketHandles {
            locked_flow: client_flow,
            client_remote,
            listener_connected,
            client_sock,
            listen_sock_type,
            upstream_remote_filter,
            upstream_local_filter,
            upstream_sock_type,
            upstream_connected,
            upstream_sock,
            version,
        })
    }

    /// Clone sockets and destination (cold path under mutexes).
    /// Use this only when your cached version != `version()`.
    #[inline]
    pub fn refresh_handles(&self) -> SocketHandles {
        // Snapshot all mutable state while holding the relevant locks so the
        // returned version matches the handles we hand back.
        let cl = self.client_listen.lock().unwrap();
        let up = self.upstream_state.lock().unwrap();

        SocketHandles {
            locked_flow: cl.flow,
            client_remote: cl.client_remote,
            listener_connected: cl.listener_connected,
            client_sock: cl.sock.try_clone().expect("clone client socket"),
            listen_sock_type: cl.sock_type,
            upstream_remote_filter: up.upstream_remote_filter,
            upstream_local_filter: up.upstream_local_filter,
            upstream_sock_type: up.sock_type,
            upstream_connected: up.upstream_connected,
            upstream_sock: up.sock.try_clone().expect("clone upstream socket"),
            version: self.get_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TimeoutAction::Drop;
    use crate::net::socket_policy::{SocketRole, socket_reuse_capability};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::thread;

    fn make_mgr() -> SocketManager {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (client_sock, actual_listen, listen_local_kernel, listen_sock_type, listen_capability) =
            make_socket(
                listen_addr,
                SupportedProtocol::UDP,
                1000,
                false,
                Drop,
                false,
            )
            .expect("create client sock");

        let upstream_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind upstream udp");
        let upstream_addr = upstream_sock.local_addr().expect("upstream udp addr");

        SocketManager::new(
            client_sock,
            actual_listen,
            listen_local_kernel,
            listen_sock_type,
            actual_listen.addr.to_string(),
            SupportedProtocol::UDP,
            listen_capability,
            false,
            CanonicalAddr::from_socket_addr(upstream_addr),
            upstream_addr.to_string(),
            0,
            SupportedProtocol::UDP,
            false,
            Drop,
            false,
        )
        .expect("create socket manager")
    }

    #[test]
    fn client_setter_keeps_callers_stale() {
        let mgr = Arc::new(make_mgr());
        let v0 = mgr.get_version();

        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11111);
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22222);

        let a = {
            let mgr = Arc::clone(&mgr);
            thread::spawn(move || {
                mgr.set_listener_remote_connected(
                    Some(ClientFlowKey::Udp(addr_a)),
                    Some(CanonicalAddr::from_socket_addr(addr_a)),
                    true,
                    v0,
                )
            })
        };
        let b = {
            let mgr = Arc::clone(&mgr);
            thread::spawn(move || {
                mgr.set_listener_remote_connected(
                    Some(ClientFlowKey::Udp(addr_b)),
                    Some(CanonicalAddr::from_socket_addr(addr_b)),
                    false,
                    v0,
                )
            })
        };

        let ra = a.join().unwrap();
        let rb = b.join().unwrap();

        assert_eq!(ra, v0 + 1);
        assert_eq!(rb, v0 + 1);
        assert_eq!(mgr.get_version(), v0 + 2);
    }

    #[test]
    fn refresh_notices_raced_updates() {
        let mgr = make_mgr();
        let mut cached = mgr.refresh_handles();
        let v0 = cached.version;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
        let canonical = CanonicalAddr::from_socket_addr(addr);
        let _ = mgr.set_listener_remote_connected(
            Some(ClientFlowKey::Udp(addr)),
            Some(canonical),
            true,
            v0,
        );
        let _ = mgr.set_listener_remote_connected(
            Some(ClientFlowKey::Udp(addr)),
            Some(canonical),
            false,
            v0,
        );

        assert_ne!(cached.version, mgr.get_version());
        cached = mgr.refresh_handles();
        assert_eq!(cached.version, mgr.get_version());
        assert_eq!(cached.locked_flow, Some(ClientFlowKey::Udp(addr)));
        assert!(!cached.listener_connected);
    }

    #[test]
    fn listener_reresolve_uses_canonical_refresh_rules() {
        let prev = CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777), 8888);
        let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 1234);
        let (fresh, action) = decide_listener_reresolve(prev, resolved);

        assert_eq!(action, ReresolveAction::ReplaceSocket);
        assert_eq!(fresh.id, 8888);
        assert_eq!(fresh.addr.port(), 8888);
        assert_eq!(fresh.addr.ip(), resolved.ip());
    }

    #[test]
    fn snapshot_preserves_role_specific_identity_names() {
        let mgr = make_mgr();
        let snapshot = mgr.snapshot_state();

        assert_eq!(snapshot.client_remote, None);
        assert_eq!(snapshot.listen_local_filter, mgr.get_listen_addr());
        assert_eq!(snapshot.upstream_remote_filter, mgr.get_upstream_dest().0);
        assert_eq!(
            snapshot.listener_connected,
            snapshot.listen_capability.starts_connected()
        );
        assert_eq!(
            snapshot.upstream_connected,
            snapshot.upstream_capability.starts_connected()
        );
    }

    #[test]
    fn upstream_same_family_connected_prefers_reconnect_when_policy_allows() {
        let prev = CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444), 5555);
        let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9999);
        let capability = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            Drop,
            false,
        );
        let (fresh, action) = decide_upstream_reresolve(prev, resolved, true, capability);

        assert_eq!(fresh.id, 5555);
        assert_eq!(fresh.addr.port(), 5555);
        assert_eq!(fresh.addr.ip(), resolved.ip());
        assert_eq!(action, ReresolveAction::ReconnectInPlace);
    }

    #[test]
    fn upstream_raw_same_family_change_falls_back_to_replace() {
        let prev = CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444), 5555);
        let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9999);
        let capability = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            Type::RAW,
            Drop,
            false,
        );
        let (_, action) = decide_upstream_reresolve(prev, resolved, true, capability);

        assert_eq!(action, ReresolveAction::ReplaceSocket);
    }

    #[test]
    fn upstream_unconnected_same_family_change_only_updates_metadata() {
        let prev = CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444), 5555);
        let resolved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9999);
        let capability = socket_reuse_capability(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            Drop,
            true,
        );
        let (_, action) = decide_upstream_reresolve(prev, resolved, false, capability);

        assert_eq!(action, ReresolveAction::UpdateMetadataOnly);
    }
}
