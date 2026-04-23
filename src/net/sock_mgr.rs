use crate::cli::SupportedProtocol;
use crate::flow_key::ClientFlowKey;
use crate::net::icmp_support::{choose_effective_local_icmp_id, listener_requires_raw_icmp};
use crate::net::params::{CanonicalAddr, IcmpHeaderIdSource};
use crate::net::socket::{
    disconnect_socket, family_changed, make_socket, make_upstream_socket_for, resolve_first,
};
use socket2::{SockAddr, Socket, Type};

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};

/// Snapshot of sockets and destination used by worker threads.
pub struct SocketHandles {
    pub locked_flow: Option<ClientFlowKey>,
    pub client_peer: Option<CanonicalAddr>,
    pub client_connected: bool,
    pub client_sock: Socket,
    pub listen: CanonicalAddr,
    pub listen_sock_type: Type,
    pub listen_icmp_header_source: IcmpHeaderIdSource,
    pub upstream: CanonicalAddr,
    pub upstream_local: CanonicalAddr,
    pub upstream_sock_type: Type,
    pub upstream_icmp_header_source: IcmpHeaderIdSource,
    pub upstream_connected: bool,
    pub upstream_sock: Socket,
    pub version: u64,
}

#[derive(Clone, Copy)]
pub struct SocketStateSnapshot {
    pub locked_flow: Option<ClientFlowKey>,
    pub client_peer: Option<CanonicalAddr>,
    pub client_connected: bool,
    pub client_proto: SupportedProtocol,
    pub listen: CanonicalAddr,
    pub listen_sock_type: Type,
    pub upstream: CanonicalAddr,
    pub upstream_local: CanonicalAddr,
    pub upstream_connected: bool,
    pub upstream_proto: SupportedProtocol,
    pub upstream_sock_type: Type,
}

#[derive(Clone, Copy)]
struct ClientState {
    flow: Option<ClientFlowKey>,
    peer: Option<CanonicalAddr>,
    connected: bool,
}

#[derive(Clone, Copy)]
struct UpstreamState {
    remote: CanonicalAddr,
    local: CanonicalAddr,
    connected: bool,
}

/// Manages both local and upstream sockets and publishes versioned updates.
///
/// **STRICT LOCK ORDER**:
/// 1. `listen`
/// 2. `client_addr_connected`
/// 3. `client_sock`
/// 4. `upstream_addr_connected`
/// 5. `upstream_sock`
/// 6. `upstream_sock_type`
pub struct SocketManager {
    client_addr_connected: Mutex<ClientState>, // cold-path updates only
    client_sock: Mutex<Socket>,                // shared listener socket
    listen: Mutex<CanonicalAddr>,              // current bound address + effective ID
    listen_sock_type: Type,
    listen_request: CanonicalAddr, // requested bind address + requested id
    listen_target: String,         // unresolved --here host:port
    listen_proto: SupportedProtocol, // never changes
    upstream_target: String,       // unresolved --there host:port
    upstream_request: CanonicalAddr,
    upstream_addr_connected: Mutex<UpstreamState>, // cold-path updates only
    upstream_proto: SupportedProtocol,             // never changes
    upstream_sock: Mutex<Socket>,                  // cold-path replacement only
    upstream_sock_type: Mutex<Type>,
    version: AtomicU64, // increments on any change
}

impl SocketManager {
    #[inline]
    fn icmp_header_source(proto: SupportedProtocol, sock_type: Type) -> IcmpHeaderIdSource {
        match proto {
            SupportedProtocol::UDP => IcmpHeaderIdSource::None,
            SupportedProtocol::ICMP if sock_type == Type::DGRAM => IcmpHeaderIdSource::Local,
            SupportedProtocol::ICMP => IcmpHeaderIdSource::Remote,
        }
    }

    pub fn new(
        client_sock: Socket,
        listen: CanonicalAddr,
        listen_sock_type: Type,
        listen_target: String,
        listen_proto: SupportedProtocol,
        upstream: CanonicalAddr,
        upstream_target: String,
        upstream_proto: SupportedProtocol,
    ) -> io::Result<Self> {
        let (sock, upstream_remote, upstream_local, upstream_sock_type) =
            make_upstream_socket_for(upstream, upstream_proto, upstream.id)?;
        Ok(Self {
            client_addr_connected: Mutex::new(ClientState {
                flow: None,
                peer: None,
                connected: false,
            }),
            client_sock: Mutex::new(client_sock),
            listen: Mutex::new(listen),
            listen_sock_type,
            listen_request: listen,
            listen_target,
            listen_proto,
            upstream_target,
            upstream_request: upstream,
            upstream_addr_connected: Mutex::new(UpstreamState {
                remote: upstream_remote,
                local: upstream_local,
                connected: true,
            }),
            upstream_proto,
            upstream_sock: Mutex::new(sock),
            upstream_sock_type: Mutex::new(upstream_sock_type),
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
    pub fn get_client_connected(&self) -> bool {
        self.client_addr_connected.lock().unwrap().connected
    }

    /// Update the locked client address/connected state and publish a new version.
    ///
    /// Returns `prev_ver + 1` so callers with a stale cached version stay stale
    /// and will refresh on the next hot-path check, even if other updates raced
    /// and advanced the global version further.
    #[inline]
    pub fn set_client_addr_connected(
        &self,
        flow: Option<ClientFlowKey>,
        peer: Option<CanonicalAddr>,
        connected: bool,
        prev_ver: u64,
    ) -> u64 {
        *self.client_addr_connected.lock().unwrap() = ClientState {
            flow,
            peer,
            connected,
        };
        self.publish_version(true);
        prev_ver + 1
    }

    /// Update the locked client address and connect the local listener socket.
    #[inline]
    pub fn set_client_sock_connected(
        &self,
        flow: Option<ClientFlowKey>,
        peer: Option<CanonicalAddr>,
        connected: bool,
        client_sa: &SockAddr,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let mut client_guard = self.client_addr_connected.lock().unwrap();
        let client_sock_guard = self.client_sock.lock().unwrap();
        *client_guard = ClientState {
            flow,
            peer,
            connected,
        };
        self.publish_version(true);
        if connected {
            client_sock_guard.connect(client_sa)?;
        }
        Ok(prev_ver + 1)
    }

    /// Update the locked client address and disconnect the local listener socket.
    #[inline]
    pub fn set_client_sock_disconnected(
        &self,
        flow: Option<ClientFlowKey>,
        peer: Option<CanonicalAddr>,
        connected: bool,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let mut client_guard = self.client_addr_connected.lock().unwrap();
        let client_sock_guard = self.client_sock.lock().unwrap();
        *client_guard = ClientState {
            flow,
            peer,
            connected,
        };
        self.publish_version(true);
        if !connected {
            // Use a clone because the original may not be marked as connected
            disconnect_socket(&client_sock_guard.try_clone()?)?;
        }
        Ok(prev_ver + 1)
    }

    #[inline]
    pub fn clear_client_lock(&self, prev_ver: u64) -> io::Result<u64> {
        if self.get_client_connected() {
            self.set_client_sock_disconnected(None, None, false, prev_ver)
        } else {
            Ok(self.set_client_addr_connected(None, None, false, prev_ver))
        }
    }

    /// Current listen bind address.
    #[inline]
    pub fn get_listen_addr(&self) -> CanonicalAddr {
        *self.listen.lock().unwrap()
    }

    /// Snapshot the current client destination/connected state and protocol.
    #[inline]
    pub fn get_client_dest(&self) -> (Option<ClientFlowKey>, bool, SupportedProtocol) {
        let state = *self.client_addr_connected.lock().unwrap();
        (state.flow, state.connected, self.listen_proto)
    }

    /// Snapshot the current upstream destination and protocol.
    #[inline]
    pub fn get_upstream_dest(&self) -> (CanonicalAddr, bool, SupportedProtocol) {
        let state = *self.upstream_addr_connected.lock().unwrap();
        (state.remote, state.connected, self.upstream_proto)
    }

    #[inline]
    pub fn snapshot_state(&self) -> SocketStateSnapshot {
        let listen_guard = self.listen.lock().unwrap();
        let client_guard = self.client_addr_connected.lock().unwrap();
        let upstream_guard = self.upstream_addr_connected.lock().unwrap();
        let upstream_sock_type = *self.upstream_sock_type.lock().unwrap();
        SocketStateSnapshot {
            locked_flow: client_guard.flow,
            client_peer: client_guard.peer,
            client_connected: client_guard.connected,
            client_proto: self.listen_proto,
            listen: *listen_guard,
            listen_sock_type: self.listen_sock_type,
            upstream: upstream_guard.remote,
            upstream_local: upstream_guard.local,
            upstream_connected: upstream_guard.connected,
            upstream_proto: self.upstream_proto,
            upstream_sock_type,
        }
    }

    fn reresolve_upstream(
        &self,
        context: &str,
    ) -> io::Result<(Socket, CanonicalAddr, CanonicalAddr, Type, bool)> {
        let fresh = CanonicalAddr::new(
            resolve_first(&self.upstream_target)?,
            self.upstream_request.id,
        );

        // Compare against previous before updating to compute correct family flip
        let mut upstream_guard = self.upstream_addr_connected.lock().unwrap();
        let (fam_flip, changed) = {
            let prev_addr = upstream_guard.remote;
            let changed = prev_addr != fresh;
            let fam_flip = if changed {
                upstream_guard.remote = fresh;
                family_changed(prev_addr.addr, fresh.addr)
            } else {
                false
            };
            (fam_flip, changed)
        };

        // Prepare a socket to return while also updating the internal socket state.
        let (ret_sock, eff_remote, eff_local, eff_type) = if fam_flip {
            log_info!("{context}: upstream {fresh} (family changed; upstream socket swapped)");
            // Family changed: create a new **connected** upstream socket and swap it in.
            let (new_sock, remote, local, new_type) =
                make_upstream_socket_for(fresh, self.upstream_proto, self.upstream_request.id)?;
            upstream_guard.local = local;
            upstream_guard.remote = remote;
            upstream_guard.connected = true;
            *self.upstream_sock.lock().unwrap() = new_sock.try_clone()?;
            *self.upstream_sock_type.lock().unwrap() = new_type;
            (new_sock, remote, local, new_type)
        } else if changed {
            log_info!("{context}: upstream {fresh}");
            let (new_sock, remote, local, new_type) =
                make_upstream_socket_for(fresh, self.upstream_proto, self.upstream_request.id)?;
            upstream_guard.local = local;
            upstream_guard.remote = remote;
            upstream_guard.connected = true;
            *self.upstream_sock.lock().unwrap() = new_sock.try_clone()?;
            *self.upstream_sock_type.lock().unwrap() = new_type;
            (new_sock, remote, local, new_type)
        } else {
            // No change: just return a clone of the current socket
            let s = self.upstream_sock.lock().unwrap().try_clone()?;
            let t = *self.upstream_sock_type.lock().unwrap();
            (s, upstream_guard.remote, upstream_guard.local, t)
        };

        Ok((
            ret_sock,
            eff_remote,
            eff_local,
            eff_type,
            fam_flip || changed,
        ))
    }

    fn reresolve_listen(
        &self,
        context: &str,
    ) -> io::Result<(
        Socket,
        Option<ClientFlowKey>,
        Option<CanonicalAddr>,
        bool,
        CanonicalAddr,
        u16,
        bool,
    )> {
        let fresh = resolve_first(&self.listen_target)?;

        let mut listen_guard = self.listen.lock().unwrap();
        let (fam_flip, changed) = {
            let prev_addr = listen_guard.addr;
            let changed = prev_addr.ip() != fresh.ip();
            let fam_flip = if changed {
                listen_guard.addr = fresh;
                family_changed(prev_addr, fresh)
            } else {
                false
            };
            (fam_flip, changed)
        };

        let (ret_sock, cflow, cpeer, cconn, laddr, eff_id) = if fam_flip || changed {
            log_info!("{context}: listen {fresh} (listener swapped)");
            let (new_sock, mut local_canonical, _new_type) = make_socket(
                fresh,
                self.listen_proto,
                1000,
                true,
                self.listen_proto == SupportedProtocol::ICMP && listener_requires_raw_icmp(),
            )?;

            let effective_listen_id = if self.listen_proto == SupportedProtocol::ICMP {
                choose_effective_local_icmp_id(self.listen_request.id, local_canonical.id, false).0
            } else {
                local_canonical.id
            };

            // Update the internal socket state
            let mut client_guard = self.client_addr_connected.lock().unwrap();
            let mut client_sock_guard = self.client_sock.lock().unwrap();
            local_canonical.id = effective_listen_id;
            *listen_guard = local_canonical;
            *client_guard = ClientState {
                flow: None,
                peer: None,
                connected: false,
            };
            *client_sock_guard = new_sock.try_clone()?;
            (new_sock, None, None, false, *listen_guard, listen_guard.id)
        } else {
            let client_guard = self.client_addr_connected.lock().unwrap();
            let client_sock_guard = self.client_sock.lock().unwrap();
            (
                client_sock_guard.try_clone()?,
                client_guard.flow,
                client_guard.peer,
                client_guard.connected,
                *listen_guard,
                listen_guard.id,
            )
        };

        Ok((
            ret_sock,
            cflow,
            cpeer,
            cconn,
            laddr,
            eff_id,
            fam_flip || changed,
        ))
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
            client_peer,
            client_connected,
            listen_canonical,
            _listen_local_id,
            listen_changed,
        ) = if allow_listen_rebind {
            let res = self.reresolve_listen(context)?;
            (res.0, res.1, res.2, res.3, res.4, res.5, res.6)
        } else {
            let listen_guard = self.listen.lock().unwrap();
            let client_guard = self.client_addr_connected.lock().unwrap();
            let client_sock_guard = self.client_sock.lock().unwrap();
            (
                client_sock_guard.try_clone()?,
                client_guard.flow,
                client_guard.peer,
                client_guard.connected,
                *listen_guard,
                listen_guard.id,
                false,
            )
        };

        let (
            upstream_sock,
            upstream_remote,
            upstream_local,
            upstream_sock_type,
            upstream_connected,
            upstream_changed,
        ) = if allow_upstream {
            let res = self.reresolve_upstream(context)?;
            (res.0, res.1, res.2, res.3, true, res.4)
        } else {
            let upstream_guard = self.upstream_addr_connected.lock().unwrap();
            let upstream_sock_guard = self.upstream_sock.lock().unwrap();
            let upstream_type_guard = self.upstream_sock_type.lock().unwrap();
            (
                upstream_sock_guard.try_clone()?,
                upstream_guard.remote,
                upstream_guard.local,
                *upstream_type_guard,
                upstream_guard.connected,
                false,
            )
        };

        let changed_any = listen_changed || upstream_changed;
        let version = self.publish_version(changed_any);

        Ok(SocketHandles {
            locked_flow: client_flow,
            client_peer,
            client_connected,
            client_sock,
            listen: listen_canonical,
            listen_sock_type: self.listen_sock_type,
            listen_icmp_header_source: Self::icmp_header_source(
                self.listen_proto,
                self.listen_sock_type,
            ),
            upstream: upstream_remote,
            upstream_local,
            upstream_sock_type,
            upstream_icmp_header_source: Self::icmp_header_source(
                self.upstream_proto,
                upstream_sock_type,
            ),
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
        let listen_guard = self.listen.lock().unwrap();
        let client_guard = self.client_addr_connected.lock().unwrap();
        let client_sock_guard = self.client_sock.lock().unwrap();
        let upstream_guard = self.upstream_addr_connected.lock().unwrap();
        let upstream_sock_guard = self.upstream_sock.lock().unwrap();
        let upstream_sock_type_guard = self.upstream_sock_type.lock().unwrap();
        let upstream_sock_type = *upstream_sock_type_guard;

        SocketHandles {
            locked_flow: client_guard.flow,
            client_peer: client_guard.peer,
            client_connected: client_guard.connected,
            client_sock: client_sock_guard.try_clone().expect("clone client socket"),
            listen: *listen_guard,
            listen_sock_type: self.listen_sock_type,
            listen_icmp_header_source: Self::icmp_header_source(
                self.listen_proto,
                self.listen_sock_type,
            ),
            upstream: upstream_guard.remote,
            upstream_local: upstream_guard.local,
            upstream_sock_type,
            upstream_icmp_header_source: Self::icmp_header_source(
                self.upstream_proto,
                upstream_sock_type,
            ),
            upstream_connected: upstream_guard.connected,
            upstream_sock: upstream_sock_guard
                .try_clone()
                .expect("clone upstream socket"),
            version: self.get_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::thread;

    fn make_mgr() -> SocketManager {
        let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (client_sock, actual_listen, listen_sock_type) =
            make_socket(listen_addr, SupportedProtocol::UDP, 1000, false, false)
                .expect("create client sock");

        let upstream_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind upstream udp");
        let upstream_addr = upstream_sock.local_addr().expect("upstream udp addr");

        SocketManager::new(
            client_sock,
            actual_listen,
            listen_sock_type,
            actual_listen.addr.to_string(),
            SupportedProtocol::UDP,
            CanonicalAddr::from_socket_addr(upstream_addr),
            upstream_addr.to_string(),
            SupportedProtocol::UDP,
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
                mgr.set_client_addr_connected(
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
                mgr.set_client_addr_connected(
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
        let _ = mgr.set_client_addr_connected(
            Some(ClientFlowKey::Udp(addr)),
            Some(canonical),
            true,
            v0,
        );
        let _ = mgr.set_client_addr_connected(
            Some(ClientFlowKey::Udp(addr)),
            Some(canonical),
            false,
            v0,
        );

        assert_ne!(cached.version, mgr.get_version());
        cached = mgr.refresh_handles();
        assert_eq!(cached.version, mgr.get_version());
        assert_eq!(cached.locked_flow, Some(ClientFlowKey::Udp(addr)));
        assert!(!cached.client_connected);
    }
}
