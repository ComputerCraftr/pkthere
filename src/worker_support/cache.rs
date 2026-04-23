use crate::cli::{IcmpListenMode, RuntimeConfig, SupportedProtocol};
use crate::net::params::{CanonicalAddr, IcmpHeaderIdSource};
use crate::net::payload::IcmpIdPolicy;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use socket2::{SockAddr, Type};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpSendPolicy {
    NoIcmpHeader,
    UseRemoteCanonicalId,
    UseLocalCanonicalId,
}

impl IcmpSendPolicy {
    #[inline]
    pub(crate) const fn resolve_header_id(
        self,
        local: CanonicalAddr,
        remote: CanonicalAddr,
    ) -> u16 {
        match self {
            Self::NoIcmpHeader => 0,
            Self::UseRemoteCanonicalId => remote.id,
            Self::UseLocalCanonicalId => local.id,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CachedSendRoute {
    pub(crate) dest: CanonicalAddr,
    pub(crate) dest_sa: SockAddr,
    pub(crate) icmp_send_policy: IcmpSendPolicy,
    pub(crate) icmp_header_id: u16,
}

pub(crate) struct CachedClientState {
    c2u: bool,
    worker_id: usize,
    pub(crate) dest_sock_type: Type,
    pub(crate) route: CachedSendRoute,
    pub(crate) recv_icmp_policy: IcmpIdPolicy,
    pub(crate) keepalive_reply_route: Option<CachedSendRoute>,
    log_handles: bool,
}

impl CachedClientState {
    #[inline]
    fn resolve_client_recv_icmp_policy(
        cfg: &RuntimeConfig,
        handles: &SocketHandles,
    ) -> IcmpIdPolicy {
        if cfg.listen_proto != SupportedProtocol::ICMP {
            IcmpIdPolicy::Exact(0)
        } else {
            match cfg.listen_icmp_mode {
                IcmpListenMode::FixedId => IcmpIdPolicy::Exact(cfg.listen.id),
                IcmpListenMode::WildcardLearn => handles
                    .locked_flow
                    .and_then(|flow| flow.icmp_ident())
                    .map_or(IcmpIdPolicy::Any, IcmpIdPolicy::Exact),
            }
        }
    }

    #[inline]
    pub(crate) fn resolve_icmp_send_policy(c2u: bool, handles: &SocketHandles) -> IcmpSendPolicy {
        if c2u {
            match handles.upstream_icmp_header_source {
                IcmpHeaderIdSource::None => IcmpSendPolicy::NoIcmpHeader,
                IcmpHeaderIdSource::Local => IcmpSendPolicy::UseLocalCanonicalId,
                IcmpHeaderIdSource::Remote => IcmpSendPolicy::UseRemoteCanonicalId,
            }
        } else {
            match handles.listen_icmp_header_source {
                IcmpHeaderIdSource::None => IcmpSendPolicy::NoIcmpHeader,
                IcmpHeaderIdSource::Local => IcmpSendPolicy::UseLocalCanonicalId,
                IcmpHeaderIdSource::Remote => IcmpSendPolicy::UseRemoteCanonicalId,
            }
        }
    }

    #[inline]
    fn build_send_route(
        c2u: bool,
        handles: &SocketHandles,
        dest: CanonicalAddr,
    ) -> CachedSendRoute {
        let local = if c2u {
            handles.upstream_local
        } else {
            handles.listen
        };
        let icmp_send_policy = Self::resolve_icmp_send_policy(c2u, handles);
        let icmp_header_id = icmp_send_policy.resolve_header_id(local, dest);
        let dest_sa = dest.as_sock_addr();
        CachedSendRoute {
            dest,
            dest_sa,
            icmp_send_policy,
            icmp_header_id,
        }
    }

    #[inline]
    pub(crate) fn build_local_keepalive_reply_route(
        handles: &SocketHandles,
        dest: CanonicalAddr,
    ) -> CachedSendRoute {
        let icmp_send_policy = Self::resolve_icmp_send_policy(false, handles);
        CachedSendRoute {
            dest,
            dest_sa: dest.as_sock_addr(),
            icmp_header_id: icmp_send_policy.resolve_header_id(handles.listen, dest),
            icmp_send_policy,
        }
    }

    #[inline]
    fn maybe_build_keepalive_reply_route(handles: &SocketHandles) -> Option<CachedSendRoute> {
        let dest = handles.client_peer.map(|peer| {
            CanonicalAddr::new(
                peer.addr,
                handles
                    .locked_flow
                    .and_then(|flow| flow.icmp_ident())
                    .unwrap_or(peer.id),
            )
        })?;
        Some(Self::build_local_keepalive_reply_route(handles, dest))
    }

    pub(crate) fn new(
        c2u: bool,
        worker_id: usize,
        cfg: &RuntimeConfig,
        handles: &SocketHandles,
        log_handles: bool,
    ) -> Self {
        if c2u {
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.upstream_sock_type,
                route: Self::build_send_route(c2u, handles, handles.upstream),
                recv_icmp_policy: Self::resolve_client_recv_icmp_policy(cfg, handles),
                keepalive_reply_route: Self::maybe_build_keepalive_reply_route(handles),
                log_handles,
            }
        } else {
            let remote = handles
                .client_peer
                .unwrap_or_else(|| CanonicalAddr::new(SocketAddr::new([0, 0, 0, 0].into(), 0), 0));
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.listen_sock_type,
                route: Self::build_send_route(c2u, handles, remote),
                recv_icmp_policy: Self::resolve_client_recv_icmp_policy(cfg, handles),
                keepalive_reply_route: Self::maybe_build_keepalive_reply_route(handles),
                log_handles,
            }
        }
    }

    pub(crate) fn refresh_from_handles(&mut self, cfg: &RuntimeConfig, handles: &SocketHandles) {
        if self.c2u {
            self.dest_sock_type = handles.upstream_sock_type;
            self.route = Self::build_send_route(self.c2u, handles, handles.upstream);
        } else {
            self.dest_sock_type = handles.listen_sock_type;
            self.route = Self::build_send_route(
                self.c2u,
                handles,
                handles.client_peer.unwrap_or(self.route.dest),
            );
        }
        self.recv_icmp_policy = Self::resolve_client_recv_icmp_policy(cfg, handles);
        self.keepalive_reply_route = Self::maybe_build_keepalive_reply_route(handles);
    }

    #[inline]
    pub(crate) fn refresh_handles_and_cache(
        &mut self,
        cfg: &RuntimeConfig,
        sock_mgr: &SocketManager,
        handles: &mut SocketHandles,
    ) {
        if handles.version != sock_mgr.get_version() {
            let prev_ver = handles.version;
            *handles = sock_mgr.refresh_handles();
            self.refresh_from_handles(cfg, handles);
            log_debug_dir!(
                self.log_handles,
                self.worker_id,
                self.c2u,
                "refresh_handles_and_cache: stale={}, new_ver={}, client_addr={:?}, client_connected={}, upstream_addr={}, upstream_connected={}",
                prev_ver,
                handles.version,
                handles.client_peer,
                handles.client_connected,
                handles.upstream,
                handles.upstream_connected
            );
            log_debug_dir!(
                self.log_handles,
                self.worker_id,
                self.c2u,
                "refresh_handles_and_cache route: dest={}, policy={:?}, icmp_header_id={}",
                self.route.dest,
                self.route.icmp_send_policy,
                self.route.icmp_header_id
            );
            log_debug_dir!(
                self.log_handles,
                self.worker_id,
                self.c2u,
                "refresh_handles_and_cache recv_policy={:?}, keepalive_reply_dest={}",
                self.recv_icmp_policy,
                self.keepalive_reply_route
                    .as_ref()
                    .map(|route| route.dest.to_string())
                    .unwrap_or_else(|| String::from("<none>"))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedClientState, IcmpSendPolicy};
    use crate::cli::{
        DebugBehavior, DebugLogs, IcmpListenMode, ReresolveMode, RuntimeConfig, SupportedProtocol,
        TimeoutAction, WorkerFlowMode,
    };
    use crate::flow_key::ClientFlowKey;
    use crate::net::params::{CanonicalAddr, IcmpHeaderIdSource};
    use crate::net::payload::IcmpIdPolicy;
    use crate::net::sock_mgr::SocketHandles;
    use socket2::{Socket, Type};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};

    fn test_config(
        listen_proto: SupportedProtocol,
        upstream_proto: SupportedProtocol,
    ) -> RuntimeConfig {
        RuntimeConfig {
            listen: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1111)),
                1111,
            ),
            listen_bind_is_dynamic: false,
            listen_proto,
            listen_icmp_mode: IcmpListenMode::FixedId,
            listen_str: String::from("test-listen"),
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2222)),
                2222,
            ),
            upstream_proto,
            upstream_str: String::from("test-upstream"),
            timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 0,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        }
    }

    fn wildcard_icmp_config() -> RuntimeConfig {
        let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        cfg.listen_icmp_mode = IcmpListenMode::WildcardLearn;
        cfg
    }

    fn udp_socket_clone() -> Socket {
        Socket::from(
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind udp socket"),
        )
    }

    fn test_handles() -> SocketHandles {
        SocketHandles {
            locked_flow: None,
            client_peer: None,
            client_connected: false,
            client_sock: udp_socket_clone(),
            listen: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)),
                3333,
            ),
            listen_sock_type: Type::DGRAM,
            listen_icmp_header_source: IcmpHeaderIdSource::Local,
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4444)),
                4444,
            ),
            upstream_local: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
                5555,
            ),
            upstream_sock_type: Type::DGRAM,
            upstream_icmp_header_source: IcmpHeaderIdSource::Local,
            upstream_connected: true,
            upstream_sock: udp_socket_clone(),
            version: 0,
        }
    }

    #[test]
    fn client_flow_key_compares_udp_and_icmp_explicitly() {
        let udp_a =
            ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2222)));
        let udp_b =
            ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3333)));
        let icmp_a = ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 11,
        };
        let icmp_b = ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 22,
        };
        let icmp_c = ClientFlowKey::IcmpV6 {
            ip: Ipv6Addr::LOCALHOST,
            ident: 11,
            flowinfo: 0,
            scope_id: 0,
        };
        assert_ne!(udp_a, udp_b);
        assert_ne!(icmp_a, icmp_b);
        assert_ne!(icmp_a, icmp_c);
    }

    #[test]
    fn upstream_raw_icmp_uses_canonical_remote_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let mut handles = test_handles();
        handles.upstream_icmp_header_source = IcmpHeaderIdSource::Remote;
        handles.upstream =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 9999);
        handles.upstream_local =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777), 7777);
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(true, &handles),
            IcmpSendPolicy::UseRemoteCanonicalId
        );
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 9999);
        assert_eq!(
            cache
                .route
                .dest_sa
                .as_socket()
                .expect("cached upstream route"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
        );
    }

    #[test]
    fn upstream_dgram_icmp_uses_realized_local_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let mut handles = test_handles();
        handles.upstream_icmp_header_source = IcmpHeaderIdSource::Local;
        handles.upstream =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 9999);
        handles.upstream_local =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777), 7777);
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(true, &handles),
            IcmpSendPolicy::UseLocalCanonicalId
        );
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 7777);
        assert_eq!(
            cache
                .route
                .dest_sa
                .as_socket()
                .expect("cached upstream route"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
        );
    }

    #[test]
    fn upstream_udp_route_uses_no_icmp_header_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.upstream_icmp_header_source = IcmpHeaderIdSource::None;
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(true, &handles),
            IcmpSendPolicy::NoIcmpHeader
        );
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 0);
    }

    #[test]
    fn client_raw_icmp_uses_locked_peer_id() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.listen_icmp_header_source = IcmpHeaderIdSource::Remote;
        handles.client_peer = Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            8888,
        ));
        handles.listen =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3333), 3333);
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(false, &handles),
            IcmpSendPolicy::UseRemoteCanonicalId
        );
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 8888);
        assert_eq!(
            cache
                .route
                .dest_sa
                .as_socket()
                .expect("cached client route"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888)
        );
    }

    #[test]
    fn client_dgram_icmp_uses_realized_listen_id() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.listen_icmp_header_source = IcmpHeaderIdSource::Local;
        handles.client_peer = Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            8888,
        ));
        handles.listen =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3333), 3333);
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(false, &handles),
            IcmpSendPolicy::UseLocalCanonicalId
        );
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 3333);
        assert_eq!(
            cache
                .route
                .dest_sa
                .as_socket()
                .expect("cached client route"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888)
        );
    }

    #[test]
    fn client_udp_route_uses_no_icmp_header_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.listen_icmp_header_source = IcmpHeaderIdSource::None;
        assert_eq!(
            CachedClientState::resolve_icmp_send_policy(false, &handles),
            IcmpSendPolicy::NoIcmpHeader
        );
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 0);
    }

    #[test]
    fn cached_recv_icmp_policy_tracks_locked_wildcard_flow_id() {
        let cfg = wildcard_icmp_config();
        let mut handles = test_handles();
        let unlocked = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(unlocked.recv_icmp_policy, IcmpIdPolicy::Any);

        handles.locked_flow = Some(ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 4242,
        });
        let locked = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(locked.recv_icmp_policy, IcmpIdPolicy::Exact(4242));
    }

    #[test]
    fn cached_keepalive_reply_route_is_built_from_locked_client_peer() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.listen_icmp_header_source = IcmpHeaderIdSource::Remote;
        handles.client_peer = Some(CanonicalAddr::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
            8888,
        ));
        handles.locked_flow = Some(ClientFlowKey::IcmpV4 {
            ip: Ipv4Addr::LOCALHOST,
            ident: 9999,
        });

        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        let route = cache
            .keepalive_reply_route
            .as_ref()
            .expect("cached keepalive reply route");
        assert_eq!(route.icmp_send_policy, IcmpSendPolicy::UseRemoteCanonicalId);
        assert_eq!(route.icmp_header_id, 9999);
        assert_eq!(route.dest.id, 9999);
        assert_eq!(
            route.dest_sa.as_socket().expect("cached keepalive route"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
        );
    }
}
