use crate::cli::RuntimeConfig;
use crate::net::params::CanonicalAddr;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use socket2::{SockAddr, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug)]
pub(crate) struct CachedSendRoute {
    pub(crate) dest: CanonicalAddr,
    pub(crate) dest_sa: SockAddr,
    pub(crate) icmp_header_id: u16,
}

pub(crate) struct CachedClientState {
    c2u: bool,
    worker_id: usize,
    pub(crate) dest_sock_type: Type,
    pub(crate) route: CachedSendRoute,
    pub(crate) session_control_reply_route: Option<CachedSendRoute>,
    log_handles: bool,
}

impl CachedClientState {
    #[inline]
    fn build_send_route(
        _c2u: bool,
        _handles: &SocketHandles,
        dest: CanonicalAddr,
    ) -> CachedSendRoute {
        CachedSendRoute {
            dest,
            dest_sa: dest.as_sock_addr(),
            icmp_header_id: dest.id,
        }
    }

    #[inline]
    pub(crate) fn build_local_session_control_reply_route(
        _handles: &SocketHandles,
        dest: CanonicalAddr,
    ) -> CachedSendRoute {
        CachedSendRoute {
            dest,
            dest_sa: dest.as_sock_addr(),
            icmp_header_id: dest.id,
        }
    }

    #[inline]
    fn maybe_build_session_control_reply_route(handles: &SocketHandles) -> Option<CachedSendRoute> {
        let dest = handles.listener_flow.outbound_destination()?;
        Some(Self::build_local_session_control_reply_route(handles, dest))
    }

    pub(crate) fn new(
        c2u: bool,
        worker_id: usize,
        _cfg: &RuntimeConfig,
        handles: &SocketHandles,
        log_handles: bool,
    ) -> Self {
        if c2u {
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.upstream_sock_type,
                route: Self::build_send_route(
                    c2u,
                    handles,
                    handles
                        .upstream_flow
                        .outbound_destination()
                        .unwrap_or(handles.upstream_remote_filter),
                ),
                session_control_reply_route: Self::maybe_build_session_control_reply_route(handles),
                log_handles,
            }
        } else {
            let remote = handles
                .listener_flow
                .outbound_destination()
                .unwrap_or_else(|| {
                    CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), 0)
                });
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.listen_sock_type,
                route: Self::build_send_route(c2u, handles, remote),
                session_control_reply_route: Self::maybe_build_session_control_reply_route(handles),
                log_handles,
            }
        }
    }

    pub(crate) fn refresh_from_handles(&mut self, _cfg: &RuntimeConfig, handles: &SocketHandles) {
        if self.c2u {
            self.dest_sock_type = handles.upstream_sock_type;
            self.route = Self::build_send_route(
                self.c2u,
                handles,
                handles
                    .upstream_flow
                    .outbound_destination()
                    .unwrap_or(handles.upstream_remote_filter),
            );
        } else {
            self.dest_sock_type = handles.listen_sock_type;
            self.route = Self::build_send_route(
                self.c2u,
                handles,
                handles
                    .listener_flow
                    .outbound_destination()
                    .unwrap_or(self.route.dest),
            );
        }
        self.session_control_reply_route = Self::maybe_build_session_control_reply_route(handles);
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
                "refresh_handles_and_cache: stale={}, new_ver={}, listener_flow={:?}, listen_kernel={}, listener_connected={}, upstream_remote_filter={}, upstream_connected={}",
                prev_ver,
                handles.version,
                handles.listener_flow,
                handles.listen_local_kernel,
                handles.listener_connected,
                handles.upstream_remote_filter,
                handles.upstream_connected
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedClientState, SocketHandles};
    use crate::cli::{
        DebugBehavior, DebugLogs, ListenMode, ReresolveMode, RuntimeConfig, SupportedProtocol,
        TimeoutAction, WorkerFlowMode,
    };
    use crate::flow_key::{ClientFlowKey, FlowEndpoint, FlowTuple, SocketLegFlow};
    use crate::net::params::CanonicalAddr;
    use socket2::{Socket, Type};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};

    fn test_config(lp: SupportedProtocol, up: SupportedProtocol) -> RuntimeConfig {
        RuntimeConfig {
            listen: CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                8888,
            ),
            listen_reply_id: None,
            listen_proto: lp,
            listen_mode: ListenMode::Fixed,
            listen_str: String::from("127.0.0.1:8888"),
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            upstream: CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
                9999,
            ),
            upstream_local_id: 0,
            upstream_proto: up,
            upstream_str: String::from("127.0.0.1:9999"),
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

    fn udp_socket_clone() -> Socket {
        Socket::from(
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind udp socket"),
        )
    }

    fn test_handles() -> SocketHandles {
        let upstream_local =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777), 7777);
        let upstream_remote =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 9999);
        let upstream_flow = SocketLegFlow::new(
            Some(FlowTuple::new(
                FlowEndpoint::from_canonical(upstream_remote),
                FlowEndpoint::from_canonical(upstream_local),
            )),
            Some(FlowTuple::new(
                FlowEndpoint::from_canonical(upstream_local),
                FlowEndpoint::from_canonical(upstream_remote),
            )),
        );
        SocketHandles {
            locked_flow: None,
            listener_flow: SocketLegFlow::empty(),
            listen_local_filter: CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                8888,
            ),
            listen_local_kernel: CanonicalAddr::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                8888,
            ),
            listener_connected: false,
            client_sock: udp_socket_clone(),
            listen_sock_type: Type::DGRAM,
            upstream_remote_filter: upstream_remote,
            upstream_local_filter: upstream_local,
            upstream_flow,
            upstream_sock_type: Type::DGRAM,
            upstream_connected: true,
            upstream_sock: udp_socket_clone(),
            version: 0,
        }
    }

    #[test]
    fn client_flow_key_compares_udp_and_icmp_explicitly() {
        let udp_a =
            ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8888)));
        let udp_b =
            ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)));
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
    fn cached_session_control_reply_route_is_built_from_listener_outbound_tuple() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        let local = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
        let remote = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555);
        handles.listener_flow = SocketLegFlow::new(
            Some(FlowTuple::new(remote, local)),
            Some(FlowTuple::new(local, remote)),
        );
        handles.locked_flow = Some(ClientFlowKey::Udp(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            5555,
        ))));

        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        let reply_route = cache
            .session_control_reply_route
            .expect("reply route exists");
        assert_eq!(reply_route.dest.id, 5555);
    }

    #[test]
    fn client_udp_route_uses_no_icmp_header_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let handles = test_handles();
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 0);
    }

    #[test]
    fn client_dgram_icmp_uses_realized_listen_id() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let handles = test_handles();
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 0);
    }

    #[test]
    fn client_raw_icmp_uses_locked_peer_id() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        handles.listen_sock_type = Type::RAW;
        let local = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
        let remote = FlowEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        handles.listener_flow = SocketLegFlow::new(
            Some(FlowTuple::new(remote, local)),
            Some(FlowTuple::new(local, remote)),
        );
        let cache = CachedClientState::new(false, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 12345);
    }

    #[test]
    fn upstream_udp_route_uses_no_icmp_header_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let handles = test_handles();
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 9999);
    }

    #[test]
    fn upstream_raw_icmp_supports_independent_local_and_remote_ids() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let mut handles = test_handles();
        handles.upstream_sock_type = Type::RAW;
        // Our "Source Port" (local ID) is 7777
        handles.upstream_local_filter =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), 7777);
        // Our "Destination Port" (remote ID) is 9999
        handles.upstream_remote_filter =
            CanonicalAddr::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), 9999);

        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);

        // Outgoing packets must use the remote/destination ID (9999)
        assert_eq!(cache.route.icmp_header_id, 9999);
    }

    #[test]
    fn upstream_dgram_icmp_uses_realized_local_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let handles = test_handles();
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 9999);
    }

    #[test]
    fn upstream_raw_icmp_uses_canonical_remote_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let handles = test_handles();
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 9999);
    }
}
