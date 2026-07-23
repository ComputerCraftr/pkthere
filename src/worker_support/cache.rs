use crate::cli::RuntimeConfig;
use crate::endpoint::LogicalEndpoint;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use socket2::SockAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug)]
pub(crate) struct CachedSendRoute {
    pub(crate) dest: LogicalEndpoint,
    pub(crate) dest_sa: SockAddr,
    pub(crate) icmp_header_id: u16,
    pub(crate) source_endpoint_id: Option<u16>,
    pub(crate) advertised_reply_id: Option<u16>,
    pub(crate) source_ip: Option<IpAddr>,
}

impl CachedSendRoute {
    #[inline]
    pub(crate) fn icmp_source_id(&self) -> u16 {
        match self.source_endpoint_id {
            Some(id) => id,
            None => self.icmp_header_id,
        }
    }

    #[inline]
    pub(crate) fn icmp_advertised_reply_id(&self) -> u16 {
        match self.advertised_reply_id {
            Some(id) => id,
            None => self.icmp_header_id,
        }
    }
}

pub(crate) struct CachedClientState {
    c2u: bool,
    worker_id: usize,
    pub(crate) route: CachedSendRoute,
    pub(crate) session_control_reply_route: Option<CachedSendRoute>,
    log_handles: bool,
}

impl CachedClientState {
    #[inline]
    fn build_send_route(
        c2u: bool,
        handles: &SocketHandles,
        dest: LogicalEndpoint,
    ) -> CachedSendRoute {
        CachedSendRoute {
            dest,
            dest_sa: dest.to_sock_addr(),
            icmp_header_id: dest.id(),
            source_endpoint_id: if c2u {
                handles
                    .upstream
                    .upstream_flow
                    .outbound
                    .map(|flow| flow.src.id())
            } else {
                handles
                    .listener
                    .listener_flow
                    .outbound
                    .map(|flow| flow.src.id())
            },
            advertised_reply_id: None,
            source_ip: if c2u {
                Some(handles.upstream.upstream_local_filter.ip())
            } else {
                match handles.listener.listener_flow.outbound {
                    Some(flow) => Some(flow.src.ip()),
                    None => Some(handles.listener.listen_local_filter.ip()),
                }
            },
        }
    }

    #[inline]
    pub(crate) fn build_local_session_control_reply_route(
        handles: &SocketHandles,
        dest: LogicalEndpoint,
    ) -> CachedSendRoute {
        CachedSendRoute {
            dest,
            dest_sa: dest.to_sock_addr(),
            icmp_header_id: dest.id(),
            source_endpoint_id: handles
                .listener
                .listener_flow
                .outbound
                .map(|flow| flow.src.id()),
            advertised_reply_id: Some(match handles.listener.listener_flow.inbound {
                Some(flow) => flow.dst.id(),
                None => handles.listener.listen_local_filter.id(),
            }),
            source_ip: Some(match handles.listener.listener_flow.outbound {
                Some(flow) => flow.src.ip(),
                None => handles.listener.listen_local_filter.ip(),
            }),
        }
    }

    #[inline]
    pub(crate) fn build_pending_session_control_reply_route(
        dest: LogicalEndpoint,
        source_endpoint_id: u16,
        source_ip: IpAddr,
        advertised_reply_id: u16,
    ) -> CachedSendRoute {
        CachedSendRoute {
            dest,
            dest_sa: dest.to_sock_addr(),
            icmp_header_id: dest.id(),
            source_endpoint_id: Some(source_endpoint_id),
            advertised_reply_id: Some(advertised_reply_id),
            source_ip: Some(source_ip),
        }
    }

    #[inline]
    fn maybe_build_session_control_reply_route(handles: &SocketHandles) -> Option<CachedSendRoute> {
        let dest = handles.listener.listener_flow.outbound_destination()?;
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
                route: Self::build_send_route(
                    c2u,
                    handles,
                    match handles.upstream.upstream_flow.outbound_destination() {
                        Some(dest) => dest,
                        None => handles.upstream.upstream_remote_filter,
                    },
                ),
                session_control_reply_route: Self::maybe_build_session_control_reply_route(handles),
                log_handles,
            }
        } else {
            let remote = match handles.listener.listener_flow.outbound_destination() {
                Some(dest) => dest,
                None => LogicalEndpoint::from_socket_addr_with_id(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    0,
                ),
            };
            Self {
                c2u,
                worker_id,
                route: Self::build_send_route(c2u, handles, remote),
                session_control_reply_route: Self::maybe_build_session_control_reply_route(handles),
                log_handles,
            }
        }
    }

    pub(crate) fn refresh_from_handles(&mut self, handles: &SocketHandles) {
        if self.c2u {
            self.route = Self::build_send_route(
                self.c2u,
                handles,
                match handles.upstream.upstream_flow.outbound_destination() {
                    Some(dest) => dest,
                    None => handles.upstream.upstream_remote_filter,
                },
            );
        } else {
            self.route = Self::build_send_route(
                self.c2u,
                handles,
                match handles.listener.listener_flow.outbound_destination() {
                    Some(dest) => dest,
                    None => self.route.dest,
                },
            );
        }
        self.session_control_reply_route = Self::maybe_build_session_control_reply_route(handles);
    }

    #[inline]
    pub(crate) fn refresh_handles_and_cache(
        &mut self,
        sock_mgr: &SocketManager,
        handles: &mut SocketHandles,
    ) {
        if handles.version != sock_mgr.get_version() {
            let prev_ver = handles.version;
            *handles = sock_mgr.refresh_handles();
            self.refresh_from_handles(handles);
            log_debug_dir!(
                self.log_handles,
                self.worker_id,
                self.c2u,
                "refresh_handles_and_cache: stale={}, new_ver={}, listener_flow={:?}, listen_kernel_addr={}, listener_connected={}, upstream_remote_filter={}, upstream_connected={}",
                prev_ver,
                handles.version,
                handles.listener.listener_flow,
                handles.listener.listen_local_kernel_addr,
                handles.listener_connected(),
                handles.upstream.upstream_remote_filter,
                handles.upstream_connected()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedClientState, SocketHandles};
    use crate::cli::{
        DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
        RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
    };
    use crate::endpoint::LogicalEndpoint;
    use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
    use crate::net::sock_mgr::{ListenerMetadata, UpstreamMetadata};
    use crate::worker_support::test_support::udp_socket;
    use pkthere_socket_policy::{
        IcmpPolicyIntent, SocketRole, resolve_socket_policy_with_icmp_intent,
    };
    use socket2::{Domain, Type};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    fn test_config(lp: SupportedProtocol, up: SupportedProtocol) -> RuntimeConfig {
        RuntimeConfig {
            listen: LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                8888,
            ),
            listener_source_id_request: IcmpReplyIdRequest::Default,
            listener_reply_id_request: IcmpReplyIdRequest::Default,
            listen_proto: lp,
            listen_mode: ListenMode::Fixed,
            listen_str: String::from("127.0.0.1:8888"),
            upstream: LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
                9999,
            ),
            upstream_source_id_request: IcmpReplyIdRequest::Default,
            upstream_reply_id_request: IcmpReplyIdRequest::Default,
            upstream_proto: up,
            upstream_str: String::from("127.0.0.1:9999"),
            options: RuntimeOptions {
                workers: 1,
                worker_flow_mode: WorkerFlowMode::SharedFlow,
                timeout_secs: 10,
                icmp_handshake_timeout_secs: 10,
                on_timeout: TimeoutAction::Drop,
                stats_interval_mins: 0,
                max_payload: 1500,
                icmp_sync_pps: 0,
                reresolve_secs: 0,
                reresolve_mode: ReresolveMode::Upstream,
                debug_reresolve_address_file: None,
                #[cfg(unix)]
                run_as_user: None,
                #[cfg(unix)]
                run_as_group: None,
                debug_behavior: DebugBehavior::default(),
                debug_logs: DebugLogs::default(),
            },
        }
    }

    fn test_handles() -> SocketHandles {
        let upstream_local = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777),
            7777,
        );
        let upstream_remote = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
            9999,
        );
        let upstream_flow = SocketLegFlow::new(
            Some(FlowTuple::new(upstream_remote, upstream_local)),
            Some(FlowTuple::new(upstream_local, upstream_remote)),
        );
        let listen_policy = resolve_socket_policy_with_icmp_intent(
            SocketRole::Listener,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );
        let upstream_policy = resolve_socket_policy_with_icmp_intent(
            SocketRole::Upstream,
            SupportedProtocol::UDP,
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            Domain::IPV4,
            IcmpPolicyIntent::default(),
        );
        SocketHandles::new(
            ListenerMetadata {
                flow: None,
                listener_flow: SocketLegFlow::empty(),
                listen_local_filter: LogicalEndpoint::from_socket_addr_with_id(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                    8888,
                ),
                listen_local_kernel_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Listener,
                    0,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
                ),
                sock_type: Type::DGRAM,
                policy: listen_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::UDP,
                    Domain::IPV4,
                    listen_policy,
                )
                .expect("listener parser"),
            },
            udp_socket(),
            UpstreamMetadata {
                upstream_remote_filter: upstream_remote,
                upstream_local_filter: upstream_local,
                upstream_local_kernel_addr: upstream_local.to_socket_addr(),
                evidence_key: crate::net::sock_mgr::SocketEvidenceKey::initial(
                    SocketRole::Upstream,
                    0,
                    upstream_local.to_socket_addr(),
                ),
                upstream_flow,
                sock_type: Type::DGRAM,
                policy: upstream_policy,
                parser: crate::net::packet_headers::select_packet_parser(
                    SupportedProtocol::UDP,
                    Domain::IPV4,
                    upstream_policy,
                )
                .expect("upstream parser"),
            },
            udp_socket(),
            0,
        )
    }

    #[test]
    fn client_flow_key_compares_udp_and_icmp_explicitly() {
        let udp_a = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8888),
        )));
        let udp_b = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999),
        )));
        let icmp_a = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 11));
        let icmp_b = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 22));
        let icmp_c = ClientFlowKey::Icmp(LogicalEndpoint::from_v6(Ipv6Addr::LOCALHOST, 11, 0, 0));
        assert_ne!(udp_a, udp_b);
        assert_ne!(icmp_a, icmp_b);
        assert_ne!(icmp_a, icmp_c);
    }

    #[test]
    fn cached_session_control_reply_route_is_built_from_listener_outbound_tuple() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        let mut handles = test_handles();
        let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
        let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555);
        let listener = Arc::make_mut(&mut handles.listener);
        listener.listener_flow = SocketLegFlow::new(
            Some(FlowTuple::new(remote, local)),
            Some(FlowTuple::new(local, remote)),
        );
        listener.flow = Some(ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555)),
        )));

        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        let reply_route = cache
            .session_control_reply_route
            .expect("reply route exists");
        assert_eq!(reply_route.dest.id(), 5555);
        assert_eq!(reply_route.icmp_source_id(), 8888);
        assert_eq!(reply_route.icmp_advertised_reply_id(), 8888);
    }

    #[test]
    fn pending_session_control_reply_route_keeps_source_and_reply_ids_distinct() {
        let route = CachedClientState::build_pending_session_control_reply_route(
            LogicalEndpoint::from_socket_addr_with_id(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001),
                40001,
            ),
            7777,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9999,
        );

        assert_eq!(route.icmp_header_id, 40001);
        assert_eq!(route.icmp_source_id(), 7777);
        assert_eq!(route.icmp_advertised_reply_id(), 9999);
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
        let listener = Arc::make_mut(&mut handles.listener);
        listener.sock_type = Type::RAW;
        let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
        let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        listener.listener_flow = SocketLegFlow::new(
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
        let upstream = Arc::make_mut(&mut handles.upstream);
        upstream.sock_type = Type::RAW;
        // Our "Source Port" (local ID) is 7777
        upstream.upstream_local_filter = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            7777,
        );
        // Our "Destination Port" (remote ID) is 9999
        upstream.upstream_remote_filter = LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            9999,
        );

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
    fn upstream_raw_icmp_uses_logical_remote_id() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let mut handles = test_handles();
        Arc::make_mut(&mut handles.upstream).sock_type = Type::RAW;
        let cache = CachedClientState::new(true, 0, &cfg, &handles, false);
        assert_eq!(cache.route.icmp_header_id, 9999);
    }
}
