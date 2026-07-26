use crate::cli::RuntimeConfig;
use crate::endpoint::LogicalEndpoint;
use crate::net::sock_mgr::{PublishedUpdate, SocketHandles, SocketManager};
use socket2::SockAddr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(crate) const fn descriptor_cache_lane_count(worker_pairs: usize) -> Option<usize> {
    worker_pairs.checked_mul(3)
}

pub(crate) const fn auxiliary_descriptor_cache_lane(
    worker_pairs: usize,
    worker_id: usize,
) -> Option<usize> {
    match worker_pairs.checked_mul(2) {
        Some(forwarding_threads) => forwarding_threads.checked_add(worker_id / 2),
        None => None,
    }
}

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
    descriptor_cache: crate::net::managed_socket::WorkerDescriptorCache,
    log_handles: bool,
}

/// One lexical send capability tying the direction-owned descriptor lease to
/// the route facts captured from the same cache. It cannot be cloned or
/// constructed outside this module.
pub(crate) struct CachedSendLease<'cache> {
    pub(crate) socket: crate::net::managed_socket::ManagedSendLease<'cache>,
    pub(crate) destination: &'cache SockAddr,
    pub(crate) source_ip: Option<IpAddr>,
    pub(crate) icmp_header_id: u16,
    pub(crate) icmp_source_id: u16,
}

pub(crate) enum WorkerStateOutcome<'flow> {
    Current(crate::flow_state::FlowTopologyReadLease<'flow>),
    Reconciled(crate::flow_state::FlowTopologyReadLease<'flow>),
}

/// Sole entry point for one complete manager-to-worker publication transfer.
/// The captured resources never escape between capture and installation, so
/// callers cannot reorder, repeat, or partially apply either phase.
struct WorkerStateTransaction<Resource> {
    staged: Resource,
}

impl<Resource> WorkerStateTransaction<Resource> {
    fn run<Output, Error>(
        capture: impl FnOnce() -> Result<Resource, Error>,
        install: impl FnOnce(Resource) -> Result<Output, Error>,
    ) -> Result<Output, Error> {
        let transaction = WorkerStateTransaction { staged: capture()? };
        let WorkerStateTransaction { staged } = transaction;
        install(staged)
    }
}

impl CachedClientState {
    pub(crate) fn service_descriptor_revocation(&mut self) -> io::Result<bool> {
        self.descriptor_cache.service_revocation()
    }

    fn reconcile_direction_cache(&mut self, handles: &SocketHandles) -> io::Result<()> {
        let socket = if self.c2u {
            &handles.upstream_sock
        } else {
            &handles.client_sock
        };
        self.descriptor_cache.reconcile(socket)
    }

    /// Acquires the send lease for this cache's fixed direction. The cache
    /// itself owns destination selection, so callers cannot pair a C2U cache
    /// with a listener descriptor or a U2C cache with an upstream descriptor.
    /// An unreconciled or revoked cache returns an error before socket I/O.
    pub(crate) fn acquire_prepared_send<'cache>(
        &'cache mut self,
        handles: &'cache SocketHandles,
    ) -> io::Result<CachedSendLease<'cache>> {
        let socket = if self.c2u {
            &handles.upstream_sock
        } else {
            &handles.client_sock
        };
        let send_lease = socket.acquire_send_lease(&mut self.descriptor_cache)?;
        Ok(CachedSendLease {
            socket: send_lease,
            destination: &self.route.dest_sa,
            source_ip: self.route.source_ip,
            icmp_header_id: self.route.icmp_header_id,
            icmp_source_id: self.route.icmp_source_id(),
        })
    }

    #[inline]
    pub(crate) fn expected_upstream_ack_destination_id(
        &self,
        handles: &SocketHandles,
    ) -> io::Result<u16> {
        let id = match handles.upstream.upstream_local_filter.id() {
            0 => self.route.icmp_header_id,
            realized => realized,
        };
        if id == 0 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ICMP upstream ACK destination ID is unresolved",
            ))
        } else {
            Ok(id)
        }
    }

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

    fn build_direction_send_route(
        c2u: bool,
        handles: &SocketHandles,
        previous_destination: Option<LogicalEndpoint>,
    ) -> CachedSendRoute {
        let destination = if c2u {
            match handles.upstream.upstream_flow.outbound_destination() {
                Some(destination) => destination,
                None => handles.upstream.upstream_remote_filter,
            }
        } else {
            match handles.listener.listener_flow.outbound_destination() {
                Some(destination) => destination,
                None => previous_destination.unwrap_or_else(|| {
                    LogicalEndpoint::from_socket_addr_with_id(
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        0,
                    )
                }),
            }
        };
        Self::build_send_route(c2u, handles, destination)
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
        cfg: &RuntimeConfig,
        handles: &SocketHandles,
        log_handles: bool,
    ) -> io::Result<Self> {
        Self::new_with_descriptor_lane(c2u, worker_id, worker_id, cfg, handles, log_handles)
    }

    pub(crate) fn new_with_descriptor_lane(
        c2u: bool,
        worker_id: usize,
        descriptor_lane: usize,
        _cfg: &RuntimeConfig,
        handles: &SocketHandles,
        log_handles: bool,
    ) -> io::Result<Self> {
        let mut state = Self {
            c2u,
            worker_id,
            route: Self::build_direction_send_route(c2u, handles, None),
            session_control_reply_route: Self::maybe_build_session_control_reply_route(handles),
            descriptor_cache: crate::net::managed_socket::WorkerDescriptorCache::for_worker(
                descriptor_lane,
            ),
            log_handles,
        };
        state.reconcile_direction_cache(handles)?;
        Ok(state)
    }

    fn install_route_snapshot(&mut self, handles: &SocketHandles) {
        self.route = Self::build_direction_send_route(self.c2u, handles, Some(self.route.dest));
        self.session_control_reply_route = Self::maybe_build_session_control_reply_route(handles);
    }

    /// Consumes one manager publication and installs its worker-visible
    /// handles, descriptor caches, and route facts as one local transaction.
    /// Callers cannot refresh any one of those resources independently.
    pub(crate) fn install_manager_publication(
        &mut self,
        handles: &mut SocketHandles,
        auxiliary_cache: Option<&mut Self>,
        publication: PublishedUpdate,
    ) -> Result<(), crate::net::sock_mgr::ManagerError> {
        let mut auxiliary_cache = auxiliary_cache;
        let staged = publication.handles;
        self.reconcile_direction_cache(&staged).map_err(|source| {
            crate::net::sock_mgr::ManagerError::io(
                "reconcile primary published descriptor cache",
                source,
            )
        })?;
        if let Some(auxiliary) = auxiliary_cache.as_mut() {
            (*auxiliary)
                .reconcile_direction_cache(&staged)
                .map_err(|source| {
                    crate::net::sock_mgr::ManagerError::io(
                        "reconcile auxiliary published descriptor cache",
                        source,
                    )
                })?;
        }
        self.install_route_snapshot(&staged);
        if let Some(auxiliary) = auxiliary_cache.as_mut() {
            (*auxiliary).install_route_snapshot(&staged);
        }
        *handles = staged;
        Ok(())
    }

    #[inline]
    pub(crate) fn ensure_worker_state<'flow>(
        &mut self,
        sock_mgr: &SocketManager,
        handles: &mut SocketHandles,
        flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
        auxiliary_cache: Option<&mut Self>,
    ) -> Result<WorkerStateOutcome<'flow>, crate::net::sock_mgr::ManagerError> {
        let capture = match sock_mgr.begin_worker_state_transaction(handles.version) {
            crate::net::sock_mgr::WorkerStateTransactionStart::Current => {
                return Ok(WorkerStateOutcome::Current(flow_read));
            }
            crate::net::sock_mgr::WorkerStateTransactionStart::Required(capture) => capture,
        };
        let previous_version = handles.version;
        let mut auxiliary_cache = auxiliary_cache;
        let log_handles = self.log_handles;
        let worker_id = self.worker_id;
        let c2u = self.c2u;
        let (flow_read, installed_version) = flow_read
                .run_released(|| {
                    WorkerStateTransaction::run(|| {
                        let staged = capture.capture()?;
                        if staged.version == previous_version {
                            return Err(crate::net::sock_mgr::ManagerError::FlowTopology {
                                operation: "capture changed worker state",
                                cause: crate::flow_state::FlowTopologyError::Busy,
                            });
                        }
                        Ok(staged)
                    }, |staged| {
                        self.reconcile_direction_cache(&staged).map_err(|source| {
                                crate::net::sock_mgr::ManagerError::io(
                                    "reconcile primary worker descriptor cache",
                                    source,
                                )
                            })?;
                            if let Some(auxiliary) = auxiliary_cache.as_mut() {
                                (*auxiliary)
                                    .reconcile_direction_cache(&staged)
                                    .map_err(|source| {
                                        crate::net::sock_mgr::ManagerError::io(
                                            "reconcile auxiliary worker descriptor cache",
                                            source,
                                        )
                                    })?;
                            }
                            self.install_route_snapshot(&staged);
                            if let Some(auxiliary) = auxiliary_cache.as_mut() {
                                (*auxiliary).install_route_snapshot(&staged);
                            }
                            log_debug_dir!(
                                log_handles,
                                worker_id,
                                c2u,
                                "ensure_worker_state: stale={}, new_ver={}, listener_key={:?}, listener_flow={:?}, listener_connected={}, upstream_key={:?}, upstream_connected={}",
                                previous_version,
                                staged.version,
                                staged.listener.evidence_key,
                                staged.listener.listener_flow,
                                staged.listener_connected(),
                                staged.upstream.evidence_key,
                                staged.upstream_connected()
                            );
                            let installed_version = staged.version;
                            let retired = std::mem::replace(handles, staged);
                            drop(retired);
                            Ok(installed_version)
                    })
                })
                .map_err(|error| match error {
                    crate::flow_state::ReleasedFlowOperationError::Operation(error) => error,
                    crate::flow_state::ReleasedFlowOperationError::Reacquire(cause) => {
                        crate::net::sock_mgr::ManagerError::FlowTopology {
                            operation: "reacquire flow authority after worker state transaction",
                            cause,
                        }
                    }
                })?;
        if !flow_read.is_current() {
            return Err(crate::net::sock_mgr::ManagerError::FlowTopology {
                operation: "validate coherent worker state transaction",
                cause: crate::flow_state::FlowTopologyError::Busy,
            });
        }
        if installed_version != handles.version {
            return Err(crate::net::sock_mgr::ManagerError::FlowTopology {
                operation: "validate installed worker-state resource version",
                cause: crate::flow_state::FlowTopologyError::OwnershipLost,
            });
        }
        Ok(WorkerStateOutcome::Reconciled(flow_read))
    }
}

#[cfg(all(test, not(miri)))]
pub(crate) mod tests;

#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod transaction_loom;
