use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::icmp_support::choose_upstream_icmp_ids;
use crate::net::managed_socket::AssociationState;
use crate::net::packet_headers::select_packet_parser;
use crate::net::socket::{
    UpstreamSocketRequest, family_changed, make_socket, make_upstream_socket_for, resolve_first,
};
use pkthere_socket_policy::SocketEvidenceKey;
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, ResolvedSocketPolicy, SocketRole};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, Mutex};

use super::evidence::socket_evidence_json;
use super::{SocketHandles, SocketManagerInit, SocketStateSnapshot};

use super::flow::upstream_leg_flow;
use super::state::{
    ClientListenState, ListenerMetadata, ReresolveAction, ReresolveResult, SocketUpdateKind,
    UpstreamMetadata, UpstreamState, decide_listener_endpoint_update, decide_listener_reresolve,
    decide_upstream_endpoint_update, decide_upstream_reresolve,
};

pub(crate) struct ReresolveSummary {
    pub(crate) handles: SocketHandles,
    pub(crate) old_locked_flow: Option<crate::flow_key::ClientFlowKey>,
    pub(crate) listener_update: SocketUpdateKind,
    pub(crate) upstream_update: SocketUpdateKind,
    pub(crate) old_listener_key: SocketEvidenceKey,
    pub(crate) new_listener_key: SocketEvidenceKey,
    pub(crate) old_upstream_key: SocketEvidenceKey,
    pub(crate) new_upstream_key: SocketEvidenceKey,
}

impl ReresolveSummary {
    pub(crate) const fn listener_replaced(&self) -> bool {
        matches!(
            self.listener_update,
            SocketUpdateKind::Replaced | SocketUpdateKind::ReplacedCrossFamily
        )
    }
}

/// Manages both listener and upstream sockets and publishes versioned updates.
///
/// **STRICT LOCK ORDER**:
/// 1. `client_listen`
/// 2. `upstream`
pub(crate) struct SocketManager {
    client_listen: Mutex<ClientListenState>, // cold-path updates only
    pub(super) listen_target: String,        // unresolved --here host:port
    listen_proto: SupportedProtocol,         // never changes
    listen_debug_unconnected: bool,
    listen_worker_socket_policy: ListenerWorkerSocketPolicy,
    pub(super) upstream_state: Mutex<UpstreamState>, // cold-path updates only
    pub(super) upstream_target: String,              // unresolved --there host:port
    upstream_source_id_request: IcmpReplyIdRequest,
    upstream_reply_id_request: IcmpReplyIdRequest,
    upstream_proto: SupportedProtocol, // never changes
    upstream_debug_unconnected: bool,
    upstream_icmp_kernel_echo_self_handshake: bool,
    force_raw_icmp_wildcard_upstream: bool,
    debug_handles: bool,
    timeout_action: TimeoutAction, // never changes
    version: AtomicU64,            // increments on any change
}

impl SocketManager {
    #[inline]
    fn upstream_socket_local_id_request(
        proto: SupportedProtocol,
        source_id_request: IcmpReplyIdRequest,
        reply_id_request: IcmpReplyIdRequest,
    ) -> u16 {
        match proto {
            SupportedProtocol::UDP => source_id_request.requested_socket_id(),
            SupportedProtocol::ICMP => reply_id_request.requested_socket_id(),
        }
    }

    fn normalized_upstream_local_after_getsockname(
        &self,
        requested_local_id: u16,
        remote: LogicalEndpoint,
        actual_local_addr: SocketAddr,
        policy: ResolvedSocketPolicy,
    ) -> LogicalEndpoint {
        let id = if let Some(icmp_policy) = policy.icmp {
            choose_upstream_icmp_ids(
                requested_local_id,
                remote.id(),
                actual_local_addr.port(),
                icmp_policy,
                self.debug_handles,
            )
            .local_id
        } else {
            actual_local_addr.port()
        };
        LogicalEndpoint::from_socket_addr_with_id(actual_local_addr, id)
    }

    fn replace_listener_after_transition_failure(
        &self,
        state: &mut ClientListenState,
        operation: &'static str,
    ) -> io::Result<()> {
        let (replacement, logical_local, kernel_addr, socket_type, policy) = make_socket(
            state.listen_local_filter.to_socket_addr(),
            self.listen_proto,
            1000,
            self.listen_worker_socket_policy,
            self.timeout_action,
            self.listen_debug_unconnected,
            self.upstream_icmp_kernel_echo_self_handshake,
        )?;
        let parser = select_packet_parser(
            self.listen_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        state.sock = replacement;
        state.listen_local_filter = logical_local;
        state.listen_local_kernel_addr = kernel_addr;
        state.evidence_key = state.evidence_key.replacement(kernel_addr);
        state.sock_type = socket_type;
        state.policy = policy;
        state.parser = parser;
        state.flow = None;
        state.listener_flow = SocketLegFlow::empty();
        if self.debug_handles {
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    state.evidence_key,
                    operation,
                    &self.listen_target,
                    kernel_addr,
                )
            );
        }
        Ok(())
    }

    pub fn new(init: SocketManagerInit) -> io::Result<Self> {
        let SocketManagerInit {
            socket_slot,
            client_sock,
            listen_local_filter,
            listen_local_kernel_addr,
            listen_sock_type,
            listen_target,
            listen_proto,
            listen_policy,
            listen_worker_socket_policy,
            listen_debug_unconnected,
            upstream_remote_filter,
            upstream_target,
            upstream_source_id_request,
            upstream_reply_id_request,
            upstream_proto,
            upstream_debug_unconnected,
            upstream_icmp_kernel_echo_self_handshake,
            force_raw_icmp_wildcard_upstream,
            timeout_act,
            debug_handles,
        } = init;
        let listen_parser = select_packet_parser(
            listen_proto,
            socket2::Domain::for_address(listen_local_kernel_addr),
            listen_policy,
        )?;
        let (
            sock,
            upstream_local,
            upstream_remote,
            upstream_local_kernel_addr,
            upstream_sock_type,
            upstream_policy,
        ) = make_upstream_socket_for(UpstreamSocketRequest {
            dest: upstream_remote_filter,
            proto: upstream_proto,
            req_local_id: Self::upstream_socket_local_id_request(
                upstream_proto,
                upstream_source_id_request,
                upstream_reply_id_request,
            ),
            timeout_act,
            debug_unconnected: upstream_debug_unconnected,
            force_raw_wildcard_icmp: force_raw_icmp_wildcard_upstream,
            allow_debug_kernel_echo_self_handshake: upstream_icmp_kernel_echo_self_handshake,
            debug_handles,
        })?;
        let upstream_parser = select_packet_parser(
            upstream_proto,
            socket2::Domain::for_address(upstream_local_kernel_addr),
            upstream_policy,
        )?;
        let listen_evidence_key =
            SocketEvidenceKey::initial(SocketRole::Listener, socket_slot, listen_local_kernel_addr);
        let upstream_evidence_key = SocketEvidenceKey::initial(
            SocketRole::Upstream,
            socket_slot,
            upstream_local_kernel_addr,
        );
        if debug_handles {
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    listen_evidence_key,
                    "create",
                    &listen_target,
                    listen_local_kernel_addr,
                )
            );
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    upstream_evidence_key,
                    "create",
                    &upstream_target,
                    upstream_local_kernel_addr,
                )
            );
        }
        Ok(Self {
            client_listen: Mutex::new(ClientListenState {
                sock: client_sock,
                metadata: Arc::new(ListenerMetadata {
                    listen_local_filter,
                    listen_local_kernel_addr,
                    evidence_key: listen_evidence_key,
                    flow: None,
                    listener_flow: SocketLegFlow::empty(),
                    sock_type: listen_sock_type,
                    policy: listen_policy,
                    parser: listen_parser,
                }),
            }),
            listen_target,
            listen_proto,
            listen_debug_unconnected,
            listen_worker_socket_policy,
            upstream_state: Mutex::new(UpstreamState {
                sock,
                metadata: Arc::new(UpstreamMetadata {
                    upstream_remote_filter: upstream_remote,
                    upstream_local_filter: upstream_local,
                    upstream_local_kernel_addr,
                    evidence_key: upstream_evidence_key,
                    upstream_flow: upstream_leg_flow(
                        upstream_local,
                        upstream_source_id_request,
                        upstream_remote,
                    ),
                    sock_type: upstream_sock_type,
                    policy: upstream_policy,
                    parser: upstream_parser,
                }),
            }),
            upstream_target,
            upstream_source_id_request,
            upstream_reply_id_request,
            upstream_proto,
            upstream_debug_unconnected,
            upstream_icmp_kernel_echo_self_handshake,
            force_raw_icmp_wildcard_upstream,
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

    #[inline]
    pub const fn get_listener_worker_socket_policy(&self) -> ListenerWorkerSocketPolicy {
        self.listen_worker_socket_policy
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

    /// Establish a client flow transaction. Socket association succeeds before
    /// any flow metadata or version becomes visible.
    pub fn establish_client_flow(
        &self,
        flow: ClientFlowKey,
        listener_flow: SocketLegFlow,
        connect_socket: bool,
        client: SocketAddr,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let mut cl_guard = self.client_listen.lock().unwrap();
        if !connect_socket && cl_guard.sock.is_connected() {
            return Err(io::Error::other(
                "listener policy requested an unconnected lock on an associated socket",
            ));
        }
        if connect_socket && let Err(transition_error) = cl_guard.sock.connect_unconnected(client) {
            self.replace_listener_after_transition_failure(
                &mut cl_guard,
                "replace-after-connect-failure",
            )
            .map_err(|replacement_error| {
                io::Error::other(format!(
                    "listener connect failed ({transition_error}); replacement also failed: {replacement_error}"
                ))
            })?;
            self.publish_version(true);
            return Err(io::Error::other(transition_error));
        }
        cl_guard.flow = Some(flow);
        cl_guard.listener_flow = listener_flow;
        self.publish_version(true);
        Ok(prev_ver + 1)
    }

    /// Reconcile a connected-send `EDESTADDRREQ` observation with kernel state.
    /// Metadata is unchanged because the flow remains valid for `send_to`.
    pub fn reconcile_client_destination_required(
        &self,
        observed: AssociationState,
        prev_ver: u64,
    ) -> io::Result<u64> {
        let cl_guard = self.client_listen.lock().unwrap();
        let changed = cl_guard
            .sock
            .reconcile_destination_required(observed)
            .map_err(io::Error::other)?;
        if changed {
            self.publish_version(true);
            Ok(prev_ver + 1)
        } else {
            Ok(prev_ver)
        }
    }

    #[inline]
    pub fn clear_client_lock(&self, prev_ver: u64) -> io::Result<u64> {
        let mut cl_guard = self.client_listen.lock().unwrap();
        if cl_guard.sock.is_connected()
            && let Err(disconnect_error) = cl_guard.sock.disconnect_connected()
        {
            log_warn!(
                "listener disconnect failed ({}); replacing listener socket",
                disconnect_error
            );
            self.replace_listener_after_transition_failure(
                &mut cl_guard,
                "replace-after-disconnect-failure",
            )?;
        }
        cl_guard.flow = None;
        cl_guard.listener_flow = SocketLegFlow::empty();
        self.publish_version(true);
        Ok(prev_ver + 1)
    }

    /// Current listener local filter address.
    #[inline]
    pub fn get_listen_addr(&self) -> LogicalEndpoint {
        self.client_listen.lock().unwrap().listen_local_filter
    }

    /// Snapshot the current client destination/connected state and protocol.
    #[inline]
    pub fn get_client_dest(&self) -> (Option<ClientFlowKey>, bool, SupportedProtocol) {
        let cl = self.client_listen.lock().unwrap();
        (cl.flow, cl.sock.is_connected(), self.listen_proto)
    }

    /// Snapshot the current upstream destination and protocol.
    #[inline]
    pub fn get_upstream_dest(&self) -> (LogicalEndpoint, bool, SupportedProtocol) {
        let up = self.upstream_state.lock().unwrap();
        (
            up.upstream_remote_filter,
            up.sock.is_connected(),
            self.upstream_proto,
        )
    }

    #[inline]
    pub fn snapshot_state(&self) -> SocketStateSnapshot {
        let cl = self.client_listen.lock().unwrap();
        let up = self.upstream_state.lock().unwrap();
        #[cfg(debug_assertions)]
        {
            cl.sock.assert_kernel_association();
            up.sock.assert_kernel_association();
        }
        SocketStateSnapshot {
            locked_flow: cl.flow,
            listener_flow: cl.listener_flow,
            listener_connected: cl.sock.is_connected(),
            client_proto: self.listen_proto,
            listen_local_filter: cl.listen_local_filter,
            listen_local_kernel_addr: cl.listen_local_kernel_addr,
            listen_evidence_key: cl.evidence_key,
            listen_sock_type: cl.sock_type,
            listen_policy: cl.policy,
            upstream_remote_filter: up.upstream_remote_filter,
            upstream_local_filter: up.upstream_local_filter,
            upstream_local_kernel_addr: up.upstream_local_kernel_addr,
            upstream_evidence_key: up.evidence_key,
            upstream_flow: up.upstream_flow,
            upstream_connected: up.sock.is_connected(),
            upstream_proto: self.upstream_proto,
            upstream_sock_type: up.sock_type,
            upstream_policy: up.policy,
        }
    }

    fn reresolve_upstream(
        &self,
        context: &str,
        endpoint_override: Option<SocketAddr>,
    ) -> io::Result<ReresolveResult<UpstreamMetadata>> {
        let mut up_guard = self.upstream_state.lock().unwrap();
        let prev_addr = up_guard.upstream_remote_filter;
        let prev_connected = up_guard.sock.is_connected();
        let prev_policy = up_guard.policy;
        let (fresh, action) = match endpoint_override {
            Some(addr) => decide_upstream_endpoint_update(
                prev_addr,
                LogicalEndpoint::from_socket_addr(addr),
                prev_connected,
                prev_policy,
            ),
            None => decide_upstream_reresolve(
                prev_addr,
                resolve_first(&self.upstream_target)?,
                prev_connected,
                prev_policy,
            ),
        };

        let changed = action != ReresolveAction::NoChange;
        let fam_flip =
            changed && family_changed(prev_addr.to_socket_addr(), fresh.to_socket_addr());

        match action {
            ReresolveAction::NoChange => Ok(ReresolveResult {
                sock: up_guard.sock.clone(),
                metadata: Arc::clone(&up_guard.metadata),
                update: SocketUpdateKind::Unchanged,
            }),
            ReresolveAction::UpdateMetadataOnly => {
                log_info!(
                    "{context}: upstream {} (IP changed; metadata updated)",
                    fresh
                );
                up_guard.upstream_remote_filter = fresh;
                up_guard.upstream_flow = upstream_leg_flow(
                    up_guard.upstream_local_filter,
                    self.upstream_source_id_request,
                    fresh,
                );
                if self.debug_handles {
                    log_debug!(
                        true,
                        "socket-evidence {}",
                        socket_evidence_json(
                            up_guard.evidence_key,
                            "metadata-update",
                            &self.upstream_target,
                            up_guard.upstream_local_kernel_addr,
                        )
                    );
                }
                Ok(ReresolveResult {
                    sock: up_guard.sock.clone(),
                    metadata: Arc::clone(&up_guard.metadata),
                    update: SocketUpdateKind::MetadataUpdated,
                })
            }
            ReresolveAction::ReconnectInPlace => {
                log_info!(
                    "{context}: upstream {} (IP changed; upstream socket reconnected)",
                    fresh
                );
                if let Err(reconnect_err) =
                    up_guard.sock.reconnect_connected(fresh.to_socket_addr())
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
                        upstream_local_kernel_addr,
                        new_type,
                        new_policy,
                    ) = make_upstream_socket_for(UpstreamSocketRequest {
                        dest: fresh,
                        proto: self.upstream_proto,
                        req_local_id: Self::upstream_socket_local_id_request(
                            self.upstream_proto,
                            self.upstream_source_id_request,
                            self.upstream_reply_id_request,
                        ),
                        timeout_act: self.timeout_action,
                        debug_unconnected: self.upstream_debug_unconnected,
                        force_raw_wildcard_icmp: self.force_raw_icmp_wildcard_upstream,
                        allow_debug_kernel_echo_self_handshake: self
                            .upstream_icmp_kernel_echo_self_handshake,
                        debug_handles: self.debug_handles,
                    })?;
                    let new_parser = select_packet_parser(
                        self.upstream_proto,
                        socket2::Domain::for_address(upstream_local_kernel_addr),
                        new_policy,
                    )?;
                    let new_evidence_key = up_guard
                        .evidence_key
                        .replacement(upstream_local_kernel_addr);
                    up_guard.upstream_local_filter = upstream_local_filter;
                    up_guard.upstream_local_kernel_addr = upstream_local_kernel_addr;
                    up_guard.upstream_remote_filter = upstream_remote_filter;
                    up_guard.upstream_flow = upstream_leg_flow(
                        upstream_local_filter,
                        self.upstream_source_id_request,
                        upstream_remote_filter,
                    );
                    up_guard.evidence_key = new_evidence_key;
                    up_guard.sock = new_sock.clone();
                    up_guard.sock_type = new_type;
                    up_guard.policy = new_policy;
                    up_guard.parser = new_parser;
                    if self.debug_handles {
                        log_debug!(
                            true,
                            "socket-evidence {}",
                            socket_evidence_json(
                                up_guard.evidence_key,
                                "replace-after-reconnect-failure",
                                &self.upstream_target,
                                upstream_local_kernel_addr,
                            )
                        );
                    }
                    return Ok(ReresolveResult {
                        sock: new_sock,
                        metadata: Arc::clone(&up_guard.metadata),
                        update: SocketUpdateKind::Replaced,
                    });
                }

                let actual_local_addr =
                    up_guard.sock.local_addr()?.as_socket().ok_or_else(|| {
                        io::Error::other(
                            "No socket resolved from getsockname after upstream reconnect",
                        )
                    })?;
                let requested_local_id = Self::upstream_socket_local_id_request(
                    self.upstream_proto,
                    self.upstream_source_id_request,
                    self.upstream_reply_id_request,
                );
                let upstream_local_filter = self.normalized_upstream_local_after_getsockname(
                    requested_local_id,
                    fresh,
                    actual_local_addr,
                    up_guard.policy,
                );
                up_guard.upstream_remote_filter = fresh;
                up_guard.upstream_local_filter = upstream_local_filter;
                up_guard.upstream_local_kernel_addr = actual_local_addr;
                up_guard.upstream_flow = upstream_leg_flow(
                    upstream_local_filter,
                    self.upstream_source_id_request,
                    fresh,
                );
                if self.debug_handles {
                    log_debug!(
                        true,
                        "socket-evidence {}",
                        socket_evidence_json(
                            up_guard.evidence_key,
                            "reconnect",
                            &self.upstream_target,
                            actual_local_addr,
                        )
                    );
                }
                Ok(ReresolveResult {
                    sock: up_guard.sock.clone(),
                    metadata: Arc::clone(&up_guard.metadata),
                    update: SocketUpdateKind::ReconnectedInPlace,
                })
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
                    upstream_local_kernel_addr,
                    new_type,
                    new_policy,
                ) = make_upstream_socket_for(UpstreamSocketRequest {
                    dest: fresh,
                    proto: self.upstream_proto,
                    req_local_id: Self::upstream_socket_local_id_request(
                        self.upstream_proto,
                        self.upstream_source_id_request,
                        self.upstream_reply_id_request,
                    ),
                    timeout_act: self.timeout_action,
                    debug_unconnected: self.upstream_debug_unconnected,
                    force_raw_wildcard_icmp: self.force_raw_icmp_wildcard_upstream,
                    allow_debug_kernel_echo_self_handshake: self
                        .upstream_icmp_kernel_echo_self_handshake,
                    debug_handles: self.debug_handles,
                })?;
                let new_parser = select_packet_parser(
                    self.upstream_proto,
                    socket2::Domain::for_address(upstream_local_kernel_addr),
                    new_policy,
                )?;
                let new_evidence_key = up_guard
                    .evidence_key
                    .replacement(upstream_local_kernel_addr);
                up_guard.upstream_local_filter = upstream_local_filter;
                up_guard.upstream_local_kernel_addr = upstream_local_kernel_addr;
                up_guard.upstream_remote_filter = upstream_remote_filter;
                up_guard.upstream_flow = upstream_leg_flow(
                    upstream_local_filter,
                    self.upstream_source_id_request,
                    upstream_remote_filter,
                );
                up_guard.evidence_key = new_evidence_key;
                up_guard.sock = new_sock.clone();
                up_guard.sock_type = new_type;
                up_guard.policy = new_policy;
                up_guard.parser = new_parser;
                if self.debug_handles {
                    log_debug!(
                        true,
                        "socket-evidence {}",
                        socket_evidence_json(
                            up_guard.evidence_key,
                            "replace",
                            &self.upstream_target,
                            upstream_local_kernel_addr,
                        )
                    );
                }
                Ok(ReresolveResult {
                    sock: new_sock,
                    metadata: Arc::clone(&up_guard.metadata),
                    update: if fam_flip {
                        SocketUpdateKind::ReplacedCrossFamily
                    } else {
                        SocketUpdateKind::Replaced
                    },
                })
            }
        }
    }

    fn reresolve_listen(
        &self,
        context: &str,
        endpoint_override: Option<SocketAddr>,
    ) -> io::Result<ReresolveResult<ListenerMetadata>> {
        let mut cl_guard = self.client_listen.lock().unwrap();
        let prev_listen = cl_guard.listen_local_filter;
        let (fresh, action) = match endpoint_override {
            Some(addr) => decide_listener_endpoint_update(
                prev_listen,
                LogicalEndpoint::from_socket_addr(addr),
            ),
            None => decide_listener_reresolve(prev_listen, resolve_first(&self.listen_target)?),
        };

        match action {
            ReresolveAction::NoChange => Ok(ReresolveResult {
                sock: cl_guard.sock.clone(),
                metadata: Arc::clone(&cl_guard.metadata),
                update: SocketUpdateKind::Unchanged,
            }),
            ReresolveAction::ReplaceSocket => {
                log_info!("{context}: listen {} (listener swapped)", fresh);
                let (new_sock, logical_local, listen_local_kernel_addr, new_type, new_policy) =
                    make_socket(
                        fresh.to_socket_addr(),
                        self.listen_proto,
                        1000,
                        self.listen_worker_socket_policy,
                        self.timeout_action,
                        self.listen_debug_unconnected,
                        self.upstream_icmp_kernel_echo_self_handshake,
                    )?;
                let new_parser = select_packet_parser(
                    self.listen_proto,
                    socket2::Domain::for_address(listen_local_kernel_addr),
                    new_policy,
                )?;
                let new_evidence_key = cl_guard.evidence_key.replacement(listen_local_kernel_addr);

                cl_guard.listen_local_filter = logical_local;
                cl_guard.listen_local_kernel_addr = listen_local_kernel_addr;
                cl_guard.flow = None;
                cl_guard.listener_flow = SocketLegFlow::empty();
                cl_guard.evidence_key = new_evidence_key;
                cl_guard.sock = new_sock.clone();
                cl_guard.sock_type = new_type;
                cl_guard.policy = new_policy;
                cl_guard.parser = new_parser;
                if self.debug_handles {
                    log_debug!(
                        true,
                        "socket-evidence {}",
                        socket_evidence_json(
                            cl_guard.evidence_key,
                            "replace",
                            &self.listen_target,
                            listen_local_kernel_addr,
                        )
                    );
                }
                Ok(ReresolveResult {
                    sock: new_sock,
                    metadata: Arc::clone(&cl_guard.metadata),
                    update: if family_changed(
                        prev_listen.to_socket_addr(),
                        logical_local.to_socket_addr(),
                    ) {
                        SocketUpdateKind::ReplacedCrossFamily
                    } else {
                        SocketUpdateKind::Replaced
                    },
                })
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
        self.reresolve_with_addresses(allow_upstream, allow_listen_rebind, context, None, None)
            .map(|summary| summary.handles)
    }

    pub(crate) fn reresolve_with_addresses(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
    ) -> io::Result<ReresolveSummary> {
        if !allow_upstream && !allow_listen_rebind {
            let handles = self.refresh_handles();
            return Ok(ReresolveSummary {
                old_locked_flow: handles.listener.flow,
                old_listener_key: handles.listener.evidence_key,
                new_listener_key: handles.listener.evidence_key,
                old_upstream_key: handles.upstream.evidence_key,
                new_upstream_key: handles.upstream.evidence_key,
                handles,
                listener_update: SocketUpdateKind::Unchanged,
                upstream_update: SocketUpdateKind::Unchanged,
            });
        }

        let old = self.snapshot_state();
        let (client_sock, listener, listener_update) = if allow_listen_rebind {
            let res = self.reresolve_listen(context, listen_addr)?;
            (res.sock, res.metadata, res.update)
        } else {
            let cl = self.client_listen.lock().unwrap();
            (
                cl.sock.clone(),
                Arc::clone(&cl.metadata),
                SocketUpdateKind::Unchanged,
            )
        };

        let (upstream_sock, upstream, upstream_update) = if allow_upstream {
            let res = self.reresolve_upstream(context, upstream_addr)?;
            (res.sock, res.metadata, res.update)
        } else {
            let up = self.upstream_state.lock().unwrap();
            (
                up.sock.clone(),
                Arc::clone(&up.metadata),
                SocketUpdateKind::Unchanged,
            )
        };

        let changed_any = listener_update.changed() || upstream_update.changed();
        let version = self.publish_version(changed_any);
        let handles = SocketHandles {
            listener,
            client_sock,
            upstream,
            upstream_sock,
            version,
        };
        Ok(ReresolveSummary {
            old_locked_flow: old.locked_flow,
            old_listener_key: old.listen_evidence_key,
            new_listener_key: handles.listener.evidence_key,
            old_upstream_key: old.upstream_evidence_key,
            new_upstream_key: handles.upstream.evidence_key,
            handles,
            listener_update,
            upstream_update,
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
            listener: Arc::clone(&cl.metadata),
            client_sock: cl.sock.clone(),
            upstream: Arc::clone(&up.metadata),
            upstream_sock: up.sock.clone(),
            version: self.get_version(),
        }
    }

    #[inline]
    pub fn set_upstream_peer_ids(&self, source_id: u16, reply_id: u16, prev_ver: u64) -> u64 {
        let mut up_guard = self.upstream_state.lock().unwrap();
        let mut changed = false;
        if up_guard.upstream_remote_filter.id() != reply_id {
            up_guard.upstream_remote_filter = up_guard.upstream_remote_filter.with_id(reply_id);
            changed = true;
        }
        if let Some(mut inbound) = up_guard.upstream_flow.inbound
            && inbound.src.id() != source_id
        {
            inbound.src = inbound.src.with_id(source_id);
            up_guard.upstream_flow.inbound = Some(inbound);
            changed = true;
        }
        if let Some(mut outbound) = up_guard.upstream_flow.outbound
            && outbound.dst.id() != reply_id
        {
            outbound.dst = outbound.dst.with_id(reply_id);
            up_guard.upstream_flow.outbound = Some(outbound);
            changed = true;
        }
        if changed {
            self.publish_version(true);
        }
        prev_ver + 1
    }
}
