use crate::cli::{IcmpReplyIdRequest, SupportedProtocol, TimeoutAction};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::ClientLockTransactionGuard;
use crate::net::icmp_support::choose_upstream_icmp_ids;
use crate::net::packet_headers::select_packet_parser;
use crate::net::socket::{
    UpstreamSocketRequest, make_socket, make_upstream_socket_for, resolve_first,
};
use pkthere_socket_policy::SocketEvidenceKey;
use pkthere_socket_policy::{ListenerWorkerSocketPolicy, ResolvedSocketPolicy, SocketRole};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use super::evidence::socket_evidence_json;
use super::version::{VersionCapacityGuard, VersionClock};
use super::{
    ClearedClientFlow, ManagerError, PublishedUpdate, RecoveryOutcome, SocketHandles,
    SocketManagerInit, SocketStateSnapshot, StateVersion, TransactionJournalEntry, TransactionLeg,
};

use super::flow::upstream_leg_flow;
use super::state::{
    ClientListenState, ListenerMetadata, SocketUpdateKind, UpstreamMetadata, UpstreamState,
};

mod reresolve;

pub(crate) struct ReresolveSummary {
    pub(crate) socket_slot: u32,
    pub(crate) handles: SocketHandles,
    pub(crate) old_locked_flow: Option<crate::flow_key::ClientFlowKey>,
    pub(crate) listener_update: SocketUpdateKind,
    pub(crate) upstream_update: SocketUpdateKind,
    pub(crate) old_listener_key: SocketEvidenceKey,
    pub(crate) new_listener_key: SocketEvidenceKey,
    pub(crate) old_upstream_key: SocketEvidenceKey,
    pub(crate) new_upstream_key: SocketEvidenceKey,
}

#[derive(Clone, Copy)]
pub(crate) struct ClientFlowUpdate {
    pub(crate) flow: ClientFlowKey,
    pub(crate) listener_flow: SocketLegFlow,
    pub(crate) connect_socket: bool,
    pub(crate) client: SocketAddr,
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
/// 1. global client-flow transaction, when applicable
/// 2. manager transactions sorted by `socket_slot`
/// 3. `client_listen`
/// 4. `upstream`
/// 5. a selected `ManagedSocket` transition mutex
pub(crate) struct SocketManager {
    transaction: Mutex<()>,
    socket_slot: u32,
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
    version: VersionClock,
}

pub(super) struct ManagerTransactionGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl SocketManager {
    pub(crate) fn establish_client_flow_group(
        managers: &[&Self],
        flow_transaction: &ClientLockTransactionGuard<'_>,
        update: ClientFlowUpdate,
    ) -> Result<Vec<PublishedUpdate>, ManagerError> {
        Self::establish_client_flow_group_with_observer(managers, flow_transaction, update, |_| {})
    }

    pub(crate) fn clear_client_flow_group(
        managers: &[&Self],
        flow_transaction: &ClientLockTransactionGuard<'_>,
    ) -> Result<ClearedClientFlow, ManagerError> {
        Self::clear_client_flow_group_with_observer(managers, flow_transaction, |_| {})
    }

    pub(super) fn clear_client_flow_group_with_observer(
        managers: &[&Self],
        flow_transaction: &ClientLockTransactionGuard<'_>,
        mut after_transition: impl FnMut(u32),
    ) -> Result<ClearedClientFlow, ManagerError> {
        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "clear shared client flow",
                io::Error::other("duplicate socket slot in shared-flow transaction"),
            ));
        }

        let transaction_guards = ordered
            .iter()
            .map(|manager| manager.lock_transaction())
            .collect::<Vec<_>>();
        let mut listener_guards = ordered
            .iter()
            .map(|manager| manager.client_listen.lock().unwrap())
            .collect::<Vec<_>>();
        let upstream_guards = ordered
            .iter()
            .map(|manager| manager.upstream_state.lock().unwrap())
            .collect::<Vec<_>>();
        let metadata_changed = listener_guards
            .iter()
            .map(|state| state.flow.is_some() || state.listener_flow != SocketLegFlow::empty())
            .collect::<Vec<_>>();
        let may_need_publication = listener_guards
            .iter()
            .zip(&metadata_changed)
            .map(|(state, metadata_changed)| *metadata_changed || state.sock.is_connected())
            .collect::<Vec<_>>();
        let mut capacities = ordered
            .iter()
            .zip(&transaction_guards)
            .zip(&may_need_publication)
            .map(|((manager, transaction), changed)| {
                changed
                    .then(|| manager.precheck_version_capacity(transaction))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut journal = ordered
            .iter()
            .map(|manager| TransactionJournalEntry {
                socket_slot: manager.socket_slot,
                leg: TransactionLeg::Listener,
                transition_attempted: false,
                transition_completed: false,
                recovery: RecoveryOutcome::NotRequired,
                forced_replacement: false,
                recovery_version: None,
            })
            .collect::<Vec<_>>();

        let mut fatal_cause: Option<String> = None;
        for index in 0..ordered.len() {
            let state = &mut listener_guards[index];
            if !state.sock.is_connected() {
                continue;
            }
            journal[index].transition_attempted = true;
            match state.sock.disconnect_connected() {
                Ok(()) => {
                    journal[index].transition_completed = true;
                    after_transition(ordered[index].socket_slot);
                }
                Err(disconnect_error) => {
                    match ordered[index].replace_listener_after_transition_failure(
                        state,
                        "replace-after-shared-flow-clear-failure",
                    ) {
                        Ok(()) => {
                            journal[index].recovery = RecoveryOutcome::Replaced;
                            journal[index].forced_replacement = true;
                        }
                        Err(replacement_error) => {
                            journal[index].recovery = RecoveryOutcome::Failed;
                            let cause = format!(
                                "listener disconnect failed ({disconnect_error}); replacement also failed: {replacement_error}"
                            );
                            match &mut fatal_cause {
                                Some(existing) => {
                                    existing.push_str("; ");
                                    existing.push_str(&cause);
                                }
                                None => fatal_cause = Some(cause),
                            }
                        }
                    }
                }
            }
        }

        for state in &mut listener_guards {
            state.flow = None;
            state.listener_flow = SocketLegFlow::empty();
        }

        let mut updates = Vec::new();
        for index in 0..ordered.len() {
            let changed =
                metadata_changed[index] || journal[index].recovery == RecoveryOutcome::Replaced;
            if !changed {
                continue;
            }
            let version = ordered[index].publish_prechecked(
                &transaction_guards[index],
                capacities[index]
                    .take()
                    .expect("changed manager has prechecked version capacity"),
            );
            if journal[index].recovery == RecoveryOutcome::Replaced {
                journal[index].recovery_version = Some(version);
            }
            updates.push(PublishedUpdate::new(SocketHandles {
                listener: Arc::clone(&listener_guards[index].metadata),
                client_sock: listener_guards[index].sock.clone(),
                upstream: Arc::clone(&upstream_guards[index].metadata),
                upstream_sock: upstream_guards[index].sock.clone(),
                version,
            }));
        }
        let dropped_handshake = flow_transaction.reset();
        if let Some(cause) = fatal_cause {
            return Err(ManagerError::TransactionFailed {
                operation: "clear shared client flow",
                cause,
                journal,
            });
        }
        Ok(ClearedClientFlow {
            updates,
            dropped_handshake,
        })
    }

    pub(super) fn establish_client_flow_group_with_observer(
        managers: &[&Self],
        flow_transaction: &ClientLockTransactionGuard<'_>,
        update: ClientFlowUpdate,
        transition_observer: impl FnMut(u32),
    ) -> Result<Vec<PublishedUpdate>, ManagerError> {
        Self::establish_client_flow_group_with_observers(
            managers,
            flow_transaction,
            update,
            |_| Ok(()),
            transition_observer,
        )
    }

    pub(super) fn establish_client_flow_group_with_observers(
        managers: &[&Self],
        flow_transaction: &ClientLockTransactionGuard<'_>,
        update: ClientFlowUpdate,
        mut before_transition: impl FnMut(u32) -> Result<(), String>,
        mut after_transition: impl FnMut(u32),
    ) -> Result<Vec<PublishedUpdate>, ManagerError> {
        if flow_transaction.is_locked() {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::other("client flow is already locked"),
            ));
        }

        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "establish shared client flow",
                io::Error::other("duplicate socket slot in shared-flow transaction"),
            ));
        }

        let transaction_guards = ordered
            .iter()
            .map(|manager| manager.lock_transaction())
            .collect::<Vec<_>>();
        let mut listener_guards = ordered
            .iter()
            .map(|manager| manager.client_listen.lock().unwrap())
            .collect::<Vec<_>>();
        let upstream_guards = ordered
            .iter()
            .map(|manager| manager.upstream_state.lock().unwrap())
            .collect::<Vec<_>>();
        let mut capacities = ordered
            .iter()
            .zip(&transaction_guards)
            .map(|(manager, transaction)| manager.precheck_version_capacity(transaction).map(Some))
            .collect::<Result<Vec<_>, _>>()?;
        let mut journal = ordered
            .iter()
            .map(|manager| TransactionJournalEntry {
                socket_slot: manager.socket_slot,
                leg: TransactionLeg::Listener,
                transition_attempted: false,
                transition_completed: false,
                recovery: RecoveryOutcome::NotRequired,
                forced_replacement: false,
                recovery_version: None,
            })
            .collect::<Vec<_>>();

        let mut failure = None;
        for (index, state) in listener_guards.iter_mut().enumerate() {
            if let Err(cause) = before_transition(ordered[index].socket_slot) {
                failure = Some((index, cause));
                break;
            }
            if !update.connect_socket && state.sock.is_connected() {
                failure = Some((
                    index,
                    String::from(
                        "listener policy requested an unconnected lock on an associated socket",
                    ),
                ));
                break;
            }
            if update.connect_socket {
                journal[index].transition_attempted = true;
                match state.sock.connect_unconnected(update.client) {
                    Ok(()) => {
                        journal[index].transition_completed = true;
                        after_transition(ordered[index].socket_slot);
                    }
                    Err(error) => {
                        failure = Some((index, error.to_string()));
                        break;
                    }
                }
            }
        }

        if let Some((failed_index, mut cause)) = failure.take() {
            for index in (0..=failed_index).rev() {
                let manager = ordered[index];
                let state = &mut listener_guards[index];
                let needs_recovery =
                    journal[index].transition_completed || journal[index].transition_attempted;
                if !needs_recovery {
                    continue;
                }
                let restored = journal[index].transition_completed
                    && state.sock.disconnect_connected().is_ok();
                if restored {
                    journal[index].recovery = RecoveryOutcome::Restored;
                    continue;
                }
                match manager.replace_listener_after_transition_failure(
                    state,
                    "replace-after-shared-flow-rollback",
                ) {
                    Ok(()) => {
                        journal[index].recovery = RecoveryOutcome::Replaced;
                        journal[index].forced_replacement = true;
                        let capacity = capacities[index]
                            .take()
                            .expect("changed manager has prechecked version capacity");
                        let version =
                            manager.publish_prechecked(&transaction_guards[index], capacity);
                        journal[index].recovery_version = Some(version);
                    }
                    Err(error) => {
                        journal[index].recovery = RecoveryOutcome::Failed;
                        cause = format!("{cause}; recovery also failed: {error}");
                    }
                }
            }
            return Err(ManagerError::TransactionFailed {
                operation: "establish shared client flow",
                cause,
                journal,
            });
        }

        for state in &mut listener_guards {
            state.flow = Some(update.flow);
            state.listener_flow = update.listener_flow;
        }

        let mut published = Vec::with_capacity(ordered.len());
        for index in 0..ordered.len() {
            let manager = ordered[index];
            let version = manager.publish_prechecked(
                &transaction_guards[index],
                capacities[index]
                    .take()
                    .expect("changed manager has prechecked version capacity"),
            );
            published.push(PublishedUpdate::new(SocketHandles {
                listener: Arc::clone(&listener_guards[index].metadata),
                client_sock: listener_guards[index].sock.clone(),
                upstream: Arc::clone(&upstream_guards[index].metadata),
                upstream_sock: upstream_guards[index].sock.clone(),
                version,
            }));
        }
        flow_transaction.publish_locked();
        Ok(published)
    }

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
        // Recreate the requested bind, not the realized kernel address. In
        // particular, a requested `:0` must obtain a fresh ephemeral port
        // while stale clones may still own the failed descriptor.
        let requested_bind = resolve_first(&self.listen_target)?;
        let (replacement, logical_local, kernel_addr, socket_type, policy) = make_socket(
            requested_bind,
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
            transaction: Mutex::new(()),
            socket_slot,
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
            version: VersionClock::new(),
        })
    }

    /// Current manager-owned topology version for lock-free dirty checks.
    #[inline]
    pub fn current_version(&self) -> StateVersion {
        self.version.current()
    }

    #[cfg(all(test, not(miri)))]
    pub(super) fn set_version_for_test(&self, version: StateVersion) {
        let _transaction = self.lock_transaction();
        self.version.set_for_test(version);
    }

    #[inline]
    pub const fn get_listener_worker_socket_policy(&self) -> ListenerWorkerSocketPolicy {
        self.listen_worker_socket_policy
    }

    #[inline]
    pub(crate) const fn socket_slot(&self) -> u32 {
        self.socket_slot
    }

    #[inline]
    fn lock_transaction(&self) -> ManagerTransactionGuard<'_> {
        ManagerTransactionGuard {
            _guard: self.transaction.lock().unwrap(),
        }
    }

    #[inline]
    fn precheck_version_capacity(
        &self,
        _transaction: &ManagerTransactionGuard<'_>,
    ) -> Result<VersionCapacityGuard, ManagerError> {
        self.version.precheck_capacity()
    }

    #[inline]
    fn publish_prechecked(
        &self,
        _transaction: &ManagerTransactionGuard<'_>,
        capacity: VersionCapacityGuard,
    ) -> StateVersion {
        self.version.publish_prechecked(capacity)
    }

    /// Establish a client flow transaction. Socket association succeeds before
    /// any flow metadata or version becomes visible.
    #[cfg(all(test, not(miri)))]
    pub fn establish_client_flow(
        &self,
        flow: ClientFlowKey,
        listener_flow: SocketLegFlow,
        connect_socket: bool,
        client: SocketAddr,
    ) -> Result<StateVersion, ManagerError> {
        let transaction = self.lock_transaction();
        let mut cl_guard = self.client_listen.lock().unwrap();
        if !connect_socket && cl_guard.sock.is_connected() {
            return Err(ManagerError::io(
                "establish client flow",
                io::Error::other(
                    "listener policy requested an unconnected lock on an associated socket",
                ),
            ));
        }
        let capacity = self.precheck_version_capacity(&transaction)?;
        if connect_socket && let Err(transition_error) = cl_guard.sock.connect_unconnected(client) {
            self.replace_listener_after_transition_failure(
                &mut cl_guard,
                "replace-after-connect-failure",
            )
            .map_err(|replacement_error| {
                ManagerError::io(
                    "recover listener after connect failure",
                    io::Error::other(format!(
                        "listener connect failed ({transition_error}); replacement also failed: {replacement_error}"
                    )),
                )
            })?;
            self.publish_prechecked(&transaction, capacity);
            return Err(ManagerError::socket(
                "connect listener for client flow",
                transition_error,
            ));
        }
        cl_guard.flow = Some(flow);
        cl_guard.listener_flow = listener_flow;
        Ok(self.publish_prechecked(&transaction, capacity))
    }

    #[inline]
    #[cfg(all(test, not(miri)))]
    pub fn clear_client_lock(&self) -> Result<StateVersion, ManagerError> {
        let transaction = self.lock_transaction();
        let mut cl_guard = self.client_listen.lock().unwrap();
        if cl_guard.flow.is_none()
            && cl_guard.listener_flow == SocketLegFlow::empty()
            && !cl_guard.sock.is_connected()
        {
            return Ok(self.current_version());
        }
        let capacity = self.precheck_version_capacity(&transaction)?;
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
            )
            .map_err(|replacement_error| {
                ManagerError::io(
                    "recover listener after disconnect failure",
                    io::Error::other(format!(
                        "listener disconnect failed ({disconnect_error}); replacement also failed: {replacement_error}"
                    )),
                )
            })?;
        }
        cl_guard.flow = None;
        cl_guard.listener_flow = SocketLegFlow::empty();
        Ok(self.publish_prechecked(&transaction, capacity))
    }

    /// Current listener local filter address.
    #[inline]
    pub fn get_listen_addr(&self) -> LogicalEndpoint {
        let _transaction = self.lock_transaction();
        self.client_listen.lock().unwrap().listen_local_filter
    }

    /// Snapshot the current client destination/connected state and protocol.
    #[inline]
    pub fn get_client_dest(&self) -> (Option<ClientFlowKey>, bool, SupportedProtocol) {
        let _transaction = self.lock_transaction();
        let cl = self.client_listen.lock().unwrap();
        (cl.flow, cl.sock.is_connected(), self.listen_proto)
    }

    /// Snapshot the current upstream destination and protocol.
    #[inline]
    pub fn get_upstream_dest(&self) -> (LogicalEndpoint, bool, SupportedProtocol) {
        let _transaction = self.lock_transaction();
        let up = self.upstream_state.lock().unwrap();
        (
            up.upstream_remote_filter,
            up.sock.is_connected(),
            self.upstream_proto,
        )
    }

    #[inline]
    pub fn snapshot_state(&self) -> SocketStateSnapshot {
        let _transaction = self.lock_transaction();
        self.snapshot_state_under_transaction()
    }

    fn snapshot_state_under_transaction(&self) -> SocketStateSnapshot {
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

    #[inline]
    pub fn refresh_handles(&self) -> SocketHandles {
        let _transaction = self.lock_transaction();
        self.refresh_handles_under_transaction()
    }

    fn refresh_handles_under_transaction(&self) -> SocketHandles {
        // Snapshot all mutable state while holding the relevant locks so the
        // returned version matches the handles we hand back.
        let cl = self.client_listen.lock().unwrap();
        let up = self.upstream_state.lock().unwrap();

        SocketHandles {
            listener: Arc::clone(&cl.metadata),
            client_sock: cl.sock.clone(),
            upstream: Arc::clone(&up.metadata),
            upstream_sock: up.sock.clone(),
            version: self.current_version(),
        }
    }

    #[inline]
    pub fn set_upstream_peer_ids(
        &self,
        source_id: u16,
        reply_id: u16,
    ) -> Result<PublishedUpdate, ManagerError> {
        let transaction = self.lock_transaction();
        let cl_guard = self.client_listen.lock().unwrap();
        let mut up_guard = self.upstream_state.lock().unwrap();
        let changed = up_guard.upstream_remote_filter.id() != reply_id
            || up_guard
                .upstream_flow
                .inbound
                .is_some_and(|inbound| inbound.src.id() != source_id)
            || up_guard
                .upstream_flow
                .outbound
                .is_some_and(|outbound| outbound.dst.id() != reply_id);
        let capacity = changed
            .then(|| self.precheck_version_capacity(&transaction))
            .transpose()?;
        if up_guard.upstream_remote_filter.id() != reply_id {
            up_guard.upstream_remote_filter = up_guard.upstream_remote_filter.with_id(reply_id);
        }
        if let Some(mut inbound) = up_guard.upstream_flow.inbound
            && inbound.src.id() != source_id
        {
            inbound.src = inbound.src.with_id(source_id);
            up_guard.upstream_flow.inbound = Some(inbound);
        }
        if let Some(mut outbound) = up_guard.upstream_flow.outbound
            && outbound.dst.id() != reply_id
        {
            outbound.dst = outbound.dst.with_id(reply_id);
            up_guard.upstream_flow.outbound = Some(outbound);
        }
        let version = match capacity {
            Some(capacity) => self.publish_prechecked(&transaction, capacity),
            None => self.current_version(),
        };
        let handles = SocketHandles {
            listener: Arc::clone(&cl_guard.metadata),
            client_sock: cl_guard.sock.clone(),
            upstream: Arc::clone(&up_guard.metadata),
            upstream_sock: up_guard.sock.clone(),
            version,
        };
        Ok(PublishedUpdate::new(handles))
    }
}
